use std::ffi::OsStr;
use std::io::{self, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crossterm::cursor::{MoveToColumn, MoveToNextLine, MoveUp};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use crossterm::{execute, queue};
use unicode_width::UnicodeWidthChar;

use crate::app::{export_display_path, resolve_export_directory_path};
use crate::export;
use crate::inventory::{self, CitySummary, NordTarget};
use crate::key::RunIdentity;
use crate::probing::{
    Attempt, AttemptOutcome, CheckMode, FullCheckPlan, ProbeOptions, WorkerMessage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

struct ColorPolicy {
    stdout: bool,
    stderr: bool,
}

impl ColorPolicy {
    fn new(choice: ColorChoice) -> Self {
        let no_color_value = std::env::var_os("NO_COLOR");
        let no_color = no_color_requested(no_color_value.as_deref());
        Self {
            stdout: color_enabled(choice, io::stdout().is_terminal(), no_color),
            stderr: color_enabled(choice, io::stderr().is_terminal(), no_color),
        }
    }

    fn out(&self, code: u8, value: impl std::fmt::Display) -> String {
        paint(self.stdout, code, value)
    }

    fn err(&self, code: u8, value: impl std::fmt::Display) -> String {
        paint(self.stderr, code, value)
    }
}

fn no_color_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn color_enabled(choice: ColorChoice, terminal: bool, no_color: bool) -> bool {
    match choice {
        ColorChoice::Auto => terminal && !no_color,
        ColorChoice::Always => true,
        ColorChoice::Never => false,
    }
}

fn paint(enabled: bool, code: u8, value: impl std::fmt::Display) -> String {
    if enabled {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

pub struct FindOptions {
    pub key_file: PathBuf,
    pub export_directory: PathBuf,
    pub query: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub refresh: bool,
    pub full: bool,
    pub ping_targets: Vec<Ipv4Addr>,
    pub resolve_names: Vec<String>,
    pub dns_server: Option<Ipv4Addr>,
    pub max_candidates: usize,
    pub color: ColorChoice,
}

impl FindOptions {
    fn check_mode(&self) -> CheckMode {
        let custom = !self.ping_targets.is_empty()
            || !self.resolve_names.is_empty()
            || self.dns_server.is_some();
        if !self.full && !custom {
            return CheckMode::HandshakeOnly;
        }

        let defaults = FullCheckPlan::default();
        CheckMode::Full(FullCheckPlan {
            ping_targets: if self.ping_targets.is_empty() {
                defaults.ping_targets
            } else {
                self.ping_targets.clone()
            },
            resolve_names: if self.resolve_names.is_empty() {
                defaults.resolve_names
            } else {
                self.resolve_names.clone()
            },
            dns_server: self.dns_server.unwrap_or(defaults.dns_server),
        })
    }
}

pub fn run(options: FindOptions) -> Result<(), String> {
    if !(1..=100).contains(&options.max_candidates) {
        return Err("--max-candidates must be from 1 through 100".into());
    }
    let export_directory = resolve_export_directory_path(&options.export_directory)?;
    let colors = ColorPolicy::new(options.color);
    let identity =
        Arc::new(RunIdentity::load(&options.key_file).map_err(|error| error.to_string())?);
    let inventory = load_inventory(options.refresh)?;
    let location = choose_location(
        &inventory,
        options.query.as_deref().unwrap_or_default(),
        options.country.as_deref(),
        options.city.as_deref(),
    )?;
    let targets = inventory::city_targets(&inventory, &location.country, &location.city);
    if targets.is_empty() {
        return Err(format!(
            "{}, {} has no usable candidates",
            location.city, location.country
        ));
    }
    println!(
        "{}: {}, {} ({} candidates)",
        colors.out(36, "Location"),
        location.city,
        location.country,
        targets.len()
    );
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|error| format!("could not install Ctrl-c handler: {error}"))?;
    let confirmed = find_first(
        Arc::clone(&identity),
        targets,
        options.max_candidates,
        options.check_mode(),
        Arc::clone(&interrupted),
        &colors,
    )?;
    if interrupted.load(Ordering::Acquire) {
        return Err("find cancelled before export".into());
    }
    let path = export::export_interruptible(
        &identity,
        &confirmed.client_public_key,
        &confirmed.target,
        &export_directory,
        &interrupted,
    )
    .map_err(|error| format!("confirmed endpoint export failed: {error}"))?;
    let display_path = export_display_path(&options.export_directory.to_string_lossy(), &path);
    println!(
        "{}: {} at {}",
        colors.out(32, "Confirmed"),
        confirmed.target.hostname,
        confirmed.target.endpoint
    );
    println!("{}: {}", colors.out(32, "Exported"), display_path.display());
    Ok(())
}

fn load_inventory(refresh: bool) -> Result<Vec<NordTarget>, String> {
    let cached = match inventory::load_cache() {
        Ok(cached) => cached,
        Err(error) => {
            eprintln!("Inventory cache ignored: {error}");
            None
        }
    };
    if !refresh && let Some(cached) = cached {
        report_cache_age(cached.fetched_at);
        return Ok(cached.targets);
    }
    match inventory::fetch() {
        Ok(targets) => {
            let fetched_at = SystemTime::now();
            if let Err(error) = inventory::store_cache(&targets, fetched_at) {
                eprintln!("Inventory cache warning: {error}");
            }
            eprintln!("Fetched current Nord inventory");
            Ok(targets)
        }
        Err(error) => {
            if let Some(cached) = cached {
                eprintln!("Inventory refresh failed; using cache: {error}");
                report_cache_age(cached.fetched_at);
                Ok(cached.targets)
            } else {
                Err(error.to_string())
            }
        }
    }
}

fn report_cache_age(fetched_at: SystemTime) {
    match cache_freshness(fetched_at, SystemTime::now()) {
        (state, Some(age)) => eprintln!(
            "Using {state} cached inventory ({} minutes old)",
            age.as_secs() / 60
        ),
        (state, None) => {
            eprintln!("Using {state} cached inventory (timestamp is in the future)")
        }
    }
}

fn cache_freshness(fetched_at: SystemTime, now: SystemTime) -> (&'static str, Option<Duration>) {
    let Ok(age) = now.duration_since(fetched_at) else {
        return ("stale", None);
    };
    if age >= inventory::CACHE_STALE_AFTER {
        ("stale", Some(age))
    } else {
        ("fresh", Some(age))
    }
}

fn choose_location(
    targets: &[NordTarget],
    query: &str,
    country: Option<&str>,
    city: Option<&str>,
) -> Result<CitySummary, String> {
    let mut choices = inventory::cities(targets, "");
    if let Some(country) = country {
        choices.retain(|choice| case_eq(&choice.country, country));
        if choices.is_empty() {
            return Err(format!(
                "no usable candidates found for country {country:?}"
            ));
        }
    }
    if let Some(city) = city {
        choices.retain(|choice| case_eq(&choice.city, city));
        if choices.is_empty() {
            return Err(format!("no usable candidates found for city {city:?}"));
        }
    }
    if choices.len() == 1 {
        return Ok(choices.remove(0));
    }
    let ranked = ranked_locations(&choices, query);
    if ranked.len() == 1 {
        return Ok(ranked[0].clone());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "location is ambiguous in non-interactive mode; provide exact --country and --city"
                .into(),
        );
    }
    inline_select(choices, query.to_owned())
}

fn ranked_locations(choices: &[CitySummary], query: &str) -> Vec<CitySummary> {
    let mut ranked: Vec<_> = choices
        .iter()
        .filter_map(|choice| {
            let label = format!("{}, {}", choice.city, choice.country);
            fuzzy_score(&label, query).map(|score| (score, choice.clone()))
        })
        .collect();
    ranked.sort_by(|(left_score, left), (right_score, right)| {
        (left_score, &left.country, &left.city).cmp(&(right_score, &right.country, &right.city))
    });
    ranked.into_iter().map(|(_, choice)| choice).collect()
}

fn fuzzy_score(candidate: &str, query: &str) -> Option<usize> {
    let candidate = candidate.to_lowercase();
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Some(0);
    }
    let mut total = 0usize;
    for term in query.split_whitespace() {
        if let Some(position) = candidate.find(term) {
            total = total.saturating_add(position);
            continue;
        }
        let mut offset = 0usize;
        let mut gap = 0usize;
        for character in term.chars() {
            let found = candidate[offset..].find(character)?;
            gap = gap.saturating_add(found);
            offset = offset.saturating_add(found + character.len_utf8());
        }
        total = total.saturating_add(100 + gap);
    }
    Some(total)
}

fn case_eq(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

fn inline_select(choices: Vec<CitySummary>, mut query: String) -> Result<CitySummary, String> {
    query.retain(|character| !character.is_control());
    enable_raw_mode().map_err(|error| format!("could not enable inline selection: {error}"))?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnableBracketedPaste) {
        let _ = disable_raw_mode();
        return Err(format!("could not enable inline paste handling: {error}"));
    }
    let _guard = InlineModeGuard;
    let mut selected = 0usize;
    let mut rendered = 0usize;
    loop {
        let matches = ranked_locations(&choices, &query);
        selected = selected.min(matches.len().min(6).saturating_sub(1));
        rendered = match draw_selector(&mut stdout, &query, &matches, selected, rendered) {
            Ok(rendered) => rendered,
            Err(error) => {
                clear_selector(&mut stdout, rendered).ok();
                return Err(format!("could not draw location selector: {error}"));
            }
        };
        let event = match event::read() {
            Ok(event) => event,
            Err(error) => {
                clear_selector(&mut stdout, rendered).ok();
                return Err(format!("could not read location selection: {error}"));
            }
        };
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    clear_selector(&mut stdout, rendered).ok();
                    return Err("location selection cancelled".into());
                }
                KeyCode::Esc => {
                    clear_selector(&mut stdout, rendered).ok();
                    return Err("location selection cancelled".into());
                }
                KeyCode::Char(character)
                    if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                        && !character.is_control() =>
                {
                    query.push(character);
                    selected = 0;
                }
                KeyCode::Backspace => {
                    query.pop();
                    selected = 0;
                }
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => {
                    selected = (selected + 1).min(matches.len().min(6).saturating_sub(1));
                }
                KeyCode::Enter if !matches.is_empty() => {
                    let choice = matches[selected].clone();
                    clear_selector(&mut stdout, rendered).ok();
                    return Ok(choice);
                }
                _ => {}
            },
            Event::Paste(value) => {
                append_query(&mut query, value.trim());
                selected = 0;
            }
            _ => {}
        }
    }
}

fn draw_selector(
    stdout: &mut io::Stdout,
    query: &str,
    matches: &[CitySummary],
    selected: usize,
    previous_lines: usize,
) -> io::Result<usize> {
    let width = crossterm::terminal::size()
        .map(|(width, _)| usize::from(width))
        .unwrap_or(80);
    let mut lines = vec![
        format!("Location: {query}"),
        "Type a city or country; Up/Down select; Enter confirms; Esc cancels".into(),
    ];
    if matches.is_empty() {
        lines.push("  No matching locations".into());
    } else {
        lines.extend(matches.iter().take(6).enumerate().map(|(index, choice)| {
            format!(
                "{} {}, {}  ({} candidates)",
                if index == selected { ">" } else { " " },
                choice.city,
                choice.country,
                choice.count
            )
        }));
    }
    let rendered = previous_lines.max(lines.len());
    if previous_lines > 0 {
        queue!(stdout, MoveUp(previous_lines as u16))?;
    }
    for index in 0..rendered {
        let line = lines.get(index).map_or("", String::as_str);
        queue!(
            stdout,
            MoveToColumn(0),
            Clear(ClearType::CurrentLine),
            crossterm::style::Print(truncate(line, width.saturating_sub(1))),
            MoveToNextLine(1)
        )?;
    }
    stdout.flush()?;
    Ok(rendered)
}

fn clear_selector(stdout: &mut io::Stdout, rendered: usize) -> io::Result<()> {
    if rendered > 0 {
        queue!(
            stdout,
            MoveUp(rendered as u16),
            MoveToColumn(0),
            Clear(ClearType::FromCursorDown)
        )?;
    }
    stdout.flush()
}

fn truncate(value: &str, width: usize) -> String {
    let mut used = 0usize;
    value
        .chars()
        .take_while(|character| {
            let character_width = character.width().unwrap_or(0);
            if used.saturating_add(character_width) > width {
                false
            } else {
                used = used.saturating_add(character_width);
                true
            }
        })
        .collect()
}

fn append_query(query: &mut String, value: &str) {
    query.extend(value.chars().filter(|character| !character.is_control()));
}

struct InlineModeGuard;

impl Drop for InlineModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), DisableBracketedPaste);
    }
}

fn find_first(
    identity: Arc<RunIdentity>,
    targets: Vec<NordTarget>,
    max_candidates: usize,
    mode: CheckMode,
    interrupted: Arc<AtomicBool>,
    colors: &ColorPolicy,
) -> Result<Attempt, String> {
    if let CheckMode::Full(checks) = &mode {
        let ping_targets = checks
            .ping_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let resolve_names = checks.resolve_names.join(", ");
        eprintln!(
            "{}: handshake; ping {ping_targets}; resolve {resolve_names} through DNS {}",
            colors.err(36, "Full checks"),
            checks.dns_server
        );
    }
    let options = ProbeOptions {
        desired_confirmed: 1,
        max_candidates: max_candidates.min(targets.len()),
        mode,
    };
    eprintln!(
        "{} up to {} candidates; stopping after the first confirmation",
        colors.err(36, "Probing"),
        options.max_candidates
    );
    let worker =
        crate::probing::start_with_cancel(identity, targets, options, Arc::clone(&interrupted));
    let mut confirmed = None;
    let mut completed = 0usize;
    let mut fatal = None;
    let mut cancelling = false;
    loop {
        if interrupted.load(Ordering::Acquire) && !cancelling {
            worker.cancel();
            cancelling = true;
            eprintln!(
                "{}: waiting for active probes to finish",
                colors.err(33, "Cancelling")
            );
        }
        let message = match worker.receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(message) => message,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("probe coordinator disconnected before completion".into());
            }
        };
        match message {
            WorkerMessage::Started { id, target } => {
                eprintln!(
                    "{} probing {} at {}",
                    colors.err(36, format!("[{id}]")),
                    target.hostname,
                    target.endpoint
                );
            }
            WorkerMessage::Phase { id, event } => match event.kind {
                wgprobe::ProbeEventKind::Started => {
                    let target = event
                        .target
                        .as_deref()
                        .map(|target| format!(" ({target})"))
                        .unwrap_or_default();
                    eprintln!(
                        "{} starting {}{}",
                        colors.err(36, format!("[{id}]")),
                        event.phase,
                        target
                    );
                }
                wgprobe::ProbeEventKind::Finished => {
                    if let Some(result) = event.result {
                        let (code, status) = match result.status {
                            wgprobe::PhaseStatus::Passed => (32, "passed"),
                            wgprobe::PhaseStatus::Sent => (36, "sent"),
                            wgprobe::PhaseStatus::Unconfirmed => (33, "unconfirmed"),
                            wgprobe::PhaseStatus::Skipped => (90, "skipped"),
                            wgprobe::PhaseStatus::Error => (31, "error"),
                        };
                        let detail = result
                            .detail
                            .as_deref()
                            .map(|detail| format!("; {detail}"))
                            .unwrap_or_default();
                        eprintln!(
                            "{} {}: {} ({} ms){}",
                            colors.err(36, format!("[{id}]")),
                            result.phase,
                            colors.err(code, status),
                            result.duration_ms,
                            detail
                        );
                    }
                }
            },
            WorkerMessage::Pacing(_) => {}
            WorkerMessage::Finished(attempt) => {
                completed += 1;
                eprintln!(
                    "[{}] {}: {}",
                    attempt.id,
                    attempt.target.hostname,
                    colored_outcome(colors, &attempt.outcome)
                );
                if confirmed.is_none() && attempt.outcome == AttemptOutcome::Confirmed {
                    confirmed = Some(*attempt);
                }
            }
            WorkerMessage::Fatal(error) => fatal = Some(error),
            WorkerMessage::Complete { .. } => break,
        }
    }
    if let Some(error) = fatal {
        return Err(error);
    }
    if cancelling {
        return Err(format!(
            "find cancelled after {completed} completed attempts"
        ));
    }
    confirmed.ok_or_else(|| format!("no endpoint confirmed after {completed} completed attempts"))
}

fn outcome_name(outcome: &AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Confirmed => "CONFIRMED",
        AttemptOutcome::Unconfirmed => "UNCONFIRMED",
        AttemptOutcome::Error(_) => "ERROR",
    }
}

fn colored_outcome(colors: &ColorPolicy, outcome: &AttemptOutcome) -> String {
    match outcome {
        AttemptOutcome::Confirmed => colors.err(32, outcome_name(outcome)),
        AttemptOutcome::Unconfirmed => colors.err(33, outcome_name(outcome)),
        AttemptOutcome::Error(_) => colors.err(31, outcome_name(outcome)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn target(country: &str, city: &str) -> NordTarget {
        NordTarget {
            name: city.into(),
            hostname: format!("{}.example", city.to_ascii_lowercase()),
            endpoint: "192.0.2.1:51820".parse::<SocketAddr>().unwrap(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            country: country.into(),
            city: city.into(),
            load: 1,
        }
    }

    #[test]
    fn fuzzy_query_finds_denver() {
        let choices = vec![
            CitySummary {
                country: "United States".into(),
                city: "Atlanta".into(),
                count: 1,
            },
            CitySummary {
                country: "United States".into(),
                city: "Denver".into(),
                count: 2,
            },
        ];
        let ranked = ranked_locations(&choices, "denv");
        assert_eq!(ranked[0].city, "Denver");
    }

    #[test]
    fn exact_country_and_city_select_without_prompt() {
        let targets = vec![
            target("United States", "Denver"),
            target("United Kingdom", "Denver"),
        ];
        let selected =
            choose_location(&targets, "", Some("united states"), Some("denver")).unwrap();
        assert_eq!(selected.country, "United States");
    }

    #[test]
    fn rejects_invalid_candidate_budget_before_network_work() {
        let options = FindOptions {
            key_file: "missing".into(),
            export_directory: "exports".into(),
            query: None,
            country: None,
            city: None,
            refresh: false,
            full: false,
            ping_targets: Vec::new(),
            resolve_names: Vec::new(),
            dns_server: None,
            max_candidates: 0,
            color: ColorChoice::Never,
        };
        assert!(run(options).unwrap_err().contains("max-candidates"));
    }

    #[test]
    fn selector_text_drops_controls_and_respects_display_width() {
        let mut query = String::new();
        append_query(&mut query, "den\n\u{1b}[31mver");
        assert_eq!(query, "den[31mver");
        assert_eq!(truncate("界界", 3), "界");
    }

    #[test]
    fn exact_matching_uses_unicode_lowercase() {
        assert!(case_eq("MÜNCHEN", "münchen"));
    }

    #[test]
    fn preexisting_interrupt_prevents_probe_start() {
        let identity =
            Arc::new(RunIdentity::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap());
        let interrupted = Arc::new(AtomicBool::new(true));

        let error = find_first(
            identity,
            vec![target("United States", "Denver")],
            1,
            CheckMode::HandshakeOnly,
            interrupted,
            &ColorPolicy::new(ColorChoice::Never),
        )
        .unwrap_err();

        assert!(error.contains("cancelled after 0 completed attempts"));
    }

    #[test]
    fn custom_targets_enable_full_checks_and_replace_defaults() {
        let options = FindOptions {
            key_file: "missing".into(),
            export_directory: "exports".into(),
            query: None,
            country: None,
            city: None,
            refresh: false,
            full: false,
            ping_targets: vec![Ipv4Addr::new(8, 8, 8, 8)],
            resolve_names: vec!["google.com".into()],
            dns_server: Some(Ipv4Addr::new(8, 8, 4, 4)),
            max_candidates: 1,
            color: ColorChoice::Never,
        };

        assert_eq!(
            options.check_mode(),
            CheckMode::Full(FullCheckPlan {
                ping_targets: vec![Ipv4Addr::new(8, 8, 8, 8)],
                resolve_names: vec!["google.com".into()],
                dns_server: Ipv4Addr::new(8, 8, 4, 4),
            })
        );
    }

    #[test]
    fn explicit_color_policy_adds_or_omits_ansi() {
        assert_eq!(paint(false, 32, "ok"), "ok");
        assert_eq!(paint(true, 32, "ok"), "\x1b[32mok\x1b[0m");
    }

    #[test]
    fn color_policy_honors_nonempty_no_color_and_explicit_modes() {
        assert!(!no_color_requested(None));
        assert!(!no_color_requested(Some(OsStr::new(""))));
        assert!(no_color_requested(Some(OsStr::new("1"))));
        assert!(color_enabled(ColorChoice::Auto, true, false));
        assert!(!color_enabled(ColorChoice::Auto, false, false));
        assert!(!color_enabled(ColorChoice::Auto, true, true));
        assert!(color_enabled(ColorChoice::Always, false, true));
        assert!(!color_enabled(ColorChoice::Never, true, false));
    }

    #[test]
    fn outcome_colors_match_status_semantics() {
        let colors = ColorPolicy {
            stdout: true,
            stderr: true,
        };
        assert!(colored_outcome(&colors, &AttemptOutcome::Confirmed).contains("[32m"));
        assert!(colored_outcome(&colors, &AttemptOutcome::Unconfirmed).contains("[33m"));
        assert!(colored_outcome(&colors, &AttemptOutcome::Error("test".into())).contains("[31m"));
    }

    #[test]
    fn future_dated_cache_is_stale() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let future = now + Duration::from_secs(1);

        assert_eq!(cache_freshness(future, now), ("stale", None));
    }
}

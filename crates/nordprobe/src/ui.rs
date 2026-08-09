use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use zeroize::Zeroizing;

use crate::app::{App, KeySource, Screen};
use crate::probing::{AttemptOutcome, CheckMode};

const ACCENT: Color = Color::Rgb(116, 154, 255);
const MUTED: Color = Color::Rgb(130, 140, 160);

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(10, 14, 24))),
        area,
    );
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);
    draw_header(frame, sections[0], app.screen);
    match app.screen {
        Screen::Setup => draw_setup(frame, sections[1], app),
        Screen::Loading => draw_loading(frame, sections[1], app),
        Screen::Locations => draw_locations(frame, sections[1], app),
        Screen::ProbeSetup => draw_probe_setup(frame, sections[1], app),
        Screen::Probing => draw_probing(frame, sections[1], app),
        Screen::Error => draw_error(frame, sections[1], app),
    }
    draw_help(frame, sections[2], app.screen);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, screen: Screen) {
    let step = match screen {
        Screen::Setup => "01 SETUP",
        Screen::Loading => "02 INVENTORY",
        Screen::Locations => "03 LOCATION",
        Screen::ProbeSetup | Screen::Probing => "04 PROBE",
        Screen::Error => "ERROR",
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " NORDPROBE ",
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(step, Style::default().fg(MUTED)),
            Span::raw("  WireGuard endpoint verification"),
        ]))
        .block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn draw_setup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let inner = centered(area, 82, 24);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new("Load one WireGuard identity from a private-key file or paste it once. On Unix, create a key file with `nordprobe key fetch --output PATH`. Pasted input is masked, validated into zeroizing memory, and cleared before inventory loads.")
            .wrap(Wrap { trim: true }),
        rows[0],
    );
    let source_border = if app.setup_focus == 0 { ACCENT } else { MUTED };
    frame.render_widget(
        Paragraph::new(match app.key_source {
            KeySource::File => "[ FILE ]   PASTE ONCE",
            KeySource::PasteOnce => "  FILE   [ PASTE ONCE ]",
        })
        .block(
            Block::default()
                .title(" Key source (left/right) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(source_border)),
        ),
        rows[1],
    );
    let key_value = Zeroizing::new(match app.key_source {
        KeySource::File => masked_path_value(&app.key_path),
        KeySource::PasteOnce
            if app.pasted_key.is_empty() && app.identity_public_key().is_some() =>
        {
            "(loaded in memory; type or paste to replace)".into()
        }
        KeySource::PasteOnce if app.reveal_pasted_key => app.pasted_key.to_string(),
        KeySource::PasteOnce => "*".repeat(app.pasted_key.chars().count()),
    });
    let key_title = match app.key_source {
        KeySource::File => " Private-key file path ",
        KeySource::PasteOnce if app.reveal_pasted_key => " Pasted private key (F2 hide) ",
        KeySource::PasteOnce => " Pasted private key (F2 show) ",
    };
    let key_border = if app.setup_focus == 1 { ACCENT } else { MUTED };
    frame.render_widget(
        Paragraph::new(key_value.as_str())
            .scroll((
                0,
                horizontal_scroll(&key_value, rows[2].width.saturating_sub(2)),
            ))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .title(key_title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(key_border)),
            ),
        rows[2],
    );
    let export_border = if app.setup_focus == 2 { ACCENT } else { MUTED };
    let export_value = Zeroizing::new(masked_path_value(&app.export_directory));
    frame.render_widget(
        Paragraph::new(export_value.as_str())
            .scroll((
                0,
                horizontal_scroll(&export_value, rows[3].width.saturating_sub(2)),
            ))
            .block(
                Block::default()
                    .title(" Export directory ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(export_border)),
            ),
        rows[3],
    );
    match app.setup_focus {
        1 => set_text_cursor(frame, rows[2], &key_value),
        2 => set_text_cursor(frame, rows[3], &export_value),
        _ => {}
    }
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                app.identity_public_key().map_or_else(
                    || "Identity: not loaded".to_owned(),
                    |key| format!("Identity loaded; client public key: {key}"),
                ),
                Style::default().fg(MUTED),
            ),
            Line::styled(&app.status, Style::default().fg(MUTED)),
        ]),
        rows[4],
    );
    frame.render_widget(
        Paragraph::new("No key source is selected automatically. Tab moves between controls; Enter validates and continues. Paste mode never saves the source key, but exported WireGuard configurations contain it. Clipboard history remains outside nordprobe's control.")
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: true }),
        rows[5],
    );
}

fn draw_loading(frame: &mut Frame<'_>, area: Rect, app: &App) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "FETCHING PUBLIC INVENTORY",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(&app.status),
            Line::raw("API status supplies candidates only. A probe is required for confirmation."),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL)),
        centered(area, 72, 9),
    );
}

fn draw_locations(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .margin(1)
        .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(app.inventory_summary(), Style::default().fg(MUTED)),
            Line::styled(&app.status, Style::default().fg(MUTED)),
        ]),
        rows[0],
    );
    let filter_border = if app.location_focus == 0 {
        ACCENT
    } else {
        MUTED
    };
    frame.render_widget(
        Paragraph::new(app.filter.as_str())
            .scroll((
                0,
                horizontal_scroll(&app.filter, rows[1].width.saturating_sub(2)),
            ))
            .block(
                Block::default()
                    .title(" Country or city filter ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(filter_border)),
            ),
        rows[1],
    );
    if app.location_focus == 0 {
        set_text_cursor(frame, rows[1], &app.filter);
    }
    let items: Vec<_> = app
        .cities
        .iter()
        .map(|city| {
            ListItem::new(format!(
                "{:<28} {:<24} {:>4} candidates",
                city.country, city.city, city.count
            ))
        })
        .collect();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.selected_city));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(format!(" Locations ({}) ", app.cities.len()))
                    .borders(Borders::ALL),
            )
            .highlight_symbol(" > ")
            .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        rows[2],
        &mut state,
    );
}

fn draw_probe_setup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let city = app
        .selected_targets
        .first()
        .map(|target| format!("{}, {}", target.city, target.country))
        .unwrap_or_else(|| "No location".into());
    let options = [
        format!(
            "Confirmation goal           {}",
            app.options.desired_confirmed
        ),
        format!("Candidate budget           {}", app.options.max_candidates),
        format!(
            "Check mode                  {}",
            match &app.options.mode {
                CheckMode::HandshakeOnly => "HANDSHAKE ONLY",
                CheckMode::Full(_) => "FULL CHECKS",
            }
        ),
    ];
    let lines = options.into_iter().enumerate().map(|(index, text)| {
        if app.option_focus == index {
            Line::styled(
                format!(" > {text}"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )
        } else {
            Line::raw(format!("   {text}"))
        }
    });
    let mut content: Vec<Line<'_>> = vec![
        Line::styled(
            city,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!(
            "{} inventory candidates",
            app.selected_targets.len()
        )),
        Line::raw(""),
    ];
    content.extend(lines);
    content.extend([
        Line::raw(""),
        Line::raw("The budget can exceed the goal so failures have fallback candidates."),
        Line::styled("FULL DEFAULTS", Style::default().fg(MUTED).add_modifier(Modifier::BOLD)),
        Line::raw("Address 10.5.0.2/32  DNS 103.86.96.100  AllowedIPs 0.0.0.0/0"),
        Line::raw("Ping 1.1.1.1  Resolve example.com"),
        Line::raw(""),
        Line::raw("Maximum four public-key groups run concurrently. Starts in one group are at least six seconds apart."),
        Line::styled(&app.status, Style::default().fg(MUTED)),
    ]);
    frame.render_widget(
        Paragraph::new(content)
            .wrap(Wrap { trim: false })
            .block(Block::default().title(" Probe plan ").borders(Borders::ALL)),
        centered(area, 88, 19),
    );
}

fn draw_probing(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .margin(1)
        .split(area);
    let city = app
        .selected_targets
        .first()
        .map(|target| format!("{}, {}", target.city, target.country))
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(format!(
                "{city}  |  plan {}  |  {}",
                app.planned_targets.len(),
                mode_name(&app.options.mode)
            )),
            Line::raw(format!(
                "Goal {}  |  confirmed {}  |  done {}  |  active {}  |  {:.1}s",
                app.options.desired_confirmed,
                app.confirmed_count(),
                app.attempts.len(),
                app.active.len(),
                app.elapsed().as_secs_f32()
            )),
            if app.pacing.is_zero() {
                Line::raw(&app.status)
            } else {
                Line::raw(format!(
                    "Same-key handshake gate: {:.1}s    {}",
                    app.pacing.as_secs_f32(),
                    app.status
                ))
            },
        ])
        .block(Block::default().title(" Run ").borders(Borders::ALL)),
        rows[0],
    );

    let mut activity = Vec::new();
    if let Some(attempt) = app.attempts.last() {
        let duration = attempt
            .report
            .as_ref()
            .map_or(0, |report| report.duration_ms);
        activity.push(ListItem::new(format!(
            "LAST {:<11} {:<16} {:<21} {:>5}ms",
            outcome_name(&attempt.outcome),
            attempt.target.hostname,
            attempt.target.endpoint,
            duration
        )));
    }
    activity.extend(app.active.iter().map(|probe| {
        ListItem::new(format!(
            "ACTIVE G{:02} {:<16} {:<21} {}",
            app.group_number(&probe.target.public_key),
            probe.target.hostname,
            probe.target.endpoint,
            probe.phase
        ))
    }));
    if activity.is_empty() {
        activity.push(ListItem::new("Waiting for the first probe to start"));
    }
    frame.render_widget(
        List::new(activity).block(Block::default().title(" Activity ").borders(Borders::ALL)),
        rows[1],
    );

    let plan: Vec<_> = app
        .planned_targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let attempt = app
                .attempts
                .iter()
                .find(|attempt| attempt.target == *target);
            let active = app.active.iter().any(|active| active.target == *target);
            let (label, style) = if let Some(attempt) = attempt {
                if app.exported_path(attempt.id).is_some() {
                    ("[E] EXPORTED", Style::default().fg(ACCENT))
                } else {
                    match &attempt.outcome {
                        AttemptOutcome::Confirmed => {
                            ("[+] CONFIRMED", Style::default().fg(Color::Green))
                        }
                        AttemptOutcome::Unconfirmed => {
                            ("[-] UNCONFIRMED", Style::default().fg(Color::Yellow))
                        }
                        AttemptOutcome::Error(_) => ("[!] ERROR", Style::default().fg(Color::Red)),
                    }
                }
            } else if active {
                ("[~] ACTIVE", Style::default().fg(ACCENT))
            } else if app.cancelling || app.run_cancelled() {
                ("[x] CANCELLED", Style::default().fg(MUTED))
            } else if app.goal_reached() {
                ("[=] NOT NEEDED", Style::default().fg(MUTED))
            } else if app.run_finished() {
                ("[ ] SKIPPED", Style::default().fg(MUTED))
            } else {
                ("[ ] PENDING", Style::default().fg(MUTED))
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<18}", label), style),
                Span::raw(format!(
                    "P{:02} G{:02} {:<16} {:<21} {:>3}%",
                    index + 1,
                    app.group_number(&target.public_key),
                    target.hostname,
                    target.endpoint,
                    target.load
                )),
            ]))
        })
        .collect();
    let mut plan_state =
        ListState::default().with_selected((!plan.is_empty()).then_some(app.plan_selected));
    frame.render_stateful_widget(
        List::new(plan)
            .block(
                Block::default()
                    .title(" Attempt plan ")
                    .borders(Borders::ALL),
            )
            .highlight_symbol(" > ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD)),
        rows[2],
        &mut plan_state,
    );
    let detail = app.planned_targets.get(app.plan_selected).map_or_else(
        || "No candidate is selected.".to_owned(),
        |target| {
            if let Some(attempt) = app.selected_attempt() {
                if let Some(path) = app.exported_path(attempt.id) {
                    return format!(
                        "Attempt #{} confirmed and exported to {}.",
                        attempt.id,
                        path.display()
                    );
                }
                return match &attempt.outcome {
                    AttemptOutcome::Confirmed => format!(
                        "Attempt #{} confirmed {} at {}. Press e to export this selected candidate.",
                        attempt.id, attempt.target.hostname, attempt.target.endpoint
                    ),
                    AttemptOutcome::Unconfirmed => format!(
                        "Attempt #{} was unconfirmed: no authenticated handshake response arrived before the deadline.",
                        attempt.id
                    ),
                    AttemptOutcome::Error(error) => {
                        format!("Attempt #{} error: {error}", attempt.id)
                    }
                };
            }
            if let Some(active) = app.active.iter().find(|active| active.target == *target) {
                format!(
                    "Probing {} at {}: {}.",
                    target.hostname, target.endpoint, active.phase
                )
            } else if app.cancelling || app.run_cancelled() {
                format!(
                    "Candidate {} at {} will not be attempted because cancellation was requested.",
                    target.hostname, target.endpoint
                )
            } else if app.goal_reached() {
                format!(
                    "Candidate {} at {} was not needed because the confirmation goal was reached.",
                    target.hostname, target.endpoint
                )
            } else if app.run_finished() {
                format!(
                    "Candidate {} at {} was not attempted before the run ended.",
                    target.hostname, target.endpoint
                )
            } else {
                format!("Pending candidate {} at {}.", target.hostname, target.endpoint)
            }
        },
    );
    frame.render_widget(
        Paragraph::new(detail).wrap(Wrap { trim: true }).block(
            Block::default()
                .title(" Selected detail ")
                .borders(Borders::ALL),
        ),
        rows[3],
    );
}

fn draw_error(frame: &mut Frame<'_>, area: Rect, app: &App) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "OPERATION FAILED",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(&app.error),
            Line::raw(""),
            Line::styled("Press Esc to return to setup.", Style::default().fg(MUTED)),
        ])
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL)),
        centered(area, 76, 12),
    );
}

fn draw_help(frame: &mut Frame<'_>, area: Rect, screen: Screen) {
    let controls = match screen {
        Screen::Setup => {
            "Tab field  |  arrows change source  |  F2 show/hide paste  |  Enter continue  |  Ctrl-c quit"
        }
        Screen::Loading => "Esc back  |  q/Ctrl-c quit",
        Screen::Locations => {
            "Tab filter/list  |  arrows select  |  Ctrl-r refresh loads  |  Enter choose  |  Esc back  |  Ctrl-c quit"
        }
        Screen::ProbeSetup => {
            "Tab option  |  arrows adjust  |  Enter start  |  Esc back  |  q/Ctrl-c quit"
        }
        Screen::Probing => {
            "arrows inspect plan  |  e export selected confirmed  |  Esc cancel/back  |  q/Ctrl-c quit"
        }
        Screen::Error => "Esc setup  |  q/Ctrl-c quit",
    };
    frame.render_widget(
        Paragraph::new(controls)
            .alignment(Alignment::Center)
            .style(Style::default().fg(MUTED)),
        area,
    );
}

fn mode_name(mode: &CheckMode) -> &'static str {
    match mode {
        CheckMode::HandshakeOnly => "handshake only",
        CheckMode::Full(_) => "full checks",
    }
}

fn outcome_name(outcome: &AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Confirmed => "CONFIRMED",
        AttemptOutcome::Unconfirmed => "UNCONFIRMED",
        AttemptOutcome::Error(_) => "ERROR",
    }
}

fn masked_path_value(value: &str) -> String {
    let mut masked = String::with_capacity(value.len());
    let mut run = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '=') {
            run.push(character);
        } else {
            push_masked_run(&mut masked, &run);
            run.clear();
            masked.push(character);
        }
    }
    push_masked_run(&mut masked, &run);
    masked
}

fn push_masked_run(output: &mut String, run: &str) {
    if run.len() >= 12 {
        output.push_str(&"*".repeat(run.chars().count()));
    } else {
        output.push_str(run);
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 2),
            Constraint::Length(height.min(area.height)),
            Constraint::Min(0),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(width) / 2),
            Constraint::Length(width.min(area.width)),
            Constraint::Min(0),
        ])
        .split(vertical[1])[1]
}

fn horizontal_scroll(value: &str, width: u16) -> u16 {
    let length = value.chars().count().min(usize::from(u16::MAX)) as u16;
    length.saturating_sub(width.saturating_sub(1))
}

fn set_text_cursor(frame: &mut Frame<'_>, area: Rect, value: &str) {
    let width = area.width.saturating_sub(2);
    let length = value.chars().count().min(usize::from(u16::MAX)) as u16;
    let scroll = horizontal_scroll(value, width);
    frame.set_cursor_position(Position::new(
        area.x + 1 + length.saturating_sub(scroll).min(width.saturating_sub(1)),
        area.y + 1,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_key_like_runs_without_hiding_normal_default_path() {
        assert_eq!(
            masked_path_value("./nordprobe-exports"),
            "./nordprobe-exports"
        );
        let masked = masked_path_value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert_eq!(masked.len(), 44);
        assert!(masked.chars().all(|character| character == '*'));
    }
}

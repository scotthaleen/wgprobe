use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::{Zeroize, Zeroizing};

use crate::export;
use crate::inventory::{self, CitySummary, NordTarget};
use crate::key::RunIdentity;
use crate::probing::{
    self, Attempt, AttemptOutcome, CheckMode, FullCheckPlan, ProbeOptions, WorkerMessage, WorkerRun,
};
use crate::scheduler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Setup,
    Loading,
    Locations,
    ProbeSetup,
    Probing,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEndReason {
    GoalReached,
    Exhausted,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    File,
    PasteOnce,
}

pub struct App {
    pub screen: Screen,
    pub setup_focus: usize,
    pub key_source: KeySource,
    pub key_path: Zeroizing<String>,
    pub pasted_key: Zeroizing<String>,
    pub reveal_pasted_key: bool,
    pub export_directory: Zeroizing<String>,
    pub inventory: Vec<NordTarget>,
    pub filter: String,
    pub cities: Vec<CitySummary>,
    pub selected_city: usize,
    pub location_focus: usize,
    pub selected_targets: Vec<NordTarget>,
    pub option_focus: usize,
    pub options: ProbeOptions,
    pub active: Vec<ActiveProbe>,
    pub attempts: Vec<Attempt>,
    pub planned_targets: Vec<NordTarget>,
    pub plan_selected: usize,
    pub pacing: Duration,
    pub status: String,
    pub error: String,
    pub should_quit: bool,
    pub cancelling: bool,
    pub probe_started: Option<Instant>,
    pub probe_elapsed: Option<Duration>,
    pub run_end_reason: Option<RunEndReason>,
    pub inventory_fetched_at: Option<SystemTime>,
    pub inventory_from_cache: bool,
    pub exported_paths: Vec<PathBuf>,
    pub exported_attempts: HashMap<u64, PathBuf>,
    identity: Option<Arc<RunIdentity>>,
    validated_export_directory: Option<PathBuf>,
    inventory_rx: Option<Receiver<Result<InventoryUpdate, String>>>,
    refreshing_inventory: bool,
    worker: Option<WorkerRun>,
    worker_fatal: Option<String>,
}

#[derive(Debug)]
pub struct ActiveProbe {
    pub id: u64,
    pub target: NordTarget,
    pub phase: String,
}

struct InventoryUpdate {
    targets: Vec<NordTarget>,
    fetched_at: SystemTime,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Setup,
            setup_focus: 0,
            key_source: KeySource::File,
            key_path: Zeroizing::new(String::new()),
            pasted_key: Zeroizing::new(String::new()),
            reveal_pasted_key: false,
            export_directory: Zeroizing::new("./nordprobe-exports".into()),
            inventory: Vec::new(),
            filter: String::new(),
            cities: Vec::new(),
            selected_city: 0,
            location_focus: 0,
            selected_targets: Vec::new(),
            option_focus: 0,
            options: ProbeOptions {
                desired_confirmed: 3,
                max_candidates: 12,
                mode: CheckMode::HandshakeOnly,
            },
            active: Vec::new(),
            attempts: Vec::new(),
            planned_targets: Vec::new(),
            plan_selected: 0,
            pacing: Duration::ZERO,
            status: String::new(),
            error: String::new(),
            should_quit: false,
            cancelling: false,
            probe_started: None,
            probe_elapsed: None,
            run_end_reason: None,
            inventory_fetched_at: None,
            inventory_from_cache: false,
            exported_paths: Vec::new(),
            exported_attempts: HashMap::new(),
            identity: None,
            validated_export_directory: None,
            inventory_rx: None,
            refreshing_inventory: false,
            worker: None,
            worker_fatal: None,
        }
    }

    pub fn tick(&mut self) {
        self.tick_inventory();
        self.tick_worker();
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        let editing_text = self.screen == Screen::Setup
            || (self.screen == Screen::Locations && self.location_focus == 0);
        if quit_requested(key, editing_text) {
            self.should_quit = true;
            return;
        }
        match self.screen {
            Screen::Setup => self.key_setup(key),
            Screen::Loading => {
                if key.code == KeyCode::Esc {
                    self.inventory_rx = None;
                    self.screen = if self.refreshing_inventory && !self.inventory.is_empty() {
                        Screen::Locations
                    } else {
                        Screen::Setup
                    };
                    self.refreshing_inventory = false;
                }
            }
            Screen::Locations => self.key_locations(key),
            Screen::ProbeSetup => self.key_probe_setup(key.code),
            Screen::Probing => self.key_probing(key.code),
            Screen::Error => {
                if key.code == KeyCode::Esc {
                    self.screen = Screen::Setup;
                }
            }
        }
    }

    pub fn handle_paste(&mut self, value: &str) {
        if self.screen != Screen::Setup {
            return;
        }
        let value = value.trim();
        if looks_like_private_key(value)
            && !(self.setup_focus == 1 && self.key_source == KeySource::PasteOnce)
        {
            self.status = "That paste is a private key; switch Key source to PASTE ONCE".into();
            return;
        }
        match self.setup_focus {
            1 if self.key_source == KeySource::File => {
                self.key_path.clear();
                self.key_path.push_str(value);
                self.identity = None;
            }
            1 => {
                if !value.chars().all(is_key_character) {
                    self.status =
                        "Paste rejected: a WireGuard key contains only base64 characters".into();
                    return;
                }
                self.pasted_key.zeroize();
                self.pasted_key.push_str(value);
                self.identity = None;
                self.status = "Private key pasted; press Enter to load it into memory".into();
            }
            2 => {
                self.export_directory.clear();
                self.export_directory.push_str(value);
                self.validated_export_directory = None;
            }
            _ => {}
        }
    }

    pub fn preload_key_file(&mut self, path: PathBuf) -> Result<(), String> {
        let export_input = self.export_directory.trim().to_owned();
        let export_directory = self
            .validated_export_directory
            .clone()
            .map_or_else(|| resolve_export_directory(&export_input), Ok)?;
        let identity = RunIdentity::load(&path).map_err(|error| error.to_string())?;
        self.key_source = KeySource::File;
        self.key_path = Zeroizing::new(path.display().to_string());
        self.identity = Some(Arc::new(identity));
        self.validated_export_directory = Some(export_directory);
        self.continue_after_identity();
        Ok(())
    }

    pub fn set_export_directory(&mut self, path: PathBuf) -> Result<(), String> {
        if path.as_os_str().is_empty() {
            return Err("Enter an export directory".into());
        }
        let resolved = resolve_export_directory_path(&path)?;
        self.export_directory = Zeroizing::new(path.to_string_lossy().into_owned());
        self.validated_export_directory = Some(resolved);
        Ok(())
    }

    pub fn identity_public_key(&self) -> Option<&str> {
        self.identity.as_deref().map(RunIdentity::public_key)
    }

    pub fn elapsed(&self) -> Duration {
        self.probe_elapsed.unwrap_or_else(|| {
            self.probe_started
                .map_or(Duration::ZERO, |time| time.elapsed())
        })
    }

    pub fn inventory_summary(&self) -> String {
        let Some(fetched_at) = self.inventory_fetched_at else {
            return "Inventory freshness unavailable".into();
        };
        let Ok(age) = SystemTime::now().duration_since(fetched_at) else {
            return "Inventory timestamp is in the future (STALE). Ctrl-r refreshes server loads."
                .into();
        };
        let freshness = if age >= inventory::CACHE_STALE_AFTER {
            "STALE"
        } else {
            "fresh"
        };
        let source = if self.inventory_from_cache {
            "cached"
        } else {
            "fetched"
        };
        format!(
            "Inventory: {source}, {} old ({freshness}). Ctrl-r refreshes server loads.",
            format_age(age)
        )
    }

    pub fn group_number(&self, key: &str) -> usize {
        let mut groups: Vec<&str> = self
            .selected_targets
            .iter()
            .map(|target| target.public_key.as_str())
            .collect();
        groups.sort_unstable();
        groups.dedup();
        groups
            .iter()
            .position(|candidate| *candidate == key)
            .unwrap_or(0)
            + 1
    }

    pub fn confirmed_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|attempt| attempt.outcome == AttemptOutcome::Confirmed)
            .count()
    }

    pub fn selected_attempt(&self) -> Option<&Attempt> {
        let target = self.planned_targets.get(self.plan_selected)?;
        self.attempts
            .iter()
            .find(|attempt| attempt.target == *target)
    }

    pub fn exported_path(&self, attempt_id: u64) -> Option<&PathBuf> {
        self.exported_attempts.get(&attempt_id)
    }

    pub fn run_finished(&self) -> bool {
        self.probe_started.is_some() && self.worker.is_none()
    }

    pub fn goal_reached(&self) -> bool {
        self.confirmed_count() >= self.options.desired_confirmed
    }

    pub fn run_cancelled(&self) -> bool {
        self.run_end_reason == Some(RunEndReason::Cancelled)
    }

    fn tick_inventory(&mut self) {
        let result = self
            .inventory_rx
            .as_ref()
            .map(|receiver| receiver.try_recv());
        match result {
            Some(Ok(Ok(update))) => {
                self.inventory_rx = None;
                self.refreshing_inventory = false;
                if update.targets.is_empty() {
                    self.fail("Nord inventory contained no usable candidates".into());
                } else {
                    self.inventory = update.targets;
                    self.inventory_fetched_at = Some(update.fetched_at);
                    self.inventory_from_cache = false;
                    self.refresh_cities();
                    self.status = inventory::store_cache(&self.inventory, update.fetched_at)
                        .err()
                        .map_or_else(
                            || "Fetched current Nord inventory and refreshed cached loads".into(),
                            |warning| format!("Fetched inventory; cache warning: {warning}"),
                        );
                    self.screen = Screen::Locations;
                }
            }
            Some(Ok(Err(error))) => {
                self.inventory_rx = None;
                if self.refreshing_inventory && !self.inventory.is_empty() {
                    self.refreshing_inventory = false;
                    self.status = format!("Refresh failed; using existing inventory: {error}");
                    self.screen = Screen::Locations;
                } else {
                    self.refreshing_inventory = false;
                    self.fail(error);
                }
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.inventory_rx = None;
                if self.refreshing_inventory && !self.inventory.is_empty() {
                    self.refreshing_inventory = false;
                    self.status =
                        "Refresh failed; the inventory worker stopped. Using existing inventory."
                            .into();
                    self.screen = Screen::Locations;
                } else {
                    self.refreshing_inventory = false;
                    self.fail("inventory worker disconnected before returning a result".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
    }

    fn tick_worker(&mut self) {
        loop {
            let result = match &self.worker {
                Some(worker) => worker.receiver.try_recv(),
                None => return,
            };
            match result {
                Ok(message) => self.handle_worker(message),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.probe_elapsed = self.probe_started.map(|started| started.elapsed());
                    self.run_end_reason = Some(RunEndReason::Failed);
                    self.worker = None;
                    self.active.clear();
                    self.cancelling = false;
                    self.fail("probe coordinator disconnected before completion".into());
                    return;
                }
            }
        }
    }

    fn key_setup(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => self.setup_focus = (self.setup_focus + 1) % 3,
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if self.setup_focus == 0 => {
                self.toggle_key_source();
            }
            KeyCode::F(2) if self.setup_focus == 1 && self.key_source == KeySource::PasteOnce => {
                self.reveal_pasted_key = !self.reveal_pasted_key;
            }
            KeyCode::Char(character) if text_modifier(key.modifiers) => match self.setup_focus {
                1 if self.key_source == KeySource::File => {
                    self.key_path.push(character);
                    if ends_with_private_key(&self.key_path) {
                        self.key_path.zeroize();
                        self.status = "Private key removed from file path; use PASTE ONCE".into();
                    }
                    self.identity = None;
                }
                1 if is_key_character(character) => {
                    self.pasted_key.push(character);
                    self.identity = None;
                }
                2 => {
                    self.export_directory.push(character);
                    if ends_with_private_key(&self.export_directory) {
                        self.export_directory.zeroize();
                        self.status = "Private key removed from export path; use PASTE ONCE".into();
                    }
                    self.validated_export_directory = None;
                }
                _ => {}
            },
            KeyCode::Backspace => match self.setup_focus {
                1 if self.key_source == KeySource::File => {
                    self.key_path.pop();
                    self.identity = None;
                }
                1 => {
                    self.pasted_key.pop();
                    self.identity = None;
                }
                2 => {
                    self.export_directory.pop();
                    self.validated_export_directory = None;
                }
                _ => {}
            },
            KeyCode::Enter => self.validate_setup(),
            _ => {}
        }
    }

    fn toggle_key_source(&mut self) {
        self.key_source = match self.key_source {
            KeySource::File => KeySource::PasteOnce,
            KeySource::PasteOnce => {
                self.pasted_key.zeroize();
                self.reveal_pasted_key = false;
                KeySource::File
            }
        };
        self.identity = None;
    }

    fn validate_setup(&mut self) {
        let export_input = self.export_directory.trim().to_owned();
        let export_directory = match self
            .validated_export_directory
            .clone()
            .map_or_else(|| resolve_export_directory(&export_input), Ok)
        {
            Ok(directory) => directory,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        let identity = match self.key_source {
            KeySource::File => {
                let path = PathBuf::from(self.key_path.trim());
                if self.key_path.trim().is_empty() {
                    self.fail("Enter the path to an existing WireGuard private-key file".into());
                    return;
                }
                RunIdentity::load(&path)
            }
            KeySource::PasteOnce if !self.pasted_key.is_empty() => {
                RunIdentity::parse(&self.pasted_key)
            }
            KeySource::PasteOnce => {
                if self.identity.is_some() {
                    self.validated_export_directory = Some(export_directory);
                    self.continue_after_identity();
                    return;
                }
                self.fail("Paste a WireGuard private key before continuing".into());
                return;
            }
        };
        match identity {
            Ok(identity) => {
                self.identity = Some(Arc::new(identity));
                self.pasted_key.zeroize();
                self.reveal_pasted_key = false;
                self.export_directory = Zeroizing::new(export_input);
                self.validated_export_directory = Some(export_directory);
                self.continue_after_identity();
            }
            Err(error) => self.fail(error.to_string()),
        }
    }

    fn continue_after_identity(&mut self) {
        match inventory::load_cache() {
            Ok(Some(cache)) => {
                self.inventory = cache.targets;
                self.inventory_fetched_at = Some(cache.fetched_at);
                self.inventory_from_cache = true;
                self.refresh_cities();
                self.status = format!("Loaded {} cached candidates", self.inventory.len());
                self.screen = Screen::Locations;
            }
            Ok(None) => self.load_inventory(false),
            Err(error) => {
                self.status = format!("Ignoring unusable inventory cache: {error}");
                self.load_inventory(false);
            }
        }
    }

    fn load_inventory(&mut self, refreshing: bool) {
        self.screen = Screen::Loading;
        self.refreshing_inventory = refreshing;
        self.status = if refreshing {
            "Refreshing public Nord inventory and server loads".into()
        } else {
            "Fetching public Nord server inventory".into()
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = inventory::fetch()
                .map_err(|error| error.to_string())
                .map(|targets| {
                    let fetched_at = SystemTime::now();
                    InventoryUpdate {
                        targets,
                        fetched_at,
                    }
                });
            let _ = sender.send(result);
        });
        self.inventory_rx = Some(receiver);
    }

    fn key_locations(&mut self, key: KeyEvent) {
        if refresh_requested(key) {
            self.load_inventory(true);
            return;
        }
        match key.code {
            KeyCode::Tab => self.location_focus = (self.location_focus + 1) % 2,
            KeyCode::Char(character)
                if self.location_focus == 0 && text_modifier(key.modifiers) =>
            {
                self.filter.push(character);
                self.refresh_cities();
            }
            KeyCode::Backspace if self.location_focus == 0 => {
                self.filter.pop();
                self.refresh_cities();
            }
            KeyCode::Down => {
                self.selected_city =
                    (self.selected_city + 1).min(self.cities.len().saturating_sub(1));
            }
            KeyCode::Up => self.selected_city = self.selected_city.saturating_sub(1),
            KeyCode::Enter => {
                if let Some(city) = self.cities.get(self.selected_city) {
                    self.selected_targets =
                        inventory::city_targets(&self.inventory, &city.country, &city.city);
                    if self.selected_targets.is_empty() {
                        self.fail("the selected city has no usable candidates".into());
                        return;
                    }
                    let available = self.selected_targets.len().min(100);
                    self.options.max_candidates = available.min(12);
                    self.options.desired_confirmed = self.options.max_candidates.min(3);
                    self.screen = Screen::ProbeSetup;
                }
            }
            KeyCode::Esc => self.screen = Screen::Setup,
            _ => {}
        }
    }

    fn refresh_cities(&mut self) {
        let previous = self
            .cities
            .get(self.selected_city)
            .map(|city| (city.country.clone(), city.city.clone()));
        self.cities = inventory::cities(&self.inventory, &self.filter);
        self.selected_city = selected_city_index(&self.cities, previous.as_ref());
    }

    fn key_probe_setup(&mut self, code: KeyCode) {
        match code {
            KeyCode::Tab => self.option_focus = (self.option_focus + 1) % 3,
            KeyCode::Up => self.adjust_option(1),
            KeyCode::Down => self.adjust_option(-1),
            KeyCode::Left | KeyCode::Right if self.option_focus == 2 => self.toggle_mode(),
            KeyCode::Enter => self.begin_probes(),
            KeyCode::Esc => self.screen = Screen::Locations,
            _ => {}
        }
    }

    fn adjust_option(&mut self, delta: isize) {
        let available = self.selected_targets.len().clamp(1, 100);
        match self.option_focus {
            0 => {
                self.options.desired_confirmed =
                    adjust(self.options.desired_confirmed, delta, 1, available.min(10));
                self.options.max_candidates = self
                    .options
                    .max_candidates
                    .max(self.options.desired_confirmed)
                    .min(available);
            }
            1 => {
                self.options.max_candidates = adjust(
                    self.options.max_candidates,
                    delta,
                    self.options.desired_confirmed,
                    available,
                );
            }
            2 => self.toggle_mode(),
            _ => {}
        }
    }

    fn toggle_mode(&mut self) {
        self.options.mode = match &self.options.mode {
            CheckMode::HandshakeOnly => CheckMode::Full(FullCheckPlan::default()),
            CheckMode::Full(_) => CheckMode::HandshakeOnly,
        };
    }

    fn begin_probes(&mut self) {
        if self.worker.is_some() {
            self.status = "Wait for the current run to finish cancelling".into();
            return;
        }
        let Some(identity) = self.identity.as_ref().map(Arc::clone) else {
            self.fail("the validated run identity is no longer available".into());
            return;
        };
        if self.selected_targets.is_empty()
            || self.options.desired_confirmed == 0
            || self.options.desired_confirmed > self.options.max_candidates
            || self.options.max_candidates > self.selected_targets.len().min(100)
        {
            self.fail("probe option bounds are inconsistent with available candidates".into());
            return;
        }
        self.attempts.clear();
        self.active.clear();
        self.exported_attempts.clear();
        self.planned_targets =
            scheduler::plan_candidates(self.selected_targets.clone(), self.options.max_candidates);
        self.plan_selected = 0;
        self.cancelling = false;
        self.worker_fatal = None;
        self.status = "Starting probes".into();
        self.probe_started = Some(Instant::now());
        self.probe_elapsed = None;
        self.run_end_reason = None;
        self.worker = Some(probing::start(
            identity,
            self.selected_targets.clone(),
            self.options.clone(),
        ));
        self.screen = Screen::Probing;
    }

    fn key_probing(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc if !self.cancelling && self.worker.is_some() => {
                if let Some(worker) = &self.worker {
                    worker.cancel();
                }
                self.cancelling = true;
                self.pacing = Duration::ZERO;
                self.status = "Cancelling: waiting for active attempts to finish".into();
            }
            KeyCode::Esc if self.worker.is_none() => self.screen = Screen::ProbeSetup,
            KeyCode::Up => {
                self.plan_selected =
                    move_plan_selection(self.plan_selected, -1, self.planned_targets.len());
            }
            KeyCode::Down => {
                self.plan_selected =
                    move_plan_selection(self.plan_selected, 1, self.planned_targets.len());
            }
            KeyCode::Char('e') if !self.cancelling => self.export_confirmed(),
            _ => {}
        }
    }

    fn handle_worker(&mut self, message: WorkerMessage) {
        match message {
            WorkerMessage::Started { id, target } => {
                self.pacing = Duration::ZERO;
                self.active.push(ActiveProbe {
                    id,
                    target,
                    phase: "starting".into(),
                });
            }
            WorkerMessage::Phase { id, event } => {
                if let Some(active) = self.active.iter_mut().find(|active| active.id == id) {
                    active.phase = event.phase;
                }
            }
            WorkerMessage::Finished(attempt) => {
                self.active.retain(|active| active.id != attempt.id);
                self.attempts.push(*attempt);
                if !self.cancelling {
                    self.status = format!(
                        "{} confirmed toward goal {}",
                        self.confirmed_count(),
                        self.options.desired_confirmed
                    );
                }
            }
            WorkerMessage::Pacing(duration) => {
                if !self.cancelling {
                    self.pacing = duration;
                }
            }
            WorkerMessage::Fatal(error) => {
                self.worker_fatal = Some(error.clone());
                self.status = error;
            }
            WorkerMessage::Complete { cancelled } => {
                self.probe_elapsed = self.probe_started.map(|started| started.elapsed());
                self.run_end_reason = Some(if self.worker_fatal.is_some() {
                    RunEndReason::Failed
                } else if cancelled {
                    RunEndReason::Cancelled
                } else if self.goal_reached() {
                    RunEndReason::GoalReached
                } else {
                    RunEndReason::Exhausted
                });
                self.worker = None;
                self.active.clear();
                self.pacing = Duration::ZERO;
                self.cancelling = false;
                if let Some(error) = self.worker_fatal.take() {
                    self.fail(error);
                } else if cancelled {
                    self.status =
                        format!("Cancelled after {} completed attempts", self.attempts.len());
                } else {
                    self.status = format!(
                        "Complete: {} confirmed, {} completed",
                        self.confirmed_count(),
                        self.attempts.len()
                    );
                }
            }
        }
    }

    fn export_confirmed(&mut self) {
        let Some(attempt) = self.selected_attempt() else {
            self.status = "The selected candidate has not completed".into();
            return;
        };
        if attempt.outcome != AttemptOutcome::Confirmed {
            self.status = "Only a selected CONFIRMED candidate can be exported".into();
            return;
        }
        if let Some(path) = self.exported_attempts.get(&attempt.id) {
            self.status = format!("Already exported {}", path.display());
            return;
        }
        let attempt_id = attempt.id;
        let client_public_key = attempt.client_public_key.clone();
        let target = attempt.target.clone();
        let Some(identity) = &self.identity else {
            self.status = "Export failed: validated run identity is unavailable".into();
            return;
        };
        let Some(directory) = &self.validated_export_directory else {
            self.status = "Export failed: validated export directory is unavailable".into();
            return;
        };
        match export::export(identity, &client_public_key, &target, directory) {
            Ok(path) => {
                let display_path = export_display_path(&self.export_directory, &path);
                self.status = format!("Exported {}", display_path.display());
                self.exported_paths.push(display_path.clone());
                self.exported_attempts.insert(attempt_id, display_path);
            }
            Err(error) => self.status = format!("Export failed: {error}"),
        }
    }

    fn fail(&mut self, error: String) {
        self.error = error;
        self.screen = Screen::Error;
    }
}

fn selected_city_index(cities: &[CitySummary], previous: Option<&(String, String)>) -> usize {
    previous
        .and_then(|(country, city)| {
            cities
                .iter()
                .position(|candidate| &candidate.country == country && &candidate.city == city)
        })
        .unwrap_or(0)
}

fn text_modifier(modifiers: KeyModifiers) -> bool {
    modifiers.is_empty() || modifiers == KeyModifiers::SHIFT
}

fn is_key_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
}

fn looks_like_private_key(value: &str) -> bool {
    value.len() == 44 && value.chars().all(is_key_character) && RunIdentity::parse(value).is_ok()
}

fn ends_with_private_key(value: &str) -> bool {
    value
        .len()
        .checked_sub(44)
        .and_then(|start| value.get(start..))
        .is_some_and(looks_like_private_key)
}

fn quit_requested(key: KeyEvent, editing_text: bool) -> bool {
    (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        || (key.code == KeyCode::Char('q') && key.modifiers.is_empty() && !editing_text)
}

fn refresh_requested(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn resolve_export_directory(value: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Enter an export directory".into());
    }
    resolve_export_directory_path(&PathBuf::from(value))
}

pub(crate) fn resolve_export_directory_path(path: &std::path::Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("could not resolve export directory: {error}"))?
            .join(path)
    };
    let path = canonicalize_for_creation(&path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && !metadata.file_type().is_dir()
    {
        return Err(format!(
            "export path {} exists and is not a directory",
            path.display()
        ));
    }
    Ok(path)
}

fn canonicalize_for_creation(path: &std::path::Path) -> Result<PathBuf, String> {
    let mut resolved = PathBuf::new();
    let mut missing = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                resolved.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !missing.pop() {
                    if !std::fs::metadata(&resolved).is_ok_and(|metadata| metadata.is_dir()) {
                        return Err(format!(
                            "could not resolve export directory {}: parent component follows a non-directory",
                            path.display()
                        ));
                    }
                    resolved.pop();
                }
            }
            std::path::Component::Normal(name) if missing.as_os_str().is_empty() => {
                let candidate = resolved.join(name);
                match std::fs::canonicalize(&candidate) {
                    Ok(canonical) => resolved = canonical,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        missing.push(name);
                    }
                    Err(error) => {
                        return Err(format!(
                            "could not resolve export directory {}: {error}",
                            path.display()
                        ));
                    }
                }
            }
            std::path::Component::Normal(name) => missing.push(name),
        }
    }
    Ok(resolved.join(missing))
}

pub(crate) fn export_display_path(input: &str, written_path: &std::path::Path) -> PathBuf {
    let input = PathBuf::from(input);
    if input.is_absolute() {
        written_path.to_owned()
    } else {
        written_path
            .file_name()
            .map_or(input.clone(), |filename| input.join(filename))
    }
}

fn format_age(age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h {}m", seconds / (60 * 60), (seconds / 60) % 60)
    } else {
        format!(
            "{}d {}h",
            seconds / (24 * 60 * 60),
            (seconds / (60 * 60)) % 24
        )
    }
}

fn adjust(value: usize, delta: isize, minimum: usize, maximum: usize) -> usize {
    value.saturating_add_signed(delta).clamp(minimum, maximum)
}

fn move_plan_selection(current: usize, delta: isize, length: usize) -> usize {
    current
        .saturating_add_signed(delta)
        .min(length.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn setup_has_no_implicit_key_and_uses_relative_export_default() {
        let app = App::new();
        assert!(app.key_path.is_empty());
        assert!(app.pasted_key.is_empty());
        assert_eq!(app.export_directory.as_str(), "./nordprobe-exports");
    }

    #[test]
    fn paste_once_accepts_base64_and_clears_when_source_changes() {
        let mut app = App::new();
        app.key_source = KeySource::PasteOnce;
        app.setup_focus = 1;
        app.handle_paste(KEY);
        assert_eq!(app.pasted_key.as_str(), KEY);

        app.handle_paste("not a key");
        assert_eq!(app.pasted_key.as_str(), KEY);

        app.toggle_key_source();
        assert!(app.pasted_key.is_empty());
        assert_eq!(app.key_source, KeySource::File);
    }

    #[test]
    fn key_shaped_paste_is_rejected_in_file_mode() {
        let mut app = App::new();
        app.setup_focus = 1;
        app.handle_paste(KEY);

        assert!(app.key_path.is_empty());
        assert!(app.status.contains("PASTE ONCE"));
    }

    #[test]
    fn key_shaped_paste_is_rejected_in_export_field() {
        let mut app = App::new();
        app.setup_focus = 2;
        app.handle_paste(KEY);

        assert_eq!(app.export_directory.as_str(), "./nordprobe-exports");
        assert!(app.status.contains("PASTE ONCE"));
    }

    #[test]
    fn key_typed_into_file_field_is_removed() {
        let mut app = App::new();
        app.setup_focus = 1;
        for character in KEY.chars() {
            app.key_setup(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }

        assert!(app.key_path.is_empty());
        assert!(app.status.contains("PASTE ONCE"));
    }

    #[test]
    fn key_typed_after_export_default_is_removed() {
        let mut app = App::new();
        app.setup_focus = 2;
        for character in KEY.chars() {
            app.key_setup(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }

        assert!(app.export_directory.is_empty());
        assert!(app.status.contains("PASTE ONCE"));
    }

    #[test]
    fn f2_toggles_pasted_key_visibility() {
        let mut app = App::new();
        app.key_source = KeySource::PasteOnce;
        app.setup_focus = 1;

        app.key_setup(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(app.reveal_pasted_key);
        app.key_setup(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(!app.reveal_pasted_key);
    }

    #[test]
    fn preserves_selected_location_by_identity_after_filtering() {
        let cities = vec![
            CitySummary {
                country: "United States".into(),
                city: "Atlanta".into(),
                count: 2,
            },
            CitySummary {
                country: "United States".into(),
                city: "Denver".into(),
                count: 3,
            },
        ];
        let previous = ("United States".into(), "Denver".into());
        assert_eq!(selected_city_index(&cities, Some(&previous)), 1);
    }

    #[test]
    fn unmodified_q_is_text_while_ctrl_c_quits() {
        let plain = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        let control_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let control_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert!(!quit_requested(plain, true));
        assert!(quit_requested(control_c, true));
        assert!(!quit_requested(control_q, true));
        assert!(quit_requested(plain, false));
    }

    #[test]
    fn formats_inventory_ages_compactly() {
        assert_eq!(format_age(Duration::from_secs(45)), "45s");
        assert_eq!(format_age(Duration::from_secs(90)), "1m");
        assert_eq!(format_age(Duration::from_secs(3_900)), "1h 5m");
        assert_eq!(format_age(Duration::from_secs(90_000)), "1d 1h");
    }

    #[test]
    fn plan_arrows_follow_visual_direction() {
        assert_eq!(move_plan_selection(1, -1, 3), 0);
        assert_eq!(move_plan_selection(1, 1, 3), 2);
        assert_eq!(move_plan_selection(0, -1, 3), 0);
        assert_eq!(move_plan_selection(2, 1, 3), 2);
    }

    #[test]
    fn elapsed_time_stops_when_worker_completes() {
        let mut app = App::new();
        app.probe_started = Some(Instant::now() - Duration::from_secs(2));
        app.handle_worker(WorkerMessage::Complete { cancelled: false });
        let elapsed = app.elapsed();
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(app.elapsed(), elapsed);
    }

    #[test]
    fn completed_cancellation_remains_visible() {
        let mut app = App::new();
        app.probe_started = Some(Instant::now());
        app.handle_worker(WorkerMessage::Complete { cancelled: true });

        assert!(app.run_cancelled());
        assert!(!app.cancelling);
    }

    #[test]
    fn resolves_relative_export_directory_from_launch_directory() {
        let resolved = resolve_export_directory("custom-exports").unwrap();
        assert_eq!(
            resolved,
            std::env::current_dir().unwrap().join("custom-exports")
        );
    }

    #[test]
    fn keeps_relative_export_path_for_display() {
        let written = std::env::current_dir()
            .unwrap()
            .join("exports")
            .join("server.conf");
        assert_eq!(
            export_display_path("./exports", &written),
            PathBuf::from("./exports/server.conf")
        );
        let absolute_input = written.parent().unwrap().display().to_string();
        assert_eq!(export_display_path(&absolute_input, &written), written);
    }

    #[test]
    fn cli_export_directory_preserves_relative_display() {
        let mut app = App::new();
        app.set_export_directory(PathBuf::from("custom-exports"))
            .unwrap();

        assert_eq!(app.export_directory.as_str(), "custom-exports");
        assert_eq!(
            app.validated_export_directory.as_deref(),
            Some(
                std::env::current_dir()
                    .unwrap()
                    .join("custom-exports")
                    .as_path()
            )
        );
    }

    #[test]
    fn unresolved_parent_components_are_normalized_without_creation() {
        let directory = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(directory.path()).unwrap();
        let input = base.join("new").join("..").join("exports");

        let resolved = resolve_export_directory_path(&input).unwrap();

        assert_eq!(resolved, base.join("exports"));
        assert!(!base.join("new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn parent_after_symlink_resolves_from_symlink_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(directory.path()).unwrap();
        let target_parent = base.join("target-parent");
        let target = target_parent.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let link = base.join("link");
        symlink(&target, &link).unwrap();

        let resolved = resolve_export_directory_path(&link.join("..").join("exports")).unwrap();

        assert_eq!(resolved, target_parent.join("exports"));
    }

    #[test]
    fn parent_after_regular_file_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();

        let error = resolve_export_directory_path(&file.join("..").join("exports")).unwrap_err();

        assert!(error.contains("non-directory"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_export_directory_preserves_non_utf8_os_path_for_writes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let relative = PathBuf::from(OsString::from_vec(vec![b'e', b'x', b'p', 0xff]));
        let mut app = App::new();
        app.set_export_directory(relative.clone()).unwrap();

        assert_eq!(
            app.validated_export_directory.as_deref(),
            Some(std::env::current_dir().unwrap().join(relative).as_path())
        );
    }
}

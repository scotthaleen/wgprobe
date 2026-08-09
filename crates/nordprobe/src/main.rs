mod app;
mod credentials;
mod export;
mod finder;
mod inventory;
mod key;
mod probing;
mod scheduler;
mod ui;

use std::io::{self, Stdout};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use zeroize::Zeroize;

use crate::app::App;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Preload a WireGuard private-key file and skip Setup (TUI/find only)
    #[arg(long, value_name = "PATH", global = true)]
    key_file: Option<PathBuf>,

    /// Set the WireGuard configuration export directory (TUI/find only)
    #[arg(long, value_name = "PATH", global = true)]
    export_directory: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Fetch public inventory and list available cities without reading a key
    Cities {
        /// Include only this country (case-insensitive exact match)
        #[arg(long)]
        country: Option<String>,
    },
    /// Select a location, confirm one endpoint, and export its configuration
    Find {
        /// Initial fuzzy country or city query
        query: Option<String>,
        /// Restrict selection to this country (case-insensitive exact match)
        #[arg(long)]
        country: Option<String>,
        /// Select this city (case-insensitive exact match when unique)
        #[arg(long)]
        city: Option<String>,
        /// Refresh public inventory instead of using its cache
        #[arg(long)]
        refresh: bool,
        /// Ping 1.1.1.1 and resolve example.com through 103.86.96.100
        #[arg(long)]
        full: bool,
        /// Ping this IPv4 address instead of the full-check default (repeatable)
        #[arg(long, value_name = "IP")]
        ping: Vec<Ipv4Addr>,
        /// Resolve this name instead of the full-check default (repeatable)
        #[arg(long, value_name = "NAME")]
        resolve: Vec<String>,
        /// Use this IPv4 DNS server for full checks
        #[arg(long, value_name = "IP")]
        dns_server: Option<Ipv4Addr>,
        /// Maximum candidates to try
        #[arg(long, default_value_t = 12)]
        max_candidates: usize,
        /// Color output: auto, always, or never
        #[arg(long, value_enum, default_value_t = finder::ColorChoice::Auto)]
        color: finder::ColorChoice,
    },
    /// Manage the NordLynx private key used for probing
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Prompt for a Nord access token and write its NordLynx private key
    Fetch {
        /// Create the private-key file at this path without overwriting
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match (cli.command, cli.key_file, cli.export_directory) {
        (Some(Command::Cities { .. }), Some(_), _) => {
            Err("--key-file is available only with the TUI or find".into())
        }
        (Some(Command::Cities { .. }), None, Some(_)) => {
            Err("--export-directory is available only with the TUI or find".into())
        }
        (Some(Command::Cities { country }), None, None) => list_cities(country.as_deref()),
        (
            Some(Command::Find {
                query,
                country,
                city,
                refresh,
                full,
                ping,
                resolve,
                dns_server,
                max_candidates,
                color,
            }),
            Some(key_file),
            export_directory,
        ) => finder::run(finder::FindOptions {
            key_file,
            export_directory: export_directory
                .unwrap_or_else(|| PathBuf::from("./nordprobe-exports")),
            query,
            country,
            city,
            refresh,
            full,
            ping_targets: ping,
            resolve_names: resolve,
            dns_server,
            max_candidates,
            color,
        }),
        (Some(Command::Find { .. }), None, _) => Err("find requires --key-file <PATH>".into()),
        (Some(Command::Key { .. }), Some(_), _) => {
            Err("--key-file is available only with the TUI or find".into())
        }
        (Some(Command::Key { .. }), None, Some(_)) => {
            Err("--export-directory is available only with the TUI or find".into())
        }
        (
            Some(Command::Key {
                command: KeyCommand::Fetch { output },
            }),
            None,
            None,
        ) => {
            let path = credentials::fetch_to(&output)?;
            println!("Wrote NordLynx private key to {}", path.display());
            Ok(())
        }
        (None, key_file, export_directory) => run_tui(key_file, export_directory),
    }
}

fn list_cities(country: Option<&str>) -> Result<(), String> {
    let targets = inventory::fetch().map_err(|error| error.to_string())?;
    let cities = filtered_cities(&targets, country)?;
    for city in cities {
        println!("{}\t{}\t{}", city.country, city.city, city.count);
    }
    Ok(())
}

fn filtered_cities(
    targets: &[inventory::NordTarget],
    country: Option<&str>,
) -> Result<Vec<inventory::CitySummary>, String> {
    let mut cities = inventory::cities(targets, "");
    if let Some(country) = country {
        cities.retain(|city| city.country.eq_ignore_ascii_case(country));
    }
    if cities.is_empty() {
        return Err(match country {
            Some(country) => format!("no usable Nord candidates found for country {country:?}"),
            None => "Nord inventory contained no usable cities".into(),
        });
    }
    Ok(cities)
}

fn run_tui(key_file: Option<PathBuf>, export_directory: Option<PathBuf>) -> Result<(), String> {
    install_panic_restore();
    let mut terminal = TerminalSession::enter().map_err(|error| error.to_string())?;
    let mut app = App::new();
    if let Some(path) = export_directory {
        app.set_export_directory(path)?;
    }
    if let Some(path) = key_file {
        app.preload_key_file(path)?;
    }
    let result = loop {
        app.tick();
        if let Err(error) = terminal.terminal.draw(|frame| ui::draw(frame, &mut app)) {
            break Err(error.to_string());
        }
        if app.should_quit {
            break Ok(());
        }
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => app.handle_key(key),
                Ok(Event::Paste(mut value)) => {
                    app.handle_paste(&value);
                    value.zeroize();
                }
                Ok(_) => {}
                Err(error) => break Err(error.to_string()),
            },
            Ok(false) => {}
            Err(error) => break Err(error.to_string()),
        }
    };
    let exported_paths = std::mem::take(&mut app.exported_paths);
    drop(terminal);
    if !exported_paths.is_empty() {
        println!("Exported configurations:");
        for path in exported_paths {
            println!("  {}", path.display());
        }
    }
    result
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableBracketedPaste) {
            restore_terminal();
            return Err(error);
        }
        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal();
                Err(error)
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn install_panic_restore() {
    let main_thread = std::thread::current().id();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == main_thread {
            restore_terminal();
        }
        previous(info);
    }));
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn unmatched_headless_country_is_an_error() {
        let targets = vec![inventory::NordTarget {
            name: "Test".into(),
            hostname: "test.example".into(),
            endpoint: "192.0.2.1:51820".parse::<SocketAddr>().unwrap(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            country: "United States".into(),
            city: "Denver".into(),
            load: 1,
        }];
        assert!(filtered_cities(&targets, Some("Nowhere")).is_err());
    }

    #[test]
    fn key_file_flag_is_tui_only() {
        let cli =
            Cli::try_parse_from(["nordprobe", "--key-file", "private.key", "cities"]).unwrap();
        assert!(run(cli).unwrap_err().contains("available only"));
    }

    #[test]
    fn export_directory_flag_is_tui_only() {
        let cli =
            Cli::try_parse_from(["nordprobe", "--export-directory", "exports", "cities"]).unwrap();
        assert!(run(cli).unwrap_err().contains("available only"));
    }

    #[test]
    fn parses_native_key_fetch_command() {
        let cli =
            Cli::try_parse_from(["nordprobe", "key", "fetch", "--output", "private-key"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Key {
                command: KeyCommand::Fetch { output }
            }) if output == std::path::Path::new("private-key")
        ));
    }

    #[test]
    fn find_still_accepts_global_options_after_subcommand() {
        let cli = Cli::try_parse_from([
            "nordprobe",
            "find",
            "--key-file",
            "private-key",
            "--export-directory",
            "exports",
        ])
        .unwrap();
        assert_eq!(cli.key_file, Some(PathBuf::from("private-key")));
        assert_eq!(cli.export_directory, Some(PathBuf::from("exports")));
    }

    #[test]
    fn parses_custom_find_checks() {
        let cli = Cli::try_parse_from([
            "nordprobe",
            "find",
            "--ping",
            "8.8.8.8",
            "--resolve",
            "google.com",
            "--dns-server",
            "8.8.4.4",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Find {
                ping,
                resolve,
                dns_server: Some(dns_server),
                ..
            }) if ping == [Ipv4Addr::new(8, 8, 8, 8)]
                && resolve == ["google.com"]
                && dns_server == Ipv4Addr::new(8, 8, 4, 4)
        ));
    }
}

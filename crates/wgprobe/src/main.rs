use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use wgprobe::{
    Ipv4Cidr, PhaseStatus, ProbeConfig, ProbeEvent, ProbeEventKind, ProbePlan, ProbeReport,
    Verdict, probe,
};
use zeroize::Zeroizing;

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
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
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        Self {
            stdout: color_enabled(choice, io::stdout().is_terminal(), no_color),
            stderr: color_enabled(choice, io::stderr().is_terminal(), no_color),
        }
    }

    fn err(&self, code: u8, value: impl std::fmt::Display) -> String {
        paint(self.stderr, code, value)
    }
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

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// WireGuard configuration file, or - to read it from stdin
    #[arg(
        required_unless_present = "private_key_file",
        conflicts_with = "private_key_file"
    )]
    config: Option<PathBuf>,

    /// File containing only the base64 client private key
    #[arg(long, requires_all = ["peer_key", "endpoint"])]
    private_key_file: Option<PathBuf>,

    /// WireGuard server public key used with --private-key-file
    #[arg(long, requires = "private_key_file")]
    peer_key: Option<String>,

    /// WireGuard server host or IP and port used with --private-key-file
    #[arg(long, requires = "private_key_file")]
    endpoint: Option<String>,

    /// Send an inner ICMP echo request (repeatable)
    #[arg(long)]
    ping: Vec<Ipv4Addr>,

    /// Send an inner DNS A query (repeatable)
    #[arg(long)]
    resolve: Vec<String>,

    /// Override the DNS server for --resolve
    #[arg(long)]
    dns_server: Option<Ipv4Addr>,

    /// Inner client address for raw-key data checks
    #[arg(long, requires_all = ["private_key_file", "allowed_ip"])]
    address: Option<String>,

    /// Peer route for raw-key data checks (repeatable)
    #[arg(long, requires_all = ["private_key_file", "address"])]
    allowed_ip: Vec<String>,

    /// Handshake timeout in milliseconds
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,

    /// Per-ping timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    ping_timeout_ms: u64,

    /// Per-DNS-query timeout in milliseconds
    #[arg(long, default_value_t = 2000)]
    dns_timeout_ms: u64,

    /// Overall probe deadline in milliseconds
    #[arg(long, default_value_t = 9000)]
    deadline_ms: u64,

    /// Emit exactly one JSON report on stdout
    #[arg(long)]
    json: bool,

    /// Suppress phase progress on stderr
    #[arg(long)]
    quiet: bool,

    /// Hide the client public key and local UDP address in reports
    #[arg(long)]
    redact: bool,

    /// Color human output: auto, always, or never
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<bool, String> {
    let colors = ColorPolicy::new(cli.color);
    let raw_mode = cli.private_key_file.is_some();
    let mut config = if let Some(private_key_file) = cli.private_key_file {
        let contents =
            read_secret_file(&private_key_file, "private key", MAX_PRIVATE_KEY_FILE_BYTES)?;
        let contents = secret_text(&contents, "private key")?;
        ProbeConfig::from_parts(
            contents,
            &cli.peer_key.expect("required by clap"),
            cli.endpoint.expect("required by clap"),
        )
        .map_err(|error| format!("invalid probe keys: {error}"))?
    } else {
        let config_path = cli.config.expect("required by clap");
        let contents = if config_path.as_os_str() == OsStr::new("-") {
            read_bounded(
                io::stdin().lock(),
                "configuration from stdin",
                MAX_CONFIG_FILE_BYTES,
            )?
        } else {
            read_secret_file(&config_path, "configuration", MAX_CONFIG_FILE_BYTES)?
        };
        let contents = secret_text(&contents, "WireGuard configuration")?;
        ProbeConfig::parse(contents)
            .map_err(|error| format!("invalid WireGuard configuration: {error}"))?
    };

    if raw_mode && let Some(address) = cli.address {
        let address = parse_cidr(&address, "--address")?;
        let allowed_ips = cli
            .allowed_ip
            .iter()
            .map(|value| parse_cidr(value, "--allowed-ip"))
            .collect::<Result<Vec<_>, _>>()?;
        config.set_data_config(address, Vec::<IpAddr>::new(), allowed_ips);
    }

    let mut plan = ProbePlan::new(config).timeouts(
        Duration::from_millis(cli.timeout_ms),
        Duration::from_millis(cli.ping_timeout_ms),
        Duration::from_millis(cli.dns_timeout_ms),
        Duration::from_millis(cli.deadline_ms),
    );
    for target in cli.ping {
        plan = plan.ping(target);
    }
    for name in cli.resolve {
        plan = plan.resolve(name);
    }
    if let Some(server) = cli.dns_server {
        plan = plan.dns_server(server);
    }

    let show_progress = !cli.quiet && !cli.json;
    let mut report = probe(plan, |event| {
        if show_progress {
            print_progress(event, &colors);
        }
    });
    let successful = matches!(
        report.verdict,
        Verdict::AuthenticationConfirmed | Verdict::DataPlaneConfirmed
    );
    if cli.redact {
        redact_report(&mut report);
    }
    if cli.json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("ProbeReport is serializable")
        );
    } else {
        print_human(&report, &colors, cli.redact);
    }
    Ok(successful)
}

fn redact_report(report: &mut ProbeReport) {
    report.client_public_key = "[redacted]".into();
    let local_address = report
        .local_udp_address
        .take()
        .map(|address| address.to_string());
    let Some(local_address) = local_address else {
        return;
    };
    for phase in &mut report.phases {
        if let Some(target) = &mut phase.target {
            *target = target.replace(&local_address, "[redacted]");
        }
        if let Some(detail) = &mut phase.detail {
            *detail = detail.replace(&local_address, "[redacted]");
        }
    }
}

fn read_secret_file(
    path: &Path,
    kind: &str,
    maximum_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {kind} file {}: {error}", path.display()))?;
    if !path_metadata.file_type().is_file() {
        return Err(format!(
            "{kind} path {} must be a regular file",
            path.display()
        ));
    }
    if path_metadata.len() > maximum_bytes {
        return Err(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        ));
    }

    let file = open_secret_file(path)
        .map_err(|error| format!("could not open {kind} file {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not inspect open {kind} file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "{kind} path {} must be a regular file",
            path.display()
        ));
    }
    if metadata.len() > maximum_bytes {
        return Err(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        ));
    }
    read_bounded(
        file,
        &format!("{kind} file {}", path.display()),
        maximum_bytes,
    )
}

fn open_secret_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn read_bounded(
    reader: impl Read,
    description: &str,
    maximum_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut contents = Zeroizing::new(Vec::new());
    reader
        .take(maximum_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|error| format!("could not read {description}: {error}"))?;
    if contents.len() as u64 > maximum_bytes {
        return Err(format!(
            "{description} exceeds the {maximum_bytes}-byte limit"
        ));
    }
    Ok(contents)
}

fn secret_text<'a>(contents: &'a [u8], kind: &str) -> Result<&'a str, String> {
    str::from_utf8(contents).map_err(|_| format!("{kind} must be valid UTF-8"))
}

fn parse_cidr(value: &str, option: &str) -> Result<Ipv4Cidr, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an IPv4 CIDR, got {value}"))
}

fn print_progress(event: &ProbeEvent, colors: &ColorPolicy) {
    match event.kind {
        ProbeEventKind::Started => eprintln!(
            "{} starting {}{}",
            colors.err(90, format!("[{} ms]", event.elapsed_ms)),
            colors.err(36, &event.phase),
            event
                .target
                .as_ref()
                .map(|target| format!(" ({target})"))
                .unwrap_or_default()
        ),
        ProbeEventKind::Finished => {
            let result = event.result.as_ref().expect("finished event has a result");
            eprintln!(
                "{} {}: {}",
                colors.err(90, format!("[{} ms]", event.elapsed_ms)),
                result.phase,
                colored_status(colors.stderr, &result.status)
            );
        }
    }
}

fn print_human(report: &ProbeReport, colors: &ColorPolicy, redacted: bool) {
    println!("{}", paint(colors.stdout, 1, "RESULT"));
    println!(
        "  {:<12} {}",
        "Verdict",
        colored_verdict(colors.stdout, &report.verdict)
    );
    println!("  {:<12} {}", "Endpoint", report.endpoint);
    if let Some(endpoint) = report.resolved_endpoint {
        println!("  {:<12} {endpoint}", "Resolved");
    }
    if redacted {
        println!("  {:<12} {}", "Local UDP", redaction_bar(colors.stdout));
    } else if let Some(address) = report.local_udp_address {
        println!("  {:<12} {address}", "Local UDP");
    }
    println!(
        "  {:<12} {}",
        "Client key",
        if redacted {
            redaction_bar(colors.stdout)
        } else {
            report.client_public_key.clone()
        }
    );
    println!("  {:<12} {} ms", "Duration", report.duration_ms);
    println!(
        "  {:<12} {} B sent / {} B received",
        "Traffic", report.sent_bytes, report.received_bytes
    );

    println!();
    println!("{}", paint(colors.stdout, 1, "PHASES"));
    for phase in &report.phases {
        println!(
            "  {} {:<20} {:>5} ms  {:>5} B -> {:>5} B",
            colored_phase_label(colors.stdout, &phase.status),
            phase.phase,
            phase.duration_ms,
            phase.sent_bytes,
            phase.received_bytes
        );
        if phase.target.is_some() || phase.detail.is_some() {
            println!(
                "  {:<11} {}{}",
                "",
                display_redactions(phase.target.as_deref().unwrap_or("-"), colors.stdout,),
                phase
                    .detail
                    .as_deref()
                    .map(|detail| format!("  |  {}", display_redactions(detail, colors.stdout)))
                    .unwrap_or_default()
            );
        }
    }
}

fn status_name(status: &PhaseStatus) -> &'static str {
    match status {
        PhaseStatus::Passed => "passed",
        PhaseStatus::Sent => "sent",
        PhaseStatus::Unconfirmed => "unconfirmed",
        PhaseStatus::Skipped => "skipped",
        PhaseStatus::Error => "error",
    }
}

fn colored_status(enabled: bool, status: &PhaseStatus) -> String {
    let code = match status {
        PhaseStatus::Passed => 32,
        PhaseStatus::Sent => 36,
        PhaseStatus::Unconfirmed => 33,
        PhaseStatus::Skipped => 90,
        PhaseStatus::Error => 31,
    };
    paint(enabled, code, status_name(status))
}

fn colored_phase_label(enabled: bool, status: &PhaseStatus) -> String {
    let (code, label) = match status {
        PhaseStatus::Passed => ("30;42", "PASS"),
        PhaseStatus::Sent => ("30;46", "SENT"),
        PhaseStatus::Unconfirmed => ("30;43", "NO REPLY"),
        PhaseStatus::Skipped => ("30;47", "SKIP"),
        PhaseStatus::Error => ("97;41", "ERROR"),
    };
    if enabled {
        format!("\x1b[{code}m {label:^9} \x1b[0m")
    } else {
        format!("[{label:^9}]")
    }
}

fn redaction_bar(enabled: bool) -> String {
    paint(enabled, 97, "████████████")
}

fn display_redactions(value: &str, color: bool) -> String {
    value.replace("[redacted]", &redaction_bar(color))
}

fn colored_verdict(enabled: bool, verdict: &Verdict) -> String {
    let (code, label) = match verdict {
        Verdict::AuthenticationConfirmed => (32, "AUTHENTICATION CONFIRMED"),
        Verdict::DataPlaneConfirmed => (32, "DATA PLANE CONFIRMED"),
        Verdict::Unconfirmed => (33, "UNCONFIRMED"),
        Verdict::LocalError => (31, "LOCAL ERROR"),
    };
    paint(enabled, code, label)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn legacy_config_invocation_is_handshake_only() {
        let cli = Cli::try_parse_from(["wgprobe", "test.conf"]).unwrap();
        assert!(cli.ping.is_empty());
        assert!(cli.resolve.is_empty());
        assert_eq!(cli.timeout_ms, 3000);
        assert_eq!(cli.deadline_ms, 9000);
        assert_eq!(cli.color, ColorChoice::Auto);
    }

    #[test]
    fn parses_repeatable_checks_and_json_flags() {
        let cli = Cli::try_parse_from([
            "wgprobe",
            "test.conf",
            "--ping",
            "10.0.0.1",
            "--ping",
            "10.0.0.2",
            "--resolve",
            "example.com",
            "--dns-server",
            "10.0.0.53",
            "--json",
        ])
        .unwrap();
        assert_eq!(cli.ping.len(), 2);
        assert_eq!(cli.resolve, ["example.com"]);
        assert!(cli.json);
    }

    #[test]
    fn color_policy_honors_terminal_no_color_and_explicit_modes() {
        assert!(color_enabled(ColorChoice::Auto, true, false));
        assert!(!color_enabled(ColorChoice::Auto, false, false));
        assert!(!color_enabled(ColorChoice::Auto, true, true));
        assert!(color_enabled(ColorChoice::Always, false, true));
        assert!(!color_enabled(ColorChoice::Never, true, false));
        assert_eq!(paint(false, 32, "passed"), "passed");
        assert_eq!(paint(true, 32, "passed"), "\x1b[32mpassed\x1b[0m");
        assert_eq!(
            colored_phase_label(false, &PhaseStatus::Passed),
            "[  PASS   ]"
        );
        assert!(colored_phase_label(true, &PhaseStatus::Error).starts_with("\x1b[97;41m"));
        assert_eq!(redaction_bar(false), "████████████");
        assert_eq!(
            display_redactions("bound [redacted]", false),
            "bound ████████████"
        );
    }

    #[test]
    fn parses_explicit_color_mode() {
        let cli =
            Cli::try_parse_from(["wgprobe", "test.conf", "--color", "always", "--redact"]).unwrap();
        assert_eq!(cli.color, ColorChoice::Always);
        assert!(cli.redact);
    }

    #[test]
    fn redacts_identity_and_local_socket_metadata() {
        let local_address = "192.168.1.10:54321".parse().unwrap();
        let mut report = ProbeReport {
            schema_version: 1,
            verdict: Verdict::DataPlaneConfirmed,
            endpoint: "198.51.100.1:51820".into(),
            resolved_endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            local_udp_address: Some(local_address),
            client_public_key: "public-identity".into(),
            duration_ms: 1,
            sent_bytes: 1,
            received_bytes: 1,
            phases: vec![wgprobe::PhaseResult {
                phase: "socket".into(),
                target: Some(local_address.to_string()),
                status: PhaseStatus::Passed,
                duration_ms: 0,
                sent_bytes: 0,
                received_bytes: 0,
                detail: Some(format!("bound {local_address}")),
            }],
        };

        redact_report(&mut report);

        assert_eq!(report.client_public_key, "[redacted]");
        assert_eq!(report.local_udp_address, None);
        assert_eq!(report.phases[0].target.as_deref(), Some("[redacted]"));
        assert_eq!(report.phases[0].detail.as_deref(), Some("bound [redacted]"));
    }

    #[test]
    fn raw_data_options_must_be_supplied_together() {
        let result = Cli::try_parse_from([
            "wgprobe",
            "--private-key-file",
            "key-file",
            "--peer-key",
            "public",
            "--endpoint",
            "127.0.0.1:1",
            "--address",
            "10.0.0.2/32",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversized_input() {
        let input = Cursor::new(vec![b'x'; 9]);
        let error = read_bounded(input, "test input", 8).unwrap_err();
        assert!(error.contains("8-byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_reader_rejects_non_regular_files() {
        let error = read_secret_file(Path::new("/dev/null"), "configuration", 8).unwrap_err();
        assert!(error.contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir();
        let unique = format!("wgprobe-symlink-{}", std::process::id());
        let link = directory.join(unique);
        let _ = fs::remove_file(&link);
        symlink("/dev/null", &link).unwrap();
        let error = read_secret_file(&link, "private key", 4096).unwrap_err();
        fs::remove_file(link).unwrap();
        assert!(error.contains("regular file"));
    }
}

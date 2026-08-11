use std::fs::{self, File};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use napi::{Error, Result, Status};
use napi_derive::napi;
use wgprobe::{Ipv4Cidr, PhaseStatus, ProbeConfig, ProbePlan, Verdict};
use zeroize::Zeroizing;

const MAX_TIMEOUT_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 4096;
const MAX_CONCURRENT_PROBES: usize = 8;

static ACTIVE_PROBES: AtomicUsize = AtomicUsize::new(0);

#[napi(object)]
#[derive(Clone, Default)]
pub struct ProbeOptions {
    pub ping: Option<Vec<String>>,
    pub resolve: Option<Vec<String>>,
    pub dns_server: Option<String>,
    pub handshake_timeout_ms: Option<f64>,
    pub ping_timeout_ms: Option<f64>,
    pub dns_timeout_ms: Option<f64>,
    pub deadline_ms: Option<f64>,
}

#[napi(object)]
#[derive(Clone, Default)]
pub struct ProbeKeyFileOptions {
    pub address: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub ping: Option<Vec<String>>,
    pub resolve: Option<Vec<String>>,
    pub dns_server: Option<String>,
    pub handshake_timeout_ms: Option<f64>,
    pub ping_timeout_ms: Option<f64>,
    pub dns_timeout_ms: Option<f64>,
    pub deadline_ms: Option<f64>,
}

#[napi(object)]
pub struct PhaseResult {
    pub phase: String,
    pub target: Option<String>,
    #[napi(ts_type = "PhaseStatus")]
    pub status: String,
    pub duration_ms: f64,
    pub sent_bytes: f64,
    pub received_bytes: f64,
    pub detail: Option<String>,
}

#[napi(object)]
pub struct ProbeReport {
    pub schema_version: u32,
    #[napi(ts_type = "Verdict")]
    pub verdict: String,
    pub endpoint: String,
    pub resolved_endpoint: Option<String>,
    pub local_udp_address: Option<String>,
    pub client_public_key: String,
    pub duration_ms: f64,
    pub sent_bytes: f64,
    pub received_bytes: f64,
    pub phases: Vec<PhaseResult>,
}

struct ParsedOptions {
    pings: Vec<Ipv4Addr>,
    resolves: Vec<String>,
    dns_server: Option<Ipv4Addr>,
    handshake_timeout: Duration,
    ping_timeout: Duration,
    dns_timeout: Duration,
    deadline: Duration,
}

impl ParsedOptions {
    fn parse(options: ProbeOptions) -> Result<Self> {
        Ok(Self {
            pings: options
                .ping
                .unwrap_or_default()
                .iter()
                .map(|value| parse_ipv4(value, "ping target"))
                .collect::<Result<_>>()?,
            resolves: options.resolve.unwrap_or_default(),
            dns_server: options
                .dns_server
                .as_deref()
                .map(|value| parse_ipv4(value, "dnsServer"))
                .transpose()?,
            handshake_timeout: timeout(
                options.handshake_timeout_ms.unwrap_or(3000.0),
                "handshakeTimeoutMs",
            )?,
            ping_timeout: timeout(options.ping_timeout_ms.unwrap_or(1000.0), "pingTimeoutMs")?,
            dns_timeout: timeout(options.dns_timeout_ms.unwrap_or(2000.0), "dnsTimeoutMs")?,
            deadline: timeout(options.deadline_ms.unwrap_or(9000.0), "deadlineMs")?,
        })
    }

    fn plan(&self, config: ProbeConfig) -> Result<ProbePlan> {
        let mut plan = ProbePlan::new(config).timeouts(
            self.handshake_timeout,
            self.ping_timeout,
            self.dns_timeout,
            self.deadline,
        );
        for target in &self.pings {
            plan = plan.ping(*target);
        }
        for name in &self.resolves {
            plan = plan.resolve(name);
        }
        if let Some(server) = self.dns_server {
            plan = plan.dns_server(server);
        }
        plan.validate().map_err(configuration_error)?;
        Ok(plan)
    }

    fn has_data_checks(&self) -> bool {
        !self.pings.is_empty() || !self.resolves.is_empty()
    }
}

enum ProbeInput {
    ConfigFile {
        path: String,
    },
    KeyFile {
        path: String,
        peer_key: String,
        endpoint: String,
        address: Option<String>,
        allowed_ips: Vec<String>,
    },
}

struct ProbeSlot;

impl ProbeSlot {
    fn acquire() -> Result<Self> {
        ACTIVE_PROBES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_PROBES).then_some(active + 1)
            })
            .map_err(|_| {
                Error::new(
                    Status::GenericFailure,
                    format!("at most {MAX_CONCURRENT_PROBES} probes can run concurrently"),
                )
            })?;
        Ok(Self)
    }
}

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        ACTIVE_PROBES.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run_probe(input: ProbeInput, options: ProbeOptions) -> Result<ProbeReport> {
    let options = ParsedOptions::parse(options)?;
    let config = match input {
        ProbeInput::ConfigFile { path } => load_config_file(Path::new(&path))?,
        ProbeInput::KeyFile {
            path,
            peer_key,
            endpoint,
            address,
            allowed_ips,
        } => {
            if address.is_some() != !allowed_ips.is_empty() {
                return Err(configuration_error(
                    "address and at least one allowedIps entry must be supplied together",
                ));
            }
            if options.has_data_checks() && address.is_none() {
                return Err(configuration_error(
                    "data checks require address and at least one allowedIps entry",
                ));
            }
            if !options.resolves.is_empty() && options.dns_server.is_none() {
                return Err(configuration_error(
                    "resolve requires an IPv4 dnsServer in raw-key mode",
                ));
            }

            let address = address
                .as_deref()
                .map(|value| parse_cidr(value, "address"))
                .transpose()?;
            let allowed_ips = allowed_ips
                .iter()
                .map(|value| parse_cidr(value, "allowedIps entry"))
                .collect::<Result<Vec<_>>>()?;
            let mut config = load_key_file(Path::new(&path), &peer_key, endpoint)?;
            if let Some(address) = address {
                config.set_data_config(address, Vec::<IpAddr>::new(), allowed_ips);
            }
            config
        }
    };
    Ok(ProbeReport::from(wgprobe::probe(
        options.plan(config)?,
        |_| {},
    )))
}

#[napi]
pub async fn probe_file(config_path: String, options: Option<ProbeOptions>) -> Result<ProbeReport> {
    let slot = ProbeSlot::acquire()?;
    napi::tokio::task::spawn_blocking(move || {
        let _slot = slot;
        run_probe(
            ProbeInput::ConfigFile { path: config_path },
            options.unwrap_or_default(),
        )
    })
    .await
    .map_err(|error| Error::from_reason(format!("probe worker failed: {error}")))?
}

#[napi]
pub async fn probe_key_file(
    private_key_path: String,
    peer_key: String,
    endpoint: String,
    options: Option<ProbeKeyFileOptions>,
) -> Result<ProbeReport> {
    let options = options.unwrap_or_default();
    let input = ProbeInput::KeyFile {
        path: private_key_path,
        peer_key,
        endpoint,
        address: options.address,
        allowed_ips: options.allowed_ips.unwrap_or_default(),
    };
    let probe_options = ProbeOptions {
        ping: options.ping,
        resolve: options.resolve,
        dns_server: options.dns_server,
        handshake_timeout_ms: options.handshake_timeout_ms,
        ping_timeout_ms: options.ping_timeout_ms,
        dns_timeout_ms: options.dns_timeout_ms,
        deadline_ms: options.deadline_ms,
    };
    let slot = ProbeSlot::acquire()?;
    napi::tokio::task::spawn_blocking(move || {
        let _slot = slot;
        run_probe(input, probe_options)
    })
    .await
    .map_err(|error| Error::from_reason(format!("probe worker failed: {error}")))?
}

#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn load_config_file(path: &Path) -> Result<ProbeConfig> {
    let contents = read_secret_file(path, "configuration", MAX_CONFIG_FILE_BYTES)?;
    let text = secret_text(&contents, "WireGuard configuration")?;
    ProbeConfig::parse(text).map_err(configuration_error)
}

fn load_key_file(path: &Path, peer_key: &str, endpoint: String) -> Result<ProbeConfig> {
    let contents = read_secret_file(path, "private key", MAX_PRIVATE_KEY_FILE_BYTES)?;
    let private_key = secret_text(&contents, "private key")?;
    ProbeConfig::from_parts(private_key, peer_key, endpoint).map_err(configuration_error)
}

fn read_secret_file(path: &Path, kind: &str, maximum_bytes: u64) -> Result<Zeroizing<Vec<u8>>> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        configuration_error(format!(
            "could not inspect {kind} file {}: {error}",
            path.display()
        ))
    })?;
    if !path_metadata.file_type().is_file() {
        return Err(configuration_error(format!(
            "{kind} path {} must be a regular file",
            path.display()
        )));
    }
    if path_metadata.len() > maximum_bytes {
        return Err(configuration_error(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        )));
    }

    let file = File::open(path).map_err(|error| {
        configuration_error(format!(
            "could not open {kind} file {}: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        configuration_error(format!(
            "could not inspect open {kind} file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(configuration_error(format!(
            "{kind} path {} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(configuration_error(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        )));
    }

    let mut contents = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(maximum_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|error| {
            configuration_error(format!(
                "could not read {kind} file {}: {error}",
                path.display()
            ))
        })?;
    if contents.len() as u64 > maximum_bytes {
        return Err(configuration_error(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        )));
    }
    Ok(contents)
}

fn secret_text<'a>(contents: &'a [u8], kind: &str) -> Result<&'a str> {
    str::from_utf8(contents)
        .map_err(|_| configuration_error(format!("{kind} file must be valid UTF-8")))
}

fn timeout(value: f64, name: &str) -> Result<Duration> {
    if !value.is_finite() || value.fract() != 0.0 || !(1.0..=MAX_TIMEOUT_MS as f64).contains(&value)
    {
        return Err(configuration_error(format!(
            "{name} must be an integer from 1 through {MAX_TIMEOUT_MS}"
        )));
    }
    Ok(Duration::from_millis(value as u64))
}

fn parse_ipv4(value: &str, name: &str) -> Result<Ipv4Addr> {
    value
        .parse()
        .map_err(|_| configuration_error(format!("{name} must be an IPv4 address, got {value}")))
}

fn parse_cidr(value: &str, name: &str) -> Result<Ipv4Cidr> {
    value
        .parse()
        .map_err(|_| configuration_error(format!("{name} must be an IPv4 CIDR, got {value}")))
}

fn configuration_error(error: impl ToString) -> Error {
    Error::new(Status::InvalidArg, error.to_string())
}

impl From<wgprobe::ProbeReport> for ProbeReport {
    fn from(report: wgprobe::ProbeReport) -> Self {
        Self {
            schema_version: u32::from(report.schema_version),
            verdict: verdict_name(&report.verdict).into(),
            endpoint: report.endpoint,
            resolved_endpoint: report.resolved_endpoint.map(|value| value.to_string()),
            local_udp_address: report.local_udp_address.map(|value| value.to_string()),
            client_public_key: report.client_public_key,
            duration_ms: report.duration_ms as f64,
            sent_bytes: report.sent_bytes as f64,
            received_bytes: report.received_bytes as f64,
            phases: report.phases.into_iter().map(PhaseResult::from).collect(),
        }
    }
}

impl From<wgprobe::PhaseResult> for PhaseResult {
    fn from(phase: wgprobe::PhaseResult) -> Self {
        Self {
            phase: phase.phase,
            target: phase.target,
            status: phase_status_name(&phase.status).into(),
            duration_ms: phase.duration_ms as f64,
            sent_bytes: phase.sent_bytes as f64,
            received_bytes: phase.received_bytes as f64,
            detail: phase.detail,
        }
    }
}

fn phase_status_name(status: &PhaseStatus) -> &'static str {
    match status {
        PhaseStatus::Passed => "passed",
        PhaseStatus::Sent => "sent",
        PhaseStatus::Unconfirmed => "unconfirmed",
        PhaseStatus::Skipped => "skipped",
        PhaseStatus::Error => "error",
    }
}

fn verdict_name(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::AuthenticationConfirmed => "authentication_confirmed",
        Verdict::DataPlaneConfirmed => "data_plane_confirmed",
        Verdict::Unconfirmed => "unconfirmed",
        Verdict::LocalError => "local_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_stable_names() {
        assert_eq!(phase_status_name(&PhaseStatus::Passed), "passed");
        assert_eq!(phase_status_name(&PhaseStatus::Error), "error");
        assert_eq!(
            verdict_name(&Verdict::AuthenticationConfirmed),
            "authentication_confirmed"
        );
        assert_eq!(verdict_name(&Verdict::LocalError), "local_error");
    }

    #[test]
    fn rejects_invalid_timeouts() {
        let error = timeout(0.0, "deadlineMs").unwrap_err();
        assert_eq!(error.status, Status::InvalidArg);
        assert!(error.reason.contains("1 through 86400000"));

        assert!(timeout(1.5, "deadlineMs").is_err());
        assert!(timeout(f64::NAN, "deadlineMs").is_err());
    }

    #[test]
    fn bounds_concurrent_probes() {
        let slots = (0..MAX_CONCURRENT_PROBES)
            .map(|_| ProbeSlot::acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(ProbeSlot::acquire().is_err());
        drop(slots);
        assert!(ProbeSlot::acquire().is_ok());
    }
}

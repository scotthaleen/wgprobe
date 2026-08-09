use std::fs::{self, File};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyTuple};
use pyo3::wrap_pyfunction;
use wgprobe::{Ipv4Cidr, PhaseStatus, ProbeConfig, ProbePlan, Verdict};
use zeroize::Zeroizing;

create_exception!(_wgprobe, WgprobeError, PyException);
create_exception!(_wgprobe, ConfigurationError, WgprobeError);

const MAX_TIMEOUT_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 4096;

#[derive(Clone, Copy)]
struct TimeoutArg(i64);

impl FromPyObject<'_, '_> for TimeoutArg {
    type Error = PyErr;

    fn extract(value: Borrowed<'_, '_, PyAny>) -> Result<Self, Self::Error> {
        value.extract::<i64>().map(Self).map_err(|_| {
            ConfigurationError::new_err(format!(
                "timeout must be an integer from 1 through {MAX_TIMEOUT_MS}"
            ))
        })
    }
}

#[pyclass(frozen, module = "wgprobe._wgprobe")]
struct PhaseResult {
    #[pyo3(get)]
    phase: String,
    #[pyo3(get)]
    target: Option<String>,
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    duration_ms: u64,
    #[pyo3(get)]
    sent_bytes: u64,
    #[pyo3(get)]
    received_bytes: u64,
    #[pyo3(get)]
    detail: Option<String>,
    json: String,
}

#[pymethods]
impl PhaseResult {
    fn to_json(&self) -> String {
        self.json.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "PhaseResult(phase={:?}, target={:?}, status={:?}, duration_ms={}, sent_bytes={}, received_bytes={})",
            self.phase,
            self.target,
            self.status,
            self.duration_ms,
            self.sent_bytes,
            self.received_bytes
        )
    }
}

#[pyclass(frozen, module = "wgprobe._wgprobe")]
struct ProbeReport {
    #[pyo3(get)]
    schema_version: u8,
    #[pyo3(get)]
    verdict: String,
    #[pyo3(get)]
    endpoint: String,
    #[pyo3(get)]
    resolved_endpoint: Option<String>,
    #[pyo3(get)]
    local_udp_address: Option<String>,
    #[pyo3(get)]
    client_public_key: String,
    #[pyo3(get)]
    duration_ms: u64,
    #[pyo3(get)]
    sent_bytes: u64,
    #[pyo3(get)]
    received_bytes: u64,
    phases: Py<PyTuple>,
    json: String,
}

#[pymethods]
impl ProbeReport {
    #[getter]
    fn phases(&self, py: Python<'_>) -> Py<PyTuple> {
        self.phases.clone_ref(py)
    }

    fn to_json(&self) -> String {
        self.json.clone()
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "ProbeReport(verdict={:?}, endpoint={:?}, duration_ms={}, sent_bytes={}, received_bytes={}, phases={})",
            self.verdict,
            self.endpoint,
            self.duration_ms,
            self.sent_bytes,
            self.received_bytes,
            self.phases.bind(py).len()
        )
    }
}

struct ProbeOptions {
    pings: Vec<Ipv4Addr>,
    resolves: Vec<String>,
    dns_server: Option<Ipv4Addr>,
    handshake_timeout: Duration,
    ping_timeout: Duration,
    dns_timeout: Duration,
    deadline: Duration,
}

impl ProbeOptions {
    fn parse(
        ping: Vec<String>,
        resolve: Vec<String>,
        dns_server: Option<String>,
        handshake_timeout_ms: TimeoutArg,
        ping_timeout_ms: TimeoutArg,
        dns_timeout_ms: TimeoutArg,
        deadline_ms: TimeoutArg,
    ) -> PyResult<Self> {
        Ok(Self {
            pings: ping
                .iter()
                .map(|value| parse_ipv4(value, "ping target"))
                .collect::<PyResult<_>>()?,
            resolves: resolve,
            dns_server: dns_server
                .as_deref()
                .map(|value| parse_ipv4(value, "dns_server"))
                .transpose()?,
            handshake_timeout: timeout(handshake_timeout_ms, "handshake_timeout_ms")?,
            ping_timeout: timeout(ping_timeout_ms, "ping_timeout_ms")?,
            dns_timeout: timeout(dns_timeout_ms, "dns_timeout_ms")?,
            deadline: timeout(deadline_ms, "deadline_ms")?,
        })
    }

    fn plan(&self, config: ProbeConfig) -> PyResult<ProbePlan> {
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
        plan.validate()
            .map_err(|error| ConfigurationError::new_err(error.to_string()))?;
        Ok(plan)
    }

    fn has_data_checks(&self) -> bool {
        !self.pings.is_empty() || !self.resolves.is_empty()
    }
}

#[pyfunction]
#[pyo3(signature = (config_path, *, ping=Vec::new(), resolve=Vec::new(), dns_server=None, handshake_timeout_ms=TimeoutArg(3000), ping_timeout_ms=TimeoutArg(1000), dns_timeout_ms=TimeoutArg(2000), deadline_ms=TimeoutArg(9000)))]
#[pyo3(
    text_signature = "(config_path, *, ping=(), resolve=(), dns_server=None, handshake_timeout_ms=3000, ping_timeout_ms=1000, dns_timeout_ms=2000, deadline_ms=9000)"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "signature is the public Python API"
)]
fn probe_file(
    py: Python<'_>,
    config_path: PathBuf,
    ping: Vec<String>,
    resolve: Vec<String>,
    dns_server: Option<String>,
    handshake_timeout_ms: TimeoutArg,
    ping_timeout_ms: TimeoutArg,
    dns_timeout_ms: TimeoutArg,
    deadline_ms: TimeoutArg,
) -> PyResult<ProbeReport> {
    let options = ProbeOptions::parse(
        ping,
        resolve,
        dns_server,
        handshake_timeout_ms,
        ping_timeout_ms,
        dns_timeout_ms,
        deadline_ms,
    )?;
    let config = py
        .detach(move || load_config_file(&config_path))
        .map_err(ConfigurationError::new_err)?;
    run_probe(py, options.plan(config)?)
}

#[pyfunction]
#[pyo3(signature = (private_key_path, peer_key, endpoint, *, address=None, allowed_ips=Vec::new(), ping=Vec::new(), resolve=Vec::new(), dns_server=None, handshake_timeout_ms=TimeoutArg(3000), ping_timeout_ms=TimeoutArg(1000), dns_timeout_ms=TimeoutArg(2000), deadline_ms=TimeoutArg(9000)))]
#[pyo3(
    text_signature = "(private_key_path, peer_key, endpoint, *, address=None, allowed_ips=(), ping=(), resolve=(), dns_server=None, handshake_timeout_ms=3000, ping_timeout_ms=1000, dns_timeout_ms=2000, deadline_ms=9000)"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "signature is the public Python API"
)]
fn probe_key_file(
    py: Python<'_>,
    private_key_path: PathBuf,
    peer_key: String,
    endpoint: String,
    address: Option<String>,
    allowed_ips: Vec<String>,
    ping: Vec<String>,
    resolve: Vec<String>,
    dns_server: Option<String>,
    handshake_timeout_ms: TimeoutArg,
    ping_timeout_ms: TimeoutArg,
    dns_timeout_ms: TimeoutArg,
    deadline_ms: TimeoutArg,
) -> PyResult<ProbeReport> {
    let options = ProbeOptions::parse(
        ping,
        resolve,
        dns_server,
        handshake_timeout_ms,
        ping_timeout_ms,
        dns_timeout_ms,
        deadline_ms,
    )?;
    if address.is_some() != !allowed_ips.is_empty() {
        return Err(ConfigurationError::new_err(
            "address and at least one allowed_ips entry must be supplied together",
        ));
    }
    if options.has_data_checks() && address.is_none() {
        return Err(ConfigurationError::new_err(
            "data checks require address and at least one allowed_ips entry",
        ));
    }
    if !options.resolves.is_empty() && options.dns_server.is_none() {
        return Err(ConfigurationError::new_err(
            "resolve requires an IPv4 dns_server in raw-key mode",
        ));
    }

    let address = address
        .as_deref()
        .map(|value| parse_cidr(value, "address"))
        .transpose()?;
    let allowed_ips = allowed_ips
        .iter()
        .map(|value| parse_cidr(value, "allowed_ips entry"))
        .collect::<PyResult<Vec<_>>>()?;
    let mut config = py
        .detach(move || load_key_file(&private_key_path, &peer_key, endpoint))
        .map_err(ConfigurationError::new_err)?;
    if let Some(address) = address {
        config.set_data_config(address, Vec::<IpAddr>::new(), allowed_ips);
    }
    run_probe(py, options.plan(config)?)
}

fn run_probe(py: Python<'_>, plan: ProbePlan) -> PyResult<ProbeReport> {
    let report = py.detach(move || wgprobe::probe(plan, |_| {}));
    ProbeReport::from_rust(py, report)
}

fn load_config_file(path: &Path) -> Result<ProbeConfig, String> {
    let contents = read_secret_file(path, "configuration", MAX_CONFIG_FILE_BYTES)?;
    let text = secret_text(&contents, "WireGuard configuration")?;
    ProbeConfig::parse(text).map_err(|error| error.to_string())
}

fn load_key_file(path: &Path, peer_key: &str, endpoint: String) -> Result<ProbeConfig, String> {
    let contents = read_secret_file(path, "private key", MAX_PRIVATE_KEY_FILE_BYTES)?;
    let private_key = secret_text(&contents, "private key")?;
    ProbeConfig::from_parts(private_key, peer_key, endpoint).map_err(|error| error.to_string())
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

    let file = File::open(path)
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

    let mut contents = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(maximum_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|error| format!("could not read {kind} file {}: {error}", path.display()))?;
    if contents.len() as u64 > maximum_bytes {
        return Err(format!(
            "{kind} file {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        ));
    }
    Ok(contents)
}

fn secret_text<'a>(contents: &'a [u8], kind: &str) -> Result<&'a str, String> {
    str::from_utf8(contents).map_err(|_| format!("{kind} file must be valid UTF-8"))
}

fn timeout(value: TimeoutArg, name: &str) -> PyResult<Duration> {
    let value = value.0;
    if !(1..=MAX_TIMEOUT_MS).contains(&value) {
        return Err(ConfigurationError::new_err(format!(
            "{name} must be an integer from 1 through {MAX_TIMEOUT_MS}"
        )));
    }
    Ok(Duration::from_millis(value as u64))
}

fn parse_ipv4(value: &str, name: &str) -> PyResult<Ipv4Addr> {
    value.parse().map_err(|_| {
        ConfigurationError::new_err(format!("{name} must be an IPv4 address, got {value}"))
    })
}

fn parse_cidr(value: &str, name: &str) -> PyResult<Ipv4Cidr> {
    value.parse().map_err(|_| {
        ConfigurationError::new_err(format!("{name} must be an IPv4 CIDR, got {value}"))
    })
}

impl ProbeReport {
    fn from_rust(py: Python<'_>, report: wgprobe::ProbeReport) -> PyResult<Self> {
        let json = serde_json::to_string(&report)
            .expect("the stable wgprobe report schema must serialize");
        let phases = report
            .phases
            .iter()
            .map(|phase| Py::new(py, PhaseResult::from_rust(phase)))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            schema_version: report.schema_version,
            verdict: verdict_name(&report.verdict).into(),
            endpoint: report.endpoint,
            resolved_endpoint: report.resolved_endpoint.map(|value| value.to_string()),
            local_udp_address: report.local_udp_address.map(|value| value.to_string()),
            client_public_key: report.client_public_key,
            duration_ms: report.duration_ms,
            sent_bytes: report.sent_bytes,
            received_bytes: report.received_bytes,
            phases: PyTuple::new(py, phases)?.unbind(),
            json,
        })
    }
}

impl PhaseResult {
    fn from_rust(phase: &wgprobe::PhaseResult) -> Self {
        Self {
            phase: phase.phase.clone(),
            target: phase.target.clone(),
            status: phase_status_name(&phase.status).into(),
            duration_ms: phase.duration_ms,
            sent_bytes: phase.sent_bytes,
            received_bytes: phase.received_bytes,
            detail: phase.detail.clone(),
            json: serde_json::to_string(phase)
                .expect("the stable wgprobe phase schema must serialize"),
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

#[pymodule]
fn _wgprobe(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<ProbeReport>()?;
    module.add_class::<PhaseResult>()?;
    module.add("WgprobeError", module.py().get_type::<WgprobeError>())?;
    module.add(
        "ConfigurationError",
        module.py().get_type::<ConfigurationError>(),
    )?;
    module.add_function(wrap_pyfunction!(probe_file, module)?)?;
    module.add_function(wrap_pyfunction!(probe_key_file, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn maps_all_stable_enum_names() {
        assert_eq!(phase_status_name(&PhaseStatus::Passed), "passed");
        assert_eq!(phase_status_name(&PhaseStatus::Sent), "sent");
        assert_eq!(phase_status_name(&PhaseStatus::Unconfirmed), "unconfirmed");
        assert_eq!(phase_status_name(&PhaseStatus::Skipped), "skipped");
        assert_eq!(phase_status_name(&PhaseStatus::Error), "error");
        assert_eq!(
            verdict_name(&Verdict::AuthenticationConfirmed),
            "authentication_confirmed"
        );
        assert_eq!(
            verdict_name(&Verdict::DataPlaneConfirmed),
            "data_plane_confirmed"
        );
        assert_eq!(verdict_name(&Verdict::Unconfirmed), "unconfirmed");
        assert_eq!(verdict_name(&Verdict::LocalError), "local_error");
    }

    #[test]
    fn converts_report_fields_and_immutable_phases() {
        Python::initialize();
        Python::attach(|py| {
            let report = wgprobe::ProbeReport {
                schema_version: 1,
                verdict: Verdict::AuthenticationConfirmed,
                endpoint: "example.test:51820".into(),
                resolved_endpoint: Some("192.0.2.1:51820".parse::<SocketAddr>().unwrap()),
                local_udp_address: Some("192.0.2.2:12345".parse::<SocketAddr>().unwrap()),
                client_public_key: "public-only".into(),
                duration_ms: 12,
                sent_bytes: 148,
                received_bytes: 92,
                phases: vec![wgprobe::PhaseResult {
                    phase: "handshake".into(),
                    target: Some("192.0.2.1:51820".into()),
                    status: PhaseStatus::Passed,
                    duration_ms: 10,
                    sent_bytes: 148,
                    received_bytes: 92,
                    detail: Some("authenticated WireGuard response".into()),
                }],
            };
            let mapped = ProbeReport::from_rust(py, report).unwrap();
            assert_eq!(mapped.verdict, "authentication_confirmed");
            assert_eq!(mapped.resolved_endpoint.as_deref(), Some("192.0.2.1:51820"));
            assert_eq!(mapped.phases.bind(py).len(), 1);
            assert_eq!(
                mapped
                    .phases
                    .bind(py)
                    .get_item(0)
                    .unwrap()
                    .getattr("status")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "passed"
            );
            assert!(
                mapped
                    .json
                    .contains("\"client_public_key\":\"public-only\"")
            );
        });
    }
}

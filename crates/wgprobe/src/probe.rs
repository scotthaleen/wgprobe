use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use boringtun::noise::{Packet, Tunn, TunnResult};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use thiserror::Error;

use crate::packet::{dns_query, icmp_echo_request, is_icmp_echo_reply, parse_dns_a_response};
use crate::{Ipv4Cidr, ProbeConfig};

const BUFFER_SIZE: usize = 65_535;
const MAX_RESOLVER_WORKERS: usize = 4;
static ACTIVE_RESOLVER_WORKERS: AtomicUsize = AtomicUsize::new(0);

pub struct ProbePlan {
    config: ProbeConfig,
    pings: Vec<Ipv4Addr>,
    resolves: Vec<String>,
    dns_server: Option<Ipv4Addr>,
    handshake_timeout: Duration,
    ping_timeout: Duration,
    dns_timeout: Duration,
    overall_timeout: Duration,
}

impl ProbePlan {
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            pings: Vec::new(),
            resolves: Vec::new(),
            dns_server: None,
            handshake_timeout: Duration::from_millis(3000),
            ping_timeout: Duration::from_millis(1000),
            dns_timeout: Duration::from_millis(2000),
            overall_timeout: Duration::from_millis(9000),
        }
    }

    pub fn ping(mut self, target: Ipv4Addr) -> Self {
        self.pings.push(target);
        self
    }

    pub fn resolve(mut self, name: impl Into<String>) -> Self {
        self.resolves.push(name.into());
        self
    }

    pub fn dns_server(mut self, server: Ipv4Addr) -> Self {
        self.dns_server = Some(server);
        self
    }

    pub fn timeouts(
        mut self,
        handshake: Duration,
        ping: Duration,
        dns: Duration,
        overall: Duration,
    ) -> Self {
        self.handshake_timeout = handshake;
        self.ping_timeout = ping;
        self.dns_timeout = dns;
        self.overall_timeout = overall;
        self
    }

    /// Validate local plan requirements without resolving or contacting the endpoint.
    pub fn validate(&self) -> Result<(), ProbeError> {
        let source = self.config.address.map(Ipv4Cidr::address);
        let dns_server = self.dns_server.or_else(|| {
            self.config.dns_servers.first().and_then(|ip| match ip {
                IpAddr::V4(ip) => Some(*ip),
                IpAddr::V6(_) => None,
            })
        });
        let now = Instant::now();
        if [
            self.handshake_timeout,
            self.ping_timeout,
            self.dns_timeout,
            self.overall_timeout,
        ]
        .iter()
        .any(|timeout| now.checked_add(*timeout).is_none())
        {
            return Err(ProbeError::InvalidPlan(
                "timeouts and the overall deadline must be representable by the system clock"
                    .into(),
            ));
        }
        match validate_plan(self, source, dns_server) {
            Some(detail) => Err(ProbeError::InvalidPlan(detail)),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Passed,
    Sent,
    Unconfirmed,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    AuthenticationConfirmed,
    DataPlaneConfirmed,
    Unconfirmed,
    LocalError,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PhaseResult {
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub status: PhaseStatus,
    pub duration_ms: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProbeReport {
    pub schema_version: u8,
    pub verdict: Verdict,
    pub endpoint: String,
    pub resolved_endpoint: Option<SocketAddr>,
    pub local_udp_address: Option<SocketAddr>,
    pub client_public_key: String,
    pub duration_ms: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub phases: Vec<PhaseResult>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeEventKind {
    Started,
    Finished,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProbeEvent {
    pub kind: ProbeEventKind,
    pub phase: String,
    pub target: Option<String>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<PhaseResult>,
}

pub fn probe<F>(plan: ProbePlan, mut progress: F) -> ProbeReport
where
    F: FnMut(&ProbeEvent),
{
    let started = Instant::now();
    let mut report = ProbeReport {
        schema_version: 1,
        verdict: Verdict::Unconfirmed,
        endpoint: plan.config.endpoint.clone(),
        resolved_endpoint: None,
        local_udp_address: None,
        client_public_key: plan.config.client_public_key(),
        duration_ms: 0,
        sent_bytes: 0,
        received_bytes: 0,
        phases: Vec::new(),
    };

    let source = plan.config.address.map(Ipv4Cidr::address);
    let dns_server = plan.dns_server.or_else(|| {
        plan.config.dns_servers.first().and_then(|ip| match ip {
            IpAddr::V4(ip) => Some(*ip),
            IpAddr::V6(_) => None,
        })
    });
    if let Err(ProbeError::InvalidPlan(detail)) = plan.validate() {
        emit_start(&mut progress, started, "validation", None);
        push_phase(
            &mut report,
            &mut progress,
            started,
            PhaseResult {
                phase: "validation".into(),
                target: None,
                status: PhaseStatus::Error,
                duration_ms: 0,
                sent_bytes: 0,
                received_bytes: 0,
                detail: Some(detail),
            },
        );
        report.verdict = Verdict::LocalError;
        finish_report(&mut report, started);
        return report;
    }
    let overall_deadline = started.checked_add(plan.overall_timeout).unwrap_or(started);

    emit_start(
        &mut progress,
        started,
        "endpoint_resolution",
        Some(&report.endpoint),
    );
    let resolution_started = Instant::now();
    let endpoint = match resolve_endpoint(
        plan.config.endpoint.clone(),
        overall_deadline.saturating_duration_since(Instant::now()),
    ) {
        Ok(address) => address,
        Err(error) => {
            push_phase(
                &mut report,
                &mut progress,
                started,
                phase_error("endpoint_resolution", None, resolution_started, error),
            );
            report.verdict = Verdict::LocalError;
            finish_report(&mut report, started);
            return report;
        }
    };
    let Some(endpoint) = endpoint else {
        push_phase(
            &mut report,
            &mut progress,
            started,
            phase_error(
                "endpoint_resolution",
                None,
                resolution_started,
                "endpoint resolved to no addresses",
            ),
        );
        report.verdict = Verdict::LocalError;
        finish_report(&mut report, started);
        return report;
    };
    report.resolved_endpoint = Some(endpoint);
    push_phase(
        &mut report,
        &mut progress,
        started,
        phase_passed(
            "endpoint_resolution",
            Some(endpoint.to_string()),
            resolution_started,
            0,
            0,
            None,
        ),
    );

    let bind_address = match endpoint {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    emit_start(
        &mut progress,
        started,
        "socket",
        Some(&endpoint.to_string()),
    );
    let socket_started = Instant::now();
    let socket = match UdpSocket::bind(bind_address).and_then(|socket| {
        socket.connect(endpoint)?;
        Ok(socket)
    }) {
        Ok(socket) => socket,
        Err(error) => {
            push_phase(
                &mut report,
                &mut progress,
                started,
                phase_error("socket", Some(endpoint.to_string()), socket_started, error),
            );
            report.verdict = Verdict::LocalError;
            finish_report(&mut report, started);
            return report;
        }
    };
    report.local_udp_address = socket.local_addr().ok();
    let local_target = report.local_udp_address.map(|address| address.to_string());
    push_phase(
        &mut report,
        &mut progress,
        started,
        phase_passed(
            "socket",
            local_target,
            socket_started,
            0,
            0,
            Some("single connected UDP socket".into()),
        ),
    );

    let mut tunnel = Tunn::new(
        plan.config.private_key.clone(),
        plan.config.peer_public_key,
        plan.config.preshared_key,
        None,
        OsRng.next_u32(),
        None,
    );
    emit_start(
        &mut progress,
        started,
        "handshake",
        Some(&endpoint.to_string()),
    );
    let handshake_started = Instant::now();
    let handshake_deadline = deadline(overall_deadline, handshake_started, plan.handshake_timeout);
    match establish_session(&socket, endpoint, &mut tunnel, handshake_deadline) {
        Ok((handshake_sent, handshake_received, keepalive)) => {
            push_phase(
                &mut report,
                &mut progress,
                started,
                phase_passed(
                    "handshake",
                    Some(endpoint.to_string()),
                    handshake_started,
                    handshake_sent,
                    handshake_received,
                    Some("authenticated WireGuard response".into()),
                ),
            );
            emit_start(
                &mut progress,
                started,
                "keepalive",
                Some(&endpoint.to_string()),
            );
            let (keepalive_status, keepalive_sent, keepalive_detail) = match keepalive {
                Ok(sent) => (
                    PhaseStatus::Sent,
                    sent,
                    "initial encrypted keepalive sent; no acknowledgement expected".into(),
                ),
                Err(error) => (PhaseStatus::Error, 0, error),
            };
            push_phase(
                &mut report,
                &mut progress,
                started,
                PhaseResult {
                    phase: "keepalive".into(),
                    target: Some(endpoint.to_string()),
                    status: keepalive_status,
                    duration_ms: 0,
                    sent_bytes: keepalive_sent,
                    received_bytes: 0,
                    detail: Some(keepalive_detail),
                },
            );
            report.verdict = Verdict::AuthenticationConfirmed;
        }
        Err(failure) => {
            let local_error = failure.status == PhaseStatus::Error;
            push_phase(
                &mut report,
                &mut progress,
                started,
                PhaseResult {
                    phase: "handshake".into(),
                    target: Some(endpoint.to_string()),
                    status: failure.status,
                    duration_ms: millis(handshake_started.elapsed()),
                    sent_bytes: failure.sent,
                    received_bytes: failure.received,
                    detail: Some(failure.detail),
                },
            );
            if local_error {
                report.verdict = Verdict::LocalError;
            }
            for target in &plan.pings {
                push_skipped(
                    &mut report,
                    &mut progress,
                    started,
                    "ping",
                    target.to_string(),
                );
            }
            for name in &plan.resolves {
                push_skipped(&mut report, &mut progress, started, "dns", name.clone());
            }
            finish_report(&mut report, started);
            return report;
        }
    }

    let source = source.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut data_confirmed = false;
    for (sequence, target) in plan.pings.iter().enumerate() {
        let echo_id = OsRng.next_u32() as u16;
        let ip_id = OsRng.next_u32() as u16;
        let packet = icmp_echo_request(source, *target, ip_id, echo_id, sequence as u16);
        let target_text = target.to_string();
        emit_start(&mut progress, started, "ping", Some(&target_text));
        let check_started = Instant::now();
        let result = run_check(
            &socket,
            endpoint,
            &mut tunnel,
            &packet,
            deadline(overall_deadline, check_started, plan.ping_timeout),
            |reply| is_icmp_echo_reply(reply, *target, source, echo_id, sequence as u16),
        );
        let phase = check_phase("ping", target_text, check_started, result);
        data_confirmed |= phase.status == PhaseStatus::Passed;
        push_phase(&mut report, &mut progress, started, phase);
    }

    for name in &plan.resolves {
        let server = dns_server.expect("validated DNS server");
        let source_port = 32768 + (OsRng.next_u32() % 28232) as u16;
        let transaction_id = OsRng.next_u32() as u16;
        let ip_id = OsRng.next_u32() as u16;
        let target_text = format!("{name} via {server}");
        emit_start(&mut progress, started, "dns", Some(&target_text));
        let check_started = Instant::now();
        let packet = match dns_query(source, server, source_port, transaction_id, ip_id, name) {
            Ok(packet) => packet,
            Err(error) => {
                push_phase(
                    &mut report,
                    &mut progress,
                    started,
                    phase_error("dns", Some(target_text), check_started, error),
                );
                continue;
            }
        };
        let mut answers = Vec::new();
        let result = run_check(
            &socket,
            endpoint,
            &mut tunnel,
            &packet,
            deadline(overall_deadline, check_started, plan.dns_timeout),
            |reply| {
                if let Some(found) =
                    parse_dns_a_response(reply, server, source, source_port, transaction_id, name)
                {
                    answers = found;
                    true
                } else {
                    false
                }
            },
        );
        let mut phase = check_phase("dns", target_text, check_started, result);
        if phase.status == PhaseStatus::Passed {
            phase.detail = Some(format!(
                "valid DNS response; A records: {}",
                if answers.is_empty() {
                    "none".into()
                } else {
                    answers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            data_confirmed = true;
        }
        push_phase(&mut report, &mut progress, started, phase);
    }

    if data_confirmed {
        report.verdict = Verdict::DataPlaneConfirmed;
    }
    finish_report(&mut report, started);
    report
}

fn validate_plan(
    plan: &ProbePlan,
    source: Option<Ipv4Addr>,
    dns_server: Option<Ipv4Addr>,
) -> Option<String> {
    if plan.handshake_timeout.is_zero()
        || plan.ping_timeout.is_zero()
        || plan.dns_timeout.is_zero()
        || plan.overall_timeout.is_zero()
    {
        return Some("all timeouts and the overall deadline must be greater than zero".into());
    }
    if plan.pings.is_empty() && plan.resolves.is_empty() {
        return None;
    }
    if source.is_none() {
        return Some("data checks require an IPv4 Interface Address (or --address)".into());
    }
    if plan.config.allowed_ips.is_empty() {
        return Some("data checks require IPv4 Peer AllowedIPs (or --allowed-ip)".into());
    }
    if !plan.resolves.is_empty() && dns_server.is_none() {
        return Some("DNS checks require an IPv4 Interface DNS server or --dns-server".into());
    }
    for target in &plan.pings {
        if !is_allowed(&plan.config.allowed_ips, *target) {
            return Some(format!("ping target {target} is outside Peer AllowedIPs"));
        }
    }
    if let Some(server) = dns_server
        && !plan.resolves.is_empty()
        && !is_allowed(&plan.config.allowed_ips, server)
    {
        return Some(format!("DNS server {server} is outside Peer AllowedIPs"));
    }
    for name in &plan.resolves {
        if let Err(error) = dns_query(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 1, 1, 1, name) {
            return Some(format!("invalid DNS name {name}: {error}"));
        }
    }
    None
}

fn resolve_endpoint(endpoint: String, timeout: Duration) -> Result<Option<SocketAddr>, String> {
    if timeout.is_zero() {
        return Err("overall deadline expired before endpoint resolution".into());
    }
    if let Ok(endpoint) = endpoint.parse::<SocketAddr>() {
        return Ok(Some(endpoint));
    }
    let slot = ResolverSlot::acquire().ok_or_else(|| {
        format!("endpoint resolver capacity exhausted ({MAX_RESOLVER_WORKERS} workers)")
    })?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("wgprobe-resolver".into())
        .spawn(move || {
            let _slot = slot;
            let result = endpoint
                .to_socket_addrs()
                .map(|mut addresses| addresses.next())
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        })
        .map_err(|error| format!("could not start endpoint resolver: {error}"))?;
    receiver
        .recv_timeout(timeout)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                String::from("endpoint resolution exceeded the overall deadline")
            }
            mpsc::RecvTimeoutError::Disconnected => {
                String::from("endpoint resolver stopped unexpectedly")
            }
        })?
}

struct ResolverSlot;

impl ResolverSlot {
    fn acquire() -> Option<Self> {
        ACTIVE_RESOLVER_WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_RESOLVER_WORKERS).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ResolverSlot {
    fn drop(&mut self) {
        ACTIVE_RESOLVER_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn is_allowed(networks: &[Ipv4Cidr], address: Ipv4Addr) -> bool {
    networks.iter().any(|network| network.contains(address))
}

struct HandshakeFailure {
    status: PhaseStatus,
    detail: String,
    sent: u64,
    received: u64,
}

fn establish_session(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    tunnel: &mut Tunn,
    deadline: Instant,
) -> Result<(u64, u64, Result<u64, String>), HandshakeFailure> {
    let mut output = vec![0u8; BUFFER_SIZE];
    let initiation = match tunnel.format_handshake_initiation(&mut output, false) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        TunnResult::Err(error) => return Err(handshake_protocol(error, 0, 0)),
        _ => {
            return Err(handshake_protocol(
                "no handshake initiation was produced",
                0,
                0,
            ));
        }
    };
    let mut sent = send(socket, &initiation, deadline).map_err(|error| match error {
        SendError::Timeout => handshake_timeout(0, 0),
        SendError::Io(error) => handshake_local(error, 0, 0),
    })?;
    let mut received = 0;
    let mut input = vec![0u8; BUFFER_SIZE];
    loop {
        let count = recv(socket, &mut input, deadline).map_err(|error| match error {
            ReceiveError::Timeout => HandshakeFailure {
                status: PhaseStatus::Unconfirmed,
                detail: "no authenticated response before the handshake deadline".into(),
                sent,
                received,
            },
            ReceiveError::Io(error) => handshake_local(error, sent, received),
        })?;
        received += count as u64;
        match Tunn::parse_incoming_packet(&input[..count]) {
            Ok(Packet::HandshakeResponse(_)) => {
                match tunnel.decapsulate(Some(endpoint.ip()), &input[..count], &mut output) {
                    TunnResult::WriteToNetwork(keepalive) => {
                        let keepalive =
                            send(socket, keepalive, deadline).map_err(|error| match error {
                                SendError::Timeout => {
                                    "handshake deadline expired before initial keepalive".into()
                                }
                                SendError::Io(error) => {
                                    format!("could not send initial keepalive: {error}")
                                }
                            });
                        return Ok((sent, received, keepalive));
                    }
                    TunnResult::Err(error) => {
                        return Err(handshake_protocol(error, sent, received));
                    }
                    _ => {
                        return Err(handshake_protocol(
                            "handshake response did not establish a session",
                            sent,
                            received,
                        ));
                    }
                }
            }
            Ok(Packet::PacketCookieReply(_)) => {
                match tunnel.decapsulate(Some(endpoint.ip()), &input[..count], &mut output) {
                    TunnResult::Done => {}
                    TunnResult::Err(error) => {
                        return Err(handshake_protocol(error, sent, received));
                    }
                    _ => return Err(handshake_protocol("invalid cookie reply", sent, received)),
                }
                match tunnel.format_handshake_initiation(&mut output, true) {
                    TunnResult::WriteToNetwork(packet) => {
                        let count =
                            send(socket, packet, deadline).map_err(|error| match error {
                                SendError::Timeout => handshake_timeout(sent, received),
                                SendError::Io(error) => handshake_local(error, sent, received),
                            })?;
                        sent += count;
                    }
                    TunnResult::Err(error) => {
                        return Err(handshake_protocol(error, sent, received));
                    }
                    _ => {
                        return Err(handshake_protocol(
                            "no cookie-authenticated retry was produced",
                            sent,
                            received,
                        ));
                    }
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
}

enum CheckOutcome {
    Passed {
        sent: u64,
        received: u64,
    },
    Unconfirmed {
        sent: u64,
        received: u64,
    },
    Error {
        detail: String,
        sent: u64,
        received: u64,
    },
}

fn run_check<F>(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    tunnel: &mut Tunn,
    inner_packet: &[u8],
    deadline: Instant,
    mut matches: F,
) -> CheckOutcome
where
    F: FnMut(&[u8]) -> bool,
{
    if deadline <= Instant::now() {
        return CheckOutcome::Unconfirmed {
            sent: 0,
            received: 0,
        };
    }
    let mut output = vec![0u8; BUFFER_SIZE];
    let encrypted = match tunnel.encapsulate(inner_packet, &mut output) {
        TunnResult::WriteToNetwork(packet) => packet,
        TunnResult::Err(error) => {
            return CheckOutcome::Error {
                detail: format!("WireGuard encapsulation error: {error:?}"),
                sent: 0,
                received: 0,
            };
        }
        _ => {
            return CheckOutcome::Error {
                detail: "WireGuard session did not encrypt the data packet".into(),
                sent: 0,
                received: 0,
            };
        }
    };
    let mut sent = match send(socket, encrypted, deadline) {
        Ok(count) => count,
        Err(SendError::Timeout) => {
            return CheckOutcome::Unconfirmed {
                sent: 0,
                received: 0,
            };
        }
        Err(SendError::Io(error)) => {
            return CheckOutcome::Error {
                detail: format!("could not send encrypted packet: {error}"),
                sent: 0,
                received: 0,
            };
        }
    };
    let mut received = 0;
    let mut input = vec![0u8; BUFFER_SIZE];
    loop {
        let count = match recv(socket, &mut input, deadline) {
            Ok(count) => count,
            Err(ReceiveError::Timeout) => return CheckOutcome::Unconfirmed { sent, received },
            Err(ReceiveError::Io(error)) => {
                return CheckOutcome::Error {
                    detail: format!("could not receive encrypted response: {error}"),
                    sent,
                    received,
                };
            }
        };
        received += count as u64;
        match tunnel.decapsulate(Some(endpoint.ip()), &input[..count], &mut output) {
            TunnResult::WriteToTunnelV4(packet, _) if matches(packet) => {
                return CheckOutcome::Passed { sent, received };
            }
            TunnResult::WriteToNetwork(packet) => match send(socket, packet, deadline) {
                Ok(count) => sent += count,
                Err(SendError::Timeout) => {
                    return CheckOutcome::Unconfirmed { sent, received };
                }
                Err(SendError::Io(error)) => {
                    return CheckOutcome::Error {
                        detail: format!("could not send WireGuard protocol packet: {error}"),
                        sent,
                        received,
                    };
                }
            },
            TunnResult::Err(error) => {
                return CheckOutcome::Error {
                    detail: format!("WireGuard decapsulation error: {error:?}"),
                    sent,
                    received,
                };
            }
            _ => {}
        }
    }
}

enum SendError {
    Timeout,
    Io(io::Error),
}

fn send(socket: &UdpSocket, packet: &[u8], deadline: Instant) -> Result<u64, SendError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SendError::Timeout);
    }
    socket
        .set_write_timeout(Some(remaining))
        .map_err(SendError::Io)?;
    if deadline <= Instant::now() {
        return Err(SendError::Timeout);
    }
    socket
        .send(packet)
        .map(|count| count as u64)
        .map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                SendError::Timeout
            } else {
                SendError::Io(error)
            }
        })
}

enum ReceiveError {
    Timeout,
    Io(io::Error),
}

fn recv(socket: &UdpSocket, input: &mut [u8], deadline: Instant) -> Result<usize, ReceiveError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ReceiveError::Timeout);
    }
    socket
        .set_read_timeout(Some(remaining))
        .map_err(ReceiveError::Io)?;
    socket.recv(input).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            ReceiveError::Timeout
        } else {
            ReceiveError::Io(error)
        }
    })
}

fn check_phase(phase: &str, target: String, started: Instant, result: CheckOutcome) -> PhaseResult {
    let (status, sent_bytes, received_bytes, detail) = match result {
        CheckOutcome::Passed { sent, received } => (
            PhaseStatus::Passed,
            sent,
            received,
            Some("valid matching reply".into()),
        ),
        CheckOutcome::Unconfirmed { sent, received } => (
            PhaseStatus::Unconfirmed,
            sent,
            received,
            Some("no valid matching reply before the check deadline".into()),
        ),
        CheckOutcome::Error {
            detail,
            sent,
            received,
        } => (PhaseStatus::Error, sent, received, Some(detail)),
    };
    PhaseResult {
        phase: phase.into(),
        target: Some(target),
        status,
        duration_ms: millis(started.elapsed()),
        sent_bytes,
        received_bytes,
        detail,
    }
}

fn phase_passed(
    phase: &str,
    target: Option<String>,
    started: Instant,
    sent_bytes: u64,
    received_bytes: u64,
    detail: Option<String>,
) -> PhaseResult {
    PhaseResult {
        phase: phase.into(),
        target,
        status: PhaseStatus::Passed,
        duration_ms: millis(started.elapsed()),
        sent_bytes,
        received_bytes,
        detail,
    }
}

fn phase_error(
    phase: &str,
    target: Option<String>,
    started: Instant,
    error: impl std::fmt::Display,
) -> PhaseResult {
    PhaseResult {
        phase: phase.into(),
        target,
        status: PhaseStatus::Error,
        duration_ms: millis(started.elapsed()),
        sent_bytes: 0,
        received_bytes: 0,
        detail: Some(error.to_string()),
    }
}

fn emit_start<F>(progress: &mut F, started: Instant, phase: &str, target: Option<&str>)
where
    F: FnMut(&ProbeEvent),
{
    progress(&ProbeEvent {
        kind: ProbeEventKind::Started,
        phase: phase.into(),
        target: target.map(str::to_owned),
        elapsed_ms: millis(started.elapsed()),
        result: None,
    });
}

fn push_phase<F>(report: &mut ProbeReport, progress: &mut F, started: Instant, phase: PhaseResult)
where
    F: FnMut(&ProbeEvent),
{
    report.sent_bytes += phase.sent_bytes;
    report.received_bytes += phase.received_bytes;
    progress(&ProbeEvent {
        kind: ProbeEventKind::Finished,
        phase: phase.phase.clone(),
        target: phase.target.clone(),
        elapsed_ms: millis(started.elapsed()),
        result: Some(phase.clone()),
    });
    report.phases.push(phase);
}

fn push_skipped<F>(
    report: &mut ProbeReport,
    progress: &mut F,
    started: Instant,
    phase: &str,
    target: String,
) where
    F: FnMut(&ProbeEvent),
{
    push_phase(
        report,
        progress,
        started,
        PhaseResult {
            phase: phase.into(),
            target: Some(target),
            status: PhaseStatus::Skipped,
            duration_ms: 0,
            sent_bytes: 0,
            received_bytes: 0,
            detail: Some("skipped because authentication was not confirmed".into()),
        },
    );
}

fn finish_report(report: &mut ProbeReport, started: Instant) {
    report.duration_ms = millis(started.elapsed());
}

fn deadline(overall: Instant, started: Instant, timeout: Duration) -> Instant {
    started
        .checked_add(timeout)
        .map_or(overall, |deadline| overall.min(deadline))
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn handshake_protocol(error: impl std::fmt::Debug, sent: u64, received: u64) -> HandshakeFailure {
    HandshakeFailure {
        status: PhaseStatus::Unconfirmed,
        detail: format!("WireGuard protocol error: {error:?}"),
        sent,
        received,
    }
}

fn handshake_local(error: impl std::fmt::Display, sent: u64, received: u64) -> HandshakeFailure {
    HandshakeFailure {
        status: PhaseStatus::Error,
        detail: format!("local UDP error: {error}"),
        sent,
        received,
    }
}

fn handshake_timeout(sent: u64, received: u64) -> HandshakeFailure {
    HandshakeFailure {
        status: PhaseStatus::Unconfirmed,
        detail: "no authenticated response before the handshake deadline".into(),
        sent,
        received,
    }
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("{0}")]
    InvalidPlan(String),
}

#[cfg(test)]
mod tests {
    use std::thread;

    use boringtun::x25519::{PublicKey, StaticSecret};

    use crate::packet::checksum;

    use super::*;

    #[test]
    fn transmits_keepalive_and_completes_userspace_ping() {
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint = socket.local_addr().unwrap();

        let server = thread::spawn(move || {
            let mut tunnel = Tunn::new(
                server_secret,
                client_public,
                None,
                None,
                OsRng.next_u32(),
                None,
            );
            let mut input = vec![0u8; BUFFER_SIZE];
            let mut output = vec![0u8; BUFFER_SIZE];
            let (received, source) = socket.recv_from(&mut input).unwrap();
            let response =
                match tunnel.decapsulate(Some(source.ip()), &input[..received], &mut output) {
                    TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                    result => panic!("unexpected handshake result: {result:?}"),
                };
            socket.send_to(&response, source).unwrap();

            let (received, _) = socket.recv_from(&mut input).unwrap();
            assert!(matches!(
                tunnel.decapsulate(Some(source.ip()), &input[..received], &mut output),
                TunnResult::Done
            ));

            let (received, _) = socket.recv_from(&mut input).unwrap();
            let request =
                match tunnel.decapsulate(Some(source.ip()), &input[..received], &mut output) {
                    TunnResult::WriteToTunnelV4(packet, _) => packet.to_vec(),
                    result => panic!("unexpected ping result: {result:?}"),
                };
            let mut reply = request;
            reply[12..16].copy_from_slice(&[10, 0, 0, 1]);
            reply[16..20].copy_from_slice(&[10, 0, 0, 2]);
            reply[10..12].fill(0);
            let ip_sum = checksum(&reply[..20]);
            reply[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            reply[20] = 0;
            reply[22..24].fill(0);
            let icmp_sum = checksum(&reply[20..]);
            reply[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
            let encrypted = match tunnel.encapsulate(&reply, &mut output) {
                TunnResult::WriteToNetwork(packet) => packet,
                result => panic!("unexpected reply result: {result:?}"),
            };
            socket.send_to(encrypted, source).unwrap();
        });

        let config = ProbeConfig {
            private_key: client_secret,
            peer_public_key: server_public,
            preshared_key: None,
            endpoint: endpoint.to_string(),
            address: Some("10.0.0.2/32".parse().unwrap()),
            dns_servers: Vec::new(),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        };
        let report = probe(
            ProbePlan::new(config)
                .ping("10.0.0.1".parse().unwrap())
                .timeouts(
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(3),
                ),
            |_| {},
        );
        assert_eq!(report.verdict, Verdict::DataPlaneConfirmed);
        assert_eq!(
            report
                .phases
                .iter()
                .find(|p| p.phase == "keepalive")
                .unwrap()
                .status,
            PhaseStatus::Sent
        );
        assert_eq!(
            report
                .phases
                .iter()
                .find(|p| p.phase == "ping")
                .unwrap()
                .status,
            PhaseStatus::Passed
        );
        server.join().unwrap();
    }

    #[test]
    fn reports_missing_data_configuration_without_network_io() {
        let config = ProbeConfig::from_parts(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "127.0.0.1:1",
        )
        .unwrap();
        let report = probe(ProbePlan::new(config).ping(Ipv4Addr::LOCALHOST), |_| {});
        assert_eq!(report.verdict, Verdict::LocalError);
        assert!(
            report.phases[0]
                .detail
                .as_ref()
                .unwrap()
                .contains("Address")
        );
    }

    #[test]
    fn expired_handshake_deadline_sends_no_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint = server.local_addr().unwrap();
        client.connect(endpoint).unwrap();
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let mut tunnel = Tunn::new(
            client_secret,
            PublicKey::from(&server_secret),
            None,
            None,
            OsRng.next_u32(),
            None,
        );

        let failure = establish_session(
            &client,
            endpoint,
            &mut tunnel,
            Instant::now() - Duration::from_millis(1),
        )
        .unwrap_err();
        assert_eq!(failure.status, PhaseStatus::Unconfirmed);
        assert_eq!(failure.sent, 0);
        let mut input = [0u8; 1];
        assert_eq!(
            server.recv(&mut input).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn expired_data_check_deadline_sends_no_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint = server.local_addr().unwrap();
        client.connect(endpoint).unwrap();
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let mut tunnel = Tunn::new(
            client_secret,
            PublicKey::from(&server_secret),
            None,
            None,
            OsRng.next_u32(),
            None,
        );

        let result = run_check(
            &client,
            endpoint,
            &mut tunnel,
            &[0; 20],
            Instant::now() - Duration::from_millis(1),
            |_| false,
        );
        assert!(matches!(
            result,
            CheckOutcome::Unconfirmed {
                sent: 0,
                received: 0
            }
        ));
        let mut input = [0u8; 1];
        assert_eq!(
            server.recv(&mut input).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn rejects_unrepresentable_timeouts_without_panicking() {
        let config = ProbeConfig::from_parts(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "127.0.0.1:1",
        )
        .unwrap();
        let plan = ProbePlan::new(config).timeouts(
            Duration::MAX,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::MAX,
        );
        assert!(matches!(plan.validate(), Err(ProbeError::InvalidPlan(_))));
        let report = probe(plan, |_| {});
        assert_eq!(report.verdict, Verdict::LocalError);
        assert!(
            report.phases[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("representable")
        );
    }

    #[test]
    fn resolver_slots_are_bounded_and_numeric_endpoints_bypass_them() {
        assert_eq!(ACTIVE_RESOLVER_WORKERS.load(Ordering::Acquire), 0);
        let slots = (0..MAX_RESOLVER_WORKERS)
            .map(|_| ResolverSlot::acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(ResolverSlot::acquire().is_none());
        assert!(
            resolve_endpoint("hostname.test:51820".into(), Duration::from_secs(1))
                .unwrap_err()
                .contains("capacity exhausted")
        );
        assert_eq!(
            resolve_endpoint("127.0.0.1:51820".into(), Duration::from_secs(1)).unwrap(),
            Some("127.0.0.1:51820".parse().unwrap())
        );
        drop(slots);
        assert_eq!(ACTIVE_RESOLVER_WORKERS.load(Ordering::Acquire), 0);
        assert!(
            resolve_endpoint("localhost:51820".into(), Duration::from_secs(1))
                .unwrap()
                .is_some()
        );
        assert_eq!(ACTIVE_RESOLVER_WORKERS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn report_schema_serializes_stable_status_names() {
        let report = ProbeReport {
            schema_version: 1,
            verdict: Verdict::AuthenticationConfirmed,
            endpoint: "example:1".into(),
            resolved_endpoint: None,
            local_udp_address: None,
            client_public_key: "public".into(),
            duration_ms: 1,
            sent_bytes: 2,
            received_bytes: 3,
            phases: vec![PhaseResult {
                phase: "keepalive".into(),
                target: None,
                status: PhaseStatus::Sent,
                duration_ms: 0,
                sent_bytes: 32,
                received_bytes: 0,
                detail: None,
            }],
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["verdict"], "authentication_confirmed");
        assert_eq!(json["phases"][0]["status"], "sent");
    }
}

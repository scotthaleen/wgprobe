use std::net::{IpAddr, Ipv4Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use wgprobe::{
    PhaseResult, PhaseStatus, ProbeEvent, ProbeEventKind, ProbePlan, ProbeReport, Verdict, probe,
};

use crate::inventory::NordTarget;
use crate::key::RunIdentity;
use crate::scheduler::Scheduler;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckMode {
    HandshakeOnly,
    Full(FullCheckPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCheckPlan {
    pub ping_targets: Vec<Ipv4Addr>,
    pub resolve_names: Vec<String>,
    pub dns_server: Ipv4Addr,
}

impl Default for FullCheckPlan {
    fn default() -> Self {
        Self {
            ping_targets: vec![Ipv4Addr::new(1, 1, 1, 1)],
            resolve_names: vec!["example.com".into()],
            dns_server: Ipv4Addr::new(103, 86, 96, 100),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub desired_confirmed: usize,
    pub max_candidates: usize,
    pub mode: CheckMode,
}

#[derive(Debug)]
pub struct Attempt {
    pub id: u64,
    pub target: NordTarget,
    pub report: Option<ProbeReport>,
    pub outcome: AttemptOutcome,
    pub client_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    Confirmed,
    Unconfirmed,
    Error(String),
}

#[derive(Debug)]
pub enum WorkerMessage {
    Started { id: u64, target: NordTarget },
    Phase { id: u64, event: ProbeEvent },
    Finished(Box<Attempt>),
    Pacing(Duration),
    Fatal(String),
    Complete { cancelled: bool },
}

pub struct WorkerRun {
    pub receiver: Receiver<WorkerMessage>,
    cancel: Arc<AtomicBool>,
}

impl WorkerRun {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

enum AttemptMessage {
    Phase {
        id: u64,
        public_key: String,
        event: ProbeEvent,
        at_ms: u64,
    },
    Finished(Attempt),
}

struct AttemptInbox {
    id: u64,
    target: NordTarget,
    client_public_key: String,
    receiver: Receiver<AttemptMessage>,
}

pub fn start(
    identity: Arc<RunIdentity>,
    targets: Vec<NordTarget>,
    options: ProbeOptions,
) -> WorkerRun {
    start_with_cancel(identity, targets, options, Arc::new(AtomicBool::new(false)))
}

pub fn start_with_cancel(
    identity: Arc<RunIdentity>,
    targets: Vec<NordTarget>,
    options: ProbeOptions,
    cancel: Arc<AtomicBool>,
) -> WorkerRun {
    let (sender, receiver) = mpsc::channel();
    let worker_cancel = Arc::clone(&cancel);
    thread::spawn(move || {
        let mut handles = Vec::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            coordinate(
                identity,
                targets,
                options,
                &sender,
                &worker_cancel,
                &mut handles,
            )
        }));
        let panicked = result.is_err();
        if panicked {
            worker_cancel.store(true, Ordering::Release);
        }
        let cancelled = worker_cancel.load(Ordering::Acquire);
        for handle in handles {
            let _ = handle.join();
        }
        if panicked {
            let _ = sender.send(WorkerMessage::Fatal(
                "probe coordinator stopped after an internal panic".into(),
            ));
        }
        let _ = sender.send(WorkerMessage::Complete { cancelled });
    });
    WorkerRun { receiver, cancel }
}

fn coordinate(
    identity: Arc<RunIdentity>,
    targets: Vec<NordTarget>,
    options: ProbeOptions,
    sender: &Sender<WorkerMessage>,
    cancel: &AtomicBool,
    handles: &mut Vec<JoinHandle<()>>,
) {
    coordinate_with_spawn(
        identity,
        targets,
        options,
        sender,
        cancel,
        handles,
        &mut spawn_attempt,
    );
}

fn coordinate_with_spawn<F>(
    identity: Arc<RunIdentity>,
    targets: Vec<NordTarget>,
    options: ProbeOptions,
    sender: &Sender<WorkerMessage>,
    cancel: &AtomicBool,
    handles: &mut Vec<JoinHandle<()>>,
    spawn: &mut F,
) where
    F: FnMut(
        u64,
        Arc<RunIdentity>,
        NordTarget,
        CheckMode,
        Instant,
    ) -> (JoinHandle<()>, AttemptInbox),
{
    let started = Instant::now();
    let mut scheduler = Scheduler::new(targets, options.max_candidates);
    let mut inboxes = Vec::new();
    let mut confirmed = 0usize;
    let mut next_id = 1u64;

    loop {
        loop {
            if !drain_attempt_messages(&mut inboxes, &mut scheduler, &mut confirmed, sender, cancel)
            {
                return;
            }
            if cancel.load(Ordering::Acquire) || confirmed >= options.desired_confirmed {
                break;
            }
            let Some(target) = scheduler.start_ready(elapsed_ms(started)) else {
                break;
            };
            if cancel.load(Ordering::Acquire) {
                scheduler.finish(&target.public_key);
                break;
            }
            let id = next_id;
            next_id += 1;
            if sender
                .send(WorkerMessage::Started {
                    id,
                    target: target.clone(),
                })
                .is_err()
            {
                cancel.store(true, Ordering::Release);
                return;
            }
            let (handle, inbox) = spawn(
                id,
                Arc::clone(&identity),
                target,
                options.mode.clone(),
                started,
            );
            handles.push(handle);
            inboxes.push(inbox);
        }

        let stopping = cancel.load(Ordering::Acquire) || confirmed >= options.desired_confirmed;
        if scheduler.active() == 0 && (stopping || scheduler.is_done()) {
            break;
        }
        let ready_in = if stopping {
            Duration::ZERO
        } else {
            scheduler
                .next_ready_in(elapsed_ms(started))
                .unwrap_or(Duration::ZERO)
        };
        if !ready_in.is_zero() && sender.send(WorkerMessage::Pacing(ready_in)).is_err() {
            cancel.store(true, Ordering::Release);
            return;
        }
        thread::sleep(if ready_in.is_zero() {
            Duration::from_millis(20)
        } else {
            ready_in.min(Duration::from_millis(200))
        });
    }
}

fn drain_attempt_messages(
    inboxes: &mut Vec<AttemptInbox>,
    scheduler: &mut Scheduler,
    confirmed: &mut usize,
    sender: &Sender<WorkerMessage>,
    cancel: &AtomicBool,
) -> bool {
    loop {
        let mut received = false;
        let mut index = 0;
        while index < inboxes.len() {
            match inboxes[index].receiver.try_recv() {
                Ok(AttemptMessage::Phase {
                    id,
                    public_key,
                    event,
                    at_ms,
                }) => {
                    received = true;
                    if event.kind == ProbeEventKind::Started && event.phase == "handshake" {
                        scheduler.acknowledge_handshake_start(&public_key, at_ms);
                    }
                    if sender.send(WorkerMessage::Phase { id, event }).is_err() {
                        cancel.store(true, Ordering::Release);
                        return false;
                    }
                    index += 1;
                }
                Ok(AttemptMessage::Finished(attempt)) => {
                    received = true;
                    scheduler.finish(&attempt.target.public_key);
                    if attempt.outcome == AttemptOutcome::Confirmed {
                        *confirmed += 1;
                    }
                    inboxes.swap_remove(index);
                    if sender
                        .send(WorkerMessage::Finished(Box::new(attempt)))
                        .is_err()
                    {
                        cancel.store(true, Ordering::Release);
                        return false;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => index += 1,
                Err(mpsc::TryRecvError::Disconnected) => {
                    received = true;
                    let inbox = inboxes.swap_remove(index);
                    scheduler.finish(&inbox.target.public_key);
                    let attempt = Attempt {
                        id: inbox.id,
                        target: inbox.target,
                        report: None,
                        outcome: AttemptOutcome::Error(
                            "probe attempt worker disconnected unexpectedly".into(),
                        ),
                        client_public_key: inbox.client_public_key,
                    };
                    if sender
                        .send(WorkerMessage::Finished(Box::new(attempt)))
                        .is_err()
                    {
                        cancel.store(true, Ordering::Release);
                        return false;
                    }
                }
            }
        }
        if !received {
            return true;
        }
    }
}

fn spawn_attempt(
    id: u64,
    identity: Arc<RunIdentity>,
    target: NordTarget,
    mode: CheckMode,
    run_started: Instant,
) -> (JoinHandle<()>, AttemptInbox) {
    let (sender, receiver) = mpsc::channel();
    let inbox = AttemptInbox {
        id,
        target: target.clone(),
        client_public_key: identity.public_key().to_owned(),
        receiver,
    };
    let handle = thread::spawn(move || {
        let fallback_target = target.clone();
        let client_public_key = identity.public_key().to_owned();
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_attempt(id, &identity, target, mode, run_started, &sender)
        }));
        let attempt = result.unwrap_or_else(|_| Attempt {
            id,
            target: fallback_target,
            report: None,
            outcome: AttemptOutcome::Error("probe attempt stopped after an internal panic".into()),
            client_public_key,
        });
        let _ = sender.send(AttemptMessage::Finished(attempt));
    });
    (handle, inbox)
}

fn run_attempt(
    id: u64,
    identity: &RunIdentity,
    target: NordTarget,
    mode: CheckMode,
    run_started: Instant,
    events: &Sender<AttemptMessage>,
) -> Attempt {
    let mut config = match identity.probe_config(&target.public_key, target.endpoint.to_string()) {
        Ok(config) => config,
        Err(error) => {
            return Attempt {
                id,
                target,
                report: None,
                outcome: AttemptOutcome::Error(format!("invalid probe configuration: {error}")),
                client_public_key: identity.public_key().to_owned(),
            };
        }
    };

    let mut plan = match mode {
        CheckMode::HandshakeOnly => ProbePlan::new(config),
        CheckMode::Full(checks) => {
            config.set_data_config(
                "10.5.0.2/32".parse().expect("constant CIDR is valid"),
                vec![IpAddr::V4(checks.dns_server)],
                vec!["0.0.0.0/0".parse().expect("constant CIDR is valid")],
            );
            let mut plan = ProbePlan::new(config);
            for target in checks.ping_targets {
                plan = plan.ping(target);
            }
            for name in checks.resolve_names {
                plan = plan.resolve(name);
            }
            plan
        }
    };
    plan = plan.timeouts(
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(9),
    );

    let public_key = target.public_key.clone();
    let report = probe(plan, |event| {
        let _ = events.send(AttemptMessage::Phase {
            id,
            public_key: public_key.clone(),
            event: event.clone(),
            at_ms: elapsed_ms(run_started),
        });
    });
    let outcome = match report.verdict {
        Verdict::AuthenticationConfirmed | Verdict::DataPlaneConfirmed => AttemptOutcome::Confirmed,
        Verdict::Unconfirmed => AttemptOutcome::Unconfirmed,
        Verdict::LocalError => AttemptOutcome::Error(local_error_detail(&report.phases)),
    };
    let client_public_key = report.client_public_key.clone();
    Attempt {
        id,
        target,
        report: Some(report),
        outcome,
        client_public_key,
    }
}

fn local_error_detail(phases: &[PhaseResult]) -> String {
    phases
        .iter()
        .find(|phase| phase.status == PhaseStatus::Error)
        .and_then(|phase| phase.detail.clone())
        .unwrap_or_else(|| "local probe error without phase detail".into())
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn target(host: &str, key: &str) -> NordTarget {
        NordTarget {
            name: host.into(),
            hostname: host.into(),
            endpoint: "192.0.2.1:51820".parse::<SocketAddr>().unwrap(),
            public_key: key.into(),
            country: "Test".into(),
            city: "Test".into(),
            load: 1,
        }
    }

    #[test]
    fn local_error_keeps_the_error_phase_cause() {
        let phases = vec![
            PhaseResult {
                phase: "socket".into(),
                target: None,
                status: PhaseStatus::Error,
                duration_ms: 1,
                sent_bytes: 0,
                received_bytes: 0,
                detail: Some("permission denied".into()),
            },
            PhaseResult {
                phase: "ping".into(),
                target: None,
                status: PhaseStatus::Skipped,
                duration_ms: 0,
                sent_bytes: 0,
                received_bytes: 0,
                detail: Some("skipped after failure".into()),
            },
        ];
        assert_eq!(local_error_detail(&phases), "permission denied");
    }

    #[test]
    fn queued_confirmation_is_processed_before_another_candidate_starts() {
        let identity =
            Arc::new(RunIdentity::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap());
        let targets = vec![target("first", "key-1"), target("second", "key-2")];
        let options = ProbeOptions {
            desired_confirmed: 1,
            max_candidates: 2,
            mode: CheckMode::HandshakeOnly,
        };
        let (worker_sender, worker_receiver) = mpsc::channel();
        let cancel = AtomicBool::new(false);
        let mut handles = Vec::new();
        let mut spawn = |id, identity: Arc<RunIdentity>, target: NordTarget, _mode, _started| {
            let (sender, receiver) = mpsc::channel();
            sender
                .send(AttemptMessage::Finished(Attempt {
                    id,
                    target: target.clone(),
                    report: None,
                    outcome: AttemptOutcome::Confirmed,
                    client_public_key: identity.public_key().to_owned(),
                }))
                .unwrap();
            let inbox = AttemptInbox {
                id,
                target,
                client_public_key: identity.public_key().to_owned(),
                receiver,
            };
            (thread::spawn(|| {}), inbox)
        };

        coordinate_with_spawn(
            identity,
            targets,
            options,
            &worker_sender,
            &cancel,
            &mut handles,
            &mut spawn,
        );
        for handle in handles {
            handle.join().unwrap();
        }

        let messages: Vec<_> = worker_receiver.try_iter().collect();
        assert_eq!(
            messages
                .iter()
                .filter(|message| matches!(message, WorkerMessage::Started { .. }))
                .count(),
            1
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| matches!(message, WorkerMessage::Finished(_)))
                .count(),
            1
        );
    }
}

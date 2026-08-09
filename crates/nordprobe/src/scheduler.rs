use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use crate::inventory::NordTarget;

pub const MIN_GROUP_INTERVAL: Duration = Duration::from_secs(6);
pub const MAX_CONCURRENCY: usize = 4;

pub fn order_candidates(mut targets: Vec<NordTarget>) -> Vec<NordTarget> {
    targets.sort_by(|left, right| {
        (left.load, &left.hostname, left.endpoint).cmp(&(
            right.load,
            &right.hostname,
            right.endpoint,
        ))
    });
    let mut seen_prefixes = HashSet::new();
    let mut distinct = Vec::new();
    let mut repeated = Vec::new();
    for target in targets {
        let prefix = ipv4_prefix(&target);
        if prefix.is_some_and(|prefix| seen_prefixes.insert(prefix)) {
            distinct.push(target);
        } else {
            repeated.push(target);
        }
    }
    distinct.extend(repeated);
    distinct
}

pub fn plan_candidates(targets: Vec<NordTarget>, maximum: usize) -> Vec<NordTarget> {
    order_candidates(targets)
        .into_iter()
        .take(maximum)
        .collect()
}

fn ipv4_prefix(target: &NordTarget) -> Option<[u8; 3]> {
    match target.endpoint.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            Some([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(_) => None,
    }
}

pub struct Scheduler {
    pending: VecDeque<NordTarget>,
    active_groups: HashSet<String>,
    last_handshake_ms: HashMap<String, u64>,
}

impl Scheduler {
    pub fn new(targets: Vec<NordTarget>, max_candidates: usize) -> Self {
        Self {
            pending: plan_candidates(targets, max_candidates).into(),
            active_groups: HashSet::new(),
            last_handshake_ms: HashMap::new(),
        }
    }

    pub fn start_ready(&mut self, now_ms: u64) -> Option<NordTarget> {
        if self.active_groups.len() >= MAX_CONCURRENCY {
            return None;
        }
        let interval_ms = MIN_GROUP_INTERVAL.as_millis() as u64;
        let index = self.pending.iter().position(|target| {
            !self.active_groups.contains(&target.public_key)
                && self
                    .last_handshake_ms
                    .get(&target.public_key)
                    .is_none_or(|last| now_ms.saturating_sub(*last) >= interval_ms)
        })?;
        let target = self.pending.remove(index)?;
        self.active_groups.insert(target.public_key.clone());
        Some(target)
    }

    pub fn acknowledge_handshake_start(&mut self, public_key: &str, now_ms: u64) {
        self.last_handshake_ms.insert(public_key.to_owned(), now_ms);
    }

    pub fn finish(&mut self, public_key: &str) {
        self.active_groups.remove(public_key);
    }

    pub fn active(&self) -> usize {
        self.active_groups.len()
    }

    pub fn is_done(&self) -> bool {
        self.pending.is_empty() && self.active_groups.is_empty()
    }

    pub fn next_ready_in(&self, now_ms: u64) -> Option<Duration> {
        let interval_ms = MIN_GROUP_INTERVAL.as_millis() as u64;
        self.pending
            .iter()
            .filter(|target| !self.active_groups.contains(&target.public_key))
            .map(|target| {
                self.last_handshake_ms
                    .get(&target.public_key)
                    .map_or(0, |last| {
                        interval_ms.saturating_sub(now_ms.saturating_sub(*last))
                    })
            })
            .min()
            .map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn target(ip: &str, load: u8, key: &str) -> NordTarget {
        NordTarget {
            name: ip.into(),
            hostname: format!("{ip}.example"),
            endpoint: format!("{ip}:51820").parse::<SocketAddr>().unwrap(),
            public_key: key.into(),
            country: "US".into(),
            city: "Denver".into(),
            load,
        }
    }

    #[test]
    fn samples_distinct_prefixes_before_repeating_one() {
        let ordered = order_candidates(vec![
            target("10.0.0.1", 1, "a"),
            target("10.0.0.2", 2, "b"),
            target("10.0.1.1", 9, "c"),
        ]);
        assert_eq!(ordered[0].endpoint.ip().to_string(), "10.0.0.1");
        assert_eq!(ordered[1].endpoint.ip().to_string(), "10.0.1.1");
        assert_eq!(ordered[2].endpoint.ip().to_string(), "10.0.0.2");
    }

    #[test]
    fn enforces_group_exclusion_and_six_second_pacing() {
        let mut scheduler = Scheduler::new(
            vec![target("10.0.0.1", 1, "same"), target("10.0.1.1", 2, "same")],
            10,
        );
        let first = scheduler.start_ready(1_000).unwrap();
        assert!(scheduler.start_ready(1_000).is_none());
        scheduler.acknowledge_handshake_start(&first.public_key, 5_000);
        scheduler.finish(&first.public_key);
        assert_eq!(scheduler.next_ready_in(6_000), Some(Duration::from_secs(5)));
        assert!(scheduler.start_ready(10_999).is_none());
        assert!(scheduler.start_ready(11_000).is_some());
    }
}

//! Token buckets for handshake processing under load.
//!
//! Buckets hold "time credit" rather than a token count: a packet costs
//! 1/rate seconds of credit, credit refills at one second per second, and
//! the cap is burst/rate. That needs no floats and no timer per bucket.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Per source, once its address is proven by mac2. Same as WireGuard.
pub const HANDSHAKES_PER_SEC: u32 = 20;
pub const HANDSHAKE_BURST: u32 = 5;
/// Distinct sources tracked at once. Reaching this needs that many
/// addresses that really receive our cookies, within about a second.
pub const MAX_SOURCES: usize = 8192;
/// All cookie replies together. They go to unproven, spoofable addresses,
/// so a per-source limit would let an attacker spend a real client's budget
/// by spoofing it. A global cap bounds our cost instead: 10k replies/s is
/// 640 KB/s out.
pub const COOKIE_REPLIES_PER_SEC: u32 = 10_000;
pub const COOKIE_REPLY_BURST: u32 = 1_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    credit: Duration,
    last: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Params {
    cost: Duration,
    cap: Duration,
}

impl Params {
    fn new(per_sec: u32, burst: u32) -> Self {
        let cost = Duration::from_secs(1) / per_sec;
        Self {
            cost,
            cap: cost * burst,
        }
    }
}

impl Bucket {
    fn full(p: Params, now: Instant) -> Self {
        Self {
            credit: p.cap,
            last: now,
        }
    }

    fn allow(&mut self, p: Params, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        self.credit = (self.credit + elapsed).min(p.cap);
        self.last = now;
        if self.credit >= p.cost {
            self.credit -= p.cost;
            true
        } else {
            false
        }
    }
}

/// One shared bucket.
pub struct GlobalLimiter {
    params: Params,
    bucket: Option<Bucket>,
}

impl GlobalLimiter {
    pub fn new(per_sec: u32, burst: u32) -> Self {
        Self {
            params: Params::new(per_sec, burst),
            bucket: None,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let p = self.params;
        self.bucket
            .get_or_insert_with(|| Bucket::full(p, now))
            .allow(p, now)
    }
}

/// A bucket per source address, with bounded memory.
pub struct SourceLimiter {
    params: Params,
    buckets: HashMap<IpAddr, Bucket>,
}

impl Default for SourceLimiter {
    fn default() -> Self {
        Self::new(HANDSHAKES_PER_SEC, HANDSHAKE_BURST)
    }
}

impl SourceLimiter {
    pub fn new(per_sec: u32, burst: u32) -> Self {
        Self {
            params: Params::new(per_sec, burst),
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        let key = group(source);
        let p = self.params;
        if let Some(b) = self.buckets.get_mut(&key) {
            return b.allow(p, now);
        }
        if self.buckets.len() >= MAX_SOURCES {
            self.forget_idle(now);
            if self.buckets.len() >= MAX_SOURCES {
                return false;
            }
        }
        let mut b = Bucket::full(p, now);
        let allowed = b.allow(p, now);
        self.buckets.insert(key, b);
        allowed
    }

    /// Drops buckets that have refilled completely; recreating one later
    /// gives the same answer as keeping it.
    pub fn forget_idle(&mut self, now: Instant) {
        let cap = self.params.cap;
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) + b.credit < cap);
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

/// IPv6 users typically get a whole /64, so one bucket per /64 rather
/// than letting one host rotate through 2^64 addresses.
fn group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_steady_rate() {
        let mut l = SourceLimiter::default();
        let t = Instant::now();
        let a = ip("198.51.100.1");
        for i in 0..HANDSHAKE_BURST {
            assert!(l.allow(a, t), "burst packet {i}");
        }
        assert!(!l.allow(a, t));
        let one = Duration::from_secs(1) / HANDSHAKES_PER_SEC;
        assert!(!l.allow(a, t + one - Duration::from_millis(1)));
        assert!(l.allow(a, t + one));
        assert!(!l.allow(a, t + one));
    }

    #[test]
    fn sources_are_independent_and_v6_groups_by_64() {
        let mut l = SourceLimiter::default();
        let t = Instant::now();
        for _ in 0..HANDSHAKE_BURST {
            assert!(l.allow(ip("2001:db8:1:2::1"), t));
        }
        assert!(!l.allow(ip("2001:db8:1:2:ffff::9"), t), "same /64");
        assert!(l.allow(ip("2001:db8:1:3::1"), t), "next /64");
        assert!(l.allow(ip("198.51.100.1"), t));
    }

    #[test]
    fn memory_is_bounded_and_idle_buckets_go() {
        let mut l = SourceLimiter::default();
        let t = Instant::now();
        for i in 0..MAX_SOURCES as u32 {
            assert!(l.allow(IpAddr::V4(i.into()), t));
        }
        assert!(!l.allow(ip("203.0.113.1"), t), "full and nothing idle");
        assert_eq!(l.tracked(), MAX_SOURCES);

        let later = t + Duration::from_secs(1);
        assert!(l.allow(ip("203.0.113.1"), later), "idle buckets made room");
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn global_limiter_caps_total() {
        let mut g = GlobalLimiter::new(10, 3);
        let t = Instant::now();
        assert_eq!((0..10).filter(|_| g.allow(t)).count(), 3);
        assert!(g.allow(t + Duration::from_millis(100)));
    }
}

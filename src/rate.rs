//! Global rate limiting for scan probes.
//!
//! `--rate` caps how many connection attempts are made per second across the
//! whole scan, so a large sweep does not overwhelm the network or trip a
//! rate-limiter. Because probes fan out across the shared rayon pool, the limit
//! is enforced by a single process-wide [`RateLimiter`] that every probe passes
//! through: each call reserves the next evenly-spaced time slot and sleeps until
//! it comes due.
//!
//! Like the thread pool, the limiter is installed once before the scan starts
//! and consulted from the low-level probe paths via [`gate`]. When no limit is
//! installed, [`gate`] is a cheap no-op.

use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// A token-bucket-style pacer that admits at most one probe per `interval`.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    /// The earliest instant the next probe may start.
    next: Mutex<Instant>,
}

impl RateLimiter {
    /// Build a limiter admitting `pps` probes per second, or `None` when `pps`
    /// is 0 (i.e. no limit).
    pub fn per_second(pps: u32) -> Option<RateLimiter> {
        if pps == 0 {
            return None;
        }
        let interval = Duration::from_secs_f64(1.0 / f64::from(pps));
        Some(RateLimiter {
            interval,
            next: Mutex::new(Instant::now()),
        })
    }

    /// The spacing between admitted probes.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Block until this probe's reserved slot comes due.
    pub fn acquire(&self) {
        let scheduled = {
            let mut next = self.next.lock().expect("rate limiter mutex poisoned");
            let (scheduled, new_next) = reserve(Instant::now(), *next, self.interval);
            *next = new_next;
            scheduled
        };
        let wait = scheduled.saturating_duration_since(Instant::now());
        if !wait.is_zero() {
            thread::sleep(wait);
        }
    }
}

/// Reserve the next slot: a probe may start no earlier than `now` and no earlier
/// than the previously reserved `next`. Returns the slot to run in and the new
/// `next` (that slot plus one `interval`).
fn reserve(now: Instant, next: Instant, interval: Duration) -> (Instant, Instant) {
    let scheduled = next.max(now);
    (scheduled, scheduled + interval)
}

/// The process-wide limiter, installed at most once via [`install`].
static LIMITER: OnceLock<RateLimiter> = OnceLock::new();

/// Install the global rate limit to `pps` probes per second. A `pps` of 0 (no
/// limit) installs nothing. Calling more than once keeps the first limiter.
pub fn install(pps: u32) {
    if let Some(limiter) = RateLimiter::per_second(pps) {
        let _ = LIMITER.set(limiter);
    }
}

/// Pass through the global rate limiter, blocking until a slot is free. A no-op
/// when no limit is installed.
pub fn gate() {
    if let Some(limiter) = LIMITER.get() {
        limiter.acquire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limiter_for_zero_pps() {
        assert!(RateLimiter::per_second(0).is_none());
    }

    #[test]
    fn interval_is_the_reciprocal_of_the_rate() {
        let limiter = RateLimiter::per_second(1000).unwrap();
        assert_eq!(limiter.interval(), Duration::from_millis(1));
        let limiter = RateLimiter::per_second(4).unwrap();
        assert_eq!(limiter.interval(), Duration::from_millis(250));
    }

    #[test]
    fn reserve_runs_immediately_when_the_slot_is_in_the_past() {
        let now = Instant::now();
        let past = now - Duration::from_secs(1);
        let interval = Duration::from_millis(10);
        let (scheduled, new_next) = reserve(now, past, interval);
        assert_eq!(scheduled, now, "a stale slot runs now");
        assert_eq!(new_next, now + interval);
    }

    #[test]
    fn reserve_queues_behind_a_future_slot() {
        let now = Instant::now();
        let future = now + Duration::from_millis(50);
        let interval = Duration::from_millis(10);
        let (scheduled, new_next) = reserve(now, future, interval);
        assert_eq!(scheduled, future, "must wait for the reserved slot");
        assert_eq!(new_next, future + interval);
    }

    #[test]
    fn consecutive_reservations_are_spaced_by_the_interval() {
        let start = Instant::now();
        let interval = Duration::from_millis(5);
        let (s1, next) = reserve(start, start, interval);
        let (s2, _) = reserve(start, next, interval);
        assert_eq!(s2 - s1, interval);
    }
}

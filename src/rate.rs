//! Global rate limiting and per-probe pacing for scan probes.
//!
//! `--rate` caps how many connection attempts are made per second across the
//! whole scan, so a large sweep does not overwhelm the network or trip a
//! rate-limiter. Because probes fan out across the shared rayon pool, the limit
//! is enforced by a single process-wide [`RateLimiter`] that every probe passes
//! through: each call reserves the next evenly-spaced time slot and sleeps until
//! it comes due.
//!
//! `--delay`/`--jitter` add a per-probe minimum interval, randomized within
//! ±PCT when jitter is set (`--delay 250 --jitter 20` → 200–300 ms). The delay
//! is enforced by the same [`RateLimiter`] as the rate cap: each probe reserves
//! a slot spaced by `max(rate_interval, delayed_interval)`, so the two limits
//! compose and the stricter one always wins. Jitter randomizes the interval per
//! probe without any extra dependency — a small xorshift64* PRNG seeded from the
//! system time plus an atomic counter gives each thread a distinct stream.
//!
//! Like the thread pool, the limiter is installed once before the scan starts
//! and consulted from the low-level probe paths via [`gate`]. When no limit or
//! delay is installed, [`gate`] is a cheap no-op.

use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// A token-bucket-style pacer that admits at most one probe per `interval`.
#[derive(Debug)]
pub struct RateLimiter {
    /// The base spacing between admitted probes, from the rate cap. Zero when no
    /// rate limit is installed (delay-only pacing).
    interval: Duration,
    /// Minimum inter-probe delay in milliseconds (`--delay`), or 0 for none.
    delay_ms: u64,
    /// Jitter as a percentage of the delay (`--jitter`, 0–100); 0 means no
    /// randomization.
    jitter_pct: u32,
    /// The earliest instant the next probe may start.
    next: Mutex<Instant>,
}

impl RateLimiter {
    /// Build a limiter admitting `pps` probes per second with an optional
    /// minimum inter-probe delay (ms) and jitter (percent of the delay). A `pps`
    /// of 0 and zero delay installs nothing. The effective spacing between
    /// admitted probes is always at least the larger of the two, so combining a
    /// rate cap with a delay never exceeds either bound.
    pub fn new(pps: u32, delay_ms: u64, jitter_pct: u32) -> Option<RateLimiter> {
        if pps == 0 && delay_ms == 0 {
            return None;
        }
        let interval = if pps > 0 {
            Duration::from_secs_f64(1.0 / f64::from(pps))
        } else {
            Duration::ZERO
        };
        Some(RateLimiter {
            interval,
            delay_ms,
            jitter_pct: jitter_pct.min(100),
            next: Mutex::new(Instant::now()),
        })
    }

    /// Build a limiter admitting `pps` probes per second with no delay. Kept for
    /// callers that only need the rate cap.
    pub fn per_second(pps: u32) -> Option<RateLimiter> {
        Self::new(pps, 0, 0)
    }

    /// The base spacing between admitted probes from the rate cap (zero when no
    /// rate limit is installed).
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The minimum inter-probe delay in milliseconds.
    pub fn delay_ms(&self) -> u64 {
        self.delay_ms
    }

    /// The jitter percentage (0–100).
    pub fn jitter_pct(&self) -> u32 {
        self.jitter_pct
    }

    /// The effective spacing for this probe: the larger of the rate interval and
    /// the (jittered) delay. When no delay is set, this is just the rate
    /// interval — the original behavior.
    fn effective_interval(&self) -> Duration {
        let base = self.interval;
        if self.delay_ms == 0 {
            return base;
        }
        let delayed = jittered_delay(self.delay_ms, self.jitter_pct);
        base.max(delayed)
    }

    /// Block until this probe's reserved slot comes due.
    pub fn acquire(&self) {
        let interval = self.effective_interval();
        let scheduled = {
            let mut next = self.next.lock().expect("rate limiter mutex poisoned");
            let (scheduled, new_next) = reserve(Instant::now(), *next, interval);
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

/// Install the global pacer with a rate cap of `pps` probes per second and an
/// optional minimum inter-probe delay (ms) randomized within ±`jitter_pct`. A
/// `pps` of 0 and zero delay installs nothing. Calling more than once keeps the
/// first limiter.
pub fn install(pps: u32, delay_ms: u64, jitter_pct: u32) {
    if let Some(limiter) = RateLimiter::new(pps, delay_ms, jitter_pct) {
        let _ = LIMITER.set(limiter);
    }
}

/// Pass through the global pacer, blocking until a slot is free. A no-op when no
/// limiter is installed.
pub fn gate() {
    if let Some(limiter) = LIMITER.get() {
        limiter.acquire();
    }
}

// ---------------------------------------------------------------------------
// Jittered delay
// ---------------------------------------------------------------------------

/// The per-probe jittered delay: `delay_ms` randomized within ±`jitter_pct`,
/// clamped to [0, 2·delay]. With zero jitter this is exactly `delay_ms`.
pub fn jittered_delay(delay_ms: u64, jitter_pct: u32) -> Duration {
    if delay_ms == 0 || jitter_pct == 0 {
        return Duration::from_millis(delay_ms);
    }
    let pct = f64::from(jitter_pct.min(100)) / 100.0;
    // A uniform offset in [-pct, +pct] of the delay.
    let offset = (next_f64() - 0.5) * 2.0 * pct;
    let base = f64::from(u32::try_from(delay_ms).unwrap_or(u32::MAX));
    let ms = (base * (1.0 + offset)).clamp(0.0, base * 2.0);
    Duration::from_millis(ms as u64)
}

/// A process-wide xorshift64* PRNG giving each caller a distinct stream of
/// pseudo-random values in [0, 1). No external dependency: the state is an
/// atomic counter mixed with a system-time seed so concurrent threads never
/// share a sequence.
fn next_f64() -> f64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xdead_beef_cafe_babe)
    });
    let mut state = COUNTER
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .wrapping_add(seed);
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15; // xorshift needs a non-zero seed
    }
    // xorshift64*
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    let bits = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limiter_for_zero_pps_and_no_delay() {
        assert!(RateLimiter::new(0, 0, 0).is_none());
        assert!(RateLimiter::per_second(0).is_none());
    }

    #[test]
    fn delay_only_installs_a_limiter() {
        let limiter = RateLimiter::new(0, 250, 0).expect("delay-only should install");
        assert_eq!(limiter.interval(), Duration::ZERO);
        assert_eq!(limiter.delay_ms(), 250);
    }

    #[test]
    fn interval_is_the_reciprocal_of_the_rate() {
        let limiter = RateLimiter::per_second(1000).unwrap();
        assert_eq!(limiter.interval(), Duration::from_millis(1));
        let limiter = RateLimiter::per_second(4).unwrap();
        assert_eq!(limiter.interval(), Duration::from_millis(250));
    }

    #[test]
    fn effective_interval_is_the_stricter_of_rate_and_delay() {
        // A 1000 pps cap (1 ms) with a 50 ms delay: the delay wins.
        let limiter = RateLimiter::new(1000, 50, 0).unwrap();
        assert_eq!(limiter.effective_interval(), Duration::from_millis(50));

        // A 4 pps cap (250 ms) with a 50 ms delay: the rate wins.
        let limiter = RateLimiter::new(4, 50, 0).unwrap();
        assert_eq!(limiter.effective_interval(), Duration::from_millis(250));

        // No delay: just the rate interval (original behavior).
        let limiter = RateLimiter::per_second(1000).unwrap();
        assert_eq!(limiter.effective_interval(), Duration::from_millis(1));
    }

    #[test]
    fn jittered_delay_stays_within_bounds() {
        // Zero delay or zero jitter: exactly the base value.
        assert_eq!(jittered_delay(0, 50), Duration::ZERO);
        assert_eq!(jittered_delay(250, 0), Duration::from_millis(250));

        // With jitter, every sample must land in [delay·(1-pct/100), delay·(1+pct/100)].
        let (lo, hi) = (Duration::from_millis(200), Duration::from_millis(300));
        for _ in 0..1000 {
            let d = jittered_delay(250, 20);
            assert!(
                d >= lo && d <= hi,
                "jittered delay {d:?} outside [200ms, 300ms]"
            );
        }

        // 100% jitter: the full range [0, 2·delay].
        for _ in 0..1000 {
            let d = jittered_delay(100, 100);
            assert!(
                d <= Duration::from_millis(200),
                "jittered delay {d:?} above 2×delay"
            );
        }
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

    #[test]
    fn delay_paces_probes_at_least_as_fast_as_the_delay() {
        // Five probes at a 50 ms minimum delay span at least 4 × 50 = 200 ms of
        // pacing. Without the delay this finishes in microseconds.
        let limiter = RateLimiter::new(0, 50, 0).expect("delay-only");
        let start = Instant::now();
        for _ in 0..5 {
            limiter.acquire();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(180),
            "five probes at 50 ms should take ≥200 ms, took {:?}",
            elapsed
        );
    }

    #[test]
    fn rate_and_delay_compose_without_exceeding_either() {
        // A 10 pps cap (100 ms) with a 30 ms delay: the effective spacing is 100
        // ms, so five probes span at least 4 × 100 = 400 ms. The rate limit is
        // never exceeded even though the delay alone would allow more.
        let limiter = RateLimiter::new(10, 30, 0).expect("rate + delay");
        let start = Instant::now();
        for _ in 0..5 {
            limiter.acquire();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(380),
            "five probes at max(100ms, 30ms) should take ≥400 ms, took {:?}",
            elapsed
        );
    }
}

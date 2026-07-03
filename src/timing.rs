//! Timing profiles (`-T0`..`-T5`), a familiar shorthand (à la nmap) for a whole
//! speed/stealth posture instead of tuning `--timeout`, `--concurrency`,
//! `--retries`, and `--rate` by hand.
//!
//! A profile is a set of presets. It fills in only the options the user did not
//! set explicitly, so any individual flag still overrides the profile — the
//! merge lives in `main`.

/// The presets a timing profile expands into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Per-connection timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent connection attempts.
    pub concurrency: usize,
    /// Extra retries per probe on no answer.
    pub retries: u32,
    /// Optional probes-per-second cap (`None` = unlimited).
    pub rate: Option<u32>,
}

/// The highest supported timing level (`-T5`).
pub const MAX_LEVEL: u8 = 5;

/// The preset bundle for a timing `level` (`0`..=`5`). Levels run from `0`
/// (paranoid: slow, serial, heavily rate-limited) to `5` (insane: fastest,
/// widest concurrency, no rate cap). Levels above [`MAX_LEVEL`] clamp to it.
pub fn profile(level: u8) -> Timing {
    match level {
        // Paranoid: one probe at a time, slow, tightly rate-limited.
        0 => Timing {
            timeout_ms: 5000,
            concurrency: 1,
            retries: 3,
            rate: Some(10),
        },
        // Sneaky.
        1 => Timing {
            timeout_ms: 4000,
            concurrency: 4,
            retries: 2,
            rate: Some(100),
        },
        // Polite: gentle on the target, still rate-limited.
        2 => Timing {
            timeout_ms: 3000,
            concurrency: 16,
            retries: 1,
            rate: Some(1000),
        },
        // Normal: the tool's out-of-the-box defaults.
        3 => Timing {
            timeout_ms: 2000,
            concurrency: 256,
            retries: 0,
            rate: None,
        },
        // Aggressive: fast, for responsive networks.
        4 => Timing {
            timeout_ms: 1000,
            concurrency: 512,
            retries: 0,
            rate: None,
        },
        // Insane (5 and anything higher): maximum speed.
        _ => Timing {
            timeout_ms: 500,
            concurrency: 1024,
            retries: 0,
            rate: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_get_faster_as_they_rise() {
        // Timeout shrinks and concurrency grows monotonically from T0 to T5.
        let profiles: Vec<Timing> = (0..=MAX_LEVEL).map(profile).collect();
        for pair in profiles.windows(2) {
            assert!(
                pair[1].timeout_ms <= pair[0].timeout_ms,
                "timeout should not increase with level"
            );
            assert!(
                pair[1].concurrency >= pair[0].concurrency,
                "concurrency should not decrease with level"
            );
        }
    }

    #[test]
    fn paranoid_is_serial_and_rate_limited() {
        let t0 = profile(0);
        assert_eq!(t0.concurrency, 1);
        assert!(t0.rate.is_some());
        assert!(t0.retries > 0);
    }

    #[test]
    fn insane_is_unlimited_and_widest() {
        let t5 = profile(5);
        assert_eq!(t5.rate, None);
        assert_eq!(t5.concurrency, 1024);
    }

    #[test]
    fn levels_above_max_clamp_to_insane() {
        assert_eq!(profile(9), profile(MAX_LEVEL));
    }
}

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Default timeout for a single TCP connection attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The outcome of a single connection attempt, classified so that retries only
/// fire when it is worth retrying.
///
/// A lossy network can drop a lone SYN and make an open port look closed. But a
/// host that actively *refuses* the connection has already answered — retrying
/// that only wastes time. So we distinguish a definitive answer (open or
/// refused/reset) from silence (timeout, unreachable), and retry only silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// The handshake completed: the port is open. Carries the connect latency.
    Open(Duration),
    /// The host answered with a reset/refusal: the port is closed. Final.
    Closed,
    /// No answer (timeout, unreachable, …): worth retrying on a lossy network.
    NoAnswer,
}

/// Run `probe` up to `retries` extra times, stopping as soon as it returns a
/// definitive answer ([`Probe::Open`] or [`Probe::Closed`]). Only
/// [`Probe::NoAnswer`] is retried. Returns the last outcome observed.
///
/// With `retries == 0` this is a single attempt — the original behaviour.
fn with_retries<F: FnMut() -> Probe>(retries: u32, mut probe: F) -> Probe {
    let mut outcome = Probe::NoAnswer;
    for _ in 0..=retries {
        outcome = probe();
        if outcome != Probe::NoAnswer {
            break;
        }
    }
    outcome
}

/// An open port together with how long the TCP handshake took.
///
/// The latency is the wall-clock time spent in [`TcpStream::connect_timeout`]
/// for the successful connection — a rough proxy for how close the target is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortHit {
    pub port: u16,
    pub latency: Duration,
}

/// Format a `host:port` authority, wrapping bare IPv6 literals in brackets so
/// that they round-trip through [`ToSocketAddrs`] (e.g. `[::1]:80`).
fn host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Resolve a host (numeric IP or DNS name) to its first IP address.
///
/// # Arguments
///
/// * `host` - The hostname or IP address to resolve
///
/// # Returns
///
/// * `Option<IpAddr>` - The first resolved address, or `None` if resolution fails
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::port::resolve_host;
///
/// assert!(resolve_host("127.0.0.1").is_some());
/// assert!(resolve_host("").is_none());
/// ```
pub fn resolve_host(host: &str) -> Option<IpAddr> {
    host_port(host, 80)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|addr| addr.ip())
}

/// Check whether a host can be resolved to an address.
///
/// This is a **name-resolution** check, not a liveness/reachability probe:
/// numeric IPs always resolve, and a hostname resolves when DNS returns at
/// least one address. It answers the question "do we have an address to
/// connect to?", which is the precondition for scanning — whether any
/// individual port is actually open is decided per-port by [`scan_port`].
///
/// # Arguments
///
/// * `host` - The hostname or IP address to check
///
/// # Returns
///
/// * `bool` - `true` if the host resolves to at least one address, `false` otherwise
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::port::is_resolvable;
///
/// if is_resolvable("example.com") {
///     println!("Host resolves; ready to scan");
/// }
/// ```
pub fn is_resolvable(host: &str) -> bool {
    resolve_host(host).is_some()
}

/// Scan a specific port on a host
///
/// # Arguments
///
/// * `host` - The hostname or IP address to scan (IPv4 or IPv6)
/// * `port` - The port number to scan
/// * `timeout` - Optional connection timeout (defaults to [`CONNECT_TIMEOUT`])
///
/// # Returns
///
/// * `Option<PortHit>` - The open port and its connect latency, or `None` if closed
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::port::scan_port;
///
/// if let Some(hit) = scan_port("example.com".to_string(), 80, None) {
///     println!("Port {} is open ({} ms)", hit.port, hit.latency.as_millis());
/// }
/// ```
pub fn scan_port(host: String, port: u16, timeout: Option<Duration>) -> Option<PortHit> {
    scan_port_with_retries(host, port, timeout, 0)
}

/// Scan a specific port, retrying up to `retries` extra times when a probe gets
/// no answer (timeout/unreachable).
///
/// On a lossy network a dropped SYN makes an open port look closed; a small
/// `retries` value (e.g. 1–2) trades a little time for fewer false negatives. A
/// refused/reset port is final and is never retried, so scans of closed ports
/// stay fast. `retries == 0` is a single attempt, identical to [`scan_port`].
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::port::scan_port_with_retries;
///
/// if let Some(hit) = scan_port_with_retries("example.com".to_string(), 80, None, 2) {
///     println!("Port {} is open ({} ms)", hit.port, hit.latency.as_millis());
/// }
/// ```
pub fn scan_port_with_retries(
    host: String,
    port: u16,
    timeout: Option<Duration>,
    retries: u32,
) -> Option<PortHit> {
    let timeout = timeout.unwrap_or(CONNECT_TIMEOUT);
    match with_retries(retries, || probe_port(&host, port, timeout)) {
        Probe::Open(latency) => Some(PortHit { port, latency }),
        Probe::Closed | Probe::NoAnswer => None,
    }
}

/// Make a single connection attempt to `host:port` and classify the outcome.
fn probe_port(host: &str, port: u16, timeout: Duration) -> Probe {
    // Respect the global rate limit (no-op when none is installed).
    crate::rate::gate();
    let Some(socket_addr) = host_port(host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        // Unresolvable: retrying will not help, so treat it as a closed result.
        return Probe::Closed;
    };
    let start = Instant::now();
    match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(_) => Probe::Open(start.elapsed()),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ) =>
        {
            Probe::Closed
        }
        Err(_) => Probe::NoAnswer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TIMEOUT: Option<Duration> = Some(Duration::from_millis(100));

    #[test]
    fn test_scan_port_success() {
        // localhost:0 is always invalid, used only for testing
        let result = scan_port("127.0.0.1".to_string(), 0, TEST_TIMEOUT);
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_port_failure() {
        let result = scan_port("127.0.0.1".to_string(), 1, TEST_TIMEOUT); // Non-existent port
        assert!(result.is_none());
    }

    #[test]
    fn test_is_resolvable_numeric_ip() {
        // A numeric IP always resolves, so it is considered scannable.
        assert!(is_resolvable("127.0.0.1"));
    }

    #[test]
    fn test_is_resolvable_invalid_host() {
        // An empty host cannot be resolved.
        assert!(!is_resolvable(""));
    }

    #[test]
    fn test_host_port_ipv6_is_bracketed() {
        assert_eq!(host_port("::1", 80), "[::1]:80");
        assert_eq!(host_port("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn test_host_port_ipv4_and_hostname_plain() {
        assert_eq!(host_port("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(host_port("example.com", 8080), "example.com:8080");
    }

    #[test]
    fn retries_stop_immediately_on_a_definitive_open() {
        let mut calls = 0;
        let outcome = with_retries(5, || {
            calls += 1;
            Probe::Open(Duration::from_millis(1))
        });
        assert_eq!(outcome, Probe::Open(Duration::from_millis(1)));
        assert_eq!(calls, 1, "an open port must not be retried");
    }

    #[test]
    fn retries_stop_immediately_on_a_definitive_closed() {
        let mut calls = 0;
        let outcome = with_retries(5, || {
            calls += 1;
            Probe::Closed
        });
        assert_eq!(outcome, Probe::Closed);
        assert_eq!(calls, 1, "a refused/reset port must not be retried");
    }

    #[test]
    fn no_answer_is_retried_exactly_retries_plus_one_times() {
        let mut calls = 0;
        let outcome = with_retries(3, || {
            calls += 1;
            Probe::NoAnswer
        });
        assert_eq!(outcome, Probe::NoAnswer);
        // One initial attempt plus three retries.
        assert_eq!(calls, 4);
    }

    #[test]
    fn no_answer_then_open_succeeds_within_the_retry_budget() {
        let mut calls = 0;
        let outcome = with_retries(3, || {
            calls += 1;
            if calls < 3 {
                Probe::NoAnswer
            } else {
                Probe::Open(Duration::from_millis(2))
            }
        });
        assert_eq!(outcome, Probe::Open(Duration::from_millis(2)));
        assert_eq!(calls, 3, "should stop on the first definitive answer");
    }

    #[test]
    fn zero_retries_is_a_single_attempt() {
        let mut calls = 0;
        let _ = with_retries(0, || {
            calls += 1;
            Probe::NoAnswer
        });
        assert_eq!(calls, 1);
    }
}

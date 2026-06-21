use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Default timeout for a single TCP connection attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

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
    let socket_addr = host_port(&host, port).to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    match TcpStream::connect_timeout(&socket_addr, timeout.unwrap_or(CONNECT_TIMEOUT)) {
        Ok(_) => Some(PortHit {
            port,
            latency: start.elapsed(),
        }),
        Err(_) => None,
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
}

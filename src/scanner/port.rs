use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Default timeout for a single TCP connection attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Check whether a host is reachable for scanning.
///
/// The host is resolved via DNS (numeric IPs and hostnames are both accepted).
/// A host that resolves to at least one address is considered scannable — note
/// that a closed port 80 does not make a host "offline", since the whole point
/// of port scanning is to probe hosts whose open ports are unknown.
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
/// use asphyxia::scanner::port::is_online;
///
/// if is_online("example.com") {
///     println!("Host is reachable");
/// }
/// ```
pub fn is_online(host: &str) -> bool {
    // A host that resolves to at least one address is considered scannable.
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
/// * `Option<u16>` - The port number if it's open, `None` otherwise
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::port::scan_port;
///
/// if let Some(port) = scan_port("example.com".to_string(), 80, None) {
///     println!("Port {} is open", port);
/// }
/// ```
pub fn scan_port(host: String, port: u16, timeout: Option<Duration>) -> Option<u16> {
    let socket_addr = host_port(&host, port).to_socket_addrs().ok()?.next()?;
    match TcpStream::connect_timeout(&socket_addr, timeout.unwrap_or(CONNECT_TIMEOUT)) {
        Ok(_) => Some(port),
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
    fn test_is_online_numeric_ip() {
        // A numeric IP always resolves, so it is considered scannable.
        assert!(is_online("127.0.0.1"));
    }

    #[test]
    fn test_is_online_invalid_host() {
        // An empty host cannot be resolved.
        assert!(!is_online(""));
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

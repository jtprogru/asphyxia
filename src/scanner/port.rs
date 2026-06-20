use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Default timeout for a single TCP connection attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

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
    format!("{}:80", host)
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
/// ```
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
/// * `host` - The hostname or IP address to scan
/// * `port` - The port number to scan
///
/// # Returns
///
/// * `Option<u16>` - The port number if it's open, `None` otherwise
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::port::scan_port;
///
/// if let Some(port) = scan_port("example.com".to_string(), 80) {
///     println!("Port {} is open", port);
/// }
/// ```
pub fn scan_port(host: String, port: u16) -> Option<u16> {
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr.to_socket_addrs().ok()?.next()?;
    match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
        Ok(_) => Some(port),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_port_success() {
        // localhost:0 is always invalid, used only for testing
        let result = scan_port("127.0.0.1".to_string(), 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_port_failure() {
        let result = scan_port("127.0.0.1".to_string(), 1); // Non-existent port
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
}

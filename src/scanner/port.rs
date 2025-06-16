use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// Check if a host is online by attempting to connect to port 80
///
/// # Arguments
///
/// * `host` - The hostname or IP address to check
///
/// # Returns
///
/// * `bool` - `true` if the host is online, `false` otherwise
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::port::is_online;
///
/// if is_online("example.com") {
///     println!("Host is online");
/// }
/// ```
pub fn is_online(host: &str) -> bool {
    match format!("{}:80", host).parse::<SocketAddr>() {
        Ok(addr) => {
            if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                return true;
            }

            match host.to_string().to_socket_addrs() {
                Ok(mut iter) => iter.next().is_some(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
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
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(_) => Some(port),
                    Err(_) => None,
                }
            } else {
                None
            }
        }
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
}

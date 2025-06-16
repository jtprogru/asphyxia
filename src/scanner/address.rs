use std::net::{TcpStream, SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use ipnetwork::IpNetwork;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

/// Scan a single IP address for availability
///
/// # Arguments
///
/// * `ip` - The IPv4 address to scan
/// * `timeout` - Optional timeout duration (defaults to 1 second)
///
/// # Returns
///
/// * `Option<Ipv4Addr>` - The IP address if it's available, `None` otherwise
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::address::scan_address;
/// use std::net::Ipv4Addr;
/// use std::time::Duration;
///
/// let ip = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
/// if let Some(available_ip) = scan_address(ip, Some(Duration::from_millis(500))) {
///     println!("Host {} is available", available_ip);
/// }
/// ```
pub fn scan_address(ip: Ipv4Addr, timeout: Option<Duration>) -> Option<Ipv4Addr> {
    match TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(ip), 80),
        timeout.unwrap_or(Duration::from_secs(1)),
    ) {
        Ok(_) => Some(ip),
        Err(_) => None,
    }
}

/// Scan an entire subnet for available hosts
///
/// # Arguments
///
/// * `subnet` - The subnet to scan in CIDR notation
///
/// # Returns
///
/// * `Vec<Ipv4Addr>` - A vector of available IP addresses
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::address::scan_subnet;
/// use ipnetwork::IpNetwork;
///
/// let subnet = "192.168.1.0/24".parse::<IpNetwork>().unwrap();
/// let available_hosts = scan_subnet(subnet);
/// println!("Found {} available hosts", available_hosts.len());
/// ```
pub fn scan_subnet(subnet: IpNetwork) -> Vec<Ipv4Addr> {
    let network = subnet.network();
    let broadcast = subnet.broadcast();
    let mut available = Vec::new();

    if let (IpAddr::V4(network), IpAddr::V4(broadcast)) = (network, broadcast) {
        let total_hosts = u32::from(broadcast) - u32::from(network) + 1;
        let pb = ProgressBar::new(total_hosts as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} addresses scanned",
            )
            .unwrap()
            .progress_chars("=> "),
        );

        let available_ips = Arc::new(Mutex::new(Vec::new()));

        (u32::from(network)..=u32::from(broadcast))
            .into_par_iter()
            .for_each(|ip| {
                let ipv4 = Ipv4Addr::from(ip);
                if let Some(available_ip) = scan_address(ipv4, None) {
                    if let Ok(mut guard) = available_ips.lock() {
                        guard.push(available_ip);
                    }
                }
                pb.inc(1);
            });

        pb.finish_with_message("Subnet scan completed");
        let mut result = available_ips.lock().unwrap();
        result.sort();
        available = result.clone();
    }

    available
}

/// Scan a range of IP addresses for available hosts
///
/// # Arguments
///
/// * `start` - The starting IPv4 address
/// * `end` - The ending IPv4 address
///
/// # Returns
///
/// * `Vec<Ipv4Addr>` - A vector of available IP addresses
///
/// # Examples
///
/// ```
/// use asphyxia::scanner::address::scan_ip_range;
/// use std::net::Ipv4Addr;
///
/// let start = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
/// let end = "192.168.1.10".parse::<Ipv4Addr>().unwrap();
/// let available_hosts = scan_ip_range(start, end);
/// println!("Found {} available hosts", available_hosts.len());
/// ```
pub fn scan_ip_range(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr> {
    let start_num = u32::from(start);
    let end_num = u32::from(end);

    if start_num > end_num {
        return Vec::new();
    }

    let total_hosts = end_num - start_num + 1;
    let pb = ProgressBar::new(total_hosts as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} addresses scanned",
        )
        .unwrap()
        .progress_chars("=> "),
    );

    let available_ips = Arc::new(Mutex::new(Vec::new()));

    (start_num..=end_num)
        .into_par_iter()
        .for_each(|ip| {
            let ipv4 = Ipv4Addr::from(ip);
            if let Some(available_ip) = scan_address(ipv4, None) {
                if let Ok(mut guard) = available_ips.lock() {
                    guard.push(available_ip);
                }
            }
            pb.inc(1);
        });

    pb.finish_with_message("Range scan completed");
    let mut result = available_ips.lock().unwrap();
    result.sort();
    result.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Helper function to check if localhost is available
    fn is_localhost_available() -> bool {
        scan_address("127.0.0.1".parse().unwrap(), Some(Duration::from_millis(100))).is_some()
    }

    #[test]
    fn test_scan_address_localhost() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_address_localhost: localhost is not available");
            return;
        }

        let ip = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        assert!(scan_address(ip, Some(Duration::from_millis(100))).is_some());
    }

    #[test]
    fn test_scan_address_unavailable() {
        // Test with an address that's very unlikely to be available
        let ip = "192.168.255.255".parse::<Ipv4Addr>().unwrap();
        assert!(scan_address(ip, Some(Duration::from_millis(100))).is_none());
    }

    #[test]
    fn test_scan_subnet() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_subnet: localhost is not available");
            return;
        }

        // Scan only localhost (127.0.0.1)
        let subnet = "127.0.0.0/24".parse::<IpNetwork>().unwrap();
        let results = scan_subnet(subnet);

        // Verify that results contain localhost and are sorted
        assert!(results.contains(&"127.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert!(results.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_scan_ip_range() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_ip_range: localhost is not available");
            return;
        }

        // Scan only localhost and a few addresses around it
        let start = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        let end = "127.0.0.3".parse::<Ipv4Addr>().unwrap();
        let results = scan_ip_range(start, end);

        // Verify that results contain localhost and are sorted
        assert!(results.contains(&"127.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert!(results.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_scan_empty_range() {
        // Test with an invalid range (start > end)
        let start = "127.0.0.10".parse::<Ipv4Addr>().unwrap();
        let end = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        let results = scan_ip_range(start, end);
        assert!(results.is_empty());
    }
}

use ipnetwork::IpNetwork;
use rayon::prelude::*;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::utils::progress_bar;

/// An available host together with how long the availability probe took.
///
/// The latency is the wall-clock time the [`PROBE_PORT`] connection spent
/// before succeeding or being refused/reset — a rough proxy for distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostHit {
    pub ip: IpAddr,
    pub latency: Duration,
}

/// TCP port used to probe a host when checking availability.
///
/// The port does not need to be open — see [`scan_address`] for how the
/// connection outcome is interpreted.
const PROBE_PORT: u16 = 80;

/// Upper bound on the number of addresses enumerated for a single subnet or
/// range scan when the family is IPv6.
///
/// IPv6 address spaces are astronomically large (a single `/64` holds 2^64
/// addresses), so scans wider than this are refused rather than attempted.
/// IPv4 scans are not capped — their address space is small enough to walk.
pub const MAX_IPV6_HOSTS: u128 = 1 << 16; // 65_536 addresses (e.g. a /112)

/// Scan a single IP address for availability.
///
/// Availability is inferred from how the host reacts to a TCP probe on
/// [`PROBE_PORT`] rather than from whether that port happens to be open:
///
/// * the connection **succeeds** — the host is up (and the port is open); or
/// * the connection is **refused/reset** — the host actively answered, so it
///   is up even though the port is closed.
///
/// A timeout, "host unreachable", "network unreachable", or any other error is
/// treated as down. This is a best-effort, unprivileged check: a live host
/// behind a firewall that silently *drops* packets (rather than refusing them)
/// is indistinguishable from one that is offline and will be reported as down.
///
/// # Arguments
///
/// * `ip` - The IP address to scan (IPv4 or IPv6)
/// * `timeout` - Optional timeout duration (defaults to [`crate::scanner::port::CONNECT_TIMEOUT`])
///
/// # Returns
///
/// * `Option<HostHit>` - The host and its probe latency if up, `None` otherwise
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::address::scan_address;
/// use std::net::IpAddr;
/// use std::time::Duration;
///
/// let ip: IpAddr = "192.168.1.1".parse().unwrap();
/// if let Some(hit) = scan_address(ip, Some(Duration::from_millis(500))) {
///     println!("Host {} is up ({} ms)", hit.ip, hit.latency.as_millis());
/// }
/// ```
pub fn scan_address(ip: IpAddr, timeout: Option<Duration>) -> Option<HostHit> {
    let timeout = timeout.unwrap_or(crate::scanner::port::CONNECT_TIMEOUT);
    let start = Instant::now();
    match TcpStream::connect_timeout(&SocketAddr::new(ip, PROBE_PORT), timeout) {
        // Port is open: the host is unambiguously up.
        Ok(_) => Some(HostHit {
            ip,
            latency: start.elapsed(),
        }),
        // The host replied with a reset — it is up, the port is just closed.
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ) =>
        {
            Some(HostHit {
                ip,
                latency: start.elapsed(),
            })
        }
        // Timeout, unreachable, or anything else: treat the host as down.
        Err(_) => None,
    }
}

/// Scan every address yielded by `addrs` in parallel and return the ones that
/// are available, sorted ascending.
///
/// This is the shared engine behind subnet and range scans: it owns the
/// progress bar and the parallel fan-out so callers only have to describe
/// which addresses to probe.
fn scan_all<I>(addrs: I, total: u64, timeout: Option<Duration>, finish_msg: &str) -> Vec<HostHit>
where
    I: ParallelIterator<Item = IpAddr>,
{
    let pb = progress_bar(total, "addresses scanned");

    let mut result: Vec<HostHit> = addrs
        .filter_map(|ip| {
            let available = scan_address(ip, timeout);
            pb.inc(1);
            available
        })
        .collect();

    pb.finish_with_message(finish_msg.to_string());
    result.sort_by_key(|h| h.ip);
    result
}

/// Scan an entire subnet for available hosts
///
/// IPv4 subnets are scanned in full. IPv6 subnets are scanned only when they
/// contain at most [`MAX_IPV6_HOSTS`] addresses; wider IPv6 subnets are refused
/// (a warning is printed and an empty vector is returned).
///
/// # Arguments
///
/// * `subnet` - The subnet to scan in CIDR notation
/// * `timeout` - Optional per-host timeout (defaults to [`crate::scanner::port::CONNECT_TIMEOUT`])
///
/// # Returns
///
/// * `Vec<HostHit>` - A vector of available hosts with their probe latency
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::address::scan_subnet;
/// use ipnetwork::IpNetwork;
///
/// let subnet = "192.168.1.0/24".parse::<IpNetwork>().unwrap();
/// let available_hosts = scan_subnet(subnet, None);
/// println!("Found {} available hosts", available_hosts.len());
/// ```
pub fn scan_subnet(subnet: IpNetwork, timeout: Option<Duration>) -> Vec<HostHit> {
    match (subnet.network(), subnet.broadcast()) {
        (IpAddr::V4(network), IpAddr::V4(broadcast)) => {
            let start = u32::from(network);
            let end = u32::from(broadcast);
            let total = u64::from(end - start) + 1;
            scan_all(
                (start..=end).into_par_iter().map(ipv4),
                total,
                timeout,
                "Subnet scan completed",
            )
        }
        (IpAddr::V6(network), IpAddr::V6(broadcast)) => match ipv6_hosts(network, broadcast) {
            Some(hosts) => {
                let total = hosts.len() as u64;
                scan_all(
                    hosts.into_par_iter(),
                    total,
                    timeout,
                    "Subnet scan completed",
                )
            }
            None => Vec::new(),
        },
        // network() and broadcast() always share the subnet's family.
        _ => Vec::new(),
    }
}

/// Scan a range of IP addresses for available hosts
///
/// The `start` and `end` addresses must belong to the same family (both IPv4 or
/// both IPv6). IPv6 ranges are scanned only when they span at most
/// [`MAX_IPV6_HOSTS`] addresses; wider ranges are refused.
///
/// # Arguments
///
/// * `start` - The starting IP address
/// * `end` - The ending IP address
/// * `timeout` - Optional per-host timeout (defaults to [`crate::scanner::port::CONNECT_TIMEOUT`])
///
/// # Returns
///
/// * `Vec<HostHit>` - A vector of available hosts with their probe latency
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::address::scan_ip_range;
/// use std::net::IpAddr;
///
/// let start: IpAddr = "192.168.1.1".parse().unwrap();
/// let end: IpAddr = "192.168.1.10".parse().unwrap();
/// let available_hosts = scan_ip_range(start, end, None);
/// println!("Found {} available hosts", available_hosts.len());
/// ```
pub fn scan_ip_range(start: IpAddr, end: IpAddr, timeout: Option<Duration>) -> Vec<HostHit> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let start = u32::from(start);
            let end = u32::from(end);
            if start > end {
                return Vec::new();
            }
            let total = u64::from(end - start) + 1;
            scan_all(
                (start..=end).into_par_iter().map(ipv4),
                total,
                timeout,
                "Range scan completed",
            )
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            if start > end {
                return Vec::new();
            }
            match ipv6_hosts(start, end) {
                Some(hosts) => {
                    let total = hosts.len() as u64;
                    scan_all(
                        hosts.into_par_iter(),
                        total,
                        timeout,
                        "Range scan completed",
                    )
                }
                None => Vec::new(),
            }
        }
        _ => {
            eprintln!("Range start and end must be the same IP family");
            Vec::new()
        }
    }
}

/// Build the inclusive list of IPv6 addresses between `start` and `end`,
/// or `None` (after warning) if the span exceeds [`MAX_IPV6_HOSTS`].
fn ipv6_hosts(start: Ipv6Addr, end: Ipv6Addr) -> Option<Vec<IpAddr>> {
    let start = u128::from(start);
    let end = u128::from(end);
    let count = end - start + 1;
    if count > MAX_IPV6_HOSTS {
        eprintln!(
            "Refusing to scan {} IPv6 addresses (limit is {}); narrow the range or prefix",
            count, MAX_IPV6_HOSTS
        );
        return None;
    }
    Some(
        (start..=end)
            .map(|n| IpAddr::V6(Ipv6Addr::from(n)))
            .collect(),
    )
}

/// Convert a packed `u32` into an [`IpAddr::V4`].
fn ipv4(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TEST_TIMEOUT: Option<Duration> = Some(Duration::from_millis(100));

    // Helper function to check if localhost is available
    fn is_localhost_available() -> bool {
        scan_address("127.0.0.1".parse().unwrap(), TEST_TIMEOUT).is_some()
    }

    #[test]
    fn test_scan_address_localhost() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_address_localhost: localhost is not available");
            return;
        }

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let hit = scan_address(ip, TEST_TIMEOUT).expect("localhost should be up");
        assert_eq!(hit.ip, ip);
    }

    #[test]
    fn test_scan_address_unavailable() {
        // Test with an address that's very unlikely to be available
        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        assert!(scan_address(ip, TEST_TIMEOUT).is_none());
    }

    #[test]
    fn test_scan_subnet() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_subnet: localhost is not available");
            return;
        }

        // Scan a tiny slice of loopback that includes 127.0.0.1
        let subnet = "127.0.0.0/30".parse::<IpNetwork>().unwrap();
        let results = scan_subnet(subnet, TEST_TIMEOUT);

        // Verify that results contain localhost and are sorted
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(results.iter().any(|h| h.ip == localhost));
        assert!(results.windows(2).all(|w| w[0].ip <= w[1].ip));
    }

    #[test]
    fn test_scan_ip_range() {
        // Skip test if localhost is not available
        if !is_localhost_available() {
            println!("Skipping test_scan_ip_range: localhost is not available");
            return;
        }

        // Scan only localhost and a few addresses around it
        let start: IpAddr = "127.0.0.1".parse().unwrap();
        let end: IpAddr = "127.0.0.3".parse().unwrap();
        let results = scan_ip_range(start, end, TEST_TIMEOUT);

        // Verify that results contain localhost and are sorted
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(results.iter().any(|h| h.ip == localhost));
        assert!(results.windows(2).all(|w| w[0].ip <= w[1].ip));
    }

    #[test]
    fn test_scan_empty_range() {
        // Test with an invalid range (start > end)
        let start: IpAddr = "127.0.0.10".parse().unwrap();
        let end: IpAddr = "127.0.0.1".parse().unwrap();
        let results = scan_ip_range(start, end, TEST_TIMEOUT);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_ip_range_family_mismatch() {
        let start: IpAddr = "127.0.0.1".parse().unwrap();
        let end: IpAddr = "::1".parse().unwrap();
        assert!(scan_ip_range(start, end, TEST_TIMEOUT).is_empty());
    }

    #[test]
    fn test_ipv6_hosts_within_limit() {
        // 2001:db8::/126 -> 4 addresses
        let start: Ipv6Addr = "2001:db8::".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let hosts = ipv6_hosts(start, end).expect("small span should be enumerated");
        assert_eq!(hosts.len(), 4);
    }

    #[test]
    fn test_ipv6_hosts_over_limit() {
        // A /64 is far larger than MAX_IPV6_HOSTS and must be refused.
        let net = "2001:db8::/64".parse::<IpNetwork>().unwrap();
        if let (IpAddr::V6(network), IpAddr::V6(broadcast)) = (net.network(), net.broadcast()) {
            assert!(ipv6_hosts(network, broadcast).is_none());
        } else {
            panic!("expected IPv6 network");
        }
    }
}

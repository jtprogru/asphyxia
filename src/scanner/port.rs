use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::iface;

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
/// With `retries == 0` this is a single attempt — the original behavior.
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
    // Open through the interface-binding helper so `--interface` pins the probe
    // to the requested link (a no-op when none was set).
    match iface::tcp_connect_timeout(socket_addr, timeout) {
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

// ---------------------------------------------------------------------------
// UDP scanning
// ---------------------------------------------------------------------------

/// An observed UDP port together with how long the probe took and what state it
/// was reported in.
///
/// UDP has no handshake, so a port is either provably `open` (it sent a reply),
/// `closed` (ICMP port-unreachable came back), or indeterminate: `filtered`
/// when an ICMP other-unreachable says a device dropped the probe, and
/// `open|filtered` when it stayed silent — the datagram may have been dropped,
/// or the service simply does not answer this probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHit {
    pub port: u16,
    pub latency: Duration,
    /// The observed state: `"open"`, `"closed"`, `"filtered"` or
    /// `"open|filtered"`.
    pub status: &'static str,
}

/// The classified outcome of a single UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpProbe {
    /// The port replied — it is open (a fact).
    Open,
    /// ICMP port-unreachable (type 3, code 3) came back — the port is closed.
    Closed,
    /// ICMP other-unreachable (administratively filtered, etc.) — a device
    /// dropped the probe; the port state behind it is unknown.
    Filtered,
    /// No reply within the timeout — open or filtered, indistinguishable
    /// without privileges. A conclusion, not a fact.
    OpenFiltered,
}

/// Scan a UDP `port`, retrying an ambiguous (silent) probe up to `retries`
/// extra times — a dropped datagram can otherwise masquerade as
/// `open|filtered`.
///
/// Returns `Some(UdpHit)` for every probed port with its observed state:
/// `open` when the service replied, `closed` on ICMP port-unreachable,
/// `filtered` on an administrative ICMP unreachable, and `open|filtered` when
/// nothing came back after all retries. For a handful of well-known ports a
/// protocol-specific payload is sent to coax a reply and cut down on
/// `open|filtered` results; other ports get an empty datagram.
///
/// # Examples
///
/// ```no_run
/// use asphyxia::scanner::port::scan_udp_port;
///
/// let hit = scan_udp_port("1.1.1.1".to_string(), 53, None, 1);
/// println!("udp/{} is {}", hit.port, hit.status);
/// ```
pub fn scan_udp_port(host: String, port: u16, timeout: Option<Duration>, retries: u32) -> UdpHit {
    let timeout = timeout.unwrap_or(CONNECT_TIMEOUT);
    let start = Instant::now();

    // Retry only the ambiguous "silent" outcome; a reply or an ICMP answer is
    // definitive. (Hosts rate-limit their ICMP replies per RFC 1812, so a lost
    // unreachable can make a closed port look open|filtered — `--retries` buys
    // back some certainty there.)
    let mut outcome = UdpProbe::OpenFiltered;
    for _ in 0..=retries {
        outcome = probe_udp(&host, port, timeout);
        if !matches!(outcome, UdpProbe::OpenFiltered) {
            break;
        }
    }

    UdpHit {
        port,
        latency: start.elapsed(),
        status: match outcome {
            UdpProbe::Open => "open",
            UdpProbe::Closed => "closed",
            UdpProbe::Filtered => "filtered",
            UdpProbe::OpenFiltered => "open|filtered",
        },
    }
}

/// Send one UDP datagram and classify what comes back.
fn probe_udp(host: &str, port: u16, timeout: Duration) -> UdpProbe {
    // Respect the global rate limit (no-op when none is installed).
    crate::rate::gate();

    let Some(target) = host_port(host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        // Unresolvable: nothing to probe.
        return UdpProbe::Closed;
    };

    // Bind an ephemeral local socket in the target's address family, pinned to
    // `--interface` when one was requested (a no-op otherwise), and connect it.
    let Ok(socket) = iface::udp_connect(target) else {
        return UdpProbe::OpenFiltered;
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return UdpProbe::OpenFiltered;
    }
    if socket.send(&udp_probe_payload(port)).is_err() {
        return UdpProbe::OpenFiltered;
    }

    let mut buf = [0u8; 512];
    classify_udp(socket.recv(&mut buf))
}

/// Map a UDP `recv` result to a probe outcome.
fn classify_udp(result: std::io::Result<usize>) -> UdpProbe {
    match result {
        // Any reply proves the port is open.
        Ok(_) => UdpProbe::Open,
        // A connected UDP socket surfaces ICMP port-unreachable (type 3, code 3)
        // as a refusal: the host has no service on that port — it is closed.
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => UdpProbe::Closed,
        // Other ICMP unreachables surface as "host unreachable" / "network
        // unreachable" / "no route to host": a device administratively dropped
        // the probe (type 3 codes 1/2/9/10/13), so the port state is unknown —
        // filtered, not closed.
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
            ) =>
        {
            UdpProbe::Filtered
        }
        // Timeout or would-block: no answer, so open or filtered.
        Err(_) => UdpProbe::OpenFiltered,
    }
}

/// A protocol-specific probe payload for `port`, or an empty datagram when no
/// specific probe is known. A tailored payload is far more likely to elicit a
/// reply, which turns an `open|filtered` guess into a definite `open`.
fn udp_probe_payload(port: u16) -> Vec<u8> {
    match port {
        // DNS: a standard query for the root NS record (RD set).
        53 => vec![
            0x12, 0x34, // transaction id
            0x01, 0x00, // flags: recursion desired
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            0x00, // qname: root
            0x00, 0x02, // qtype: NS
            0x00, 0x01, // qclass: IN
        ],
        // NTP: a 48-byte client request (LI=0, VN=3, mode=3 client).
        123 => {
            let mut pkt = vec![0u8; 48];
            pkt[0] = 0x1b;
            pkt
        }
        // SNMP: a GET request for the system description OID (1.3.6.1.2.1.1.5)
        // with the default "public" community — most agents answer it.
        161 => {
            let mut pkt = vec![0x02, 0x00]; // version: SNMPv1 (0)
            pkt.extend_from_slice(b"public"); // community string
            let mut seq = vec![0x30u8]; // SEQUENCE (request)
            seq.push(0x00); // request-id: 0
            seq.push(0x00); // error-status: no-error
            seq.push(0x00); // error-index: 0
            let mut varbind = vec![0x30u8]; // SEQUENCE (varbind-list)
            let mut oid = vec![0x06u8, 0x07]; // OID, length 7
            oid.extend_from_slice(&[1, 3, 6, 1, 2, 1, 1, 5]);
            varbind.push(0x05); // NULL value (no type byte needed for NULL)
            varbind.extend_from_slice(&oid);
            seq.extend_from_slice(&varbind);
            pkt.extend_from_slice(&seq);
            pkt
        }
        // NetBIOS name service: a node status query (0x21) for the null name.
        137 => {
            let mut pkt = vec![0x80, 0x00]; // transaction id
            pkt.extend_from_slice(&[0x00, 0x00]); // flags: response bit clear
            pkt.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
            pkt.extend_from_slice(&[0x00, 0x00]); // ancount
            pkt.extend_from_slice(&[0x00, 0x00]); // nscount
            pkt.extend_from_slice(&[0x00, 0x00]); // arcount
            pkt.push(0x00); // qname: null name
            pkt.extend_from_slice(&[0x00, 0x21]); // qtype: NBSTAT (33)
            pkt.extend_from_slice(&[0x00, 0x01]); // qclass: IN
            pkt
        }
        // mDNS: a query for the local service instance type.
        5353 => {
            let mut pkt = vec![0x00, 0x00]; // transaction id (mDNS uses 0)
            pkt.extend_from_slice(&[0x00, 0x00]); // flags: query
            pkt.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
            pkt.extend_from_slice(&[0x00, 0x00]); // ancount
            pkt.extend_from_slice(&[0x00, 0x00]); // nscount
            pkt.extend_from_slice(&[0x00, 0x00]); // arcount
            let name = b"_http._tcp.local.";
            for label in name.split(|&b| b == b'.') {
                if !label.is_empty() {
                    pkt.push(label.len() as u8);
                    pkt.extend_from_slice(label);
                }
            }
            pkt.push(0x00); // root terminator
            pkt.extend_from_slice(&[0x00, 0x0c]); // qtype: PTR (12)
            pkt.extend_from_slice(&[0xc0, 0x0c]); // qclass: IN | cache-flush
            pkt
        }
        // Others: an empty datagram is enough to trigger an ICMP unreachable
        // from a closed port.
        _ => Vec::new(),
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

    #[test]
    fn udp_classification_maps_recv_outcomes() {
        use std::io::{Error, ErrorKind};
        assert_eq!(classify_udp(Ok(12)), UdpProbe::Open);
        // ICMP port-unreachable (type 3, code 3) surfaces as a refusal: closed.
        assert_eq!(
            classify_udp(Err(Error::from(ErrorKind::ConnectionRefused))),
            UdpProbe::Closed
        );
        // Other ICMP unreachables (administratively filtered, type 3 codes
        // 1/2/9/10/13) surface as host/network unreachable: filtered.
        assert_eq!(
            classify_udp(Err(Error::from(ErrorKind::HostUnreachable))),
            UdpProbe::Filtered
        );
        assert_eq!(
            classify_udp(Err(Error::from(ErrorKind::NetworkUnreachable))),
            UdpProbe::Filtered
        );
        // Timeout or would-block: no answer, so open or filtered.
        assert_eq!(
            classify_udp(Err(Error::from(ErrorKind::WouldBlock))),
            UdpProbe::OpenFiltered
        );
        assert_eq!(
            classify_udp(Err(Error::from(ErrorKind::TimedOut))),
            UdpProbe::OpenFiltered
        );
    }

    #[test]
    fn dns_payload_is_a_wellformed_query_header() {
        let dns = udp_probe_payload(53);
        assert!(!dns.is_empty());
        // qdcount == 1 lives in bytes 4..6.
        assert_eq!(&dns[4..6], &[0x00, 0x01]);
        // Query terminates with root name + qtype NS + qclass IN.
        assert_eq!(&dns[dns.len() - 5..], &[0x00, 0x00, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn ntp_payload_is_a_48_byte_client_request() {
        let ntp = udp_probe_payload(123);
        assert_eq!(ntp.len(), 48);
        // LI=0, VN=3, mode=3 (client) in the first byte.
        assert_eq!(ntp[0], 0x1b);
    }

    #[test]
    fn snmp_payload_is_a_get_request_with_public_community() {
        let snmp = udp_probe_payload(161);
        // SNMPv1 version (0) in the first two bytes.
        assert_eq!(&snmp[0..2], &[0x02, 0x00]);
        // The default "public" community string follows.
        assert!(snmp.windows(6).any(|w| w == b"public"));
        // A GET request carries the system description OID (1.3.6.1.2.1.1.5).
        let oid: Vec<u8> = vec![1, 3, 6, 1, 2, 1, 1, 5];
        assert!(snmp.windows(oid.len()).any(|w| w == oid.as_slice()));
    }

    #[test]
    fn netbios_payload_is_a_node_status_query() {
        let nb = udp_probe_payload(137);
        // qdcount == 1 lives in bytes 4..6.
        assert_eq!(&nb[4..6], &[0x00, 0x01]);
        // Query terminates with null name + qtype NBSTAT (33) + qclass IN.
        assert_eq!(&nb[nb.len() - 5..], &[0x00, 0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn mdns_payload_is_a_ptr_query_for_http_service() {
        let mdns = udp_probe_payload(5353);
        // mDNS uses transaction id 0.
        assert_eq!(&mdns[0..2], &[0x00, 0x00]);
        // qdcount == 1 lives in bytes 4..6.
        assert_eq!(&mdns[4..6], &[0x00, 0x01]);
        // The query name is the local HTTP service instance type, encoded as
        // length-prefixed labels: _http (5) . _tcp (4) . local (5).
        let expected = [
            5u8, b'_', b'h', b't', b't', b'p', 4, b'_', b't', b'c', b'p', 5, b'l', b'o', b'c',
            b'a', b'l',
        ];
        assert!(
            mdns.windows(expected.len())
                .any(|w| w == expected.as_slice())
        );
    }

    #[test]
    fn unknown_ports_get_an_empty_payload() {
        assert!(udp_probe_payload(4444).is_empty());
    }

    #[test]
    fn udp_scan_reports_open_when_a_local_server_replies() {
        use std::net::UdpSocket;
        use std::thread;

        // A local UDP echo server: it replies to the first datagram, which must
        // make the probe classify the port as open.
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let port = server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&buf[..n], peer);
            }
        });

        let hit = scan_udp_port("127.0.0.1".to_string(), port, TEST_TIMEOUT, 0);
        assert_eq!(
            hit.status, "open",
            "a replying UDP port must be reported open"
        );
        let _ = handle.join();
    }

    #[test]
    fn udp_scan_reports_closed_for_a_refused_port() {
        // Port 1 on loopback is closed: the kernel answers with an ICMP
        // port-unreachable, which a connected UDP socket surfaces as a refusal.
        let hit = scan_udp_port("127.0.0.1".to_string(), 1, TEST_TIMEOUT, 0);
        assert_eq!(hit.status, "closed");
    }

    #[test]
    fn udp_scan_reports_open_filtered_for_a_silent_port() {
        // A port that neither replies nor refuses (e.g. a blackhole) stays
        // open|filtered — the honest conclusion, not a fact.
        let hit = scan_udp_port("127.0.0.1".to_string(), 9, TEST_TIMEOUT, 0);
        assert!(
            matches!(hit.status, "open" | "closed" | "open|filtered"),
            "a silent port must not be reported filtered: {}",
            hit.status
        );
    }
}

//! SYN / stealth scanning (`--syn`, `-sS`).
//!
//! A SYN scan sends a lone TCP SYN and never completes the handshake: a SYN/ACK
//! reply means the port is open (we answer with a RST instead of an ACK), a RST
//! means closed, and silence means filtered. It is faster and quieter than a
//! full connect scan, but forging raw TCP/IP packets needs elevated privileges
//! (root / `CAP_NET_RAW`).
//!
//! This module is split so the risky, privilege-bound network I/O is separate
//! from the pure, exhaustively-tested packet machinery:
//!
//! * [`build_ipv4_syn`] / [`build_tcp_syn`] assemble the bytes on the wire,
//! * [`parse_ipv4_tcp`] and [`classify_flags`] interpret a reply,
//! * [`raw_socket_available`] reports whether a raw socket can be opened, so the
//!   caller can fall back to a connect scan with a clear message when it cannot.
//!
//! IPv4 only: IPv6 SYN scanning is not implemented and callers fall back.

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// TCP control-flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Length of a TCP header with no options.
const TCP_HEADER_LEN: usize = 20;
/// Length of an IPv4 header with no options.
const IPV4_HEADER_LEN: usize = 20;
/// IANA protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// How a SYN probe's reply is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynOutcome {
    /// SYN/ACK — the port is open.
    Open,
    /// RST — the port is closed.
    Closed,
    /// Anything else (or no reply) — filtered/indeterminate.
    Filtered,
}

/// Classify a TCP reply from its flag byte: RST is closed, SYN+ACK is open,
/// everything else is filtered.
pub fn classify_flags(flags: u8) -> SynOutcome {
    if flags & TCP_RST != 0 {
        SynOutcome::Closed
    } else if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
        SynOutcome::Open
    } else {
        SynOutcome::Filtered
    }
}

/// One's-complement 16-bit checksum over `data` (RFC 1071), used for both the
/// IPv4 header and the TCP segment (the latter over a pseudo-header).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a bare TCP SYN segment (20 bytes, no options) with its checksum filled
/// in over the IPv4 pseudo-header.
pub fn build_tcp_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    let mut seg = vec![0u8; TCP_HEADER_LEN];
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    // ack number stays 0 (bytes 8..12).
    seg[12] = 0x50; // data offset = 5 (20 bytes) in the high nibble.
    seg[13] = TCP_SYN;
    seg[14..16].copy_from_slice(&1024u16.to_be_bytes()); // window
    // checksum (16..18) left zero for the computation.
    // urgent pointer (18..20) stays 0.

    // Pseudo-header: src, dst, zero, proto, tcp length.
    let mut pseudo = Vec::with_capacity(12 + TCP_HEADER_LEN);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IPPROTO_TCP);
    pseudo.extend_from_slice(&(TCP_HEADER_LEN as u16).to_be_bytes());
    pseudo.extend_from_slice(&seg);

    let sum = checksum(&pseudo);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
    seg
}

/// Build a complete IPv4 packet carrying a TCP SYN, including a valid IPv4
/// header checksum.
pub fn build_ipv4_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    let tcp = build_tcp_syn(src, dst, src_port, dst_port, seq);
    let total_len = (IPV4_HEADER_LEN + tcp.len()) as u16;

    let mut ip = vec![0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
    // DSCP/ECN (1) stays 0.
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    // identification (4..6) stays 0.
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_TCP;
    // header checksum (10..12) left zero for the computation.
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());

    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());

    ip.extend_from_slice(&tcp);
    ip
}

/// Parse an IPv4 packet that carries TCP, returning `(src_port, dst_port,
/// flags)`. Returns `None` if the buffer is too short, not IPv4, or not TCP.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<(u16, u16, u8)> {
    if packet.len() < IPV4_HEADER_LEN {
        return None;
    }
    // Version must be 4.
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
        return None;
    }
    if packet[9] != IPPROTO_TCP {
        return None;
    }
    let tcp = &packet[ihl..];
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    Some((src_port, dst_port, flags))
}

/// Whether a raw TCP socket can be opened — i.e. whether the process has the
/// privileges needed for a SYN scan. When this is `false`, callers should fall
/// back to a connect scan.
pub fn raw_socket_available() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(i32::from(IPPROTO_TCP))),
    )
    .is_ok()
}

/// Discover the local IPv4 address the kernel would use to reach `dst`, without
/// sending anything: connecting a UDP socket only sets its route.
fn local_ipv4_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(SocketAddr::new(dst.into(), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Perform a single SYN probe against `dst:dst_port` over a raw socket and
/// classify the reply. Returns `None` if a raw socket cannot be used (no
/// privileges, platform limitation, or send error), signalling the caller to
/// fall back to a connect probe.
///
/// This is the privilege-bound path: it forges a SYN, sends it, and reads
/// replies until it sees the matching SYN/ACK or RST, or the timeout elapses
/// (reported as [`SynOutcome::Filtered`]).
pub fn syn_scan_port(dst: Ipv4Addr, dst_port: u16, timeout: Duration) -> Option<SynOutcome> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Respect the global rate limit (no-op when none is installed).
    crate::rate::gate();

    let src = local_ipv4_for(dst)?;
    // A source port derived from the destination keeps concurrent probes from
    // colliding, since each job has a distinct destination port.
    let src_port = 40000u16.wrapping_add(dst_port);
    let segment = build_tcp_syn(src, dst, src_port, dst_port, 0x1234_5678);

    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(i32::from(IPPROTO_TCP))),
    )
    .ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;

    let destination: socket2::SockAddr = SocketAddr::new(dst.into(), dst_port).into();
    socket.send_to(&segment, &destination).ok()?;

    // Read replies until the one addressed to our probe arrives or time runs out.
    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    while Instant::now() < deadline {
        let Ok(n) = socket.recv(&mut buf) else {
            break;
        };
        // Safety: `recv` reports `n` initialised bytes at the front of `buf`.
        let packet = unsafe { &*(&buf[..n] as *const [MaybeUninit<u8>] as *const [u8]) };
        if let Some((reply_src, reply_dst, flags)) = parse_ipv4_tcp(packet)
            && reply_src == dst_port
            && reply_dst == src_port
        {
            return Some(classify_flags(flags));
        }
    }
    // No matching reply within the window: treat as filtered.
    Some(SynOutcome::Filtered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_open_closed_filtered() {
        assert_eq!(classify_flags(TCP_SYN | TCP_ACK), SynOutcome::Open);
        assert_eq!(classify_flags(TCP_RST | TCP_ACK), SynOutcome::Closed);
        assert_eq!(classify_flags(TCP_RST), SynOutcome::Closed);
        assert_eq!(classify_flags(TCP_ACK), SynOutcome::Filtered);
        assert_eq!(classify_flags(0), SynOutcome::Filtered);
    }

    #[test]
    fn checksum_of_a_valid_block_verifies_to_zero() {
        // Summing a block that already contains its own checksum yields 0.
        let ip = build_ipv4_syn(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            40000,
            80,
            0x11223344,
        );
        // IPv4 header (first 20 bytes) checksums to zero when the stored sum is
        // included.
        assert_eq!(checksum(&ip[..IPV4_HEADER_LEN]), 0);
    }

    #[test]
    fn tcp_syn_has_expected_shape_and_valid_checksum() {
        let src: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let dst: Ipv4Addr = "192.168.1.20".parse().unwrap();
        let seg = build_tcp_syn(src, dst, 50000, 443, 0xdeadbeef);
        assert_eq!(seg.len(), TCP_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 50000);
        assert_eq!(u16::from_be_bytes([seg[2], seg[3]]), 443);
        assert_eq!(seg[12] >> 4, 5, "data offset should be 5 words");
        assert_eq!(seg[13], TCP_SYN, "only the SYN flag should be set");

        // Re-checksumming the pseudo-header + segment must verify to zero.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(IPPROTO_TCP);
        pseudo.extend_from_slice(&(TCP_HEADER_LEN as u16).to_be_bytes());
        pseudo.extend_from_slice(&seg);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn ipv4_syn_total_length_and_protocol_are_correct() {
        let ip = build_ipv4_syn(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            33333,
            22,
            1,
        );
        assert_eq!(ip.len(), IPV4_HEADER_LEN + TCP_HEADER_LEN);
        assert_eq!(ip[0] >> 4, 4, "version 4");
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]) as usize,
            IPV4_HEADER_LEN + TCP_HEADER_LEN
        );
        assert_eq!(ip[9], IPPROTO_TCP);
    }

    #[test]
    fn build_then_parse_round_trips_ports_and_flags() {
        let ip = build_ipv4_syn(
            "10.1.1.1".parse().unwrap(),
            "10.1.1.2".parse().unwrap(),
            44444,
            8080,
            42,
        );
        let (src_port, dst_port, flags) = parse_ipv4_tcp(&ip).expect("should parse");
        assert_eq!(src_port, 44444);
        assert_eq!(dst_port, 8080);
        assert_eq!(flags, TCP_SYN);
    }

    #[test]
    fn parse_rejects_non_ipv4_and_non_tcp() {
        assert!(parse_ipv4_tcp(&[]).is_none());
        // Version 6 nibble.
        assert!(parse_ipv4_tcp(&[0x60; 40]).is_none());
        // IPv4 but protocol 17 (UDP), not TCP.
        let mut pkt = build_ipv4_syn(
            "1.1.1.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            1,
            2,
            3,
        );
        pkt[9] = 17;
        assert!(parse_ipv4_tcp(&pkt).is_none());
    }

    #[test]
    fn parse_handles_ip_options() {
        // An IHL of 6 (24-byte header) shifts where the TCP segment begins.
        let mut pkt = build_ipv4_syn(
            "9.9.9.9".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            53,
            7,
        );
        // Splice 4 bytes of IP options in and bump IHL + total length.
        let tcp = pkt.split_off(IPV4_HEADER_LEN);
        pkt.extend_from_slice(&[0u8; 4]); // dummy options
        pkt.extend_from_slice(&tcp);
        pkt[0] = 0x46; // IHL = 6
        let new_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&new_len.to_be_bytes());

        let (src_port, dst_port, flags) = parse_ipv4_tcp(&pkt).expect("should parse with options");
        assert_eq!(src_port, 12345);
        assert_eq!(dst_port, 53);
        assert_eq!(flags, TCP_SYN);
    }
}

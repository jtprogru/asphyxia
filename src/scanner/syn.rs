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
//! The SYN is *sent* over a raw socket, but replies are *received* with
//! libpcap/BPF via a single shared [`SynReceiver`] rather than `recv()` on the
//! raw socket. That receive path matters: on macOS/BSD the kernel never hands
//! inbound TCP to a raw socket, so a `recv()`-based reader reads nothing and
//! every port looks filtered. A pcap capture works uniformly on Linux and macOS
//! (this is what nmap does too). See issues #38 / #39.
//!
//! IPv4 only: IPv6 SYN scanning is not implemented and callers fall back.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
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
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = remainder {
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

/// Parse an IPv4 packet that carries TCP, returning `(src_ip, dst_ip, src_port,
/// dst_port, flags)`. Returns `None` if the buffer is too short, not IPv4, or
/// not TCP. The addresses are needed to correlate a captured reply to the host
/// it came from when several targets are scanned at once.
pub fn parse_ipv4_tcp_addrs(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, u8)> {
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
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl..];
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    Some((src_ip, dst_ip, src_port, dst_port, flags))
}

/// Parse an IPv4 packet that carries TCP, returning `(src_port, dst_port,
/// flags)`. Returns `None` if the buffer is too short, not IPv4, or not TCP.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<(u16, u16, u8)> {
    parse_ipv4_tcp_addrs(packet)
        .map(|(_, _, src_port, dst_port, flags)| (src_port, dst_port, flags))
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

/// Base for the ephemeral source port a probe forges: the source port is
/// `SRC_PORT_BASE + dst_port`, giving each concurrent probe a distinct one.
/// Replies are correlated by their own `(source ip, source port)`, not by this
/// value, since NAT/VPN may rewrite the source port before the packet leaves.
const SRC_PORT_BASE: u16 = 40000;

/// The source port a probe to `dst_port` forges.
fn src_port_for(dst_port: u16) -> u16 {
    SRC_PORT_BASE.wrapping_add(dst_port)
}

/// Perform a single SYN probe against `dst:dst_port`: forge and send a SYN over
/// a raw socket, then wait for the shared [`SynReceiver`] to observe the reply.
/// A SYN/ACK is [`SynOutcome::Open`], a RST is [`SynOutcome::Closed`], and no
/// reply within `timeout` is [`SynOutcome::Filtered`].
///
/// Returns `None` when the SYN scan cannot run — the receiver was never
/// installed (no [`init_receiver`], or it failed), a raw socket cannot be
/// opened, or the send errored — signalling the caller to fall back to a
/// connect probe. Replies are read by the receiver's pcap capture, never by a
/// `recv()` here, so this works on macOS as well as Linux.
pub fn syn_scan_port(dst: Ipv4Addr, dst_port: u16, timeout: Duration) -> Option<SynOutcome> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Without a running capture there is nothing to read replies, so let the
    // caller fall back rather than send SYNs into a void.
    let receiver = receiver()?;

    // Respect the global rate limit (no-op when none is installed).
    crate::rate::gate();

    let dbg = debug_enabled();
    let src = local_ipv4_for(dst)?;
    let src_port = src_port_for(dst_port);

    // Send a full IPv4 packet with the header included. macOS refuses to send
    // TCP through a bare IPPROTO_TCP raw socket (EPROTOTYPE), so we build the IP
    // header ourselves over an IPPROTO_RAW socket, which implies IP_HDRINCL.
    #[allow(unused_mut)]
    let mut packet = build_ipv4_syn(src, dst, src_port, dst_port, 0x1234_5678);
    #[cfg(target_os = "macos")]
    {
        // Darwin's IP_HDRINCL path reads ip_len and ip_off in host byte order
        // and swaps them to network order itself. The header checksum was
        // computed over the network-order header, so it stays valid after that
        // swap-back. (On a big-endian host this is a no-op, as it should be.)
        let ip_len = u16::from_be_bytes([packet[2], packet[3]]);
        packet[2..4].copy_from_slice(&ip_len.to_ne_bytes());
        let ip_off = u16::from_be_bytes([packet[6], packet[7]]);
        packet[6..8].copy_from_slice(&ip_off.to_ne_bytes());
    }

    const IPPROTO_RAW: i32 = 255;
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW))).ok()?;
    socket.set_header_included_v4(true).ok()?;

    let destination: socket2::SockAddr = SocketAddr::new(dst.into(), dst_port).into();
    match socket.send_to(&packet, &destination) {
        Ok(n) => {
            if dbg {
                eprintln!("[syn] sent {n}B SYN {src}:{src_port} -> {dst}:{dst_port}");
            }
        }
        Err(e) => {
            if dbg {
                eprintln!("[syn] send_to {dst}:{dst_port} failed: {e}");
            }
            return None;
        }
    }

    let started = Instant::now();
    let outcome = receiver.wait_for(dst, dst_port, timeout);
    if dbg {
        eprintln!(
            "[syn] wait {dst}:{dst_port} = {outcome:?} after {:?}",
            started.elapsed()
        );
    }
    Some(outcome)
}

// ---------------------------------------------------------------------------
// pcap/BPF reply receiver
// ---------------------------------------------------------------------------

/// How long a pcap read blocks before it returns so the reader can re-check its
/// stop flag. Short enough to shut down promptly, long enough not to spin.
const READ_TIMEOUT_MS: i32 = 200;
/// Enough to hold a link header plus a full IPv4 + TCP header with options.
const SNAPLEN: i32 = 128;

/// State shared between the probe threads and the background pcap reader.
struct ReceiverShared {
    /// Observed outcomes keyed by `(target_ip, target_port)` — i.e. the source
    /// address of the reply. Only definitive results (open/closed) are stored.
    outcomes: Mutex<HashMap<(Ipv4Addr, u16), SynOutcome>>,
    /// Woken whenever a new outcome is recorded, so waiters re-check the map.
    signal: Condvar,
    /// Set on drop to stop the reader loop.
    stop: AtomicBool,
}

/// A single libpcap capture that reads every SYN/stealth reply for the whole
/// scan and lets per-port probes wait for their answer. One capture is far
/// cheaper than one `recv()` per port and, on macOS, avoids exhausting the
/// limited pool of `/dev/bpf*` devices that a capture-per-probe would.
pub struct SynReceiver {
    shared: Arc<ReceiverShared>,
    reader: Option<JoinHandle<()>>,
}

impl SynReceiver {
    /// Open a capture on the interface that routes to `target` and spawn the
    /// reader. Returns `None` if no interface, capture, or filter could be set
    /// up (missing privileges, no libpcap, unusual link type).
    fn start(target: Ipv4Addr) -> Option<SynReceiver> {
        let src = local_ipv4_for(target)?;
        let shared = Arc::new(ReceiverShared {
            outcomes: Mutex::new(HashMap::new()),
            signal: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let reader_shared = Arc::clone(&shared);

        // The pcap `Capture` is created and consumed entirely inside the reader
        // thread, so it never has to cross a thread boundary. The thread reports
        // back over a channel whether the capture opened.
        let (ready_tx, ready_rx) = sync_channel::<bool>(1);
        let reader = thread::spawn(move || match open_capture(src) {
            Some((cap, offset)) => {
                let _ = ready_tx.send(true);
                reader_loop(cap, offset, &reader_shared);
            }
            None => {
                let _ = ready_tx.send(false);
            }
        });

        match ready_rx.recv() {
            Ok(true) => Some(SynReceiver {
                shared,
                reader: Some(reader),
            }),
            _ => {
                let _ = reader.join();
                None
            }
        }
    }

    /// Block until a reply for `(target, port)` is recorded or `timeout`
    /// elapses. A missing reply is [`SynOutcome::Filtered`].
    fn wait_for(&self, target: Ipv4Addr, port: u16, timeout: Duration) -> SynOutcome {
        let key = (target, port);
        let deadline = Instant::now() + timeout;
        let mut map = self
            .shared
            .outcomes
            .lock()
            .expect("syn receiver mutex poisoned");
        loop {
            if let Some(&outcome) = map.get(&key) {
                return outcome;
            }
            let now = Instant::now();
            if now >= deadline {
                return SynOutcome::Filtered;
            }
            let (guard, _timed_out) = self
                .shared
                .signal
                .wait_timeout(map, deadline - now)
                .expect("syn receiver condvar poisoned");
            map = guard;
        }
    }
}

impl Drop for SynReceiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The process-wide receiver, installed at most once via [`init_receiver`].
static RECEIVER: OnceLock<SynReceiver> = OnceLock::new();

/// Start the shared pcap receiver for a scan whose (first) IPv4 target is
/// `target`, choosing the capture interface from the route to it. Returns
/// `true` if a receiver is installed and ready (idempotent: a second call with
/// one already running is a no-op that returns `true`), `false` if the capture
/// could not be opened — in which case the caller should warn and fall back to
/// the connect scan.
pub fn init_receiver(target: Ipv4Addr) -> bool {
    if RECEIVER.get().is_some() {
        return true;
    }
    match SynReceiver::start(target) {
        Some(receiver) => RECEIVER.set(receiver).is_ok(),
        None => false,
    }
}

/// The installed receiver, if any.
fn receiver() -> Option<&'static SynReceiver> {
    RECEIVER.get()
}

/// Open a pcap capture on the interface bearing `src`, filtered to inbound
/// SYN/ACK and RST segments, and report the datalink header length to strip.
fn open_capture(src: Ipv4Addr) -> Option<(pcap::Capture<pcap::Active>, usize)> {
    let device = device_for(src)?;
    let dbg = debug_enabled();
    if dbg {
        let addrs: Vec<_> = device.addresses.iter().map(|a| a.addr).collect();
        eprintln!("[syn] src={src} device={} addrs={addrs:?}", device.name);
    }
    let mut cap = pcap::Capture::from_device(device)
        .ok()?
        .immediate_mode(true)
        .snaplen(SNAPLEN)
        .timeout(READ_TIMEOUT_MS)
        .open()
        .ok()?;
    // Keep only TCP segments whose SYN or RST flag is set: SYN/ACK (open) and
    // RST (closed) are the only replies that answer a probe.
    cap.filter("tcp and (tcp[13] & 6) != 0", true).ok()?;
    let link = cap.get_datalink();
    let offset = datalink_offset(link);
    if dbg {
        eprintln!("[syn] datalink={link:?} offset={offset}");
    }
    Some((cap, offset))
}

/// Whether verbose SYN-scan capture diagnostics are enabled via the
/// `ASPHYXIA_SYN_DEBUG` environment variable. Read once and cached, since a
/// large scan queries it per probe.
fn debug_enabled() -> bool {
    static DEBUG: OnceLock<bool> = OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("ASPHYXIA_SYN_DEBUG").is_some())
}

/// The pcap device whose addresses include `src`, else libpcap's default.
fn device_for(src: Ipv4Addr) -> Option<pcap::Device> {
    let list = pcap::Device::list().ok()?;
    list.into_iter()
        .find(|dev| {
            dev.addresses
                .iter()
                .any(|a| matches!(a.addr, IpAddr::V4(v4) if v4 == src))
        })
        .or_else(|| pcap::Device::lookup().ok().flatten())
}

/// Bytes of link-layer header before the IPv4 packet, by datalink type. The
/// common cases; anything else is assumed Ethernet, and [`extract_ipv4_tcp`]
/// recovers if that guess is wrong.
fn datalink_offset(link: pcap::Linktype) -> usize {
    if link == pcap::Linktype::ETHERNET {
        14
    } else if link == pcap::Linktype::NULL || link == pcap::Linktype::LOOP {
        4
    } else if link == pcap::Linktype::LINUX_SLL {
        16
    } else if link == pcap::Linktype::RAW {
        0
    } else {
        14
    }
}

/// Locate and parse the IPv4/TCP reply inside a captured link-layer `frame`,
/// returning `(src_ip, src_port, dst_port, flags)`. Tries the datalink `hint`
/// first, then a few common offsets, so a misjudged link type degrades to a
/// missed reply (re-checked by the connect fallback) rather than a wrong one.
fn extract_ipv4_tcp(frame: &[u8], hint: usize) -> Option<(Ipv4Addr, u16, u16, u8)> {
    for offset in [hint, 0, 14, 4, 16] {
        if frame.len() > offset
            && frame[offset] >> 4 == 4
            && let Some((src_ip, _dst_ip, src_port, dst_port, flags)) =
                parse_ipv4_tcp_addrs(&frame[offset..])
        {
            return Some((src_ip, src_port, dst_port, flags));
        }
    }
    None
}

/// Read captured replies until stopped, recording each definitive outcome.
fn reader_loop(mut cap: pcap::Capture<pcap::Active>, offset: usize, shared: &ReceiverShared) {
    let dbg = debug_enabled();
    while !shared.stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let Some((src_ip, src_port, dst_port, flags)) =
                    extract_ipv4_tcp(packet.data, offset)
                else {
                    if dbg {
                        let n = packet.data.len().min(20);
                        eprintln!(
                            "[syn] unparsed frame len={} head={:02x?}",
                            packet.data.len(),
                            &packet.data[..n]
                        );
                    }
                    continue;
                };
                let outcome = classify_flags(flags);
                if dbg {
                    eprintln!(
                        "[syn] pkt src={src_ip} sport={src_port} dport={dst_port} flags={flags:#04x} outcome={outcome:?}"
                    );
                }
                // A SYN/ACK or RST identifies the port it came from: key the
                // outcome on the reply's (source ip, source port), i.e. the
                // scanned target and port. We deliberately do not match on the
                // source port we forged — NAT/VPN can rewrite it in flight, so
                // the reply arrives at the translated port. Our own outbound
                // SYN/RST has our source ip, a key no probe waits on, so it is
                // harmless; a lone SYN or other flags classify as Filtered and
                // are dropped here.
                if outcome == SynOutcome::Filtered {
                    continue;
                }
                let mut map = shared.outcomes.lock().expect("syn receiver mutex poisoned");
                map.entry((src_ip, src_port)).or_insert(outcome);
                shared.signal.notify_all();
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
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

    #[test]
    fn parse_addrs_extracts_endpoints() {
        let src: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.9".parse().unwrap();
        let pkt = build_ipv4_syn(src, dst, 41443, 443, 1);
        let (s_ip, d_ip, s_port, d_port, flags) =
            parse_ipv4_tcp_addrs(&pkt).expect("should parse addrs");
        assert_eq!(s_ip, src);
        assert_eq!(d_ip, dst);
        assert_eq!(s_port, 41443);
        assert_eq!(d_port, 443);
        assert_eq!(flags, TCP_SYN);
    }

    /// Prefix `pkt` with `len` bytes of dummy link-layer header.
    fn with_link_header(pkt: &[u8], len: usize) -> Vec<u8> {
        let mut frame = vec![0xabu8; len];
        frame.extend_from_slice(pkt);
        frame
    }

    #[test]
    fn extract_strips_ethernet_header_with_correct_hint() {
        let src: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let pkt = build_ipv4_syn(src, "10.0.0.6".parse().unwrap(), 40080, 80, 9);
        let frame = with_link_header(&pkt, 14);
        let (s_ip, s_port, d_port, flags) = extract_ipv4_tcp(&frame, 14).expect("eth strip");
        assert_eq!(s_ip, src);
        assert_eq!(s_port, 40080);
        assert_eq!(d_port, 80);
        assert_eq!(flags, TCP_SYN);
    }

    #[test]
    fn extract_recovers_when_the_hint_is_wrong() {
        // Frame really has a 14-byte Ethernet header, but we pass a bogus hint;
        // the fallback offsets must still find the IPv4/TCP packet.
        let pkt = build_ipv4_syn(
            "172.16.0.1".parse().unwrap(),
            "172.16.0.2".parse().unwrap(),
            40022,
            22,
            3,
        );
        let frame = with_link_header(&pkt, 14);
        let (_s_ip, s_port, d_port, _flags) =
            extract_ipv4_tcp(&frame, 0).expect("should recover via fallback offsets");
        assert_eq!(s_port, 40022);
        assert_eq!(d_port, 22);
    }

    #[test]
    fn extract_rejects_a_frame_without_ipv4() {
        assert!(extract_ipv4_tcp(&[0xff; 40], 14).is_none());
    }

    #[test]
    fn datalink_offsets_for_known_link_types() {
        assert_eq!(datalink_offset(pcap::Linktype::ETHERNET), 14);
        assert_eq!(datalink_offset(pcap::Linktype::NULL), 4);
        assert_eq!(datalink_offset(pcap::Linktype::LOOP), 4);
        assert_eq!(datalink_offset(pcap::Linktype::LINUX_SLL), 16);
        assert_eq!(datalink_offset(pcap::Linktype::RAW), 0);
    }

    #[test]
    fn source_ports_are_distinct_per_scanned_port() {
        // Each probe forges a distinct source port, so concurrent raw sends do
        // not clash. Correlation of replies does not depend on this value.
        let a = src_port_for(22);
        let b = src_port_for(443);
        let c = src_port_for(6443);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn a_reply_identifies_its_port_by_source() {
        // A SYN/ACK from the target carries the scanned port as its TCP source
        // port; that (plus the source ip) is how reader_loop keys the outcome,
        // independent of any NAT rewrite of the destination (our source) port.
        let target: Ipv4Addr = "198.51.100.20".parse().unwrap();
        // Reply built as the target would send it: src = target:6443,
        // dst = us:<a NAT-rewritten port that is not src_port_for(6443)>.
        let reply = build_ipv4_syn(target, "203.0.113.5".parse().unwrap(), 6443, 63839, 1);
        let (src_ip, src_port, dst_port, _flags) =
            extract_ipv4_tcp(&reply, 0).expect("parse reply");
        assert_eq!(src_ip, target);
        assert_eq!(src_port, 6443, "keying uses the reply's source port");
        assert_ne!(
            dst_port,
            src_port_for(6443),
            "the destination (our) port may be NAT-rewritten and is not used for keying"
        );
    }
}

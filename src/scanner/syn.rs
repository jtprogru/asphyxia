//! Raw-packet TCP probing: SYN / stealth scanning (`--syn`), ACK scanning
//! (`--scan ack`) and the FIN/NULL/XMAS family (`--scan fin|null|xmas`).
//!
//! A SYN scan sends a lone TCP SYN and never completes the handshake: a SYN/ACK
//! reply means the port is open (we answer with an RST instead of an ACK), an RST
//! means closed, and silence means filtered. It is faster and quieter than a
//! full connect scan, but forging raw TCP/IP packets needs elevated privileges
//! (root / `CAP_NET_RAW`).
//!
//! An ACK scan sends a lone ACK instead. Any host that receives a stray ACK
//! answers with an RST whether the port is open or closed, so the reply says
//! nothing about the service behind it — only that the probe got through, i.e.
//! the port is `unfiltered`. Silence means a filtering device swallowed the
//! probe (`filtered`). It maps the firewall, not the services.
//!
//! FIN/NULL/XMAS probes carry no SYN at all: per RFC 793 a closed port answers
//! any unexpected segment with an RST while an open port drops it silently, so
//! an RST means `closed` and silence means `open|filtered`. They are the most
//! stealthy of the family — a NULL probe (no flags set) is invisible to many
//! stateful filters that key on SYN.
//!
//! Both share one packet path: [`ProbeMode`] picks the flag profile that goes
//! out and the rules that read the reply, so another mode is another profile
//! rather than a second scanner.
//!
//! This module is split so the risky, privilege-bound network I/O is separate
//! from the pure, exhaustively-tested packet machinery:
//!
//! * [`build_ipv4_probe`] / [`build_tcp_probe`] assemble the bytes on the wire,
//! * [`parse_ipv4_tcp`], [`classify_flags`] and [`classify_reply`] interpret a
//!   reply,
//! * [`raw_socket_available`] reports whether a raw socket can be opened, so the
//!   caller can fall back to a connect scan with a clear message when it cannot.
//!
//! The probe is *sent* over a raw socket, but replies are *received* with
//! libpcap/BPF via a single shared [`SynReceiver`] rather than `recv()` on the
//! raw socket. That receive path matters: on macOS/BSD the kernel never hands
//! inbound TCP to a raw socket, so a `recv()`-based reader reads nothing and
//! every port looks filtered. A pcap capture works uniformly on Linux and macOS
//! (this is what nmap does too). See issues #38 / #39.
//!
//! IPv4 only: raw-packet probing of IPv6 targets is not implemented and callers
//! fall back.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// TCP control-flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// Length of a TCP header with no options.
const TCP_HEADER_LEN: usize = 20;
/// Length of an IPv4 header with no options.
const IPV4_HEADER_LEN: usize = 20;
/// IANA protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// How a raw probe's reply is interpreted. Which variants a scan can produce
/// depends on its [`ProbeMode`]: a SYN probe decides open/closed/filtered, an
/// ACK probe decides unfiltered/filtered and never claims open or closed, and
/// the FIN/NULL/XMAS probes decide closed/open|filtered — silence there is not
/// `open`, it is the honest `open|filtered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// SYN/ACK — the port is open. SYN mode only.
    Open,
    /// RST to a SYN or FIN/NULL/XMAS probe — the port is closed.
    Closed,
    /// RST to an ACK — the probe reached the port, so nothing filtered it. It
    /// says nothing about open/closed. ACK mode only.
    Unfiltered,
    /// An ICMP destination-unreachable answered the probe: a filter or host
    /// actively rejected it. Treated as `filtered` by every mode.
    Unreachable,
    /// Anything else (or no reply) — filtered/indeterminate.
    Filtered,
}

/// The former name of [`ProbeOutcome`], kept so existing callers keep building.
pub type SynOutcome = ProbeOutcome;

/// Which flag profile a raw probe carries, and hence how its reply is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// A lone SYN: SYN/ACK means open, RST means closed, silence is filtered.
    Syn,
    /// A lone ACK: an RST proves the probe reached the port (`unfiltered`),
    /// silence means something dropped it (`filtered`). It cannot tell open
    /// from closed — both answer a stray ACK with an RST.
    Ack,
    /// FIN only: per RFC 793 a closed port answers with an RST, an open one
    /// drops the unexpected segment silently (`open|filtered`).
    Fin,
    /// No flags set at all (a "NULL" probe): same reply rules as [`ProbeMode::Fin`].
    Null,
    /// FIN + PSH + URG ("XMAS"): same reply rules as [`ProbeMode::Fin`].
    Xmas,
}

impl ProbeMode {
    /// The TCP control flags a probe in this mode sets.
    pub fn flags(self) -> u8 {
        match self {
            ProbeMode::Syn => TCP_SYN,
            ProbeMode::Ack => TCP_ACK,
            ProbeMode::Fin => TCP_FIN,
            ProbeMode::Null => 0,
            ProbeMode::Xmas => TCP_FIN | TCP_PSH | TCP_URG,
        }
    }

    /// Stable name for this mode in structured output and messages.
    pub fn label(self) -> &'static str {
        match self {
            ProbeMode::Syn => "syn",
            ProbeMode::Ack => "ack",
            ProbeMode::Fin => "fin",
            ProbeMode::Null => "null",
            ProbeMode::Xmas => "xmas",
        }
    }

    /// Whether this mode's silence is the honest `open|filtered` (FIN/NULL/XMAS)
    /// rather than a plain `filtered` verdict.
    pub fn silent_means_open_filtered(self) -> bool {
        matches!(self, ProbeMode::Fin | ProbeMode::Null | ProbeMode::Xmas)
    }
}

/// Classify the reply to a SYN probe from its flag byte: RST is closed, SYN+ACK
/// is open, everything else is filtered.
pub fn classify_flags(flags: u8) -> ProbeOutcome {
    if flags & TCP_RST != 0 {
        ProbeOutcome::Closed
    } else if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
        ProbeOutcome::Open
    } else {
        ProbeOutcome::Filtered
    }
}

/// Classify a reply's flag byte the way `mode` requires.
///
/// The same RST means different things per mode: to a SYN it says the port is
/// closed, to an ACK it says only that the probe was not filtered on the way in,
/// and to FIN/NULL/XMAS it again says closed — while silence there (the
/// [`ProbeOutcome::Filtered`] returned by the receiver when nothing arrives) is
/// reported as `open|filtered`, never merged into a plain `open`.
pub fn classify_reply(mode: ProbeMode, flags: u8) -> ProbeOutcome {
    match mode {
        ProbeMode::Syn => classify_flags(flags),
        ProbeMode::Ack | ProbeMode::Fin | ProbeMode::Null | ProbeMode::Xmas => {
            if flags & TCP_RST != 0 {
                // An RST to an ACK proves the probe was not filtered; an RST to a
                // FIN/NULL/XMAS probe is RFC 793's "closed" answer.
                if mode == ProbeMode::Ack {
                    ProbeOutcome::Unfiltered
                } else {
                    ProbeOutcome::Closed
                }
            } else {
                ProbeOutcome::Filtered
            }
        }
    }
}

/// Whether a captured segment can answer a probe at all: only an RST or a
/// SYN+ACK does. Anything else (a bare SYN from unrelated traffic, our own
/// outbound packets) is noise the receiver must not record.
fn is_probe_reply(flags: u8) -> bool {
    flags & TCP_RST != 0 || (flags & TCP_SYN != 0 && flags & TCP_ACK != 0)
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

/// Build a bare TCP segment (20 bytes, no options) carrying `flags`, with its
/// checksum filled in over the IPv4 pseudo-header.
///
/// The flag byte is what separates one raw scan mode from another — a lone SYN
/// for a stealth scan, a lone ACK for a firewall-state scan — so every mode goes
/// through this one builder.
pub fn build_tcp_probe(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut seg = vec![0u8; TCP_HEADER_LEN];
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = 0x50; // data offset = 5 (20 bytes) in the high nibble.
    seg[13] = flags;
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

/// Build a bare TCP SYN segment — [`build_tcp_probe`] with the SYN profile and
/// no acknowledgement number.
pub fn build_tcp_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    build_tcp_probe(src, dst, src_port, dst_port, seq, 0, TCP_SYN)
}

/// Build a complete IPv4 packet carrying a TCP segment with `flags`, including a
/// valid IPv4 header checksum.
pub fn build_ipv4_probe(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    build_ipv4_probe_with_ttl(src, dst, src_port, dst_port, seq, ack, flags, 64)
}

/// [`build_ipv4_probe`] with an explicit TTL, used by traceroute.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_probe_with_ttl(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ttl: u8,
) -> Vec<u8> {
    let tcp = build_tcp_probe(src, dst, src_port, dst_port, seq, ack, flags);
    build_ipv4_packet(src, dst, IPPROTO_TCP, &tcp, ttl)
}

/// Wrap `payload` in an IPv4 header for `protocol` with a valid header checksum
/// and the given TTL. Shared by the raw TCP and ICMP probe builders.
pub(crate) fn build_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let total_len = (IPV4_HEADER_LEN + payload.len()) as u16;

    let mut ip = vec![0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
    // DSCP/ECN (1) stays 0.
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    // identification (4..6) stays 0.
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip[8] = ttl;
    ip[9] = protocol;
    // header checksum (10..12) left zero for the computation.
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());

    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());

    ip.extend_from_slice(payload);
    ip
}

/// Build a complete IPv4 packet carrying a TCP SYN — [`build_ipv4_probe`] with
/// the SYN profile.
pub fn build_ipv4_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    build_ipv4_probe(src, dst, src_port, dst_port, seq, 0, TCP_SYN)
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
///
/// The socket is opened through the interface-binding helper, so with
/// `--interface` the source address (and hence the pcap capture device chosen
/// from it) follows the requested link rather than the default route.
pub(crate) fn local_ipv4_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = crate::iface::udp_connect(SocketAddr::new(dst.into(), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Base for the ephemeral source port a probe forges: the source port is
/// `SRC_PORT_BASE + dst_port`, giving each concurrent probe a distinct one.
/// Replies are correlated by their own `(source ip, source port)`, not by this
/// value, since NAT/VPN may rewrite the source port before the packet leaves.
const SRC_PORT_BASE: u16 = 40000;

/// The source port a probe to `dst_port` forges when no fixed source port is
/// requested: `SRC_PORT_BASE + dst_port`, giving each concurrent probe a
/// distinct one. With a fixed source port, every probe carries that port and
/// replies are correlated by the reply's destination port instead (see
/// [`SynReceiver::wait_for`]).
fn src_port_for(dst_port: u16) -> u16 {
    SRC_PORT_BASE.wrapping_add(dst_port)
}

/// The process-wide fixed source port for raw probes, set via
/// [`set_source_port`] when the operator requests one (e.g. `--source-port 53`
/// to test firewall rules keyed on source port). When unset, each probe forges
/// a distinct ephemeral source port per scanned port.
static SOURCE_PORT: OnceLock<u16> = OnceLock::new();

/// Set the fixed source port every raw probe carries. Idempotent: a second call
/// is ignored (the first value wins), so it can be called from any thread before
/// scanning starts. Returns `true` if this call set the port, `false` if one was
/// already installed.
pub fn set_source_port(port: u16) -> bool {
    SOURCE_PORT.set(port).is_ok()
}

/// The fixed source port for raw probes, if one was requested; otherwise each
/// probe uses its own ephemeral per-port value from [`src_port_for`].
fn source_port(dst_port: u16) -> u16 {
    SOURCE_PORT
        .get()
        .copied()
        .unwrap_or_else(|| src_port_for(dst_port))
}

/// Whether a fixed source port is in effect for raw probes. When true, replies
/// must be correlated by the reply's destination port (the scanned port), since
/// every probe carries the same source port and NAT/VPN may rewrite it.
pub fn has_fixed_source_port() -> bool {
    SOURCE_PORT.get().is_some()
}

/// Sequence number every forged probe carries. Fixed rather than random: no
/// connection is ever established, and replies are correlated by address and
/// port, so the value only has to look like a real one.
const PROBE_SEQ: u32 = 0x1234_5678;

/// Acknowledgement number an ACK probe carries.
const PROBE_ACK: u32 = 0x2f1a_0b3c;

/// Perform a single SYN probe against `dst:dst_port` — [`probe_port`] in
/// [`ProbeMode::Syn`].
pub fn syn_scan_port(dst: Ipv4Addr, dst_port: u16, timeout: Duration) -> Option<ProbeOutcome> {
    probe_port(ProbeMode::Syn, dst, dst_port, timeout)
}

/// Perform a single raw probe against `dst:dst_port` in `mode`: forge and send
/// the segment over a raw socket, then wait for the shared [`SynReceiver`] to
/// observe the reply and read it by that mode's rules.
///
/// In [`ProbeMode::Syn`] a SYN/ACK is [`ProbeOutcome::Open`], an RST is
/// [`ProbeOutcome::Closed`]. In [`ProbeMode::Ack`] an RST is
/// [`ProbeOutcome::Unfiltered`]. In FIN/NULL/XMAS an RST is
/// [`ProbeOutcome::Closed`] and the caller reports silence as `open|filtered`.
/// In every mode no reply within `timeout` is [`ProbeOutcome::Filtered`].
///
/// Returns `None` when the raw scan cannot run — the receiver was never
/// installed (no [`init_receiver`], or it failed), a raw socket cannot be
/// opened, or the send errored — signaling the caller to fall back to a
/// connect probe. Replies are read by the receiver's pcap capture, never by a
/// `recv()` here, so this works on macOS as well as Linux.
pub fn probe_port(
    mode: ProbeMode,
    dst: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
) -> Option<ProbeOutcome> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Without a running capture there is nothing to read replies, so let the
    // caller fall back rather than send probes into a void.
    let receiver = receiver()?;

    // Respect the rate cap and this host's own --delay (no-op when unset).
    crate::rate::gate_for(IpAddr::V4(dst));

    let dbg = debug_enabled();
    let src = local_ipv4_for(dst)?;
    let src_port = source_port(dst_port);

    // Send a full IPv4 packet with the header included. macOS refuses to send
    // TCP through a bare IPPROTO_TCP raw socket (EPROTOTYPE), so we build the IP
    // header ourselves over an IPPROTO_RAW socket, which implies IP_HDRINCL.
    #[allow(unused_mut)]
    let mut packet = build_ipv4_probe(
        src,
        dst,
        src_port,
        dst_port,
        PROBE_SEQ,
        // A stray ACK draws an RST whatever it acknowledges, but a plausible
        // non-zero value looks less synthetic on the wire than a bare zero.
        if mode == ProbeMode::Ack { PROBE_ACK } else { 0 },
        mode.flags(),
    );
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
                let label = mode.label();
                eprintln!("[syn] sent {n}B {label} probe {src}:{src_port} -> {dst}:{dst_port}");
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
    let outcome = receiver.wait_for(dst, dst_port, timeout, mode);
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

/// A recorded answer: TCP flag bytes, or an ICMP unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    Flags(u8),
    Unreachable,
}

/// State shared between the probe threads and the background pcap reader.
struct ReceiverShared {
    /// Reply flag bytes keyed by `(target_ip, target_port)` — i.e. the source
    /// address of the reply. The raw flags are stored rather than a verdict,
    /// because what an RST means depends on the [`ProbeMode`] that asked; only
    /// segments that can answer a probe at all are kept (see [`is_probe_reply`]).
    replies: Mutex<HashMap<(Ipv4Addr, u16), Reply>>,
    /// Woken whenever a new reply is recorded, so waiters re-check the map.
    signal: Condvar,
    /// Set on drop to stop the reader loop.
    stop: AtomicBool,
}

/// A single libpcap capture that reads every raw-probe reply for the whole
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
            replies: Mutex::new(HashMap::new()),
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
    /// elapses, then read it by `mode`'s rules. A missing reply is
    /// [`ProbeOutcome::Filtered`] in every mode.
    ///
    /// With a fixed source port (see [`has_fixed_source_port`]), replies are
    /// keyed by the reply's *destination* port — which is the scanned port, since
    /// the target answers to whatever destination our probe carried. Without one,
    /// replies are keyed by their own source port as before. Both keyings use the
    /// same `(target_ip, port)` shape, so the map and waiter need no other change.
    fn wait_for(
        &self,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
        mode: ProbeMode,
    ) -> ProbeOutcome {
        let key = (target, port);
        let deadline = Instant::now() + timeout;
        let mut map = self
            .shared
            .replies
            .lock()
            .expect("syn receiver mutex poisoned");
        loop {
            if let Some(&reply) = map.get(&key) {
                return outcome_for(mode, reply);
            }
            let now = Instant::now();
            if now >= deadline {
                return ProbeOutcome::Filtered;
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

/// Open a pcap capture on the interface bearing `src`, filtered to the segments
/// that can answer a probe (SYN/ACK and RST), and report the datalink header
/// length to strip.
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
    // Keep only TCP segments whose SYN or RST flag is set: a SYN/ACK and an RST
    // are the only replies that answer a probe, in any mode. Our own outbound
    // ACK probes carry neither bit and never come back through this filter.
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
pub(crate) fn device_for(src: Ipv4Addr) -> Option<pcap::Device> {
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
pub(crate) fn datalink_offset(link: pcap::Linktype) -> usize {
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

/// Turn a recorded reply into the verdict for `mode`: an ICMP unreachable is
/// `filtered` for every probe mode.
fn outcome_for(mode: ProbeMode, reply: Reply) -> ProbeOutcome {
    match reply {
        Reply::Flags(flags) => classify_reply(mode, flags),
        Reply::Unreachable => ProbeOutcome::Unreachable,
    }
}

/// Extract the original `(target_ip, target_port)` from an ICMP
/// destination-unreachable that quotes our TCP probe.
fn extract_icmp_unreachable(frame: &[u8], hint: usize) -> Option<(Ipv4Addr, u16)> {
    for offset in [hint, 0, 14, 4, 16] {
        if frame.len() <= offset || frame[offset] >> 4 != 4 {
            continue;
        }
        let packet = &frame[offset..];
        if packet.len() < 20 {
            continue;
        }
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < 20 || packet.len() < ihl + 8 || packet[9] != 1 {
            continue;
        }
        let icmp = &packet[ihl..];
        if icmp[0] != 3 || icmp.len() < 8 + 20 + 8 {
            continue;
        }
        let quoted = &icmp[8..];
        if quoted[0] >> 4 != 4 {
            continue;
        }
        let inner_ihl = (quoted[0] & 0x0f) as usize * 4;
        if inner_ihl < 20 || quoted.len() < inner_ihl + 8 || quoted[9] != 6 {
            continue;
        }
        // ICMP errors commonly quote only the IP header plus 8 bytes of the
        // original TCP segment; the destination port lives in the first four.
        let tcp = &quoted[inner_ihl..];
        if tcp.len() < 4 {
            continue;
        }
        let target = Ipv4Addr::new(quoted[16], quoted[17], quoted[18], quoted[19]);
        let port = u16::from_be_bytes([tcp[2], tcp[3]]);
        return Some((target, port));
    }
    None
}

/// Read captured replies until stopped, recording each definitive outcome.
fn reader_loop(mut cap: pcap::Capture<pcap::Active>, offset: usize, shared: &ReceiverShared) {
    let dbg = debug_enabled();
    while !shared.stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some((src_ip, src_port, dst_port, flags)) =
                    extract_ipv4_tcp(packet.data, offset)
                {
                    if dbg {
                        eprintln!(
                            "[syn] pkt src={src_ip} sport={src_port} dport={dst_port} flags={flags:#04x}"
                        );
                    }
                    // A SYN/ACK or RST identifies the port it came from.
                    // Without a fixed source port, key the reply on its
                    // (source ip, source port), i.e. the scanned target and
                    // port — we deliberately do not match on the source port we
                    // forged, since NAT/VPN can rewrite it in flight. With a
                    // fixed source port every probe carries the same source
                    // port, so replies are keyed by their destination port
                    // instead (the scanned port, which is what our probe
                    // carried as its destination). Our own outbound probes have
                    // our source ip, a key no probe waits on, so they are
                    // harmless; anything that cannot answer a probe is dropped
                    // here, and the waiter turns the stored flags into a verdict
                    // for its mode.
                    if !is_probe_reply(flags) {
                        continue;
                    }
                    let mut map = shared.replies.lock().expect("syn receiver mutex poisoned");
                    let key = if has_fixed_source_port() {
                        (src_ip, dst_port)
                    } else {
                        (src_ip, src_port)
                    };
                    map.entry(key).or_insert(Reply::Flags(flags));
                    shared.signal.notify_all();
                } else if let Some((target, port)) = extract_icmp_unreachable(packet.data, offset) {
                    if dbg {
                        eprintln!("[syn] icmp unreachable for {target}:{port}");
                    }
                    let mut map = shared.replies.lock().expect("syn receiver mutex poisoned");
                    map.entry((target, port)).or_insert(Reply::Unreachable);
                    shared.signal.notify_all();
                } else if dbg {
                    let n = packet.data.len().min(20);
                    eprintln!(
                        "[syn] unparsed frame len={} head={:02x?}",
                        packet.data.len(),
                        &packet.data[..n]
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a TCP segment's checksum verifies over its pseudo-header.
    fn tcp_checksum_verifies(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> bool {
        let mut pseudo = Vec::with_capacity(12 + seg.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(IPPROTO_TCP);
        pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(seg);
        checksum(&pseudo) == 0
    }

    #[test]
    fn classify_covers_open_closed_filtered() {
        assert_eq!(classify_flags(TCP_SYN | TCP_ACK), ProbeOutcome::Open);
        assert_eq!(classify_flags(TCP_RST | TCP_ACK), ProbeOutcome::Closed);
        assert_eq!(classify_flags(TCP_RST), ProbeOutcome::Closed);
        assert_eq!(classify_flags(TCP_ACK), ProbeOutcome::Filtered);
        assert_eq!(classify_flags(0), ProbeOutcome::Filtered);
    }

    #[test]
    fn probe_modes_carry_their_own_flag_profile() {
        assert_eq!(ProbeMode::Syn.flags(), TCP_SYN);
        assert_eq!(ProbeMode::Ack.flags(), TCP_ACK);
        assert_eq!(ProbeMode::Fin.flags(), TCP_FIN);
        // A NULL probe sets no flags at all — that is the point of it.
        assert_eq!(ProbeMode::Null.flags(), 0);
        assert_eq!(ProbeMode::Xmas.flags(), TCP_FIN | TCP_PSH | TCP_URG);
    }

    #[test]
    fn every_mode_has_a_stable_label() {
        assert_eq!(ProbeMode::Syn.label(), "syn");
        assert_eq!(ProbeMode::Ack.label(), "ack");
        assert_eq!(ProbeMode::Fin.label(), "fin");
        assert_eq!(ProbeMode::Null.label(), "null");
        assert_eq!(ProbeMode::Xmas.label(), "xmas");
    }

    #[test]
    fn fin_null_and_xmas_probes_reach_the_wire_with_their_flags() {
        let src: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let dst: Ipv4Addr = "192.168.1.20".parse().unwrap();

        for mode in [ProbeMode::Fin, ProbeMode::Null, ProbeMode::Xmas] {
            let seg = build_tcp_probe(src, dst, 50000, 443, 0xdead_beef, 0, mode.flags());
            assert_eq!(seg.len(), TCP_HEADER_LEN);
            assert_eq!(seg[13], mode.flags(), "{mode:?} must carry its own profile");
            // None of the family may ever set SYN — that is what makes them
            // stealthier than a half-open scan.
            assert_eq!(seg[13] & TCP_SYN, 0, "{mode:?} must not carry a SYN");
            assert!(tcp_checksum_verifies(src, dst, &seg), "{mode:?} checksum");

            let ip = build_ipv4_probe(src, dst, 50000, 443, 0xdead_beef, 0, mode.flags());
            assert_eq!(checksum(&ip[..IPV4_HEADER_LEN]), 0, "{mode:?} ip header");
            let (_, _, flags) = parse_ipv4_tcp(&ip).expect("should parse");
            assert_eq!(flags, mode.flags(), "{mode:?} round-trips its profile");
        }

        // XMAS is the only one of the three that sets more than a single bit.
        assert_eq!(ProbeMode::Fin.flags().count_ones(), 1);
        assert_eq!(ProbeMode::Null.flags().count_ones(), 0);
        assert_eq!(ProbeMode::Xmas.flags().count_ones(), 3);
    }

    #[test]
    fn an_ack_probe_sets_only_ack_and_checksums_correctly() {
        let src: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let dst: Ipv4Addr = "192.168.1.20".parse().unwrap();
        let seg = build_tcp_probe(src, dst, 50000, 443, 0xdead_beef, 0x0bad_f00d, TCP_ACK);

        assert_eq!(seg.len(), TCP_HEADER_LEN);
        assert_eq!(seg[13], TCP_ACK, "an ACK probe carries the ACK flag alone");
        assert_eq!(seg[13] & TCP_SYN, 0, "and never a SYN");
        assert_eq!(seg[12] >> 4, 5, "data offset should be 5 words");
        assert_eq!(
            u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]),
            0x0bad_f00d,
            "the acknowledgement number must reach the wire"
        );
        assert!(tcp_checksum_verifies(src, dst, &seg));
    }

    #[test]
    fn an_ipv4_ack_packet_is_wellformed() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let ip = build_ipv4_probe(src, dst, 40080, 80, PROBE_SEQ, PROBE_ACK, TCP_ACK);

        assert_eq!(ip.len(), IPV4_HEADER_LEN + TCP_HEADER_LEN);
        assert_eq!(ip[9], IPPROTO_TCP);
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]) as usize,
            IPV4_HEADER_LEN + TCP_HEADER_LEN
        );
        // The stored header checksum makes the header sum to zero.
        assert_eq!(checksum(&ip[..IPV4_HEADER_LEN]), 0);
        assert!(tcp_checksum_verifies(src, dst, &ip[IPV4_HEADER_LEN..]));

        let (src_port, dst_port, flags) = parse_ipv4_tcp(&ip).expect("should parse");
        assert_eq!((src_port, dst_port, flags), (40080, 80, TCP_ACK));
    }

    #[test]
    fn the_syn_builders_still_produce_a_bare_syn() {
        // The generalized builder must not have changed what --syn sends.
        let src: Ipv4Addr = "10.1.1.1".parse().unwrap();
        let dst: Ipv4Addr = "10.1.1.2".parse().unwrap();
        assert_eq!(
            build_tcp_syn(src, dst, 40022, 22, 7),
            build_tcp_probe(src, dst, 40022, 22, 7, 0, TCP_SYN)
        );
        assert_eq!(
            build_ipv4_syn(src, dst, 40022, 22, 7),
            build_ipv4_probe(src, dst, 40022, 22, 7, 0, TCP_SYN)
        );
    }

    #[test]
    fn an_rst_means_closed_to_a_syn_but_unfiltered_to_an_ack() {
        // The same reply, read by two different questions.
        assert_eq!(
            classify_reply(ProbeMode::Syn, TCP_RST | TCP_ACK),
            ProbeOutcome::Closed
        );
        assert_eq!(
            classify_reply(ProbeMode::Ack, TCP_RST | TCP_ACK),
            ProbeOutcome::Unfiltered
        );
        assert_eq!(
            classify_reply(ProbeMode::Ack, TCP_RST),
            ProbeOutcome::Unfiltered
        );
    }

    #[test]
    fn silence_and_non_rst_replies_are_filtered_for_an_ack_probe() {
        // Nothing but an RST answers an ACK probe; a stray SYN/ACK does not.
        assert_eq!(
            classify_reply(ProbeMode::Ack, TCP_SYN | TCP_ACK),
            ProbeOutcome::Filtered
        );
        assert_eq!(classify_reply(ProbeMode::Ack, 0), ProbeOutcome::Filtered);
    }

    #[test]
    fn an_ack_scan_never_claims_open_or_closed() {
        // Whatever comes back, an ACK probe only ever reports firewall state:
        // it cannot tell a listening port from a closed one.
        for flags in 0u8..=u8::MAX {
            let outcome = classify_reply(ProbeMode::Ack, flags);
            assert!(
                matches!(outcome, ProbeOutcome::Unfiltered | ProbeOutcome::Filtered),
                "flags {flags:#04x} produced {outcome:?}"
            );
        }
    }

    #[test]
    fn syn_classification_is_unchanged_by_the_mode_split() {
        for flags in 0u8..=u8::MAX {
            assert_eq!(classify_reply(ProbeMode::Syn, flags), classify_flags(flags));
        }
    }

    #[test]
    fn an_rst_means_closed_to_fin_null_and_xmas_probes() {
        // RFC 793: a closed port answers any unexpected segment with an RST.
        for mode in [ProbeMode::Fin, ProbeMode::Null, ProbeMode::Xmas] {
            assert_eq!(classify_reply(mode, TCP_RST), ProbeOutcome::Closed);
            assert_eq!(
                classify_reply(mode, TCP_RST | TCP_ACK),
                ProbeOutcome::Closed
            );
        }
    }

    #[test]
    fn fin_null_and_xmas_never_claim_open_or_unfiltered() {
        // Whatever comes back, these probes only ever report closed or
        // filtered (silence, reported as open|filtered by the caller) — they
        // cannot tell a listening port from one that drops the probe.
        for mode in [ProbeMode::Fin, ProbeMode::Null, ProbeMode::Xmas] {
            for flags in 0u8..=u8::MAX {
                let outcome = classify_reply(mode, flags);
                assert!(
                    matches!(outcome, ProbeOutcome::Closed | ProbeOutcome::Filtered),
                    "{mode:?} with flags {flags:#04x} produced {outcome:?}"
                );
            }
        }
    }

    #[test]
    fn fin_null_and_xmas_share_the_silent_means_open_filtered_rule() {
        for mode in [ProbeMode::Fin, ProbeMode::Null, ProbeMode::Xmas] {
            assert!(mode.silent_means_open_filtered());
        }
        assert!(!ProbeMode::Syn.silent_means_open_filtered());
        assert!(!ProbeMode::Ack.silent_means_open_filtered());
    }

    #[test]
    fn only_an_rst_or_syn_ack_counts_as_a_reply() {
        assert!(is_probe_reply(TCP_RST));
        assert!(is_probe_reply(TCP_RST | TCP_ACK));
        assert!(is_probe_reply(TCP_SYN | TCP_ACK));
        // A bare SYN is someone else's traffic, not an answer to a probe.
        assert!(!is_probe_reply(TCP_SYN));
        assert!(!is_probe_reply(0));
        // Our own outbound ACK probes can never be mistaken for replies, which
        // matters most on loopback, where the capture sees both directions.
        assert!(!is_probe_reply(ProbeMode::Ack.flags()));
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
    fn explicit_ttl_reaches_the_ip_header() {
        let ip = build_ipv4_probe_with_ttl(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            40000,
            80,
            1,
            0,
            TCP_SYN,
            7,
        );
        assert_eq!(ip[8], 7);
        assert_eq!(checksum(&ip[..IPV4_HEADER_LEN]), 0);
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
    fn extracts_target_and_port_from_an_icmp_unreachable() {
        let target: Ipv4Addr = "192.0.2.10".parse().unwrap();
        let us: Ipv4Addr = "192.0.2.2".parse().unwrap();
        let inner = build_ipv4_probe_with_ttl(us, target, 40000, 443, 1, 0, TCP_SYN, 64);
        let mut icmp = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&inner);
        let outer = build_ipv4_packet("192.0.2.254".parse().unwrap(), us, 1, &icmp, 64);
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&outer);

        assert_eq!(extract_icmp_unreachable(&frame, 14), Some((target, 443)));
    }

    #[test]
    fn an_icmp_unreachable_is_filtered_for_every_mode() {
        for mode in [
            ProbeMode::Syn,
            ProbeMode::Ack,
            ProbeMode::Fin,
            ProbeMode::Null,
            ProbeMode::Xmas,
        ] {
            assert_eq!(
                outcome_for(mode, Reply::Unreachable),
                ProbeOutcome::Unreachable
            );
        }
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
    fn a_fixed_source_port_is_carried_by_every_probe() {
        // With --source-port 53 every probe carries port 53 as its source, so
        // firewall rules keyed on source port can be tested. The builder takes
        // the port as a parameter; this pins that the value reaches the wire.
        let src: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let dst: Ipv4Addr = "192.168.1.20".parse().unwrap();

        for dst_port in [22u16, 80, 443] {
            let seg = build_tcp_probe(src, dst, 53, dst_port, 0xdead_beef, 0, TCP_SYN);
            assert_eq!(
                u16::from_be_bytes([seg[0], seg[1]]),
                53,
                "the fixed source port must reach the wire"
            );
            let ip = build_ipv4_probe(src, dst, 53, dst_port, 0xdead_beef, 0, TCP_SYN);
            let (src_port, dport, _) = parse_ipv4_tcp(&ip).expect("should parse");
            assert_eq!(src_port, 53, "round-trips the fixed source port");
            assert_eq!(dport, dst_port, "and keeps the scanned destination port");
        }
    }

    #[test]
    fn replies_are_keyed_by_destination_port_with_a_fixed_source() {
        // With a fixed source port every probe carries the same source port, so
        // replies must be attributed by their destination port (the scanned
        // port) rather than their own source. This pins the keying rule that
        // reader_loop applies when has_fixed_source_port() is true: a reply from
        // target:80 to us:53 belongs to the probe of port 80, not port 53.
        let target: Ipv4Addr = "198.51.100.20".parse().unwrap();
        let our_ip: Ipv4Addr = "203.0.113.5".parse().unwrap();

        // Reply built as the target would send it with a fixed source port 53:
        // src = target:80 (the scanned port), dst = us:53 (our fixed source).
        let reply = build_ipv4_probe(target, our_ip, 80, 53, 1, 0, TCP_SYN | TCP_ACK);
        let (src_ip, _dst_ip, src_port, dst_port, flags) =
            parse_ipv4_tcp_addrs(&reply).expect("parse reply");

        assert_eq!(src_ip, target);
        assert_eq!(src_port, 80, "the reply's source port is the scanned port");
        assert_eq!(dst_port, 53, "and its destination is our fixed source port");
        assert!(is_probe_reply(flags));

        // The keying rule: with a fixed source port the waiter looks up
        // (target_ip, scanned_port), which is exactly (src_ip, src_port) here —
        // so the reply lands in the right slot even though every probe carried
        // the same source port.
        let key = (src_ip, dst_port); // what reader_loop stores with a fixed source
        assert_eq!(
            key,
            (target, 53),
            "the stored key uses the reply's destination"
        );
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

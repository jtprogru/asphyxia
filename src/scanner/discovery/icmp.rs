//! ICMP echo host discovery (an IPv4 ping sweep).
//!
//! The default TCP-based discovery misses hosts that silently drop the probed
//! ports, and ARP only works on the local L2 segment. ICMP echo reaches any
//! routed IPv4 host that answers pings, so `--discovery icmp` fills the gap for
//! networks where ICMP is permitted.
//!
//! One raw ICMP socket is shared by the whole scan: probes submit an echo
//! request through a channel, the reader thread sends it and records replies and
//! destination-unreachable messages keyed by the ICMP sequence number. Sequence
//! numbers are unique per probe; the identifier is not used for matching because
//! some kernels rewrite it for raw sockets.
//!
//! IPv4 only. IPv6 targets and a missing raw socket fall back to the TCP probe
//! with a visible warning. A destination-unreachable is a fact that the host is
//! not reachable; silence after the retry budget is a separate `no-response`
//! outcome, not the same guess.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// ICMP type: echo request.
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type: echo reply.
const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP type: destination unreachable.
const ICMP_DEST_UNREACHABLE: u8 = 3;
/// IANA protocol number for ICMP.
const IPPROTO_ICMP: u8 = 1;
/// Length of an IPv4 header with no options.
const IPV4_HEADER_LEN: usize = 20;
/// Length of an ICMP header (type, code, checksum, id, sequence).
const ICMP_HEADER_LEN: usize = 8;
/// Payload carried by each echo request. Any non-empty payload is enough to
/// make the request look like a normal ping.
const ECHO_PAYLOAD: &[u8] = b"asphyxia";
/// How long a raw-socket read blocks before the reader re-checks its send queue
/// and stop flag.
const READ_TIMEOUT: Duration = Duration::from_millis(10);

/// The result of probing one IPv4 address with ICMP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpProbe {
    /// An echo reply came back; carries the round-trip time.
    Up(Duration),
    /// An ICMP destination-unreachable came back: the host is not reachable.
    Unreachable,
    /// No reply and no unreachable after the retry budget.
    NoResponse,
    /// The raw socket or its receiver is unavailable.
    Unavailable,
}

/// One's-complement 16-bit checksum (RFC 1071) over `data`.
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

/// Build an ICMP echo request with `id`/`seq` and a valid checksum.
pub fn build_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![0u8; ICMP_HEADER_LEN];
    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0; // code
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(ECHO_PAYLOAD);
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// A reply the receiver understands: an echo reply or an unreachable, both
/// identified by the original probe's sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    Echo(u16),
    Unreachable(u16),
}

/// Parse an ICMP message (starting at the ICMP header, no IP header).
fn parse_icmp_message(message: &[u8]) -> Option<Reply> {
    if message.len() < ICMP_HEADER_LEN {
        return None;
    }
    match message[0] {
        ICMP_ECHO_REPLY => Some(Reply::Echo(u16::from_be_bytes([message[6], message[7]]))),
        ICMP_DEST_UNREACHABLE => {
            // The quoted original datagram follows the 8-byte ICMP header.
            let quoted = &message[ICMP_HEADER_LEN..];
            if quoted.len() < IPV4_HEADER_LEN + ICMP_HEADER_LEN {
                return None;
            }
            if quoted[0] >> 4 != 4 {
                return None;
            }
            let ihl = (quoted[0] & 0x0f) as usize * 4;
            if ihl < IPV4_HEADER_LEN || quoted.len() < ihl + ICMP_HEADER_LEN {
                return None;
            }
            if quoted[9] != IPPROTO_ICMP {
                return None;
            }
            let original = &quoted[ihl..];
            if original[0] != ICMP_ECHO_REQUEST {
                return None;
            }
            Some(Reply::Unreachable(u16::from_be_bytes([
                original[6],
                original[7],
            ])))
        }
        _ => None,
    }
}

/// Parse a packet that may carry an IPv4 header before the ICMP message, as a
/// raw IPv4 socket normally returns. If the first byte is not an IPv4 header,
/// the buffer is treated as a bare ICMP message (some platforms deliver it that
/// way).
fn parse_packet(packet: &[u8]) -> Option<Reply> {
    if packet.len() >= IPV4_HEADER_LEN && packet[0] >> 4 == 4 {
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < IPV4_HEADER_LEN || packet.len() < ihl + ICMP_HEADER_LEN {
            return None;
        }
        if packet[9] != IPPROTO_ICMP {
            return None;
        }
        parse_icmp_message(&packet[ihl..])
    } else {
        parse_icmp_message(packet)
    }
}

/// A recorded outcome for a sequence number.
#[derive(Debug, Clone, Copy)]
enum ReplyState {
    Up(Instant),
    Unreachable,
}

/// State shared between the probing threads and the raw-socket reader.
struct Shared {
    replies: Mutex<HashMap<u16, ReplyState>>,
    signal: Condvar,
    stop: AtomicBool,
}

/// The process-wide raw ICMP socket and its reader thread.
struct IcmpReceiver {
    shared: Arc<Shared>,
    sender: Option<Sender<(Ipv4Addr, Vec<u8>)>>,
    reader: Option<JoinHandle<()>>,
}

impl IcmpReceiver {
    /// Open a raw ICMP socket and spawn its reader. Returns `None` when the
    /// socket cannot be opened or pinned to the requested interface (no root /
    /// `CAP_NET_RAW`, or no `-e` binding support).
    fn start() -> Option<IcmpReceiver> {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(i32::from(IPPROTO_ICMP))),
        )
        .ok()?;
        crate::iface::bind_raw(&socket, true).ok()?;
        socket.set_read_timeout(Some(READ_TIMEOUT)).ok()?;

        let (sender, queue) = mpsc::channel::<(Ipv4Addr, Vec<u8>)>();
        let shared = Arc::new(Shared {
            replies: Mutex::new(HashMap::new()),
            signal: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let reader_shared = Arc::clone(&shared);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);
        let reader = thread::spawn(move || {
            let _ = ready_tx.send(true);
            reader_loop(socket, queue, &reader_shared);
        });

        match ready_rx.recv() {
            Ok(true) => Some(IcmpReceiver {
                shared,
                sender: Some(sender),
                reader: Some(reader),
            }),
            _ => {
                let _ = reader.join();
                None
            }
        }
    }

    /// Queue an echo request for `target`.
    fn submit(&self, target: Ipv4Addr, packet: Vec<u8>) -> bool {
        self.sender
            .as_ref()
            .is_some_and(|sender| sender.send((target, packet)).is_ok())
    }

    /// Drop a stale reply for `seq` before a fresh request goes out.
    fn clear(&self, seq: u16) {
        if let Ok(mut replies) = self.shared.replies.lock() {
            replies.remove(&seq);
        }
    }

    /// Block until `seq` gets a reply or `timeout` elapses.
    fn wait_for(&self, seq: u16, sent_at: Instant, timeout: Duration) -> Option<ReplyState> {
        let deadline = sent_at + timeout;
        let mut replies = self
            .shared
            .replies
            .lock()
            .expect("icmp receiver mutex poisoned");
        loop {
            if let Some(state) = replies.remove(&seq) {
                return Some(state);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .shared
                .signal
                .wait_timeout(replies, deadline - now)
                .expect("icmp receiver condvar poisoned");
            replies = guard;
        }
    }
}

impl Drop for IcmpReceiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.sender.take();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The shared receiver, opened at most once. `None` caches an unavailable raw
/// socket so a scan does not retry a failing open for every address.
fn receiver() -> Option<Arc<IcmpReceiver>> {
    static RECEIVER: OnceLock<Option<Arc<IcmpReceiver>>> = OnceLock::new();
    RECEIVER
        .get_or_init(|| IcmpReceiver::start().map(Arc::new))
        .clone()
}

/// Whether ICMP probing can run for `targets`: at least one IPv4 target and a
/// usable raw socket. This opens the receiver, so calling it before the scan
/// also makes the fallback visible once.
pub fn prepare(targets: &[IpAddr]) -> bool {
    if !targets.iter().any(|ip| ip.is_ipv4()) {
        return false;
    }
    receiver().is_some()
}

/// Probe one IPv4 target with ICMP echo, retrying only silence.
pub fn probe_with_retries(target: Ipv4Addr, timeout: Duration, retries: u32) -> IcmpProbe {
    let Some(receiver) = receiver() else {
        return IcmpProbe::Unavailable;
    };
    let id = std::process::id() as u16;
    for _ in 0..=retries {
        // Respect the rate cap and this host's own --delay.
        crate::rate::gate_for(IpAddr::V4(target));
        let seq = next_seq();
        receiver.clear(seq);
        let sent_at = Instant::now();
        if !receiver.submit(target, build_echo_request(id, seq)) {
            return IcmpProbe::Unavailable;
        }
        match receiver.wait_for(seq, sent_at, timeout) {
            Some(ReplyState::Up(received_at)) => {
                return IcmpProbe::Up(received_at.saturating_duration_since(sent_at));
            }
            Some(ReplyState::Unreachable) => return IcmpProbe::Unreachable,
            None => continue,
        }
    }
    IcmpProbe::NoResponse
}

/// Allocate the next sequence number. The identifier is not used for matching,
/// so a 16-bit counter is enough for one scan; wrapping after 65 535 probes is
/// harmless once the earlier probes have timed out.
fn next_seq() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Send queued requests and read replies until stopped.
fn reader_loop(
    socket: socket2::Socket,
    queue: mpsc::Receiver<(Ipv4Addr, Vec<u8>)>,
    shared: &Shared,
) {
    let debug = debug_enabled();
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    while !shared.stop.load(Ordering::Relaxed) {
        while let Ok((target, packet)) = queue.try_recv() {
            let destination = SocketAddr::new(IpAddr::V4(target), 0);
            if let Err(e) = socket.send_to(&packet, &destination.into())
                && debug
            {
                eprintln!("[icmp] send to {target} failed: {e}");
            }
        }

        match socket.recv_from(&mut buffer) {
            Ok((n, _from)) => {
                // SAFETY: recv_from initialized the first `n` bytes of `buffer`.
                let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
                let Some(reply) = parse_packet(data) else {
                    continue;
                };
                if debug {
                    eprintln!("[icmp] reply: {reply:?}");
                }
                let state = match reply {
                    Reply::Echo(_) => ReplyState::Up(Instant::now()),
                    Reply::Unreachable(_) => ReplyState::Unreachable,
                };
                let seq = match reply {
                    Reply::Echo(seq) | Reply::Unreachable(seq) => seq,
                };
                let mut replies = shared.replies.lock().expect("icmp receiver mutex poisoned");
                replies.insert(seq, state);
                shared.signal.notify_all();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => {
                if debug {
                    eprintln!("[icmp] receive failed: {e}");
                }
                break;
            }
        }
    }
}

/// Whether ICMP diagnostics are enabled via `ASPHYXIA_ICMP_DEBUG`.
fn debug_enabled() -> bool {
    static DEBUG: OnceLock<bool> = OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("ASPHYXIA_ICMP_DEBUG").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, icmp: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        let total = (IPV4_HEADER_LEN + icmp.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_ICMP;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet.extend_from_slice(icmp);
        packet
    }

    #[test]
    fn echo_request_has_a_valid_checksum() {
        let packet = build_echo_request(0x1234, 0x5678);
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x5678);
        assert_eq!(checksum(&packet), 0, "a checksummed packet sums to zero");
    }

    #[test]
    fn parses_an_echo_reply_with_or_without_the_ip_header() {
        let mut reply = build_echo_request(1, 42);
        reply[0] = ICMP_ECHO_REPLY;
        reply[2..4].fill(0); // checksum is not validated here

        let framed = ipv4(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            &reply,
        );
        assert_eq!(parse_packet(&framed), Some(Reply::Echo(42)));
        assert_eq!(parse_packet(&reply), Some(Reply::Echo(42)));
    }

    #[test]
    fn parses_a_destination_unreachable_with_the_quoted_request() {
        let request = build_echo_request(1, 99);
        let mut unreachable = vec![ICMP_DEST_UNREACHABLE, 1, 0, 0, 0, 0, 0, 0];
        unreachable.extend_from_slice(&ipv4(
            "198.51.100.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            &request,
        ));
        let packet = ipv4(
            "192.0.2.254".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            &unreachable,
        );
        assert_eq!(parse_packet(&packet), Some(Reply::Unreachable(99)));
    }

    #[test]
    fn rejects_malformed_and_unrelated_packets() {
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[ICMP_ECHO_REPLY; 4]).is_none());
        // A non-echo ICMP message is not a discovery reply.
        assert!(parse_packet(&[11, 0, 0, 0, 0, 0, 0, 0]).is_none());
        // A destination-unreachable without a quoted echo request is ignored.
        let mut unreachable = vec![ICMP_DEST_UNREACHABLE; 8];
        unreachable.extend_from_slice(&[0u8; 28]);
        assert!(parse_packet(&unreachable).is_none());
    }

    #[test]
    fn sequence_numbers_advance() {
        let first = next_seq();
        let second = next_seq();
        assert_eq!(second, first.wrapping_add(1));
    }
}

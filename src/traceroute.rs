//! IPv4 traceroute (`asphyxia trace`).
//!
//! Probes carry an increasing IP TTL: a router that drops an expired packet
//! answers with ICMP time-exceeded, revealing its address, while the target's
//! TCP SYN/ACK/RST or ICMP echo reply ends the trace. TCP is the default
//! transport because it traverses filters that drop ICMP; `--transport icmp`
//! uses echo requests instead.
//!
//! IPv4 only. Raw packets need root/`CAP_NET_RAW`; replies are read through one
//! libpcap capture per trace, and a hop that never answers is kept as a visible
//! silent hop rather than disappearing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Probe transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Transport {
    /// TCP SYN probes (default), useful through ICMP-filtering paths.
    Tcp,
    /// ICMP echo probes.
    Icmp,
}

impl Transport {
    /// Stable name in output.
    pub fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Icmp => "icmp",
        }
    }
}

/// One probe's observation at a hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeResult {
    /// Router or target that answered; `None` for a timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Round-trip time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u128>,
    /// Whether this reply came from the target (or proved it unreachable).
    pub reached: bool,
}

/// All probes sent with one TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub ttl: u8,
    pub probes: Vec<ProbeResult>,
    pub loss_pct: u8,
    pub silent: bool,
}

/// The complete trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceReport {
    pub target: String,
    pub transport: &'static str,
    pub port: u16,
    pub max_hops: u8,
    pub hops: Vec<Hop>,
    pub reached: bool,
    /// `reached`, `unreachable`, or `max-hops`.
    pub status: &'static str,
    /// First TTL that produced no reply at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_silent_hop: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProbeKey {
    TcpPort(u16),
    IcmpSeq(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyKind {
    Router,
    Target,
    Unreachable,
}

#[derive(Debug, Clone, Copy)]
struct TraceReply {
    ip: Ipv4Addr,
    kind: ReplyKind,
    at: Instant,
}

/// State shared between the sender and the pcap reader.
struct Shared {
    replies: Mutex<HashMap<ProbeKey, TraceReply>>,
    signal: Condvar,
    stop: AtomicBool,
}

/// One pcap capture per trace, reading ICMP and TCP replies.
struct TraceReceiver {
    shared: Arc<Shared>,
    reader: Option<JoinHandle<()>>,
}

impl TraceReceiver {
    fn start(target: Ipv4Addr) -> Option<TraceReceiver> {
        let shared = Arc::new(Shared {
            replies: Mutex::new(HashMap::new()),
            signal: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let reader_shared = Arc::clone(&shared);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<bool>(1);
        let reader = thread::spawn(move || match open_capture(target) {
            Some((mut capture, offset)) => {
                let _ = ready_tx.send(true);
                reader_loop(&mut capture, offset, &reader_shared);
            }
            None => {
                let _ = ready_tx.send(false);
            }
        });
        match ready_rx.recv() {
            Ok(true) => Some(TraceReceiver {
                shared,
                reader: Some(reader),
            }),
            _ => {
                let _ = reader.join();
                None
            }
        }
    }

    fn clear(&self, key: ProbeKey) {
        if let Ok(mut replies) = self.shared.replies.lock() {
            replies.remove(&key);
        }
    }

    fn wait(&self, key: ProbeKey, sent_at: Instant, timeout: Duration) -> Option<TraceReply> {
        let deadline = sent_at + timeout;
        let mut replies = self.shared.replies.lock().expect("trace mutex poisoned");
        loop {
            if let Some(reply) = replies.remove(&key) {
                return Some(reply);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .shared
                .signal
                .wait_timeout(replies, deadline - now)
                .expect("trace condvar poisoned");
            replies = guard;
        }
    }
}

impl Drop for TraceReceiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// Raw IPv4 sender with IP_HDRINCL.
struct RawSender {
    socket: socket2::Socket,
    src: Ipv4Addr,
}

impl RawSender {
    fn new(target: Ipv4Addr) -> Option<RawSender> {
        use socket2::{Domain, Protocol, Socket, Type};

        let src = crate::scanner::syn::local_ipv4_for(target)?;
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255))).ok()?;
        socket.set_header_included_v4(true).ok()?;
        crate::iface::bind_raw(&socket, true).ok()?;
        Some(RawSender { socket, src })
    }

    fn send(&self, packet: Vec<u8>, target: Ipv4Addr) -> std::io::Result<()> {
        #[allow(unused_mut)]
        let mut packet = packet;
        #[cfg(target_os = "macos")]
        {
            // See scanner::syn: Darwin's IP_HDRINCL path wants these fields in
            // host byte order.
            let ip_len = u16::from_be_bytes([packet[2], packet[3]]);
            packet[2..4].copy_from_slice(&ip_len.to_ne_bytes());
            let ip_off = u16::from_be_bytes([packet[6], packet[7]]);
            packet[6..8].copy_from_slice(&ip_off.to_ne_bytes());
        }
        let destination: socket2::SockAddr = SocketAddr::new(IpAddr::V4(target), 0).into();
        self.socket.send_to(&packet, &destination).map(|_| ())
    }
}

const READ_TIMEOUT_MS: i32 = 10;
const SNAPLEN: i32 = 256;

/// Open a capture on the interface that routes to `target`, filtered to ICMP
/// and TCP SYN/RST replies.
fn open_capture(target: Ipv4Addr) -> Option<(pcap::Capture<pcap::Active>, usize)> {
    let src = crate::scanner::syn::local_ipv4_for(target)?;
    let device = crate::scanner::syn::device_for(src)?;
    let mut capture = pcap::Capture::from_device(device)
        .ok()?
        .immediate_mode(true)
        .snaplen(SNAPLEN)
        .timeout(READ_TIMEOUT_MS)
        .open()
        .ok()?;
    capture
        .filter("icmp or (tcp and (tcp[13] & 6) != 0)", true)
        .ok()?;
    let offset = crate::scanner::syn::datalink_offset(capture.get_datalink());
    Some((capture, offset))
}

/// Read replies until stopped.
fn reader_loop(capture: &mut pcap::Capture<pcap::Active>, offset: usize, shared: &Shared) {
    while !shared.stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((key, reply)) = parse_frame(packet.data, offset) {
                    let mut replies = shared.replies.lock().expect("trace mutex poisoned");
                    replies.insert(key, reply);
                    shared.signal.notify_all();
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
}

/// Locate the IPv4 packet inside a link-layer frame and classify a reply.
fn parse_frame(frame: &[u8], hint: usize) -> Option<(ProbeKey, TraceReply)> {
    for offset in [hint, 0, 14, 4, 16] {
        if frame.len() > offset
            && frame[offset] >> 4 == 4
            && let Some(reply) = parse_ipv4(&frame[offset..])
        {
            return Some(reply);
        }
    }
    None
}

fn parse_ipv4(packet: &[u8]) -> Option<(ProbeKey, TraceReply)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    match packet[9] {
        1 => parse_icmp(src, &packet[ihl..]),
        6 => parse_tcp(src, &packet[ihl..]),
        _ => None,
    }
}

fn parse_tcp(src: Ipv4Addr, tcp: &[u8]) -> Option<(ProbeKey, TraceReply)> {
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    // A final answer to a SYN probe is an RST or a SYN/ACK.
    if flags & 0x04 == 0 && (flags & 0x02 == 0 || flags & 0x10 == 0) {
        return None;
    }
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some((
        ProbeKey::TcpPort(dst_port),
        TraceReply {
            ip: src,
            kind: ReplyKind::Target,
            at: Instant::now(),
        },
    ))
}

fn parse_icmp(src: Ipv4Addr, icmp: &[u8]) -> Option<(ProbeKey, TraceReply)> {
    if icmp.len() < 8 {
        return None;
    }
    match icmp[0] {
        // Echo reply: the target answered an ICMP probe.
        0 => {
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            Some((
                ProbeKey::IcmpSeq(seq),
                TraceReply {
                    ip: src,
                    kind: ReplyKind::Target,
                    at: Instant::now(),
                },
            ))
        }
        // Time exceeded or destination unreachable: the quoted original packet
        // identifies which probe the router is answering.
        3 | 11 => {
            let kind = if icmp[0] == 3 {
                ReplyKind::Unreachable
            } else {
                ReplyKind::Router
            };
            let key = quoted_probe_key(&icmp[8..])?;
            Some((
                key,
                TraceReply {
                    ip: src,
                    kind,
                    at: Instant::now(),
                },
            ))
        }
        _ => None,
    }
}

/// Extract the probe key from the IP packet quoted inside an ICMP error.
fn quoted_probe_key(quoted: &[u8]) -> Option<ProbeKey> {
    if quoted.len() < 20 || quoted[0] >> 4 != 4 {
        return None;
    }
    let ihl = (quoted[0] & 0x0f) as usize * 4;
    if ihl < 20 || quoted.len() < ihl + 8 {
        return None;
    }
    match quoted[9] {
        // TCP: the source port is the probe's unique key.
        6 => Some(ProbeKey::TcpPort(u16::from_be_bytes([
            quoted[ihl],
            quoted[ihl + 1],
        ]))),
        // ICMP: the quoted echo request's sequence number is the key.
        1 => {
            let inner = &quoted[ihl..];
            if inner[0] != 8 {
                return None;
            }
            Some(ProbeKey::IcmpSeq(u16::from_be_bytes([inner[6], inner[7]])))
        }
        _ => None,
    }
}

/// Run a traceroute.
#[allow(clippy::too_many_arguments)]
pub fn trace(
    target: Ipv4Addr,
    transport: Transport,
    port: u16,
    max_hops: u8,
    probes: u8,
    timeout: Duration,
) -> Result<TraceReport, String> {
    let receiver = TraceReceiver::start(target)
        .ok_or_else(|| "traceroute needs root/CAP_NET_RAW and libpcap".to_string())?;
    let sender =
        RawSender::new(target).ok_or_else(|| "traceroute needs root/CAP_NET_RAW".to_string())?;

    let mut report = TraceReport {
        target: target.to_string(),
        transport: transport.label(),
        port,
        max_hops,
        hops: Vec::new(),
        reached: false,
        status: "max-hops",
        first_silent_hop: None,
    };
    let id = std::process::id() as u16;
    let mut probe_index: u16 = 0;

    for ttl in 1..=max_hops {
        let mut results = Vec::new();
        let mut replied = 0u8;
        let mut sent = 0u8;
        let mut reached = false;
        let mut unreachable = false;

        for _ in 0..probes {
            probe_index = probe_index.wrapping_add(1);
            let (key, packet) = match transport {
                Transport::Tcp => {
                    let src_port = 40_000 + (probe_index % 20_000);
                    let packet = crate::scanner::syn::build_ipv4_probe_with_ttl(
                        sender.src,
                        target,
                        src_port,
                        port,
                        0x1234_5678,
                        0,
                        crate::scanner::syn::TCP_SYN,
                        ttl,
                    );
                    (ProbeKey::TcpPort(src_port), packet)
                }
                Transport::Icmp => {
                    let seq = probe_index;
                    let packet = crate::scanner::discovery::icmp::build_ipv4_echo(
                        sender.src, target, id, seq, ttl,
                    );
                    (ProbeKey::IcmpSeq(seq), packet)
                }
            };
            receiver.clear(key);
            sent += 1;
            let sent_at = Instant::now();
            sender
                .send(packet, target)
                .map_err(|e| format!("Could not send probe: {e}"))?;
            if let Some(reply) = receiver.wait(key, sent_at, timeout) {
                replied += 1;
                let is_final = reply.kind != ReplyKind::Router;
                results.push(ProbeResult {
                    ip: Some(reply.ip.to_string()),
                    rtt_ms: Some(reply.at.saturating_duration_since(sent_at).as_millis()),
                    reached: is_final,
                });
                if is_final {
                    reached = true;
                    unreachable = reply.kind == ReplyKind::Unreachable;
                    break;
                }
            } else {
                results.push(ProbeResult {
                    ip: None,
                    rtt_ms: None,
                    reached: false,
                });
            }
        }

        let loss_pct = if sent == 0 {
            0
        } else {
            (u16::from(sent - replied) * 100 / u16::from(sent)) as u8
        };
        let silent = replied == 0;
        if silent && report.first_silent_hop.is_none() {
            report.first_silent_hop = Some(ttl);
        }
        report.hops.push(Hop {
            ttl,
            probes: results,
            loss_pct,
            silent,
        });

        if reached {
            report.reached = true;
            report.status = if unreachable {
                "unreachable"
            } else {
                "reached"
            };
            break;
        }
    }

    Ok(report)
}

/// Human-readable trace.
pub fn render_text(report: &TraceReport) -> String {
    let mut out = format!(
        "Trace to {} via {}/{} (max {} hops)\n",
        report.target, report.transport, report.port, report.max_hops
    );
    for hop in &report.hops {
        let mut line = format!("{:2} ", hop.ttl);
        for probe in &hop.probes {
            match (&probe.ip, probe.rtt_ms) {
                (Some(ip), Some(rtt)) => line.push_str(&format!("  {ip} {rtt} ms")),
                _ => line.push_str("  *"),
            }
        }
        if hop.silent {
            line.push_str("  [silent]");
        }
        out.push_str(&line);
        out.push('\n');
    }
    match report.status {
        "reached" => out.push_str(&format!("Reached after {} hops\n", report.hops.len())),
        "unreachable" => out.push_str("Destination unreachable\n"),
        _ => out.push_str("No final answer within max hops\n"),
    }
    out
}

/// JSON Lines: one hop per line plus trace/summary records.
pub fn render_jsonl(report: &TraceReport) -> String {
    let mut out = String::new();
    out.push_str(
        &serde_json::json!({
            "event": "trace",
            "target": report.target,
            "transport": report.transport,
            "port": report.port,
            "max_hops": report.max_hops
        })
        .to_string(),
    );
    out.push('\n');
    for hop in &report.hops {
        out.push_str(&serde_json::json!({"event": "hop", "hop": hop}).to_string());
        out.push('\n');
    }
    out.push_str(
        &serde_json::json!({
            "event": "summary",
            "status": report.status,
            "reached": report.reached,
            "first_silent_hop": report.first_silent_hop
        })
        .to_string(),
    );
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(src: &str, dst: &str, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        packet[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp
    }

    #[test]
    fn parses_a_tcp_reset_from_the_target() {
        let frame = ethernet(&ipv4("192.0.2.10", "192.0.2.2", 6, &tcp(80, 40_001, 0x14)));
        let (key, reply) = parse_frame(&frame, 14).expect("TCP reset");
        assert_eq!(key, ProbeKey::TcpPort(40_001));
        assert_eq!(reply.kind, ReplyKind::Target);
        assert_eq!(reply.ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn parses_an_icmp_time_exceeded_for_a_quoted_tcp_probe() {
        let inner = ipv4("192.0.2.2", "198.51.100.1", 6, &tcp(40_002, 443, 0x02));
        let mut icmp = vec![11u8, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&inner);
        let frame = ethernet(&ipv4("192.0.2.1", "192.0.2.2", 1, &icmp));
        let (key, reply) = parse_frame(&frame, 14).expect("time exceeded");
        assert_eq!(key, ProbeKey::TcpPort(40_002));
        assert_eq!(reply.kind, ReplyKind::Router);
        assert_eq!(reply.ip, "192.0.2.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn parses_an_echo_reply_and_a_quoted_icmp_probe() {
        let mut reply = vec![0u8, 0, 0, 0, 0, 1, 0, 7];
        reply.extend_from_slice(b"asphyxia");
        let frame = ethernet(&ipv4("198.51.100.1", "192.0.2.2", 1, &reply));
        let (key, parsed) = parse_frame(&frame, 14).expect("echo reply");
        assert_eq!(key, ProbeKey::IcmpSeq(7));
        assert_eq!(parsed.kind, ReplyKind::Target);

        let mut request = vec![8u8, 0, 0, 0, 0, 1, 0, 9];
        request.extend_from_slice(b"asphyxia");
        let inner = ipv4("192.0.2.2", "198.51.100.1", 1, &request);
        let mut unreachable = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        unreachable.extend_from_slice(&inner);
        let frame = ethernet(&ipv4("192.0.2.254", "192.0.2.2", 1, &unreachable));
        let (key, parsed) = parse_frame(&frame, 14).expect("unreachable");
        assert_eq!(key, ProbeKey::IcmpSeq(9));
        assert_eq!(parsed.kind, ReplyKind::Unreachable);
    }

    #[test]
    fn silent_hops_render_as_stars() {
        let report = TraceReport {
            target: "192.0.2.1".to_string(),
            transport: "tcp",
            port: 80,
            max_hops: 2,
            hops: vec![Hop {
                ttl: 1,
                probes: vec![ProbeResult {
                    ip: None,
                    rtt_ms: None,
                    reached: false,
                }],
                loss_pct: 100,
                silent: true,
            }],
            reached: false,
            status: "max-hops",
            first_silent_hop: Some(1),
        };
        let text = render_text(&report);
        assert!(text.contains("*"));
        assert!(text.contains("[silent]"));
    }
}

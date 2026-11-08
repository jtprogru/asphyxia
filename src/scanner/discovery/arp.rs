//! ARP-request host discovery for locally-connected IPv4 subnets.
//!
//! The default TCP-based discovery (`address::scan_address`) misses live hosts
//! that silently drop all probed ports (80, 443, 22, 3389). ARP closes that gap:
//! a host on the local L2 segment answers an ARP request with its MAC address
//! regardless of any IP-level firewall. This module builds raw ARP-request
//! frames, sends them through a libpcap handle on the interface that routes to
//! the target, and reads the replies through the same handle.
//!
//! Valid only for IPv4 targets on a locally-connected subnet (same network as an
//! interface address, or reachable via `--interface`). Remote subnets, IPv6, and
//! missing raw-socket privileges all fall back to the TCP probe with a clear
//! message.
//!
//! The capture handle is owned by one reader thread per interface. Probes submit
//! their frame over a channel; the reader sends it and records every ARP reply
//! in a shared map, waking the waiting probe. One handle per interface (rather
//! than one per probe) keeps a `/24` sweep from opening hundreds of `/dev/bpf*`
//! devices on macOS.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Ethernet type for ARP (0x0806).
const ETHERTYPE_ARP: u16 = 0x0806;
/// ARP opcode: request.
const ARP_REQUEST: u16 = 0x0001;
/// ARP opcode: reply.
const ARP_REPLY: u16 = 0x0002;
/// ARP hardware type: Ethernet.
const ARPHRD_ETHERNET: u16 = 0x0001;
/// ARP protocol type: IPv4.
const ARPOP_IPV4: u16 = 0x0800;
/// Ethernet header length.
const ETHERNET_HEADER_LEN: usize = 14;
/// ARP payload length for Ethernet/IPv4.
const ARP_PAYLOAD_LEN: usize = 28;
/// How long a pcap read blocks before the reader re-checks its send queue and
/// stop flag. Short enough to send promptly, long enough not to spin.
const READ_TIMEOUT_MS: i32 = 10;
/// Enough to hold a link header plus a full ARP frame.
const SNAPLEN: i32 = 128;

/// A MAC address (six octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Parse a `aa:bb:cc:dd:ee:ff` string.
    pub fn parse(s: &str) -> Option<MacAddr> {
        let octets: Vec<u8> = s
            .split(':')
            .map(|part| u8::from_str_radix(part, 16).ok())
            .collect::<Option<Vec<_>>>()?;
        if octets.len() != 6 {
            return None;
        }
        Some(MacAddr(octets.try_into().unwrap()))
    }

    /// The six raw octets.
    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }

    /// The vendor OUI (first three octets), as a hex string `aa-bb-cc`.
    pub fn oui(&self) -> String {
        self.0[..3]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        f.write_str(&text)
    }
}

/// An ARP reply confirming a host is up, with its MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpHit {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub latency: Duration,
}

/// A locally-connected IPv4 interface usable for ARP probing.
#[derive(Debug, Clone)]
struct Interface {
    name: String,
    ip: Ipv4Addr,
    prefix_len: u8,
    mac: MacAddr,
}

/// Build an Ethernet + ARP-request frame asking "who has `target_ip`?" from
/// `src_mac`/`src_ip`. The frame is ready to send over a packet handle on the
/// local interface.
pub fn build_arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN];

    // Destination MAC: broadcast.
    frame[0..6].copy_from_slice(&[0xff; 6]);
    // Source MAC: ours.
    frame[6..12].copy_from_slice(&src_mac);
    // EtherType: ARP.
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    let arp = &mut frame[ETHERNET_HEADER_LEN..];
    // Hardware type: Ethernet.
    arp[0..2].copy_from_slice(&ARPHRD_ETHERNET.to_be_bytes());
    // Protocol type: IPv4.
    arp[2..4].copy_from_slice(&ARPOP_IPV4.to_be_bytes());
    // Hardware address length: 6.
    arp[4] = 6;
    // Protocol address length: 4.
    arp[5] = 4;
    // Opcode: request.
    arp[6..8].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    // Sender hardware address (our MAC).
    arp[8..14].copy_from_slice(&src_mac);
    // Sender protocol address (our IP).
    arp[14..18].copy_from_slice(&src_ip.octets());
    // Target hardware address: zero (we don't know it yet).
    arp[18..24].copy_from_slice(&[0u8; 6]);
    // Target protocol address (the IP we're asking about).
    arp[24..28].copy_from_slice(&target_ip.octets());

    frame
}

/// The fields of an ARP reply, extracted from an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArpReply {
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

/// Parse an Ethernet + ARP packet, returning the reply's sender and target
/// fields. Returns `None` for non-ARP frames, requests, or malformed payloads.
fn parse_arp_reply_fields(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = &frame[ETHERNET_HEADER_LEN..];
    // Hardware type must be Ethernet.
    if u16::from_be_bytes([arp[0], arp[1]]) != ARPHRD_ETHERNET {
        return None;
    }
    // Protocol type must be IPv4.
    if u16::from_be_bytes([arp[2], arp[3]]) != ARPOP_IPV4 {
        return None;
    }
    // Only Ethernet (6-byte) hardware addresses carrying IPv4 (4-byte) protocol
    // addresses have the fixed layout parsed below.
    if arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    // Only replies answer a probe; requests are ignored.
    if u16::from_be_bytes([arp[6], arp[7]]) != ARP_REPLY {
        return None;
    }
    Some(ArpReply {
        sender_mac: MacAddr(arp[8..14].try_into().ok()?),
        sender_ip: Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]),
        target_ip: Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]),
    })
}

/// Parse an Ethernet + ARP-reply frame, returning `(sender_mac, sender_ip)` if
/// the frame is a valid ARP reply. Returns `None` for non-ARP frames, requests,
/// or malformed payloads.
pub fn parse_arp_reply(frame: &[u8]) -> Option<(MacAddr, Ipv4Addr)> {
    parse_arp_reply_fields(frame).map(|reply| (reply.sender_mac, reply.sender_ip))
}

/// Whether `target` is on a locally-connected IPv4 subnet — i.e. shares the same
/// network as at least one usable interface address. Only such targets can be
/// reached by an ARP request; anything else must fall back to TCP.
///
/// Loopback is deliberately *not* considered ARP-able: there is no L2 segment to
/// broadcast on, so a loopback address always takes the TCP path.
pub fn is_local_ipv4(target: Ipv4Addr) -> bool {
    if target.is_loopback() {
        return false;
    }
    select_interface(target, crate::iface::requested(), interfaces()).is_some()
}

/// The `(address, prefix)` pairs for all non-loopback, up IPv4 interfaces that
/// have a usable MAC address. Loaded once per process; interfaces do not change
/// in the middle of a scan.
fn interfaces() -> &'static [Interface] {
    static INTERFACES: OnceLock<Vec<Interface>> = OnceLock::new();
    INTERFACES.get_or_init(load_interfaces)
}

/// Enumerate interfaces through libpcap (address and netmask) and resolve their
/// MAC addresses through `getifaddrs`.
fn load_interfaces() -> Vec<Interface> {
    let macs = mac_map();
    let Ok(devices) = pcap::Device::list() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for device in devices {
        if device.flags.is_loopback() || !device.flags.is_up() {
            continue;
        }
        let Some(&mac) = macs.get(&device.name) else {
            continue;
        };
        for address in &device.addresses {
            let (IpAddr::V4(ip), Some(IpAddr::V4(mask))) = (address.addr, address.netmask) else {
                continue;
            };
            let Some(prefix_len) = prefix_from_mask(mask) else {
                continue;
            };
            // A /0 address says nothing useful about reachability; never ARP the
            // whole internet from it.
            if prefix_len == 0 {
                continue;
            }
            out.push(Interface {
                name: device.name.clone(),
                ip,
                prefix_len,
                mac,
            });
        }
    }
    out
}

/// Pick the interface that can reach `target`. When `requested` is set (from
/// `-e/--interface`), only that interface is considered; otherwise the first
/// interface whose subnet contains the target wins.
fn select_interface<'a>(
    target: Ipv4Addr,
    requested: Option<&str>,
    ifaces: &'a [Interface],
) -> Option<&'a Interface> {
    if let Some(name) = requested {
        return ifaces
            .iter()
            .find(|iface| iface.name == name && same_subnet(target, iface.ip, iface.prefix_len));
    }
    ifaces
        .iter()
        .find(|iface| same_subnet(target, iface.ip, iface.prefix_len))
}

/// Whether `a` and `b` share the same `/prefix_len` network.
fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix_len);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Convert a contiguous IPv4 netmask to its prefix length, or `None` when the
/// mask has holes.
fn prefix_from_mask(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (bits == expected).then_some(prefix)
}

/// Read interface MAC addresses from the system, keyed by interface name.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn mac_map() -> HashMap<String, MacAddr> {
    use std::ffi::CStr;

    let mut out = HashMap::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a valid linked list on success; it is
    // released with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }

    let mut current = list;
    while !current.is_null() {
        // SAFETY: `current` points into the list returned by getifaddrs.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated string owned by the list.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if let std::collections::hash_map::Entry::Vacant(slot) = out.entry(name) {
                // SAFETY: ifa_addr points to a sockaddr owned by the list.
                if let Some(mac) = unsafe { mac_from_sockaddr(entry.ifa_addr) } {
                    slot.insert(mac);
                }
            }
        }
        current = entry.ifa_next;
    }

    // SAFETY: `list` was allocated by getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(list) };
    out
}

/// Platforms without `getifaddrs` support (or without a link-layer address
/// layout we know) simply cannot discover MAC addresses, so ARP falls back.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn mac_map() -> HashMap<String, MacAddr> {
    HashMap::new()
}

/// Extract a six-byte MAC from a link-layer `sockaddr`, if it is one.
#[cfg(target_os = "macos")]
unsafe fn mac_from_sockaddr(addr: *const libc::sockaddr) -> Option<MacAddr> {
    // SAFETY: the caller passes a pointer owned by getifaddrs.
    let sa = unsafe { &*addr };
    if i32::from(sa.sa_family) != libc::AF_LINK {
        return None;
    }
    // SAFETY: an AF_LINK address is a sockaddr_dl.
    let sdl = unsafe { &*(addr as *const libc::sockaddr_dl) };
    let name_len = sdl.sdl_nlen as usize;
    let addr_len = sdl.sdl_alen as usize;
    // sdl_data starts 8 bytes into the structure; the link address follows the
    // interface name. Validate the declared length before reading.
    if addr_len != 6 || (sdl.sdl_len as usize) < 8 + name_len + 6 {
        return None;
    }
    let start = unsafe { (addr as *const u8).add(8 + name_len) };
    let mut mac = [0u8; 6];
    // SAFETY: the length check above proves six bytes are available.
    unsafe { std::ptr::copy_nonoverlapping(start, mac.as_mut_ptr(), 6) };
    Some(MacAddr(mac))
}

/// Extract a six-byte MAC from a Linux `sockaddr_ll`, if it is one.
#[cfg(target_os = "linux")]
unsafe fn mac_from_sockaddr(addr: *const libc::sockaddr) -> Option<MacAddr> {
    // SAFETY: the caller passes a pointer owned by getifaddrs.
    let sa = unsafe { &*addr };
    if i32::from(sa.sa_family) != libc::AF_PACKET {
        return None;
    }
    // SAFETY: an AF_PACKET address is a sockaddr_ll.
    let sll = unsafe { &*(addr as *const libc::sockaddr_ll) };
    if sll.sll_halen as usize != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    // SAFETY: sll_addr is an 8-byte array and sll_halen says six bytes are used.
    unsafe { std::ptr::copy_nonoverlapping(sll.sll_addr.as_ptr(), mac.as_mut_ptr(), 6) };
    Some(MacAddr(mac))
}

/// Start ARP probing for `targets`, opening a capture on every interface that
/// holds a local target. Returns `true` when at least one probe can actually
/// run; `false` means the caller should fall back to TCP (no local IPv4 target,
/// no usable MAC, or no permission/libpcap to open a capture).
///
/// This is called before the scan so the fallback is reported once, rather than
/// per address.
pub fn prepare(targets: &[IpAddr]) -> bool {
    let requested = crate::iface::requested();
    let ifaces = interfaces();
    let mut ready = false;
    for target in targets {
        let IpAddr::V4(target) = target else {
            continue;
        };
        let Some(iface) = select_interface(*target, requested, ifaces) else {
            continue;
        };
        let ready_now = receiver_for(iface).is_some();
        if debug_enabled() {
            eprintln!(
                "[arp] target {target} via {} ({}/{}, mac {}) — capture {}",
                iface.name,
                iface.ip,
                iface.prefix_len,
                iface.mac,
                if ready_now { "ready" } else { "unavailable" }
            );
        }
        if ready_now {
            ready = true;
        }
    }
    ready
}

/// Probe a single IPv4 address with an ARP request and wait for the reply.
///
/// Returns `Some(ArpHit)` when the host answers, `None` on timeout or when the
/// raw path is unusable (caller should fall back to TCP). Respects the global
/// rate limit via [`crate::rate::gate_for`].
pub fn arp_probe(target: Ipv4Addr, timeout: Duration) -> Option<ArpHit> {
    arp_probe_with_retries(target, timeout, 0)
}

/// [`arp_probe`] with up to `retries` extra attempts on silence. A lost request
/// and a host that does not answer look identical, so retries buy back some
/// certainty on a lossy L2 segment.
pub fn arp_probe_with_retries(target: Ipv4Addr, timeout: Duration, retries: u32) -> Option<ArpHit> {
    let iface = select_interface(target, crate::iface::requested(), interfaces())?;
    let receiver = receiver_for(iface)?;
    let frame = build_arp_request(iface.mac.as_bytes(), iface.ip, target);

    for _ in 0..=retries {
        // Respect the rate cap and this host's own --delay (no-op when unset).
        crate::rate::gate_for(IpAddr::V4(target));
        receiver.clear(target);
        let sent_at = Instant::now();
        if !receiver.submit(frame.clone()) {
            // The reader thread is gone; no point waiting for a reply that can
            // never be recorded.
            return None;
        }
        if let Some(hit) = receiver.wait_for(target, sent_at, timeout) {
            return Some(hit);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// pcap sender/receiver
// ---------------------------------------------------------------------------

/// State shared between the probing threads and the capture reader thread.
struct Shared {
    /// Reply MACs keyed by the reply's sender IPv4 address (the scanned host).
    replies: Mutex<HashMap<Ipv4Addr, (MacAddr, Instant)>>,
    /// Woken whenever a new reply is recorded, so waiters re-check the map.
    signal: Condvar,
    /// Set on drop to stop the reader loop.
    stop: AtomicBool,
}

/// One pcap capture per interface, used both to inject ARP requests and to read
/// the replies. The handle lives entirely inside the reader thread.
struct ArpReceiver {
    shared: Arc<Shared>,
    sender: Option<Sender<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl ArpReceiver {
    /// Open a capture on `iface` and spawn its reader. Returns `None` if the
    /// capture or the ARP reply filter could not be set up (no privileges, no
    /// libpcap, an unusual link type).
    fn start(iface: &Interface) -> Option<ArpReceiver> {
        let (sender, receiver) = mpsc::channel::<Vec<u8>>();
        let shared = Arc::new(Shared {
            replies: Mutex::new(HashMap::new()),
            signal: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let reader_shared = Arc::clone(&shared);
        let name = iface.name.clone();
        let our_ip = iface.ip;

        // Report readiness over a channel so `start` can fail cleanly when the
        // capture cannot be opened, instead of handing out a dead receiver.
        let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);
        let reader = thread::spawn(move || match open_capture(&name) {
            Some(mut capture) => {
                let _ = ready_tx.send(true);
                reader_loop(&mut capture, receiver, &reader_shared, our_ip);
            }
            None => {
                let _ = ready_tx.send(false);
            }
        });

        match ready_rx.recv() {
            Ok(true) => Some(ArpReceiver {
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

    /// Queue a frame for the reader thread to send.
    fn submit(&self, frame: Vec<u8>) -> bool {
        self.sender
            .as_ref()
            .is_some_and(|sender| sender.send(frame).is_ok())
    }

    /// Drop any stale reply for `target` before a fresh request goes out.
    fn clear(&self, target: Ipv4Addr) {
        if let Ok(mut replies) = self.shared.replies.lock() {
            replies.remove(&target);
        }
    }

    /// Block until a reply for `target` is recorded or `timeout` elapses.
    fn wait_for(&self, target: Ipv4Addr, sent_at: Instant, timeout: Duration) -> Option<ArpHit> {
        let deadline = sent_at + timeout;
        let mut replies = self
            .shared
            .replies
            .lock()
            .expect("arp receiver mutex poisoned");
        loop {
            if let Some((mac, received_at)) = replies.remove(&target) {
                return Some(ArpHit {
                    ip: target,
                    mac,
                    latency: received_at.saturating_duration_since(sent_at),
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _timed_out) = self
                .shared
                .signal
                .wait_timeout(replies, deadline - now)
                .expect("arp receiver condvar poisoned");
            replies = guard;
        }
    }
}

impl Drop for ArpReceiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Dropping the sender wakes the reader's try_recv; the stop flag makes
        // the loop exit even when no frame is pending.
        self.sender.take();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The process-wide receiver registry, one entry per interface name. A `None`
/// entry caches a capture that could not be opened, so a scan does not retry a
/// failing open for every address.
fn receiver_for(iface: &Interface) -> Option<Arc<ArpReceiver>> {
    static RECEIVERS: OnceLock<Mutex<HashMap<String, Option<Arc<ArpReceiver>>>>> = OnceLock::new();

    let registry = RECEIVERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut entries = registry.lock().expect("arp receiver registry poisoned");
    if let Some(existing) = entries.get(&iface.name) {
        return existing.clone();
    }
    let receiver = ArpReceiver::start(iface).map(Arc::new);
    entries.insert(iface.name.clone(), receiver.clone());
    receiver
}

/// Open a pcap capture on `name`, filtered to ARP replies. The filter is what
/// keeps unrelated traffic out of the reader; `sendpacket` bypasses it, so the
/// same handle can inject requests.
fn open_capture(name: &str) -> Option<pcap::Capture<pcap::Active>> {
    let debug = debug_enabled();
    let inactive = match pcap::Capture::from_device(name) {
        Ok(inactive) => inactive,
        Err(e) => {
            if debug {
                eprintln!("[arp] cannot look up capture device {name}: {e}");
            }
            return None;
        }
    };
    let mut capture = match inactive
        .immediate_mode(true)
        .snaplen(SNAPLEN)
        .timeout(READ_TIMEOUT_MS)
        .open()
    {
        Ok(capture) => capture,
        Err(e) => {
            if debug {
                eprintln!("[arp] cannot open capture on {name}: {e}");
            }
            return None;
        }
    };
    // `arp[6:2] = 2` is the opcode field: 2 means reply.
    if let Err(e) = capture.filter("arp and arp[6:2] = 2", true) {
        if debug {
            eprintln!("[arp] cannot set the ARP filter on {name}: {e}");
        }
        return None;
    }
    Some(capture)
}

/// Read replies and send queued requests until stopped. Only replies addressed
/// to our interface IP are recorded, so unrelated ARP traffic is ignored.
fn reader_loop(
    capture: &mut pcap::Capture<pcap::Active>,
    queue: mpsc::Receiver<Vec<u8>>,
    shared: &Shared,
    our_ip: Ipv4Addr,
) {
    let debug = debug_enabled();
    while !shared.stop.load(Ordering::Relaxed) {
        // Drain everything queued since the last wake-up. Sending is cheap, and
        // doing it in one batch keeps a large sweep responsive.
        while let Ok(frame) = queue.try_recv() {
            if let Err(e) = capture.sendpacket(frame)
                && debug
            {
                eprintln!("[arp] send failed: {e}");
            }
        }

        match capture.next_packet() {
            Ok(packet) => {
                let Some(reply) = parse_arp_reply_fields(packet.data) else {
                    continue;
                };
                if reply.target_ip != our_ip {
                    continue;
                }
                if debug {
                    eprintln!(
                        "[arp] reply {} is-at {} (target {})",
                        reply.sender_ip, reply.sender_mac, reply.target_ip
                    );
                }
                let mut replies = shared.replies.lock().expect("arp receiver mutex poisoned");
                replies.insert(reply.sender_ip, (reply.sender_mac, Instant::now()));
                shared.signal.notify_all();
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                if debug {
                    eprintln!("[arp] capture stopped: {e}");
                }
                break;
            }
        }
    }
}

/// Whether ARP-scan diagnostics are enabled via the `ASPHYXIA_ARP_DEBUG`
/// environment variable. Read once and cached, since a large scan queries it
/// occasionally.
fn debug_enabled() -> bool {
    static DEBUG: OnceLock<bool> = OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("ASPHYXIA_ARP_DEBUG").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix_len: u8) -> Interface {
        Interface {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
            prefix_len,
            mac: MacAddr([0x02, 0, 0, 0, 0, 1]),
        }
    }

    #[test]
    fn mac_addr_round_trips() {
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").expect("valid MAC");
        assert_eq!(mac.as_bytes(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mac.oui(), "aa-bb-cc");
    }

    #[test]
    fn mac_addr_rejects_malformed() {
        assert!(MacAddr::parse("zz:bb:cc:dd:ee:ff").is_none());
        assert!(MacAddr::parse("aa:bb:cc:dd:ee").is_none()); // too short
        assert!(MacAddr::parse("").is_none());
    }

    #[test]
    fn arp_request_has_correct_structure() {
        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let src_ip: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let target: Ipv4Addr = "192.168.1.50".parse().unwrap();

        let frame = build_arp_request(src_mac, src_ip, target);
        assert_eq!(frame.len(), ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN);

        // Destination MAC is broadcast.
        assert_eq!(&frame[0..6], &[0xff; 6]);
        // Source MAC is ours.
        assert_eq!(&frame[6..12], &src_mac);
        // EtherType is ARP.
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);

        let arp = &frame[ETHERNET_HEADER_LEN..];
        // Hardware type: Ethernet.
        assert_eq!(u16::from_be_bytes([arp[0], arp[1]]), ARPHRD_ETHERNET);
        // Protocol type: IPv4.
        assert_eq!(u16::from_be_bytes([arp[2], arp[3]]), ARPOP_IPV4);
        // Hardware address length: 6, protocol address length: 4.
        assert_eq!(arp[4], 6);
        assert_eq!(arp[5], 4);
        // Opcode: request.
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), ARP_REQUEST);
        // Sender MAC and IP.
        assert_eq!(&arp[8..14], &src_mac);
        assert_eq!(&arp[14..18], &src_ip.octets());
        // Target MAC is zero, target IP is the one we're asking about.
        assert_eq!(&arp[18..24], &[0u8; 6]);
        assert_eq!(&arp[24..28], &target.octets());
    }

    #[test]
    fn parse_arp_reply_extracts_mac_and_ip() {
        let src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let target: Ipv4Addr = "192.168.1.50".parse().unwrap();

        // Build a request frame, then flip the opcode to reply and fill in the
        // sender fields as the target would answer.
        let mut frame = build_arp_request([0x11; 6], "192.168.1.10".parse().unwrap(), target);
        let arp = &mut frame[ETHERNET_HEADER_LEN..];
        arp[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
        // In a reply, the sender fields carry the answerer's MAC and IP.
        arp[8..14].copy_from_slice(&src_mac);
        arp[14..18].copy_from_slice(&target.octets());

        let (mac, ip) = parse_arp_reply(&frame).expect("should parse a valid reply");
        assert_eq!(mac.as_bytes(), src_mac);
        assert_eq!(ip, target);
    }

    #[test]
    fn parse_arp_reply_rejects_requests_and_non_arp() {
        let frame = build_arp_request(
            [0x11; 6],
            "192.168.1.10".parse().unwrap(),
            "192.168.1.50".parse().unwrap(),
        );
        // A request is not a reply.
        assert!(parse_arp_reply(&frame).is_none());

        // A non-ARP EtherType is rejected.
        let mut bad = frame.clone();
        bad[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not ARP
        assert!(parse_arp_reply(&bad).is_none());

        // A too-short frame is rejected.
        assert!(parse_arp_reply(&frame[..20]).is_none());
    }

    #[test]
    fn parse_arp_reply_rejects_unexpected_address_lengths() {
        let mut frame = build_arp_request(
            [0x11; 6],
            "192.168.1.10".parse().unwrap(),
            "192.168.1.50".parse().unwrap(),
        );
        let arp = &mut frame[ETHERNET_HEADER_LEN..];
        arp[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
        arp[4] = 8; // not an Ethernet MAC length
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn loopback_is_not_arp_able() {
        // There is no L2 segment on loopback, so ARP must fall back to TCP.
        let lo: Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert!(!is_local_ipv4(lo));
    }

    #[test]
    fn same_subnet_checks_prefix() {
        let a: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let b: Ipv4Addr = "192.168.1.50".parse().unwrap();
        let c: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert!(same_subnet(a, b, 24));
        assert!(!same_subnet(a, c, 24));
        // A /16 covers both 192.168.1.0/24 and 192.168.2.0/24.
        assert!(same_subnet(a, "192.168.2.50".parse().unwrap(), 16));
    }

    #[test]
    fn prefix_from_mask_accepts_only_contiguous_masks() {
        assert_eq!(prefix_from_mask("255.255.255.0".parse().unwrap()), Some(24));
        assert_eq!(prefix_from_mask("255.255.0.0".parse().unwrap()), Some(16));
        assert_eq!(
            prefix_from_mask("255.255.255.255".parse().unwrap()),
            Some(32)
        );
        assert_eq!(prefix_from_mask("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(prefix_from_mask("255.0.255.0".parse().unwrap()), None);
    }

    #[test]
    fn select_interface_prefers_an_on_link_interface() {
        let ifaces = vec![
            iface("en0", "192.168.1.10", 24),
            iface("en1", "10.0.0.5", 8),
        ];
        let target: Ipv4Addr = "192.168.1.50".parse().unwrap();
        assert_eq!(
            select_interface(target, None, &ifaces).map(|i| i.name.as_str()),
            Some("en0")
        );
        let target: Ipv4Addr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            select_interface(target, None, &ifaces).map(|i| i.name.as_str()),
            Some("en1")
        );
        let remote: Ipv4Addr = "203.0.113.5".parse().unwrap();
        assert!(select_interface(remote, None, &ifaces).is_none());
    }

    #[test]
    fn select_interface_respects_the_requested_interface() {
        let ifaces = vec![
            iface("en0", "192.168.1.10", 24),
            iface("en1", "192.168.1.20", 24),
        ];
        let target: Ipv4Addr = "192.168.1.50".parse().unwrap();
        assert_eq!(
            select_interface(target, Some("en1"), &ifaces).map(|i| i.name.as_str()),
            Some("en1")
        );
        // Requested interface does not cover the target: no ARP.
        assert!(select_interface(target, Some("en9"), &ifaces).is_none());
        let remote: Ipv4Addr = "203.0.113.5".parse().unwrap();
        assert!(select_interface(remote, Some("en0"), &ifaces).is_none());
    }

    #[test]
    fn select_interface_ignores_a_loopback_target() {
        // Loopback has no ARP segment; callers must fall back to TCP.
        let ifaces = vec![iface("en0", "192.168.1.10", 24)];
        let lo: Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert!(select_interface(lo, None, &ifaces).is_none());
    }
}

//! Binding scan sockets to a specific network interface (`-e`/`--interface`).
//!
//! By default the OS routes every probe through whatever the routing table
//! picks — usually the default route. When a host is reachable only through a
//! particular interface (a VPN, a tunnel, a secondary link carrying a more
//! specific route whose source address the default route never uses), the
//! probes have to be pinned to that interface, exactly as `ssh -B en0` or
//! `nmap -e en0` do. Otherwise the kernel sends from the wrong source address
//! and the replies never come back, so an open port looks closed.
//!
//! Like the rate limiter, the chosen interface is installed once before the
//! scan starts (see [`install`]) and consulted from the low-level probe paths,
//! which open their sockets through [`tcp_connect_timeout`] / [`udp_connect`]
//! instead of the std constructors. When no interface is requested those are
//! thin wrappers around the ordinary connect, so the common path pays nothing.
//!
//! Platform support mirrors what `socket2` exposes:
//!
//! * Linux/Android/Fuchsia — `SO_BINDTODEVICE` (needs root/`CAP_NET_RAW`).
//! * macOS/iOS/…, illumos/Solaris — `IP_BOUND_IF` / `IPV6_BOUND_IF` (no
//!   privilege required).
//!
//! On any other platform binding is unsupported: [`install`] fails up front and
//! the connect helpers behave like their std counterparts.

use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

// Platforms whose interface-binding socket option `socket2` exposes. Kept in
// one place so the real implementation and its fallback stay in lockstep.
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
))]
pub use imp::{install, requested, tcp_connect_timeout, udp_connect};

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
)))]
pub use stub::{install, requested, tcp_connect_timeout, udp_connect};

// ---------------------------------------------------------------------------
// Supported platforms: resolve the interface and set the bind-to-device option.
// ---------------------------------------------------------------------------
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
))]
mod imp {
    use super::*;
    use std::num::NonZeroU32;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::OnceLock;
    use std::time::Instant;

    use socket2::{Domain, Protocol, Socket, Type};

    /// The interface every probe socket is pinned to, resolved once by
    /// [`install`].
    struct Bound {
        /// The name as typed on the command line (`en0`), used for
        /// `SO_BINDTODEVICE` and for diagnostics.
        name: String,
        /// The `if_nametoindex` index, used for `IP_BOUND_IF` / `IPV6_BOUND_IF`.
        #[allow(dead_code)] // Unused on the SO_BINDTODEVICE (Linux) path.
        index: NonZeroU32,
    }

    /// The process-wide bound interface, set at most once via [`install`].
    static IFACE: OnceLock<Bound> = OnceLock::new();

    /// Resolve `name` to an interface index and pin every subsequent probe
    /// socket to it. The binding is validated immediately (Linux
    /// `SO_BINDTODEVICE` needs root), so an unusable interface fails here rather
    /// than turning every probe into a silent error. Calling more than once
    /// keeps the first interface.
    pub fn install(name: &str) -> Result<(), String> {
        let index =
            name_to_index(name).ok_or_else(|| format!("no such network interface: '{name}'"))?;
        let bound = Bound {
            name: name.to_string(),
            index,
        };

        // Prove the binding works now, on a throwaway socket, so a privilege or
        // support problem surfaces before the scan starts.
        let probe = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| format!("could not open a socket to test interface binding: {e}"))?;
        apply(&probe, &bound, true)
            .map_err(|e| format!("cannot bind to interface '{name}': {e}"))?;

        let _ = IFACE.set(bound);
        Ok(())
    }

    /// The name of the installed interface, if any, for diagnostics.
    pub fn requested() -> Option<&'static str> {
        IFACE.get().map(|b| b.name.as_str())
    }

    /// Open a TCP connection to `addr` within `timeout`, first pinning the
    /// socket to the installed interface (a no-op when none is set). The
    /// interface-aware replacement for [`TcpStream::connect_timeout`], with the
    /// same error classification.
    pub fn tcp_connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        if let Some(bound) = IFACE.get() {
            apply(&socket, bound, addr.is_ipv4())?;
        }
        connect_timeout(&socket, addr, timeout)?;
        Ok(TcpStream::from(OwnedFd::from(socket)))
    }

    /// Create a connected UDP socket to `target`, pinned to the installed
    /// interface (a no-op when none is set). Mirrors binding an ephemeral local
    /// socket in the target's address family and connecting it.
    pub fn udp_connect(target: SocketAddr) -> io::Result<UdpSocket> {
        let socket = Socket::new(
            Domain::for_address(target),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if let Some(bound) = IFACE.get() {
            apply(&socket, bound, target.is_ipv4())?;
        }
        let local: SocketAddr = if target.is_ipv4() {
            SocketAddr::from(([0u8; 4], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        socket.bind(&local.into())?;
        socket.connect(&target.into())?;
        Ok(UdpSocket::from(OwnedFd::from(socket)))
    }

    /// Connect `socket` to `addr` within `timeout`, resolving the outcome via
    /// `SO_ERROR` rather than `POLLHUP`.
    ///
    /// This mirrors `std::net::TcpStream::connect_timeout` on purpose.
    /// `socket2`'s own `connect_timeout` treats a `POLLHUP` returned by `poll`
    /// as a connection failure, but a peer that answers and then closes
    /// immediately (a banner service, a reset) can set `POLLHUP` on a socket
    /// whose connect actually *succeeded* — making an open port look closed
    /// under load. Checking `SO_ERROR` (which is 0 on success) is the robust
    /// test, so the error classification the scanners rely on
    /// (`ConnectionRefused` / `ConnectionReset` vs. no answer) stays correct.
    fn connect_timeout(socket: &Socket, addr: SocketAddr, timeout: Duration) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        let started = socket.connect(&addr.into());
        match started {
            // Connected synchronously (common for loopback).
            Ok(()) => {
                socket.set_nonblocking(false)?;
                return Ok(());
            }
            // Connection is in progress: wait for it below.
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            // Any other error is final.
            Err(e) => {
                let _ = socket.set_nonblocking(false);
                return Err(e);
            }
        }

        let poll_result = poll_writable(socket, timeout);
        socket.set_nonblocking(false)?;
        poll_result?;

        // The socket is writable (or hung up): the real outcome is in SO_ERROR.
        match socket.take_error()? {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Block until `socket` is writable or `timeout` elapses, via `poll`.
    /// A `POLLHUP`/`POLLERR` also wakes the poll; the caller then reads the true
    /// result from `SO_ERROR`.
    fn poll_writable(socket: &Socket, timeout: Duration) -> io::Result<()> {
        let start = Instant::now();
        let mut pollfd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let remaining = (timeout - elapsed)
                .as_millis()
                .clamp(1, libc::c_int::MAX as u128) as libc::c_int;
            // SAFETY: `pollfd` is a valid, initialised single-element array for
            // the duration of the call.
            let rv = unsafe { libc::poll(&mut pollfd, 1, remaining) };
            if rv < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if rv == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            return Ok(());
        }
    }

    /// Apply the platform's bind-to-device option to `socket`.
    fn apply(socket: &Socket, bound: &Bound, ipv4: bool) -> io::Result<()> {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            let _ = ipv4;
            socket.bind_device(Some(bound.name.as_bytes()))
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            if ipv4 {
                socket.bind_device_by_index_v4(Some(bound.index))
            } else {
                socket.bind_device_by_index_v6(Some(bound.index))
            }
        }
    }

    /// Resolve an interface name to its kernel index via `if_nametoindex`.
    /// Returns `None` for an unknown interface (index 0) or a name with an
    /// embedded NUL.
    fn name_to_index(name: &str) -> Option<NonZeroU32> {
        let cname = std::ffi::CString::new(name).ok()?;
        // SAFETY: `cname` is a valid NUL-terminated C string that outlives the
        // call; `if_nametoindex` only reads through the pointer.
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        NonZeroU32::new(index)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unknown_interface_has_no_index() {
            assert!(name_to_index("definitely-not-an-iface-9999").is_none());
        }

        #[test]
        fn install_rejects_an_unknown_interface() {
            let err = install("definitely-not-an-iface-9999").unwrap_err();
            assert!(err.contains("no such network interface"), "got: {err}");
        }

        #[test]
        fn loopback_resolves_to_an_index() {
            // The loopback interface is named `lo` on Linux and `lo0` on the
            // BSD/Darwin family; at least one must resolve.
            let resolved = name_to_index("lo").is_some() || name_to_index("lo0").is_some();
            assert!(resolved, "loopback interface should resolve to an index");
        }
    }
}

// ---------------------------------------------------------------------------
// Unsupported platforms: no interface binding; behave like the std connect.
// ---------------------------------------------------------------------------
#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
)))]
mod stub {
    use super::*;

    /// Interface binding is unavailable here; fail up front so the user is not
    /// misled into thinking a scan was pinned to an interface when it was not.
    pub fn install(_name: &str) -> Result<(), String> {
        Err("binding to a network interface is not supported on this platform".to_string())
    }

    /// No interface can be installed on this platform.
    pub fn requested() -> Option<&'static str> {
        None
    }

    /// Plain connect: no interface can be bound on this platform.
    pub fn tcp_connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout)
    }

    /// Plain connected UDP socket: no interface can be bound on this platform.
    pub fn udp_connect(target: SocketAddr) -> io::Result<UdpSocket> {
        let local = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(target)?;
        Ok(socket)
    }
}

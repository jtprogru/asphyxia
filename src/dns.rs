//! Reverse-DNS enrichment (`--resolve-ptr`).
//!
//! For each live host this module asks the system resolver for a PTR record and
//! then forward-confirms it by resolving the returned name back to an address.
//! The result is deliberately two fields — the observed `ptr` name and a
//! separate `ptr_confirmed` verdict — so a stale or spoofed PTR cannot be
//! mistaken for a fact.
//!
//! Lookups run on a worker thread with a caller-supplied timeout: a slow or
//! unresponsive resolver cannot extend the scan past that budget. A timeout is
//! reported as "no enrichment", never as a wrong answer.

use std::ffi::CStr;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Run `lookup` on a worker thread and wait at most `timeout` for its result.
///
/// The worker cannot be cancelled once it is blocked inside the OS resolver;
/// on timeout it is detached and the scan continues without enrichment. That is
/// the price of a bounded caller without pulling in an async DNS stack.
fn with_timeout<T, F>(timeout: Duration, lookup: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(lookup());
    });
    rx.recv_timeout(timeout).ok()
}

/// Resolve `ip` to a PTR name, then forward-confirm it.
///
/// Returns `(None, None)` when there is no PTR or the lookup timed out, and
/// `(Some(name), Some(false))` when a PTR exists but its forward lookup does not
/// contain `ip`. The two fields stay separate so a consumer can tell a fact
/// (`ptr`) from a verdict (`ptr_confirmed`).
pub fn resolve_ptr(ip: IpAddr, timeout: Duration) -> (Option<String>, Option<bool>) {
    let name = match with_timeout(timeout, move || ptr_lookup(ip)) {
        Some(Some(name)) => name,
        _ => return (None, None),
    };
    let name_for_lookup = name.clone();
    let confirmed =
        with_timeout(timeout, move || forward_confirm(ip, &name_for_lookup)).unwrap_or(false);
    (Some(name), Some(confirmed))
}

/// Ask the system resolver for a PTR record. Returns `None` on NXDOMAIN, a
/// resolver error, or a numeric-only answer.
#[cfg(unix)]
fn ptr_lookup(ip: IpAddr) -> Option<String> {
    use std::mem::size_of;

    let mut host = [0 as libc::c_char; 1025];
    let result = unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                // sockaddr stores the address in network byte order, which is
                // exactly the octet order of `Ipv4Addr`.
                addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                libc::getnameinfo(
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
                addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                addr.sin6_addr.s6_addr = v6.octets();
                libc::getnameinfo(
                    &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if result != 0 {
        return None;
    }
    // SAFETY: getnameinfo NUL-terminated the host buffer on success.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let name = name.trim_end_matches('.').to_string();
    if name.is_empty() || name == ip.to_string() {
        None
    } else {
        Some(name)
    }
}

/// Platforms without the Unix resolver API simply cannot enrich.
#[cfg(not(unix))]
fn ptr_lookup(_ip: IpAddr) -> Option<String> {
    None
}

/// Whether `name` resolves forward to `ip`.
fn forward_confirm(ip: IpAddr, name: &str) -> bool {
    (name, 0)
        .to_socket_addrs()
        .map(|addrs| addrs.into_iter().any(|addr| addr.ip() == ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn timeout_bounds_a_slow_lookup() {
        let start = Instant::now();
        let result = with_timeout(Duration::from_millis(20), || {
            thread::sleep(Duration::from_millis(200));
            Some("late")
        });
        assert!(result.is_none(), "a slow lookup must time out");
        assert!(
            start.elapsed() < Duration::from_millis(150),
            "the caller must not wait for the worker"
        );
    }

    #[test]
    fn timeout_returns_a_fast_result() {
        assert_eq!(
            with_timeout(Duration::from_secs(1), || Some("ok")),
            Some(Some("ok"))
        );
    }

    #[test]
    fn forward_confirm_rejects_an_unrelated_name() {
        // A syntactically valid name that does not resolve to the target. This
        // uses the system resolver, so it is kept to an obviously unrelated
        // address and accepts either a resolution failure or a mismatch.
        assert!(!forward_confirm(
            "192.0.2.1".parse().unwrap(),
            "localhost.invalid"
        ));
    }

    #[test]
    fn forward_confirm_accepts_matching_and_rejects_mismatching_names() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(forward_confirm(ip, "127.0.0.1"));
        assert!(!forward_confirm(ip, "192.0.2.1"));
    }

    #[cfg(unix)]
    #[test]
    fn ptr_lookup_returns_a_name_or_none_without_panicking() {
        // The exact answer depends on the host resolver; the invariant is that
        // the call returns cleanly and never fabricates the numeric address.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        if let Some(name) = ptr_lookup(ip) {
            assert_ne!(name, ip.to_string());
        }
    }
}

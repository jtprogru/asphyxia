//! Lightweight service and version detection (`--sV`).
//!
//! Once a TCP port is known to be open, this grabs a small banner from it and
//! matches that text against a compact set of built-in signatures (SSH, HTTP,
//! SMTP, FTP, …). It is deliberately not a full nmap-service-probes database —
//! just enough to answer "what is probably listening here?" without the network
//! cost or complexity of exhaustive probing.
//!
//! Detection has two phases: read whatever the service volunteers on connect
//! (SSH, SMTP, FTP announce themselves), and if it stays quiet, send a minimal
//! HTTP request to coax a reply out of web servers.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::iface;

/// Maximum number of banner bytes read from a service.
const BANNER_LIMIT: usize = 512;

/// A minimal probe for services that do not speak first; enough to make an HTTP
/// server reply with its status line and `Server:` header.
const HTTP_PROBE: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

/// Detect the service on an open TCP `port`, returning `(service, banner)`.
///
/// `service` is a short identification derived from the banner (or, failing
/// that, the well-known port), and `banner` is the sanitized first line the
/// service sent. Either may be `None` when nothing could be determined.
pub fn detect(ip: &str, port: u16, timeout: Duration) -> (Option<String>, Option<String>) {
    let banner = ip
        .parse::<IpAddr>()
        .ok()
        .and_then(|addr| grab_banner(SocketAddr::new(addr, port), timeout));

    let service = banner
        .as_deref()
        .and_then(match_service)
        .map(str::to_string)
        .or_else(|| service_by_port(port).map(str::to_string));

    (service, banner)
}

/// Connect and read a banner: take whatever the service offers on connect, and
/// if it is silent, nudge it with an HTTP request and read again. Returns the
/// sanitized first line, or `None` if nothing readable came back.
fn grab_banner(addr: SocketAddr, timeout: Duration) -> Option<String> {
    // Bind to `--interface` when set (a no-op otherwise) so the banner grab
    // follows the same route the port probe did.
    let mut stream = iface::tcp_connect_timeout(addr, timeout).ok()?;
    // Cap the read wait so a chatty-but-slow service cannot stall the scan.
    let read_timeout = timeout.min(Duration::from_secs(3));
    stream.set_read_timeout(Some(read_timeout)).ok()?;

    if let Some(banner) = read_banner(&mut stream) {
        return Some(banner);
    }

    // Quiet so far: send a tiny HTTP probe and try once more.
    stream.write_all(HTTP_PROBE).ok()?;
    read_banner(&mut stream)
}

/// Read up to [`BANNER_LIMIT`] bytes and sanitize them into a printable first
/// line. Returns `None` on read error or when nothing (printable) was received.
fn read_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; BANNER_LIMIT];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let banner = sanitize(&buf[..n]);
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

/// Turn raw banner bytes into a single printable line: decode as UTF-8 lossily,
/// take the first line, keep only printable characters, and trim.
fn sanitize(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let first_line = text.lines().next().unwrap_or("");
    first_line
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Match a banner against the built-in signatures, returning a short service
/// label (often including the product/version the banner revealed).
pub fn match_service(banner: &str) -> Option<&'static str> {
    let lower = banner.to_ascii_lowercase();

    // SSH and (E)SMTP/FTP/POP3/IMAP announce themselves on connect.
    if banner.starts_with("SSH-") {
        return Some("ssh");
    }
    if banner.starts_with("HTTP/") || lower.contains("server:") {
        return Some("http");
    }
    if banner.starts_with("220") && (lower.contains("ftp")) {
        return Some("ftp");
    }
    if banner.starts_with("220") && (lower.contains("smtp") || lower.contains("esmtp")) {
        return Some("smtp");
    }
    if banner.starts_with("+OK") {
        return Some("pop3");
    }
    if banner.starts_with("* OK") {
        return Some("imap");
    }
    if lower.contains("mysql") || lower.contains("mariadb") {
        return Some("mysql");
    }
    if lower.contains("-err") || lower.contains("+pong") || lower.contains("redis") {
        return Some("redis");
    }
    None
}

/// A best-effort service name for a well-known `port`, used only when no banner
/// could be matched.
pub fn service_by_port(port: u16) -> Option<&'static str> {
    let name = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "domain",
        80 | 8080 | 8000 | 8008 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        6379 => "redis",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ssh_banner() {
        assert_eq!(match_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu"), Some("ssh"));
    }

    #[test]
    fn matches_http_by_status_line_and_server_header() {
        assert_eq!(match_service("HTTP/1.1 200 OK"), Some("http"));
        assert_eq!(match_service("Server: nginx/1.25.3"), Some("http"));
    }

    #[test]
    fn matches_mail_and_ftp_greetings() {
        assert_eq!(
            match_service("220 mail.example.com ESMTP Postfix"),
            Some("smtp")
        );
        assert_eq!(match_service("220 (vsFTPd 3.0.5)"), Some("ftp"));
        assert_eq!(match_service("+OK POP3 ready"), Some("pop3"));
    }

    #[test]
    fn unknown_banner_matches_nothing() {
        assert_eq!(match_service("random gibberish"), None);
    }

    #[test]
    fn falls_back_to_well_known_port_names() {
        assert_eq!(service_by_port(22), Some("ssh"));
        assert_eq!(service_by_port(443), Some("https"));
        assert_eq!(service_by_port(9999), None);
    }

    #[test]
    fn sanitize_takes_the_first_printable_line() {
        assert_eq!(sanitize(b"SSH-2.0-OpenSSH\r\nextra\r\n"), "SSH-2.0-OpenSSH");
        // Control bytes are stripped; surrounding whitespace trimmed.
        assert_eq!(sanitize(b"  \x01\x02hello\x03  \n"), "hello");
        assert_eq!(sanitize(b""), "");
    }

    #[test]
    fn detect_reads_a_banner_from_a_local_server() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        // A local server that greets like SSH the moment a client connects.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
            }
        });

        let (service, banner) = detect("127.0.0.1", port, Duration::from_millis(500));
        assert_eq!(service.as_deref(), Some("ssh"));
        assert_eq!(banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        let _ = handle.join();
    }
}

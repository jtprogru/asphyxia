//! Privileged smoke tests for the raw-packet paths.
//!
//! They are `#[ignore]`d so an ordinary `cargo test` stays unprivileged and
//! hermetic. Run them explicitly with root / `CAP_NET_RAW`:
//!
//! ```text
//! sudo env "PATH=$PATH" cargo test --test root -- --ignored --nocapture
//! ```
//!
//! ARP/combined checks need a real on-link IPv4 target:
//!
//! ```text
//! sudo env "PATH=$PATH" ASPHYXIA_ARP_TARGET=192.168.1.1 \
//!   cargo test --test root -- --ignored --nocapture
//! ```

use assert_cmd::Command;
use predicates::prelude::*;

fn asphyxia() -> Command {
    let mut cmd = Command::cargo_bin("asphyxia").expect("binary should be built");
    cmd.env("ASPHYXIA_CONFIG", "/nonexistent/asphyxia-root-test.toml");
    cmd
}

#[test]
#[ignore = "requires root/CAP_NET_RAW; run with --ignored"]
fn icmp_discovery_reports_loopback() {
    asphyxia()
        .args([
            "as",
            "-t",
            "127.0.0.1",
            "--discovery",
            "icmp",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"discovery\":\"icmp\""))
        .stdout(predicate::str::contains("\"status\":\"up\""));
}

#[test]
#[ignore = "requires root/CAP_NET_RAW and an on-link target; set ASPHYXIA_ARP_TARGET"]
fn arp_discovery_reports_a_mac() {
    let Ok(target) = std::env::var("ASPHYXIA_ARP_TARGET") else {
        eprintln!("skipping: set ASPHYXIA_ARP_TARGET to an on-link IPv4 address");
        return;
    };
    asphyxia()
        .args(["as", "-t", &target, "--discovery", "arp", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"discovery\":\"arp\""))
        .stdout(predicate::str::contains("\"mac\":"));
}

#[test]
#[ignore = "requires root/CAP_NET_RAW and an on-link target; set ASPHYXIA_ARP_TARGET"]
fn combined_discovery_prefers_a_raw_probe() {
    let Ok(target) = std::env::var("ASPHYXIA_ARP_TARGET") else {
        eprintln!("skipping: set ASPHYXIA_ARP_TARGET to an on-link IPv4 address");
        return;
    };
    asphyxia()
        .args([
            "as",
            "-t",
            &target,
            "--discovery",
            "arp,icmp,tcp",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"discovery\":\"arp\"")
                .or(predicate::str::contains("\"discovery\":\"icmp\"")),
        );
}

#[test]
#[ignore = "requires root/CAP_NET_RAW and libpcap; run with --ignored"]
fn icmp_traceroute_reaches_loopback() {
    asphyxia()
        .args([
            "trace",
            "127.0.0.1",
            "--transport",
            "icmp",
            "--max-hops",
            "1",
            "--probes",
            "1",
            "--timeout",
            "500",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"reached\""))
        .stdout(predicate::str::contains("\"hops\""));
}

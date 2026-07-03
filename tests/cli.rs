//! End-to-end tests for the `asphyxia` binary.
//!
//! These exercise argument parsing and the validation/guidance paths that do
//! not touch the network, so they stay fast and deterministic. Numeric IPs are
//! used where a host is required, since they resolve without DNS.

use assert_cmd::Command;
use predicates::prelude::*;

fn asphyxia() -> Command {
    Command::cargo_bin("asphyxia").expect("binary `asphyxia` should be built")
}

#[test]
fn help_describes_the_tool() {
    asphyxia()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("network scanner"));
}

#[test]
fn version_flag_prints_version() {
    asphyxia()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn port_scan_requires_a_target() {
    // A target source is mandatory: either `-t/--host` or `--stdin`. With
    // neither, clap rejects the command and names the missing options.
    asphyxia()
        .args(["ps", "-s", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--host"))
        .stderr(predicate::str::contains("--stdin"));
}

#[test]
fn port_scan_host_and_stdin_are_mutually_exclusive() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "--stdin", "-s", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn port_scan_all_ports_conflicts_with_specific() {
    // `--all-ports` shares the `ports` group with `-r`/`-s`, so combining them
    // is rejected at parse time.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "--all-ports", "-s", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn port_scan_without_range_or_specific_prints_guidance() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Please specify either -r, -s, or --all-ports",
        ));
}

#[test]
fn port_scan_stdin_reads_plain_targets() {
    // A bare host per line is fed in; port 1 on loopback is closed, so the
    // machine output is an empty array — proving the target was read and scanned.
    asphyxia()
        .args(["ps", "--stdin", "-s", "1", "-o", "json"])
        .write_stdin("127.0.0.1\n")
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn port_scan_stdin_reads_jsonl_from_address_scan() {
    // The `ip` field of an `asphyxia as -o jsonl` record is used as the target.
    asphyxia()
        .args(["ps", "--stdin", "-s", "1", "-o", "json"])
        .write_stdin("{\"ip\":\"127.0.0.1\",\"proto\":\"tcp\",\"status\":\"up\"}\n")
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn port_scan_stdin_with_no_targets_prints_guidance() {
    asphyxia()
        .args(["ps", "--stdin", "-s", "1"])
        .write_stdin("")
        .assert()
        .success()
        .stderr(predicate::str::contains("No targets read from stdin"));
}

#[test]
fn port_scan_rejects_invalid_ports() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "22,abc,443"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid port number: abc"));
}

#[test]
fn port_scan_reports_unresolvable_host() {
    asphyxia()
        .args(["ps", "-t", "this-host-does-not-exist.invalid", "-s", "80"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Could not resolve host"));
}

#[test]
fn address_scan_without_args_prints_guidance() {
    asphyxia()
        .arg("as")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Please specify either -s, -t, or -r",
        ));
}

#[test]
fn address_scan_rejects_invalid_ip() {
    asphyxia()
        .args(["as", "-t", "not-an-ip"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid IP address: not-an-ip"));
}

#[test]
fn address_scan_rejects_invalid_subnet() {
    asphyxia()
        .args(["as", "-s", "192.168.1.0/33"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid subnet format"));
}

#[test]
fn concurrency_flag_is_accepted() {
    // The flag should parse on both subcommands; a bad subnet keeps the scan
    // off the network so the test stays fast and deterministic.
    asphyxia()
        .args(["as", "-s", "192.168.1.0/33", "--concurrency", "64"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid subnet format"));
}

#[test]
fn concurrency_flag_rejects_non_numeric() {
    asphyxia()
        .args(["as", "-s", "192.168.1.0/24", "--concurrency", "lots"])
        .assert()
        .failure();
}

#[test]
fn port_scan_json_with_no_open_ports_emits_empty_array() {
    // Port 1 on loopback is closed, so the machine output is an empty JSON
    // array and none of the human-facing banners leak onto stdout.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "json"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn port_scan_jsonl_with_no_open_ports_emits_nothing() {
    // JSON Lines prints one object per result; with no open ports stdout is
    // empty (zero lines), keeping the stream clean for a consumer.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::eq(""));
}

#[test]
fn address_scan_json_with_no_hosts_emits_empty_array() {
    asphyxia()
        .args(["as", "-t", "192.168.255.255", "-o", "json"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn output_flag_rejects_unknown_format() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "bogus"])
        .assert()
        .failure();
}

#[test]
fn text_output_remains_the_default() {
    // Without `-o`, the human-facing banner is still printed: this pins the
    // backwards-compatible default behaviour.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Game Over"));
}

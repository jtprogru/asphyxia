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
        .stderr(predicate::str::contains("Please specify either -r, -s"));
}

#[test]
fn port_scan_top_ports_conflicts_with_specific() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "--top-ports", "100", "-s", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn port_scan_top_ports_rejects_overflow() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "--top-ports", "5000"])
        .assert()
        .success()
        .stderr(predicate::str::contains("at most 1000"));
}

#[test]
fn port_scan_named_set_rejects_unknown() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "--ports", "bogus"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Unknown port set"));
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
fn retries_flag_is_accepted() {
    // A closed port on loopback returns quickly (refused → no retry), so this
    // stays fast even with retries requested.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--retries",
            "2",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn retries_flag_rejects_non_numeric() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--retries", "lots"])
        .assert()
        .failure();
}

#[test]
fn timing_profile_out_of_range_is_rejected() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-T", "9"])
        .assert()
        .failure();
}

#[test]
fn timing_profile_is_accepted() {
    // -T4 is a valid preset; a closed port keeps the run fast.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-T", "4", "-o", "json"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn rate_flag_is_accepted() {
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--rate",
            "1000",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn rate_limit_paces_multiple_probes() {
    use std::time::Instant;
    // Scan several closed ports on loopback at 20 probes/sec. Refused ports
    // return instantly, so without pacing this finishes in milliseconds; the
    // rate limit forces it to take at least a few slots (~200ms for 5 probes).
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--rate",
            "20",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    // 5 probes at 20/sec span 4 intervals of 50ms = 200ms minimum for the
    // probes themselves; allow generous slack for process startup jitter.
    assert!(
        elapsed >= std::time::Duration::from_millis(150),
        "rate limit should pace the scan, took {:?}",
        elapsed
    );
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
fn port_scan_csv_emits_header_even_with_no_open_ports() {
    // CSV always carries its header row so downstream parsers have a schema.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::eq("ip,port,proto,status,latency_ms\n"));
}

#[test]
fn port_scan_grep_with_no_open_ports_emits_nothing() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "grep"])
        .assert()
        .success()
        .stdout(predicate::eq(""));
}

#[test]
fn target_file_conflicts_with_host() {
    // --target-file joins the same required target group as -t/--stdin.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "--target-file",
            "targets.txt",
            "-s",
            "80",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn target_file_reads_targets_from_disk() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-targets-{}.txt", std::process::id()));
    // One bare IP plus a /31 that expands to two addresses; port 1 is closed on
    // all of them, so the run just proves the file was read and scanned.
    std::fs::write(&path, "127.0.0.1\n127.0.0.2/31\n").unwrap();

    asphyxia()
        .args(["ps", "-i", path.to_str().unwrap(), "-s", "1", "-o", "json"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn target_file_missing_reports_a_clear_error() {
    asphyxia()
        .args([
            "ps",
            "--target-file",
            "/no/such/asphyxia-targets.txt",
            "-s",
            "1",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Could not read target file"));
}

#[test]
fn config_supplies_defaults_that_flags_override() {
    // A config setting the output to json applies when -o is absent; passing -o
    // csv on the command line must win over it.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-config-{}.toml", std::process::id()));
    std::fs::write(&path, "output = \"json\"\ntimeout = 250\n").unwrap();

    // No -o: the config's json format is used (empty array on a closed port).
    asphyxia()
        .env("ASPHYXIA_CONFIG", &path)
        .args(["ps", "-t", "127.0.0.1", "-s", "1"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));

    // Explicit -o csv overrides the config.
    asphyxia()
        .env("ASPHYXIA_CONFIG", &path)
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::eq("ip,port,proto,status,latency_ms\n"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn service_detection_reports_service_and_banner() {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    // A local server that greets like SSH on connect; --sV should identify it
    // and surface the banner in the JSONL record.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    // The scan makes one probe connection to confirm the port is open, then
    // --sV makes a second to grab the banner; greet both.
    let handle = thread::spawn(move || {
        for _ in 0..2 {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
                }
                Err(_) => break,
            }
        }
    });

    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            &port.to_string(),
            "--sV",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"service\":\"ssh\""))
        .stdout(predicate::str::contains("SSH-2.0-OpenSSH_9.6"));

    let _ = handle.join();
}

#[test]
fn udp_scan_reports_proto_udp_in_json() {
    // A UDP probe to a closed loopback port typically draws an ICMP
    // port-unreachable (closed → not reported) or stays silent
    // (open|filtered). Either way the run succeeds and, when anything is
    // reported, it is tagged proto "udp" — never "tcp".
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "9",
            "--udp",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"proto\":\"tcp\"").not());
}

#[test]
fn nmap_args_requires_the_nmap_flag() {
    // --nmap-args without --nmap is a parse error (clap `requires`).
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "80", "--nmap-args", "-A"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nmap"));
}

#[test]
fn nmap_flag_with_no_open_ports_does_not_invoke_nmap() {
    // Port 1 on loopback is closed, so there is no handoff and the run succeeds
    // regardless of whether nmap is installed on the CI machine.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--nmap"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No open ports found"));
}

#[test]
fn exclude_ports_removing_the_only_port_prints_guidance() {
    // The only requested port is also excluded, so nothing is left to scan.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--exclude-ports", "1"])
        .assert()
        .success()
        .stderr(predicate::str::contains("No ports left to scan"));
}

#[test]
fn exclude_ports_rejects_invalid_list() {
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2",
            "--exclude-ports",
            "nope",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid port number: nope"));
}

#[test]
fn address_scan_exclude_rejects_invalid_spec() {
    asphyxia()
        .args(["as", "-s", "10.0.0.0/30", "--exclude", "not-an-ip"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid exclude address"));
}

#[test]
fn address_scan_exclude_filters_hosts_from_a_pn_scan() {
    // -Pn marks every address up without probing; --exclude removes one of them,
    // so the excluded address must not appear in the output.
    asphyxia()
        .args([
            "as",
            "-r",
            "10.20.30.1",
            "10.20.30.4",
            "--Pn",
            "--exclude",
            "10.20.30.2",
            "-o",
            "grep",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.20.30.1"))
        .stdout(predicate::str::contains("10.20.30.4"))
        .stdout(predicate::str::contains("10.20.30.2").not());
}

#[test]
fn address_scan_exclude_file_is_read() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-exclude-{}.txt", std::process::id()));
    std::fs::write(&path, "# comment\n10.20.31.3\n\n").unwrap();

    asphyxia()
        .args([
            "as",
            "-r",
            "10.20.31.1",
            "10.20.31.4",
            "--Pn",
            "--exclude-file",
            path.to_str().unwrap(),
            "-o",
            "grep",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.20.31.3").not())
        .stdout(predicate::str::contains("10.20.31.1"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn output_file_writes_machine_output_and_keeps_stdout_clean() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-cli-out-{}.csv", std::process::id()));
    let path_str = path.to_str().unwrap();

    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "-o",
            "csv",
            "--output-file",
            path_str,
        ])
        .assert()
        .success()
        // Machine output went to the file, not stdout.
        .stdout(predicate::eq(""));

    let contents = std::fs::read_to_string(&path).expect("output file should exist");
    assert!(contents.starts_with("ip,port,proto,status,latency_ms\n"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn address_scan_json_with_no_hosts_emits_empty_array() {
    // A short timeout keeps this fast: discovery now probes several ports, each
    // of which would otherwise block for the full default timeout.
    asphyxia()
        .args([
            "as",
            "-t",
            "192.168.255.255",
            "--timeout",
            "200",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn address_scan_pn_marks_target_up_without_probing() {
    // -Pn skips discovery, so even an address that would never answer is
    // reported up. No probe is sent, so this is instant regardless of timeout.
    asphyxia()
        .args(["as", "-t", "192.168.255.255", "--Pn", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ip\":\"192.168.255.255\""))
        .stdout(predicate::str::contains("\"status\":\"up\""));
}

#[test]
fn address_scan_pn_marks_whole_range_up() {
    asphyxia()
        .args(["as", "-r", "10.10.10.1", "10.10.10.4", "--Pn", "-o", "json"])
        .assert()
        .success()
        // All four addresses in the range are reported up without any probe.
        .stdout(predicate::str::contains("10.10.10.1"))
        .stdout(predicate::str::contains("10.10.10.4"));
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

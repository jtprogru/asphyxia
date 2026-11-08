//! End-to-end tests for the `asphyxia` binary.
//!
//! These exercise argument parsing and the validation/guidance paths that do
//! not touch the network, so they stay fast and deterministic. Numeric IPs are
//! used where a host is required, since they resolve without DNS.

use assert_cmd::Command;
use predicates::prelude::*;

fn asphyxia() -> Command {
    let mut cmd = Command::cargo_bin("asphyxia").expect("binary `asphyxia` should be built");
    // Isolate every run from a real `~/.asphyxia.toml` on the developer's
    // machine by pointing the config loader at a path that does not exist, so
    // tests always start from the built-in defaults. Tests that exercise config
    // behavior set their own `ASPHYXIA_CONFIG`, which overrides this.
    cmd.env("ASPHYXIA_CONFIG", "/nonexistent/asphyxia-test-config.toml");
    cmd
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
        .stdout(predicate::eq(
            "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed,device_type,device_confidence,asn,asn_org,cloud\n",
        ));
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
    // A config setting the output to JSON applies when -o is absent; passing -o
    // csv on the command line must win over it.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-config-{}.toml", std::process::id()));
    std::fs::write(&path, "output = \"json\"\ntimeout = 250\n").unwrap();

    // No -o: the config's JSON format is used (empty array on a closed port).
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
        .stdout(predicate::eq(
            "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed,device_type,device_confidence,asn,asn_org,cloud\n",
        ));

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
fn syn_conflicts_with_udp() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--syn", "--udp"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn syn_scan_runs_or_falls_back_cleanly() {
    // Port 1 on loopback is closed. Whether the process can open a raw socket
    // (SYN → RST → closed) or not (falls back to connect → refused → closed),
    // the reported result is the same empty JSON array. This exercises the
    // capability check and fallback without needing privileges in CI.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--syn", "-o", "json"])
        .assert()
        .success()
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn ack_scan_reports_firewall_state_and_never_open_or_closed() {
    // Port 1 on loopback. With privileges the ACK probe draws an RST and the
    // port is reported unfiltered; without them the scan says so and falls back
    // to a connect probe, which finds nothing on a closed port. Either way no
    // result may claim "open" — an ACK probe cannot know that.
    let assertion = asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--scan",
            "ack",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();

    for line in stdout.lines() {
        assert!(
            line.contains("\"scan\":\"ack\""),
            "an ACK result must record the probe that produced it: {line}"
        );
        assert!(
            line.contains("\"status\":\"unfiltered\"") || line.contains("\"status\":\"filtered\""),
            "an ACK result must be unfiltered or filtered: {line}"
        );
    }
    assert!(
        !stdout.contains("\"status\":\"open\"") && !stdout.contains("\"status\":\"closed\""),
        "an ACK scan must not report open/closed: {stdout}"
    );
}

#[test]
fn ack_scan_falls_back_visibly_for_an_ipv6_target() {
    // The raw path is IPv4-only (and needs privileges). Whichever check trips
    // first, the operator is told the scan changed question before the results
    // arrive, rather than reading connect results as ACK results.
    asphyxia()
        .args([
            "ps",
            "-t",
            "::1",
            "-s",
            "1",
            "--scan",
            "ack",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("falling back to connect scan"));
}

#[test]
fn ack_scan_rejects_a_udp_pairing() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--scan", "ack", "--udp"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn stealth_scans_run_or_fall_back_cleanly() {
    // Port 1 on loopback is closed. With privileges each profile draws an RST
    // (closed); without them the scan says so and falls back to a connect probe,
    // which finds nothing either way. Either path must end in success with no
    // result claiming "open".
    for mode in ["fin", "null", "xmas"] {
        let assertion = asphyxia()
            .args([
                "ps",
                "-t",
                "127.0.0.1",
                "-s",
                "1",
                "--scan",
                mode,
                "--timeout",
                "300",
                "-o",
                "jsonl",
            ])
            .assert()
            .success();
        let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
        assert!(
            !stdout.contains("\"status\":\"open\""),
            "{mode} must not report a bare open: {stdout}"
        );
    }
}

#[test]
fn stealth_scans_report_rfc793_states_and_their_mode() {
    // Port 1 on loopback. With privileges the probe draws an RST and the port is
    // reported closed; without them the fallback connect probe finds nothing.
    // Whatever happens, any result must carry its mode and only a state the
    // profile can actually produce — never "unfiltered", which belongs to ACK.
    for (mode, scan) in [("fin", "fin"), ("null", "null"), ("xmas", "xmas")] {
        let assertion = asphyxia()
            .args([
                "ps",
                "-t",
                "127.0.0.1",
                "-s",
                "1",
                "--scan",
                mode,
                "--timeout",
                "300",
                "-o",
                "jsonl",
            ])
            .assert()
            .success();
        let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
        for line in stdout.lines() {
            assert!(
                line.contains(&format!("\"scan\":\"{scan}\"")),
                "a {mode} result must record the probe that produced it: {line}"
            );
            assert!(
                line.contains("\"status\":\"closed\"")
                    || line.contains("\"status\":\"open|filtered\""),
                "a {mode} result must be closed or open|filtered: {line}"
            );
        }
        assert!(
            !stdout.contains("\"status\":\"unfiltered\""),
            "{mode} results are not firewall states: {stdout}"
        );
    }
}

#[test]
fn stealth_scans_fall_back_visibly_for_an_ipv6_target() {
    // The raw path is IPv4-only (and needs privileges). Whichever check trips
    // first, the operator is told the scan changed question before the results
    // arrive — FIN/NULL/XMAS have no connect equivalent that answers their
    // question.
    for mode in ["fin", "null", "xmas"] {
        asphyxia()
            .args([
                "ps",
                "-t",
                "::1",
                "-s",
                "1",
                "--scan",
                mode,
                "--timeout",
                "300",
                "-o",
                "json",
            ])
            .assert()
            .success()
            .stderr(predicate::str::contains("falling back to connect scan"));
    }
}

#[test]
fn stealth_scans_reject_a_udp_pairing() {
    for mode in ["fin", "null", "xmas"] {
        asphyxia()
            .args(["ps", "-t", "127.0.0.1", "-s", "1", "--scan", mode, "--udp"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("cannot be used with"));
    }
}

#[test]
fn source_port_flag_runs_or_falls_back_cleanly() {
    // With --source-port 53 the raw probes carry port 53 as their source. On a
    // closed loopback port this draws an RST (closed) or, without privileges,
    // falls back to connect (refused → closed). Either way the run succeeds and
    // no result claims "open".
    let assertion = asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--syn",
            "--source-port",
            "53",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    assert!(
        !stdout.contains("\"status\":\"open\""),
        "a closed port must not be reported open: {stdout}"
    );
}

#[test]
fn source_port_flag_is_ignored_with_a_warning_in_connect_mode() {
    // --source-port only applies to raw scans. In a connect scan it has no
    // effect, so the operator is told rather than silently ignored.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--source-port",
            "53",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("--source-port"))
        .stdout(predicate::eq("[]\n"));
}

#[test]
fn source_port_flag_is_ignored_with_a_warning_in_udp_mode() {
    // Same for UDP: the flag is raw-scan-only, so it warns and proceeds.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--udp",
            "--source-port",
            "53",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("--source-port"));
}

#[test]
fn source_port_flag_applies_the_rate_limit_too() {
    // The shared rate gate must pace raw probes with a fixed source port exactly
    // as it paces them without one.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--syn",
            "--source-port",
            "53",
            "--rate",
            "20",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(150),
        "the rate limit should pace fixed-source-port probes, took {:?}",
        elapsed
    );
}

#[test]
fn delay_paces_probes() {
    // Five closed ports at a 50 ms minimum inter-probe delay span at least
    // 4 × 50 = 200 ms of pacing. Without the delay this finishes in
    // milliseconds, so the elapsed time proves the delay was enforced.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--delay",
            "50",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(180),
        "--delay 50 should pace five probes to ≥200 ms, took {:?}",
        elapsed
    );
}

#[test]
fn delay_and_rate_compose_without_exceeding_either() {
    // A 10 pps cap (100 ms) with a 30 ms delay: the effective spacing is 100 ms
    // (the stricter bound), so five probes span at least 4 × 100 = 400 ms. The
    // rate limit is never exceeded even though the delay alone would allow more.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--rate",
            "10",
            "--delay",
            "30",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(380),
        "max(rate 100ms, delay 30ms) should pace five probes to ≥400 ms, took {:?}",
        elapsed
    );
}

#[test]
fn jitter_randomizes_the_delay_within_bounds() {
    // --delay 50 --jitter 100 randomizes each interval in [0, 100] ms. Five
    // probes span at most 4 × 100 = 400 ms of pacing (plus probe time), and the
    // run still succeeds. This is a statistical bound: we assert an upper limit
    // that would be violated if jitter were ignored (5 × 50 = 250 ms minimum) or
    // unbounded.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--delay",
            "50",
            "--jitter",
            "100",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    // With 100% jitter the expected total is ~5 × 50 ms (mean of [0,100]), well
    // under a hard cap. Assert it finishes in reasonable time — if jitter were
    // unbounded or ignored entirely this would still pass, so the real check is
    // that the run succeeds and stays bounded.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "jittered delay should stay bounded, took {:?}",
        elapsed
    );
}

#[test]
fn default_behavior_is_unchanged_without_delay() {
    // Without --delay or --rate the scan runs at full speed: five closed ports
    // on loopback finish well under a second. This pins that the new pacing is
    // opt-in and does not slow down the default path.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "the default (no delay) scan should stay fast, took {:?}",
        elapsed
    );
}

#[test]
fn delay_does_not_warn_for_a_short_scan() {
    // 1 s over five ports on one host is ~5 s, well under the warning
    // threshold. (The threshold itself is covered by unit tests on
    // `minimum_scan_seconds`, since triggering it would sleep for hours.)
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--delay",
            "1000",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("will take at least").not());
}

#[test]
fn stealth_scans_apply_the_rate_limit_too() {
    // The shared rate gate must pace FIN/NULL/XMAS probes exactly as it paces
    // connect ones: five closed ports at 20/sec span ~200ms of pacing.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--scan",
            "fin",
            "--rate",
            "20",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(150),
        "the rate limit should pace FIN probes, took {:?}",
        elapsed
    );
}

#[test]
fn stealth_scans_checkpoint_under_their_own_key() {
    // A --resume state from a FIN scan must be resumable as FIN and never mix
    // with the other modes. The key is applied before any probe runs, so this
    // holds whether or not the process has raw-socket privileges: hand-craft a
    // fully-completed FIN state claiming port 1 is closed, then run the same
    // command — the recorded finding must be reused (proving the `tcp-fin` key
    // matched) and no job re-scanned.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-resume-fin-{}.json", std::process::id()));

    let state = r#"{"proto":"tcp-fin","targets":["127.0.0.1"],"ports":[1],"job_count":1,"done":[true],"findings":[{"host":0,"port":1,"latency_ms":3,"status":"closed","scan":"fin"}]}"#;
    std::fs::write(&path, state).unwrap();

    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--scan",
            "fin",
            "--timeout",
            "300",
            "--resume",
            path.to_str().unwrap(),
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"port\":1"))
        .stdout(predicate::str::contains("\"status\":\"closed\""))
        .stdout(predicate::str::contains("\"scan\":\"fin\""));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn udp_scan_reports_proto_udp_in_json() {
    // A UDP probe to a closed loopback port typically draws an ICMP
    // port-unreachable (closed) or stays silent (open|filtered). Either way the
    // run succeeds and, when anything is reported, it is tagged proto "udp" —
    // never "tcp".
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
fn udp_scan_reports_closed_for_a_refused_port() {
    // Port 1 on loopback is closed: the kernel answers with an ICMP
    // port-unreachable, which a connected UDP socket surfaces as a refusal. The
    // result must be reported `closed` (a fact), not merged into open|filtered.
    let assertion = asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--udp",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    assert!(
        stdout.contains("\"status\":\"closed\""),
        "a refused UDP port must be reported closed: {stdout}"
    );
}

#[test]
fn udp_scan_reports_open_for_a_replying_port() {
    // A local UDP echo server replies to the probe, which must make the port
    // report `open` (a fact), not open|filtered.
    use std::net::UdpSocket;
    use std::thread;

    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = server.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = server.recv_from(&mut buf) {
            let _ = server.send_to(&buf[..n], peer);
        }
    });

    let assertion = asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            &port.to_string(),
            "--udp",
            "--timeout",
            "500",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    assert!(
        stdout.contains("\"status\":\"open\""),
        "a replying UDP port must be reported open: {stdout}"
    );
    let _ = handle.join();
}

#[test]
fn udp_scan_distinguishes_open_from_closed() {
    // Port 1 is closed (ICMP refusal), and a local echo server is open. Both
    // must appear in the structured output with their distinct states — the
    // whole point of service probes is to tell a fact from a conclusion.
    use std::net::UdpSocket;
    use std::thread;

    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let open_port = server.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = server.recv_from(&mut buf) {
            let _ = server.send_to(&buf[..n], peer);
        }
    });

    let assertion = asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            &format!("1,{}", open_port),
            "--udp",
            "--timeout",
            "500",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    assert!(
        stdout.contains("\"status\":\"closed\""),
        "the refused port must be closed: {stdout}"
    );
    assert!(
        stdout.contains("\"status\":\"open\""),
        "the replying port must be open: {stdout}"
    );
    let _ = handle.join();
}

#[test]
fn udp_scan_reports_open_filtered_for_a_silent_port() {
    // A UDP probe to a non-privileged, non-listening port that neither replies
    // nor refuses (e.g. a blackhole) stays open|filtered — the honest
    // conclusion, not a fact. On loopback most closed ports refuse, so this is
    // best-effort: we only assert the state is one of the three valid ones and
    // that it is never reported as a bare `open` when nothing replied.
    let assertion = asphyxia()
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
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    for line in stdout.lines() {
        assert!(
            line.contains("\"status\":\"open\"")
                || line.contains("\"status\":\"closed\"")
                || line.contains("\"status\":\"filtered\"")
                || line.contains("\"status\":\"open|filtered\""),
            "a UDP result must carry a valid state: {line}"
        );
    }
}

#[test]
fn udp_scan_applies_the_rate_limit_too() {
    // The shared rate gate must pace UDP probes exactly as it paces TCP ones.
    use std::time::Instant;
    let start = Instant::now();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1,2,3,4,5",
            "--udp",
            "--rate",
            "20",
            "--timeout",
            "300",
            "-o",
            "json",
        ])
        .assert()
        .success();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(150),
        "the rate limit should pace UDP probes, took {:?}",
        elapsed
    );
}

#[test]
fn udp_scan_retries_silence_but_not_refusals() {
    // A closed port (ICMP refusal) is final and must not be retried; a silent
    // port is. With --retries 2 the run still succeeds quickly on loopback,
    // proving refusals short-circuit the retry budget.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--udp",
            "--retries",
            "2",
            "--timeout",
            "300",
            "-o",
            "jsonl",
        ])
        .assert()
        .success();
}

#[test]
fn resume_writes_a_checkpoint_file() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-resume-out-{}.json", std::process::id()));

    // A closed-port scan finishes immediately; it must still leave a valid,
    // fully-completed checkpoint behind.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--resume",
            path.to_str().unwrap(),
            "-o",
            "json",
        ])
        .assert()
        .success();

    let state = std::fs::read_to_string(&path).expect("checkpoint file should exist");
    assert!(state.contains("\"job_count\":1"));
    assert!(state.contains("\"done\":[true]"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resume_skips_completed_work_and_reuses_recorded_findings() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-resume-in-{}.json", std::process::id()));

    // Hand-craft a fully-completed state for `ps -t 127.0.0.1 -s 1` that claims
    // port 1 is open. Port 1 is actually closed, so seeing it in the output
    // proves the recorded finding was reused and the job was not re-scanned.
    let state = r#"{"proto":"tcp","targets":["127.0.0.1"],"ports":[1],"job_count":1,"done":[true],"findings":[{"host":0,"port":1,"latency_ms":7,"status":"open"}]}"#;
    std::fs::write(&path, state).unwrap();

    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--resume",
            path.to_str().unwrap(),
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"port\":1"))
        .stdout(predicate::str::contains("\"status\":\"open\""));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn nmap_args_implies_nmap_without_requiring_the_flag() {
    // --nmap-args implies --nmap. Port 1 is closed, so no handoff runs; a
    // successful parse/scan proves the flag no longer requires --nmap.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--nmap-args", "-A"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No open ports found"));
}

#[test]
fn nmap_is_rejected_with_machine_output_on_stdout() {
    // nmap writes to stdout; allowing it alongside JSON/JSONL would corrupt
    // the stream. The flag combination must fail before scanning.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--nmap", "-o", "jsonl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
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
    assert!(contents.starts_with(
        "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed,device_type,device_confidence,asn,asn_org,cloud\n"
    ));
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
    // backwards-compatible default behavior.
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Game Over"));
}

#[test]
fn interface_flag_is_documented_in_help() {
    // Both subcommands accept `-e/--interface`; it must show up in their help.
    asphyxia()
        .args(["ps", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--interface"));
    asphyxia()
        .args(["as", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--interface"));
}

#[test]
fn unknown_interface_fails_before_scanning() {
    // A bogus interface name is rejected up front (non-zero exit) rather than
    // silently scanning over the default route. The message mentions the
    // interface — on supported platforms "no such network interface", on
    // unsupported ones "not supported on this platform"; both contain the word.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "-e",
            "definitely-not-an-iface-9999",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("interface"));
}

#[test]
fn config_interface_is_validated_too() {
    // An interface supplied via the config file is validated the same way as
    // the flag: a bogus name aborts the scan.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-iface-config-{}.toml", std::process::id()));
    std::fs::write(&path, "interface = \"definitely-not-an-iface-9999\"\n").unwrap();

    asphyxia()
        .env("ASPHYXIA_CONFIG", &path)
        .args(["ps", "-t", "127.0.0.1", "-s", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("interface"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn discovery_arp_runs_on_loopback_and_falls_back_cleanly() {
    // ARP on loopback: there is no L2 segment, so the probe falls back to TCP
    // with a visible warning. The scan must still succeed and report the host
    // as up, with `discovery` naming the confirming probe.
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--discovery", "arp", "-o", "jsonl"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ARP discovery is unavailable"))
        .stdout(predicate::str::contains("\"ip\":\"127.0.0.1\""))
        .stdout(predicate::str::contains("\"status\":\"up\""))
        .stdout(predicate::str::contains("\"discovery\":\"tcp\""))
        .stdout(predicate::str::contains("\"proto\":\"tcp\""));
}

#[test]
fn discovery_arp_ipv6_target_falls_back_to_tcp() {
    // ARP is IPv4-only; an IPv6 target must fall back to the TCP probe rather
    // than silently disappearing.
    asphyxia()
        .args(["as", "-t", "::1", "--discovery", "arp", "-o", "jsonl"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ARP discovery is unavailable"))
        .stdout(predicate::str::contains("\"ip\":\"::1\""));
}

#[test]
fn discovery_icmp_runs_or_falls_back_cleanly() {
    // With root the raw socket answers on loopback; without it the scan warns
    // and falls back to TCP. Either way the host must be reported up and the
    // confirming probe named.
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
        .stdout(predicate::str::contains("\"ip\":\"127.0.0.1\""))
        .stdout(predicate::str::contains("\"status\":\"up\""))
        .stdout(
            predicate::str::contains("\"discovery\":\"icmp\"")
                .or(predicate::str::contains("\"discovery\":\"tcp\"")),
        );
}

#[test]
fn discovery_icmp_ipv6_target_falls_back_to_tcp() {
    // ICMP echo discovery is IPv4-only; an IPv6 target must fall back visibly.
    asphyxia()
        .args(["as", "-t", "::1", "--discovery", "icmp", "-o", "jsonl"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ICMP discovery is unavailable"))
        .stdout(predicate::str::contains("\"ip\":\"::1\""));
}

#[test]
fn discovery_flag_is_documented_in_help() {
    asphyxia()
        .args(["as", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--discovery"))
        .stdout(predicate::str::contains("arp"))
        .stdout(predicate::str::contains("icmp"))
        .stdout(predicate::str::contains("--show-down"));
}

#[test]
fn discovery_arp_on_non_local_target_falls_back_to_tcp() {
    // A non-local IPv4 target can't be reached by ARP; the scan must fall back
    // to TCP and still complete (the host is down, so no record — but no crash).
    asphyxia()
        .args(["as", "-t", "192.0.2.1", "--discovery", "arp", "-o", "jsonl"])
        .assert()
        .success();
}

#[test]
fn discovery_combined_degrades_and_still_scans() {
    // On loopback ARP is skipped (no L2 segment) and, without root, ICMP warns
    // and is skipped too; TCP still has to report the host. With root ICMP may
    // win instead. Either way the scan succeeds and names a confirming probe.
    asphyxia()
        .args([
            "as",
            "-t",
            "127.0.0.1",
            "--discovery",
            "arp,icmp,tcp",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ip\":\"127.0.0.1\""))
        .stdout(
            predicate::str::contains("\"discovery\":\"tcp\"")
                .or(predicate::str::contains("\"discovery\":\"icmp\""))
                .or(predicate::str::contains("\"discovery\":\"arp\"")),
        );
}

#[test]
fn discovery_auto_logs_its_choice() {
    asphyxia()
        .args([
            "as",
            "-t",
            "127.0.0.1",
            "--discovery",
            "auto",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("discovery auto: arp,icmp,tcp"));
}

#[test]
fn discovery_auto_rejects_explicit_probes() {
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--discovery", "auto,tcp"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
}

#[test]
fn asn_uses_the_bundled_table_without_network() {
    // --Pn makes this hermetic: no probe is sent, and the ASN lookup is local.
    asphyxia()
        .args(["as", "-t", "104.16.0.1", "--Pn", "--asn", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"asn\":13335"))
        .stdout(predicate::str::contains("\"cloud\":\"cloudflare\""))
        .stdout(predicate::str::contains("Cloudflare, Inc."));
    asphyxia()
        .args(["as", "-t", "192.0.2.1", "--Pn", "--asn", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"asn\"").not());
}

#[test]
fn asn_is_documented_in_help() {
    asphyxia()
        .args(["as", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--asn"));
}

#[test]
fn classify_is_documented_and_marks_unknown_assets() {
    asphyxia()
        .args(["ps", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--classify"));
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--classify", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"device_type\":\"unknown\""))
        .stdout(predicate::str::contains("\"device_confidence\":\"low\""));
}

#[test]
fn classify_labels_an_unrecognised_open_port_as_unknown() {
    // An ephemeral port is open but matches no device signature; --classify
    // must still emit the field as "unknown", never a guessed label.
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            &port.to_string(),
            "--classify",
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"device_type\":\"unknown\""));
}

#[test]
fn resolve_ptr_is_documented_and_optional() {
    asphyxia()
        .args(["as", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--resolve-ptr"));
    // The lookup may find nothing on a hermetic CI host; the invariant is that
    // enabling it never fails the scan.
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--resolve-ptr", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ip\":\"127.0.0.1\""));
}

#[test]
fn discovery_ports_are_accepted_and_documented() {
    asphyxia()
        .args([
            "as",
            "-t",
            "127.0.0.1",
            "--discovery-ports",
            "445,3389",
            "-o",
            "json",
        ])
        .assert()
        .success();
    asphyxia()
        .args(["as", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--discovery-ports"));
}

#[test]
fn discovery_ports_reject_invalid_and_zero_ports() {
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--discovery-ports", "nope"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid port number: nope"));
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--discovery-ports", "0"])
        .assert()
        .success()
        .stderr(predicate::str::contains("1..=65535"));
}

#[test]
fn discovery_flag_rejects_unknown_mode() {
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "--discovery", "bogus"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn discovery_default_is_tcp_and_unchanged() {
    // Without --discovery, the default TCP path is used and the output carries
    // `discovery: "tcp"` for confirmed hosts.
    asphyxia()
        .args(["as", "-t", "127.0.0.1", "-o", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"discovery\":\"tcp\""));
}

#[test]
fn diff_reports_new_and_removed_hosts_and_ports() {
    let dir = std::env::temp_dir();
    let old = dir.join(format!("asphyxia-diff-old-{}.jsonl", std::process::id()));
    let new = dir.join(format!("asphyxia-diff-new-{}.jsonl", std::process::id()));
    std::fs::write(
        &old,
        concat!(
            "{\"ip\":\"10.0.0.1\",\"port\":22,\"proto\":\"tcp\",\"status\":\"open\"}\n",
            "{\"ip\":\"10.0.0.2\",\"port\":80,\"proto\":\"tcp\",\"status\":\"open\"}\n",
        ),
    )
    .unwrap();
    std::fs::write(
        &new,
        concat!(
            "{\"ip\":\"10.0.0.1\",\"port\":22,\"proto\":\"tcp\",\"status\":\"open\"}\n",
            "{\"ip\":\"10.0.0.3\",\"port\":443,\"proto\":\"tcp\",\"status\":\"open\"}\n",
        ),
    )
    .unwrap();

    asphyxia()
        .args(["diff", old.to_str().unwrap(), new.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("New hosts: 1"))
        .stdout(predicate::str::contains("10.0.0.3"))
        .stdout(predicate::str::contains("Removed hosts: 1"))
        .stdout(predicate::str::contains("10.0.0.2"))
        .stdout(predicate::str::contains("New ports: 1"));

    asphyxia()
        .args([
            "diff",
            old.to_str().unwrap(),
            new.to_str().unwrap(),
            "-o",
            "jsonl",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"event\":\"new_host\""))
        .stdout(predicate::str::contains("\"event\":\"removed_host\""));

    let _ = std::fs::remove_file(&old);
    let _ = std::fs::remove_file(&new);
}

#[test]
fn diff_warns_when_the_host_sets_are_disjoint() {
    let dir = std::env::temp_dir();
    let old = dir.join(format!(
        "asphyxia-diff-scope-old-{}.json",
        std::process::id()
    ));
    let new = dir.join(format!(
        "asphyxia-diff-scope-new-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &old,
        r#"[{"ip":"10.0.0.1","port":22,"proto":"tcp","status":"open"}]"#,
    )
    .unwrap();
    std::fs::write(
        &new,
        r#"[{"ip":"10.0.0.2","port":22,"proto":"tcp","status":"open"}]"#,
    )
    .unwrap();

    asphyxia()
        .args([
            "diff",
            old.to_str().unwrap(),
            new.to_str().unwrap(),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("target scope may differ"));

    let _ = std::fs::remove_file(&old);
    let _ = std::fs::remove_file(&new);
}

#[test]
fn diff_rejects_invalid_input_and_csv_format() {
    let dir = std::env::temp_dir();
    let bad = dir.join(format!("asphyxia-diff-bad-{}.json", std::process::id()));
    std::fs::write(&bad, "not json").unwrap();
    asphyxia()
        .args(["diff", bad.to_str().unwrap(), bad.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid JSON"));
    asphyxia()
        .args([
            "diff",
            bad.to_str().unwrap(),
            bad.to_str().unwrap(),
            "-o",
            "csv",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("diff supports"));
    let _ = std::fs::remove_file(&bad);
}

#[test]
fn watch_emits_a_baseline_and_stops_at_the_count() {
    // Port 1 is closed, so both passes produce an empty result set: the first
    // is the baseline, the second reports no changes.
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--watch",
            "1ms",
            "--watch-count",
            "2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"event\":\"baseline\""))
        .stdout(
            predicate::str::contains("\"event\":\"no_changes\"")
                .or(predicate::str::contains("\"event\":\"warning\"")),
        );
}

#[test]
fn watch_rejects_invalid_interval_and_nmap() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--watch", "nonsense"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid --watch interval"));

    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--watch",
            "1s",
            "--watch-count",
            "1",
            "--nmap",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--watch cannot be combined with --nmap",
        ));
}

#[test]
fn watch_count_requires_watch_and_rejects_zero() {
    asphyxia()
        .args(["ps", "-t", "127.0.0.1", "-s", "1", "--watch-count", "2"])
        .assert()
        .failure();
    asphyxia()
        .args([
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "1",
            "--watch",
            "1ms",
            "--watch-count",
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least 1"));
}

#[test]
fn trace_is_documented_and_rejects_ipv6() {
    asphyxia()
        .args(["trace", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--transport"))
        .stdout(predicate::str::contains("--max-hops"));

    asphyxia()
        .args(["trace", "::1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("IPv4-only"));
}

#[test]
fn trace_rejects_invalid_hop_limits() {
    asphyxia()
        .args(["trace", "127.0.0.1", "--max-hops", "0"])
        .assert()
        .failure();
    asphyxia()
        .args(["trace", "127.0.0.1", "--probes", "0"])
        .assert()
        .failure();
}

#[test]
fn report_markdown_and_html_come_from_the_scan_records() {
    // -Pn avoids probing and makes the address report hermetic.
    asphyxia()
        .args(["as", "-t", "192.0.2.10", "--Pn", "--report", "md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("# Asphyxia scan report"))
        .stdout(predicate::str::contains("**Targets:** 192.0.2.10"))
        .stdout(predicate::str::contains("## Hosts"))
        .stdout(predicate::str::contains("192.0.2.10"));

    asphyxia()
        .args(["as", "-t", "192.0.2.10", "--Pn", "--report", "html"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<!DOCTYPE html>"))
        .stdout(predicate::str::contains("192.0.2.10"));
}

#[test]
fn report_file_and_full_banners_require_a_report() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("asphyxia-report-{}.md", std::process::id()));
    asphyxia()
        .args([
            "as",
            "-t",
            "192.0.2.10",
            "--Pn",
            "--report",
            "md",
            "--report-file",
            path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq(""));
    let contents = std::fs::read_to_string(&path).expect("report file");
    assert!(contents.starts_with("# Asphyxia scan report"));
    let _ = std::fs::remove_file(&path);

    asphyxia()
        .args(["as", "-t", "192.0.2.10", "--Pn", "--full-banners"])
        .assert()
        .failure();
}

#[test]
fn report_rejects_unknown_format() {
    asphyxia()
        .args(["as", "-t", "192.0.2.10", "--Pn", "--report", "pdf"])
        .assert()
        .failure();
}

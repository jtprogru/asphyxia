# Changelog

All notable changes to Asphyxia are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.11.0] - 2026-11-08

This release completes the network-reconnaissance roadmap: discovery beyond
TCP, asset identity, temporal comparison, topology and reporting.

### Added

- **ARP host discovery** (`as --discovery arp`) for locally-connected IPv4
  subnets, with MAC/OUI output and a visible TCP fallback.
- **ICMP echo discovery** (`as --discovery icmp`) for routed IPv4 hosts.
- **Combined discovery** (`--discovery arp,icmp,tcp`) and `auto`, naming the
  probe that confirmed each host and degrading unavailable probes to warnings.
- **`--discovery-ports`** for a custom TCP discovery-port set.
- **`--show-down`** to emit ICMP non-responders with `reason: "unreachable"` or
  `"no-response"`.
- **Reverse DNS enrichment** (`as --resolve-ptr`) with separate `ptr` and
  forward-confirmed `ptr_confirmed` fields.
- **Device classification** (`--classify`) with `device_type` and
  `device_confidence`, using only already-collected ports/banners/OUI.
- **Offline ASN/cloud hints** (`--asn`) from a bundled prefix table; no DNS or
  API requests.
- **`asphyxia diff`** for new/removed hosts and ports plus status/service/banner
  changes, with text, JSON and JSONL event output.
- **Watch mode** (`ps --watch <interval>`, `--watch-count`) with a baseline,
  per-pass diff events and bounded memory.
- **`asphyxia trace`** with TCP (default) and ICMP transports, per-hop RTT/loss,
  visible silent hops and `first_silent_hop`.
- **Markdown/HTML reports** (`--report md|html`, `--report-file`,
  `--full-banners`) grouped by host, service and device type.
- Output fields `discovery`, `mac`, `oui`, `reason`, `ptr`, `ptr_confirmed`,
  `device_type`, `device_confidence`, `asn`, `asn_org` and `cloud`; CSV/grep now
  carry the full 19-column record.

### Changed

- `--delay` is now a **per-host** interval; `--rate` remains a single global
  cap. The ETA warning uses the correct per-host/global lower bound.
- `--nmap` uses `-sU -sV` for UDP handoffs, `--nmap-args` implies `--nmap`, and
  `--nmap` is rejected when a machine format writes to stdout.
- Report mode replaces normal output and skips the `--nmap` handoff (with a
  warning); `--watch` ignores report/output flags and rejects `--nmap`,
  `--stdin` and `--resume`.
- `--discovery` accepts a comma-separated list; `auto` is opt-in while `tcp`
  stays the unprivileged default.
- CSV/grep gained the enrichment/reason/classification columns (strict
  six-column consumers should update).

### Fixed

- Replaced the non-functional ARP stub with a real libpcap request/reply path.
- Made the SNMP BER GetRequest and mDNS query valid on the wire.
- Corrected the UDP `closed` documentation and status handling.
- SYN findings now report real latency instead of zero.
- `--sV` banner grabs pass through the rate/delay pacer.
- Fixed `--nmap`/machine-output corruption and rustdoc warnings.
- Corrected the vacuous delay-warning test and several documentation overclaims.

### Documentation

- README, `--help`, the roadmap and all 16 task files were synchronized with the
  implemented behavior and explicit limitations (ICMP `filtered` for
  FIN/NULL/XMAS, external ASN, scanner-format import/export).
- Root smoke tests confirmed ARP, ICMP and combined discovery on a live
  `192.168.55.0/24` network.

[0.11.0]: https://github.com/jtprogru/asphyxia/releases/tag/0.11.0

# Asphyxia

[![CI](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml)
[![Rust Release](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml)
[![crates.io](https://img.shields.io/crates/v/asphyxia.svg)](https://crates.io/crates/asphyxia)
[![docs.rs](https://img.shields.io/docsrs/asphyxia)](https://docs.rs/asphyxia)
[![Downloads](https://img.shields.io/crates/d/asphyxia.svg)](https://crates.io/crates/asphyxia)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/crates/l/asphyxia.svg)](LICENSE)

A fast and efficient network scanner written in Rust.

## Description

Asphyxia is a command-line network scanner that helps you discover open ports on a host and find reachable hosts on a network. It runs scans in parallel for speed and shows live progress while it works.

## Features

- **Port scanning** — scan a range of ports, a specific comma-separated list, the entire port range (`--all-ports`), the N most common ports (`--top-ports`), or a named port set (`--ports web`) on a target host.
- **Address scanning** — check a single IP, scan an IP range, or scan an entire subnet (CIDR).
- **Chainable scans** — pipe the hosts an address scan discovers straight into a port scan with `--stdin`, turning host discovery and port scanning into a single pipeline.
- **IPv4 and IPv6** — every scan mode accepts both address families.
- **Configurable timeout** — tune the per-connection timeout with `--timeout`.
- **Parallel execution** — scans run concurrently via [rayon](https://crates.io/crates/rayon), with tunable concurrency (`--concurrency`) for large subnet scans.
- **Live progress bars** — long-running scans show real-time progress.
- **Colorized output** — readable, colored terminal output.
- **Machine-readable output** — emit results as JSON, JSON Lines, CSV, or greppable text with `--output`, and write them straight to a file with `--output-file`, for piping into other tools.

> Note: IPv6 subnet and range scans are capped at 65 536 addresses (e.g. a `/112`), since larger IPv6 spaces are impractical to walk exhaustively.

## Installation

### Homebrew (macOS & Linux)

```bash
brew tap jtprogru/tap
brew install jtprogru/tap/asphyxia
```

The formula is published automatically to the [jtprogru/homebrew-tap](https://github.com/jtprogru/homebrew-tap) tap on every release and supports macOS (Apple Silicon) and Linux (x86_64 & arm64).

### Cargo

Install the latest published release from [crates.io](https://crates.io/crates/asphyxia):

```bash
cargo install asphyxia
```

Or install the current `main` branch straight from the repository:

```bash
cargo install --git https://github.com/jtprogru/asphyxia
```

### Prebuilt binaries

Download the archive for your platform from the [latest release](https://github.com/jtprogru/asphyxia/releases/latest), unzip it, and place the `asphyxia` binary somewhere on your `PATH`. Builds are provided for:

- Linux: `x86_64`, `aarch64`
- macOS: `aarch64` (Apple Silicon)

Each archive is shipped with a detached GPG signature (`.asc`). After importing the signing key you can verify an archive with:

```bash
gpg --verify asphyxia-<target>.zip.asc asphyxia-<target>.zip
```

### Building from source

Requires Rust 1.88 or newer (the project uses the 2024 edition).

```bash
git clone https://github.com/jtprogru/asphyxia.git
cd asphyxia
cargo build --release
```

The compiled binary will be available at `target/release/asphyxia`.

## Usage

Asphyxia exposes two subcommands: `ps` (port scan) and `as` (address scan).

```bash
asphyxia --help        # general help
asphyxia ps --help     # port scan options
asphyxia as --help     # address scan options
```

### Port scanning (`ps`)

```bash
# Scan a range of ports (start end)
asphyxia ps -t example.com -r 80 443

# Scan specific ports (comma-separated)
asphyxia ps -t example.com -s 22,80,443,8080

# Scan every port (1-65535)
asphyxia ps -t example.com --all-ports

# Scan the N most common TCP ports (frequency-ordered, no manual list)
asphyxia ps -t example.com --top-ports 100
asphyxia ps -t example.com --top-ports 1000

# Scan a named port set (web, mail, db, remote, windows)
asphyxia ps -t example.com --ports web

# Drop specific ports from the set, and spare known CDN/WAF targets (80/443 only)
asphyxia ps -t example.com --top-ports 1000 --exclude-ports 9100,631
asphyxia ps --stdin --top-ports 1000 --exclude-cdn < hosts.txt

# Find open ports fast, then hand them to nmap for a deep dive
asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap
asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap --nmap-args "-A -T4"

# Scan an IPv6 host with a shorter timeout
asphyxia ps -t 2001:db8::1 -s 22,80,443 --timeout 500

# Read targets from stdin instead of -t (one host per line, or JSON/JSONL from `as`)
asphyxia ps --stdin -s 22,80,443 < hosts.txt
```

Exactly one target source is required — either `-t/--host` or `--stdin` — and they are mutually exclusive. Likewise `-r`, `-s`, `--all-ports`, `--top-ports`, and `--ports` are mutually exclusive.

| Flag | Description |
|------|-------------|
| `-t, --host <HOST>` | Target host (hostname, IPv4, or IPv6) |
| `--stdin` | Read targets from stdin instead of `-t`: one host per line, or the JSON/JSONL emitted by `asphyxia as -o` (the `ip` field is used) |
| `-r, --range <START> <END>` | Scan an inclusive range of ports |
| `-s, --specific <PORTS>` | Scan specific comma-separated ports |
| `-a, --all-ports` | Scan the entire port range (1-65535) |
| `--top-ports <N>` | Scan the `N` most common TCP ports (frequency-ordered, up to 1000) |
| `--ports <NAME>` | Scan a named port set: `web`, `mail`, `db`, `remote`, `windows` |
| `--exclude-ports <PORTS>` | Remove these comma-separated ports from the scan set |
| `--exclude-cdn` | For known CDN/WAF targets, scan only 80 and 443 instead of the full set |
| `--nmap` | After the scan, run nmap on each host's open ports for a deep dive |
| `--nmap-args <ARGS>` | Custom nmap arguments (replace the default `-sV -sC`); implies `--nmap` |
| `--timeout <MS>` | Per-connection timeout in milliseconds (default: 2000) |
| `-c, --concurrency <N>` | Maximum concurrent connection attempts (default: 256) |
| `--retries <N>` | Extra retries per probe on no answer/timeout (default: 0); refused ports are never retried |
| `-o, --output <FORMAT>` | Output format: `text` (default), `json`, `jsonl`, `csv`, or `grep` |
| `--output-file <PATH>` (`--oF`) | Write machine-readable output to a file instead of stdout |

### Address scanning (`as`)

```bash
# Scan a subnet in CIDR notation (IPv4 or IPv6)
asphyxia as -s 192.168.1.0/24
asphyxia as -s 2001:db8::/120

# Scan a single IP address (IPv4 or IPv6)
asphyxia as -t 192.168.1.1
asphyxia as -t 2001:db8::1

# Scan a range of IP addresses (start end)
asphyxia as -r 192.168.1.1 192.168.1.20

# Scan a subnet with a custom timeout
asphyxia as -s 192.168.1.0/24 --timeout 300

# Skip discovery and treat every address as up (like nmap -Pn)
asphyxia as -s 192.168.1.0/24 --Pn -o jsonl | asphyxia ps --stdin --top-ports 100

# Exclude hosts/CIDRs from a subnet scan (inline and/or from a file)
asphyxia as -s 192.168.1.0/24 --exclude 192.168.1.0/28 --exclude 192.168.1.100
asphyxia as -s 10.0.0.0/22 --exclude-file skip.txt
```

| Flag | Description |
|------|-------------|
| `-s, --subnet <SUBNET>` | Scan a subnet, e.g. `192.168.1.0/24` or `2001:db8::/120` |
| `-t, --target <IP>` | Scan a single IPv4 or IPv6 address |
| `-r, --range <START> <END>` | Scan an inclusive range of IPs (start and end must share the same family) |
| `--Pn` (`--skip-discovery`) | Skip host discovery and treat every target as up (like nmap `-Pn`) |
| `--exclude <SPEC>` | Exclude hosts/CIDRs from the scan (repeatable; each value may be comma-separated) |
| `--exclude-file <PATH>` | Exclude hosts/CIDRs listed in a file (one per line; `#` comments allowed) |
| `--timeout <MS>` | Per-connection timeout in milliseconds (default: 2000) |
| `-c, --concurrency <N>` | Maximum concurrent connection attempts (default: 256) |
| `--retries <N>` | Extra retries per probe on no answer/timeout (default: 0); refused ports are never retried |
| `-o, --output <FORMAT>` | Output format: `text` (default), `json`, `jsonl`, `csv`, or `grep` |
| `--output-file <PATH>` (`--oF`) | Write machine-readable output to a file instead of stdout |

> `--exclude-cdn` uses a small, static list of well-known CDN/WAF ranges (Cloudflare, Fastly, some Akamai) baked into the binary. It is a convenience, not an authoritative registry, and can drift as providers change allocations.

> Host availability is inferred from TCP probes across a small spread of common ports (80, 443, 22, 3389), tried in order until one answers: a host counts as up when any probed port either accepts the connection or actively refuses it (a closed port still proves the host answered). Probing more than one port finds live hosts that firewall port 80 but answer elsewhere. Only when every probed port times out or is unreachable is the host reported as down — so a host that silently drops packets on all of them may still appear offline. This is an unprivileged, best-effort check, not an ICMP ping; use `--Pn` to skip discovery entirely and treat every target as up.

### Machine-readable output (`--output`)

By default Asphyxia prints a colorized, human-friendly report. Pass `--output` (alias `-o`) with one of `json`, `jsonl`, `csv`, or `grep` to emit structured results instead — for example to feed a network map, a spreadsheet, a ticket, or a downstream tool. Each result is a self-contained record with the fields `ip`, `port` (omitted/blank for address scans), `proto`, `latency_ms`, and `status`.

```bash
# One JSON object per open port, on its own line (JSON Lines)
asphyxia ps -t example.com -s 22,80,443 -o jsonl
# {"ip":"93.184.216.34","port":80,"proto":"tcp","latency_ms":12,"status":"open"}

# A single JSON array of available hosts
asphyxia as -s 192.168.1.0/24 -o json

# CSV with a header row (ip,port,proto,status,latency_ms)
asphyxia ps -t example.com --top-ports 100 -o csv

# Greppable, tab-separated columns for grep/awk/cut
asphyxia ps -t example.com -s 22,80,443 -o grep
```

Records are written to stdout; the progress bar and any errors go to stderr, so a consumer reading stdout sees only the data stream. An empty result is `[]` for `json`, a lone header for `csv`, and no output for `jsonl`/`grep`. Pipe straight into `jq`:

```bash
asphyxia ps -t example.com -r 1 1024 -o jsonl 2>/dev/null | jq -c 'select(.port == 443)'
```

Use `--output-file <PATH>` (alias `--oF`) to write the machine-readable output to a file instead of stdout — handy for saving a scan while still watching the progress bar on the terminal:

```bash
asphyxia ps -t example.com --top-ports 1000 -o csv --output-file scan.csv
```

### Chaining discovery into port scanning (`--stdin`)

`asphyxia ps --stdin` reads its targets from standard input, so the hosts an address scan finds can flow directly into a port scan. The input format is auto-detected line by line: a line that is a JSON object or array has its `ip` field(s) taken as targets (so the `-o json`/`-o jsonl` output of `as` works as-is), and any other non-empty line is treated as a bare host or IP (so a plain `hosts.txt` works too). Blank lines are skipped and duplicate targets are scanned once.

```bash
# Discover live hosts on a subnet, then scan common ports on each of them
asphyxia as -s 192.168.1.0/24 -o jsonl 2>/dev/null \
  | asphyxia ps --stdin -s 22,80,443 -o jsonl

# Same, but scan every port on each discovered host
asphyxia as -s 192.168.1.0/24 -o jsonl 2>/dev/null \
  | asphyxia ps --stdin --all-ports -o jsonl

# Feed a hand-written host list
asphyxia ps --stdin -s 22,80,443 < hosts.txt
```

### Nmap handoff (`--nmap`)

Asphyxia finds open ports quickly; nmap interrogates them thoroughly. `--nmap` bridges the two: after the scan, it groups the open ports by host and runs `nmap` on each, so the classic "scan fast, then deep-dive" workflow is one command.

```bash
# Fast port sweep, then nmap service/version + default scripts on what's open
asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap

# Pass your own nmap flags (these replace the default -sV -sC); ports/target stay owned by asphyxia
asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap --nmap-args "-A -T4"
```

By default asphyxia runs `nmap -sV -sC -p <open-ports> <host>`. With `--nmap-args` your flags replace `-sV -sC`, while asphyxia still supplies `-p <open-ports>` and the target. If nmap is not on your `PATH`, asphyxia prints an install hint instead of a deep dive. Nmap's output streams straight to the terminal, so combine `--nmap` with the human (`text`) output rather than a machine format.

## Performance

Scanning is network-I/O-bound — most of the time is spent waiting for TCP handshakes and timeouts, not using the CPU. Asphyxia therefore runs many more concurrent probes than there are CPU cores (256 by default), so an unresponsive address (which blocks for the full `--timeout`) does not stall the rest of the scan.

To tune a scan:

- **`--concurrency`** — raise it to finish large subnets faster (e.g. `--concurrency 512` for a `/22`); lower it if you want a gentler scan. Capped at 1024.
- **`--timeout`** — on a responsive LAN a shorter timeout (e.g. `--timeout 500`) makes unreachable hosts give up much sooner.
- **`--retries`** — on a lossy network (Wi-Fi, VPN, distant hosts) a dropped SYN makes an open port or live host look closed/down. A small value like `--retries 1` or `--retries 2` re-probes only when a probe got *no answer* (timeout/unreachable); a port that actively refuses the connection has already answered, so it is never retried and closed-port scans stay fast.

For example, a `/24` with the defaults completes in roughly one timeout window instead of serially walking every address.

## Dependencies

- [clap](https://crates.io/crates/clap) — command-line argument parsing
- [rayon](https://crates.io/crates/rayon) — parallel computing
- [indicatif](https://crates.io/crates/indicatif) — progress bars and spinners
- [owo-colors](https://crates.io/crates/owo-colors) — terminal colors
- [ipnetwork](https://crates.io/crates/ipnetwork) — IP network address handling

## Development

```bash
cargo fmt --all          # format
cargo clippy --all-targets -- -D warnings   # lint
cargo test               # run unit and doc tests
```

CI runs formatting, Clippy (warnings denied), build, and tests on every pull request and push to `main`.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

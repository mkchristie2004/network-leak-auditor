# network-leak-auditor
Lightweight, open-source telemetry and network leak audit tool that monitors outgoing connections, matches destinations against known tracker/data-broker lists, and produces structured audit reports.

## Features

- Zero-root snapshot collection with `psutil.net_connections(kind='inet')`
- Modular `collect → normalize → enrich → match → report` pipeline
- `scan` for one-shot audits and `watch` for polling plus aggregation
- JSON, CSV, and terminal text output
- Bundled offline starter tracker list plus local custom list support
- Optional reverse DNS enrichment with short timeouts and `--no-rdns`
- JSON-lines input path for auditing pre-recorded connection data

## Installation

```bash
pip install .
```

Or with pipx:

```bash
pipx install .
```

## Quickstart

One-shot unprivileged scan:

```bash
network-leak-auditor scan
```

JSON output to stdout:

```bash
network-leak-auditor scan --format json
```

CSV output to a file:

```bash
network-leak-auditor scan --format csv --output findings.csv
```

Watch mode for 30 seconds:

```bash
network-leak-auditor watch --duration 30 --interval 5
```

Audit JSON-lines input instead of a live psutil snapshot:

```bash
network-leak-auditor scan --input connections.jsonl --format json
cat connections.jsonl | network-leak-auditor scan --input - --format text
```

Disable reverse DNS and include private destinations:

```bash
network-leak-auditor scan --no-rdns --include-private
```

## Commands

### `scan`

Runs a one-shot snapshot audit from:

- the local socket table via `psutil.net_connections(kind='inet')`, or
- `--input FILE` / `--input -` JSON-lines records

### `watch`

Polls the socket table every `--interval` seconds (default `5`) until:

- interrupted with `Ctrl-C`, or
- `--duration` seconds elapse

Repeated matches are aggregated with `first_seen`, `last_seen`, and `count`.

## JSON-lines input format

Each line must be a JSON object with:

```json
{
  "process_name": "browser",
  "pid": 1234,
  "protocol": "tcp",
  "remote_ip": "8.8.8.8",
  "remote_port": 443,
  "observed_at": "2026-01-01T00:00:00Z",
  "domain": "api.segment.io"
}
```

`observed_at` and `domain` are optional. If `domain` is omitted, reverse DNS may be used unless `--no-rdns` is set.

## Matching rules

- Rules are local flat files with one domain per line
- `#` starts a comment
- Matching is case-insensitive
- Exact and suffix matches are supported
  - `example.com` matches `example.com`
  - `example.com` also matches `a.b.example.com`

## Rule lists

The bundled starter list lives at `src/network_leak_auditor/data/trackers.txt` and intentionally contains a small, extensible set of common analytics/telemetry domains.

- `--list FILE` replaces the bundled default
- `--extra-list FILE` adds another local list and can be repeated

No live list downloads, update checks, or other external network calls are made by the tool itself.

## Output formats

`--format` supports:

- `text` (default)
- `json`
- `csv`

Use `--output FILE` to write to disk; otherwise output is written to stdout.

### JSON report schema

```json
{
  "tool": "network-leak-auditor",
  "version": "0.1.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "host": "hostname",
  "summary": {
    "connections_seen": 12,
    "unique_destinations": 4,
    "flagged": 2,
    "lists_used": ["trackers.txt"]
  },
  "findings": [
    {
      "process_name": "browser",
      "pid": 1234,
      "protocol": "tcp",
      "remote_ip": "8.8.8.8",
      "remote_port": 443,
      "domain": "api.segment.io",
      "matched_domain": "segment.io",
      "list_name": "trackers.txt",
      "first_seen": "2026-01-01T00:00:00Z",
      "last_seen": "2026-01-01T00:05:00Z",
      "count": 3
    }
  ]
}
```

## Exit codes

- `0`: no flagged destinations found
- `1`: at least one flagged destination found
- `2`: runtime error

## Zero-root guarantee

The live collector uses `psutil.net_connections(kind='inet')` only. It does not use raw sockets, packet sniffing, `libpcap`, scapy, or any root/sudo-dependent capture path. On operating systems that restrict visibility into other users' processes, the tool degrades gracefully and reports whatever the current user can access.

## Reverse DNS behavior

Reverse DNS is optional enrichment for already-observed destinations only:

- short timeout
- cached results
- disabled entirely with `--no-rdns`
- never required for matching or report generation

## Development and testing

Run tests offline with:

```bash
pytest
```

GitHub Actions runs pytest on Ubuntu, macOS, and Windows across Python 3.9 through 3.13.

## Legal and ethical note

Only audit devices and networks you own or are explicitly authorized to test.

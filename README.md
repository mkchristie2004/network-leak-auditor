# network-leak-auditor
Lightweight, open-source telemetry and network leak audit tool that monitors outgoing connections, matches destinations against known tracker/data-broker lists, and produces structured audit reports.

## Features
- Snapshots outgoing TCP and UDP connections with process names, PIDs, protocol, remote IPs, and ports.
- Uses `psutil` socket-table inspection (no raw sockets, no pcap, no root/sudo requirement to run).
- Ignores loopback, link-local, multicast, and private destinations by default, with `--include-private` to include them.
- Performs reverse-DNS lookups with caching and short timeouts so scans remain offline-safe, with `--no-rdns` to disable reverse DNS entirely.
- Supports optional `domain=ip,ip,...` mapping files to label destinations when reverse DNS is unavailable.
- Matches destinations against an extensible starter tracker/data-broker list using exact and subdomain suffix matching.
- Emits reports in text, JSON, or CSV for local review or CI automation.
- Returns CI-friendly exit codes: `0` when nothing is flagged, `1` when flagged destinations are found, and `2` on runtime errors.
- Supports `scan --input FILE` (or `--input -` for stdin) to audit JSON-lines captures through the same normalize/enrich/match/report pipeline.

## Install
```bash
pip install .
```

With `pipx`:
```bash
pipx install .
```

## Quickstart
Run a one-shot scan:
```bash
network-leak-auditor scan
```

Use the short alias:
```bash
nla scan --format json --output audit.json
```

Watch connections for 30 seconds and write CSV output:
```bash
network-leak-auditor watch --interval 5 --duration 30 --format csv --output audit.csv
```

Include private destinations and a mapping file:
```bash
network-leak-auditor scan --include-private --mapping-file mappings.txt
```

Disable reverse DNS:
```bash
network-leak-auditor scan --no-rdns
```

Audit JSON-lines capture data from a file:
```bash
network-leak-auditor scan --input capture.jsonl --format json
```

## Commands
### `scan`
Collects a single snapshot of current outgoing connections.

When `--input FILE` is provided (or `--input -` for stdin), `scan` reads JSON-lines records instead of live `psutil` collection. Each line must be a JSON object with:
- `process_name` (string)
- `pid` (integer or `null`)
- `protocol` (`"tcp"` or `"udp"`)
- `remote_ip` (string)
- `remote_port` (integer)

Example JSON-lines record:
```json
{"process_name":"python","pid":1234,"protocol":"tcp","remote_ip":"8.8.8.8","remote_port":443}
```

### `watch`
Polls every `--interval` seconds (default `5`) until interrupted with `Ctrl-C` or until `--duration` seconds elapse. Matching connections are aggregated and deduplicated with `first_seen`, `last_seen`, and `count` fields.

Shared options:
- `--format text|json|csv` (default: `text`)
- `--output FILE`
- `--include-private`
- `--mapping-file FILE`
- `--no-rdns`
- `--list FILE` to replace the bundled starter list
- `--extra-list FILE` (repeatable) to append additional lists

## Tracker list matching
The bundled starter list ships in the package at `src/network_leak_auditor/data/trackers.txt` and is intended to be extended over time. Entries are case-insensitive, support `#` comments, and match both exact domains and subdomains. For example, a list entry of `example.com` matches `example.com` and `api.us.example.com`.

Provide a completely custom list:
```bash
network-leak-auditor scan --list custom-trackers.txt
```

Append one or more extra lists:
```bash
network-leak-auditor scan --extra-list internal-list.txt --extra-list vendor-list.txt
```

Optional mapping file format:
```text
cdn.example.com=203.0.113.5,203.0.113.6
```

## JSON report schema
`scan` and `watch` emit the following JSON shape:

```json
{
  "tool": "network-leak-auditor",
  "version": "0.1.0",
  "generated_at": "2026-01-01T00:00:00+00:00",
  "host": "hostname",
  "visibility_warning": "Some connections or process names may be hidden: the OS restricts cross-process visibility without elevated privileges. Results may be incomplete.",
  "summary": {
    "connections_seen": 3,
    "unique_destinations": 2,
    "flagged": 1,
    "unclassified": 1,
    "unclassified_unique_domains": 1,
    "lists_used": ["trackers.txt"]
  },
  "findings": [
    {
      "process_name": "python",
      "pid": 1234,
      "protocol": "tcp",
      "remote_ip": "8.8.8.8",
      "remote_port": 443,
      "domain": "api.segment.io",
      "matched_domain": "segment.io",
      "list_name": "trackers.txt",
      "first_seen": "2026-01-01T00:00:00+00:00",
      "last_seen": "2026-01-01T00:00:05+00:00",
      "count": 2
    }
  ]
}
```

- `visibility_warning` is `null` during normal visibility, and populated when the OS denies access to some connections/process names.
- `summary.unclassified` is the count of unique findings where `matched_domain` is `null` (unique by finding tuple: `process_name`, `pid`, `protocol`, `remote_ip`, `remote_port`; not unique by domain).
- `summary.unclassified_unique_domains` is the number of unique unclassified domain names (domain-level count, unlike tuple-based `summary.unclassified`).

## Exit codes
- `0`: no flagged destinations were found
- `1`: at least one destination matched a configured list
- `2`: runtime error (including malformed `--input` JSON-lines data)

## Zero-root visibility caveats
This tool is designed for unprivileged runs and does not use raw packet capture. However, platform visibility differs:
- Linux: same-user visibility is generally good when unprivileged, but can vary by kernel/security policy.
- macOS: process/connection visibility is often restricted without elevated privileges.
- Windows: visibility can be restricted for processes owned by other users or protected/system processes.

When restricted visibility is detected, reports include `visibility_warning` and text output includes a `WARNING:` line.

## Known limitations
- Static tracker lists can become stale and require periodic updates.
- Suffix matching cannot reliably detect CDN fronting (`*.cloudfront.net`-style) or first-party CNAME cloaking.
- Use the `unclassified` summary count to spot destinations that did not match any configured list.

## Development
Run tests locally:
```bash
python -m pip install .[test]
pytest
```

CI runs `pytest` on Ubuntu, macOS, and Windows across Python 3.9 through 3.13.

## Legal and ethical use
Only audit devices and networks you own or are explicitly authorized to test.

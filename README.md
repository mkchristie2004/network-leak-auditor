# network-leak-auditor
Lightweight, open-source telemetry and network leak audit tool that monitors outgoing connections, matches destinations against known tracker/data-broker lists, and produces structured audit reports.

## Features
- Snapshots outgoing TCP and UDP connections with process names, PIDs, protocol, remote IPs, and ports.
- Ignores loopback, link-local, multicast, and private destinations by default, with `--include-private` to include them.
- Performs reverse-DNS lookups with caching and short timeouts so scans remain offline-safe.
- Supports optional `domain=ip,ip,...` mapping files to label destinations when reverse DNS is unavailable.
- Matches destinations against an extensible starter tracker/data-broker list using exact and subdomain suffix matching.
- Emits reports in text, JSON, or CSV for local review or CI automation.
- Returns CI-friendly exit codes: `0` when nothing is flagged, `1` when flagged destinations are found, and `2` on runtime errors.

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

## Commands
### `scan`
Collects a single snapshot of current outgoing connections.

### `watch`
Polls every `--interval` seconds (default `5`) until interrupted with `Ctrl-C` or until `--duration` seconds elapse. Matching connections are aggregated and deduplicated with `first_seen`, `last_seen`, and `count` fields.

Shared options:
- `--format text|json|csv` (default: `text`)
- `--output FILE`
- `--include-private`
- `--mapping-file FILE`
- `--list FILE` to replace the bundled starter list
- `--extra-list FILE` (repeatable) to append additional lists

## Tracker list matching
The starter list ships at `data/trackers.txt` and is intended to be extended over time. Entries are case-insensitive, support `#` comments, and match both exact domains and subdomains. For example, a list entry of `example.com` matches `example.com` and `api.us.example.com`.

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
  "summary": {
    "connections_seen": 3,
    "unique_destinations": 2,
    "flagged": 1,
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

## Exit codes
- `0`: no flagged destinations were found
- `1`: at least one destination matched a configured list
- `2`: runtime error

## Development
Run tests locally:
```bash
python -m pip install .[test]
pytest
```

CI runs `pytest` on Ubuntu, macOS, and Windows across Python 3.9 through 3.13.

## Legal and ethical use
Only audit devices and networks you own or are explicitly authorized to test.

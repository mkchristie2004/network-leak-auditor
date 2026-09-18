import argparse
import sys
import time

from network_leak_auditor.collectors import collect_psutil_snapshot, parse_connection_input
from network_leak_auditor.enrich import ReverseDNSResolver, enrich_records
from network_leak_auditor.matching import DomainMatcher, load_rule_lists
from network_leak_auditor.reporting import build_report, render_report, write_report_output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-leak-auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a one-shot audit")
    scan_parser.add_argument("--input", help="Read JSON-lines connection records from FILE or - for stdin")
    _add_common_arguments(scan_parser)

    watch_parser = subparsers.add_parser("watch", help="Poll for connections and aggregate findings")
    watch_parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds")
    watch_parser.add_argument("--duration", type=float, help="Optional maximum runtime in seconds")
    _add_common_arguments(watch_parser)

    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", help="Write output to FILE instead of stdout")
    parser.add_argument("--no-rdns", action="store_true", help="Disable reverse DNS enrichment")
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include private, loopback, multicast, and link-local destinations",
    )
    parser.add_argument("--list", dest="list_path", help="Replace the bundled tracker list with FILE")
    parser.add_argument(
        "--extra-list",
        dest="extra_lists",
        action="append",
        default=[],
        help="Add domains from FILE alongside the default or replacement list",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = _run_command(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    rendered = render_report(report, args.format)
    write_report_output(rendered, args.output)
    return 1 if report["summary"]["flagged"] else 0


def _run_command(args: argparse.Namespace) -> dict:
    if args.command == "scan":
        records = (
            parse_connection_input(args.input, include_private=args.include_private)
            if args.input
            else collect_psutil_snapshot(include_private=args.include_private)
        )
        return _audit_records(records, args)

    return _watch_records(args)


def _watch_records(args: argparse.Namespace) -> dict:
    if args.interval <= 0:
        raise ValueError("--interval must be greater than 0")
    if args.duration is not None and args.duration < 0:
        raise ValueError("--duration must be greater than or equal to 0")

    records = []
    deadline = time.monotonic() + args.duration if args.duration is not None else None

    try:
        while True:
            records.extend(collect_psutil_snapshot(include_private=args.include_private))
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(args.interval, remaining))
            else:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    return _audit_records(records, args)


def _audit_records(records, args: argparse.Namespace) -> dict:
    rule_lists = load_rule_lists(args.list_path, args.extra_lists)
    matcher = DomainMatcher(rule_lists)
    resolver = ReverseDNSResolver(enabled=not args.no_rdns)
    enriched_records = enrich_records(records, resolver)
    return build_report(enriched_records, matcher, rule_lists)

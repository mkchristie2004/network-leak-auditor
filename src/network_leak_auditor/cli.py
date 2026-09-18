from __future__ import annotations

import argparse
import sys
import time
from typing import Optional, Sequence

from .auditor import (
    ReverseDNSResolver,
    build_report,
    collect_connections,
    load_lists,
    parse_mapping_file,
    render_report,
    sleep_until_next,
    update_aggregate,
    utc_now,
    write_output,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-leak-auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "csv"], default="text")
    common.add_argument("--output")
    common.add_argument("--include-private", action="store_true")
    common.add_argument("--mapping-file")
    common.add_argument("--list", dest="list_file")
    common.add_argument("--extra-list", action="append", default=[])

    subparsers.add_parser("scan", parents=[common], help="Run a one-shot connection audit")

    watch = subparsers.add_parser("watch", parents=[common], help="Poll connections until stopped")
    watch.add_argument("--interval", type=float, default=5.0)
    watch.add_argument("--duration", type=float)
    return parser


def run_scan(args: argparse.Namespace) -> int:
    resolver = ReverseDNSResolver()
    try:
        loaded_lists = load_lists(args.list_file, args.extra_list)
        mappings = parse_mapping_file(args.mapping_file) if args.mapping_file else {}
        aggregate = {}
        timestamp = utc_now()
        update_aggregate(
            aggregate,
            collect_connections(include_private=args.include_private),
            timestamp,
            resolver,
            mappings,
            loaded_lists,
        )
        report = build_report(list(aggregate.values()), [name for name, _ in loaded_lists], timestamp)
        write_output(render_report(report, args.format), args.output)
        return 1 if report["summary"]["flagged"] else 0
    finally:
        resolver.close()


def run_watch(args: argparse.Namespace) -> int:
    resolver = ReverseDNSResolver()
    started = time.monotonic()
    aggregate = {}
    loaded_lists = load_lists(args.list_file, args.extra_list)
    mappings = parse_mapping_file(args.mapping_file) if args.mapping_file else {}
    try:
        while True:
            timestamp = utc_now()
            update_aggregate(
                aggregate,
                collect_connections(include_private=args.include_private),
                timestamp,
                resolver,
                mappings,
                loaded_lists,
            )
            if args.duration is not None and (time.monotonic() - started) >= args.duration:
                break
            if not sleep_until_next(args.interval, started, args.duration):
                break
    except KeyboardInterrupt:
        pass
    report = build_report(list(aggregate.values()), [name for name, _ in loaded_lists], utc_now())
    write_output(render_report(report, args.format), args.output)
    resolver.close()
    return 1 if report["summary"]["flagged"] else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return run_scan(args)
        if args.command == "watch":
            return run_watch(args)
        parser.error(f"Unknown command: {args.command}")
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

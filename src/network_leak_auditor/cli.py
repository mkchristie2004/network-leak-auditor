from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
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


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def load_configured_lists(list_file: Optional[str], extra_lists: Sequence[str]) -> list[tuple[str, set[str]]]:
    if list_file and not Path(list_file).is_file():
        raise FileNotFoundError(f"--list file not found: {list_file}")
    for extra_list in extra_lists:
        if not Path(extra_list).is_file():
            raise FileNotFoundError(f"--extra-list file not found: {extra_list}")
    return load_lists(list_file, extra_lists)


def load_configured_mappings(mapping_file: Optional[str]) -> dict[str, str]:
    if not mapping_file:
        return {}
    if not Path(mapping_file).is_file():
        raise FileNotFoundError(f"--mapping-file not found: {mapping_file}")
    return parse_mapping_file(Path(mapping_file))


def write_report_output(content: str, output_path: Optional[str]) -> None:
    try:
        write_output(content, output_path)
    except OSError as exc:
        if output_path:
            raise OSError(f"--output path could not be written: {output_path}") from exc
        raise


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
    watch.add_argument("--interval", type=positive_float, default=5.0)
    watch.add_argument("--duration", type=positive_float)
    return parser


def run_scan(args: argparse.Namespace) -> int:
    resolver = ReverseDNSResolver()
    try:
        loaded_lists = load_configured_lists(args.list_file, args.extra_list)
        mappings = load_configured_mappings(args.mapping_file)
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
        write_report_output(render_report(report, args.format), args.output)
        return 1 if report["summary"]["flagged"] else 0
    finally:
        resolver.close()


def run_watch(args: argparse.Namespace) -> int:
    resolver = ReverseDNSResolver()
    started = time.monotonic()
    aggregate = {}
    try:
        loaded_lists = load_configured_lists(args.list_file, args.extra_list)
        mappings = load_configured_mappings(args.mapping_file)
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
        write_report_output(render_report(report, args.format), args.output)
        return 1 if report["summary"]["flagged"] else 0
    finally:
        resolver.close()


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

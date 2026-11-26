"""Command-line interface for ShiftSentinel."""

from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import __version__
from .grouping import group_alerts
from .ingest import IngestError, ingest_file
from .metrics import compute_metrics
from .report_html import generate_html_report
from .report_md import generate_markdown_report
from .report_terminal import generate_terminal_summary
from .watchlist import (
    WATCHLIST_TYPES,
    WatchlistError,
    add_entry,
    apply_watchlist,
    auto_watch_incidents,
    list_entries,
    resolve_entry,
    resolve_watchlist_path,
)

DEFAULT_CONFIG: dict[str, Any] = {
    "team_name": "Security Operations Center",
    "organisation": "",
    "shifts": ["Morning", "Evening", "Night"],
    "severity_thresholds": {
        "watchlist_auto_add": "critical",
    },
    "escalation_contacts": {
        "P1": "",
        "P2": "",
    },
    "watchlist_path": None,
}


class ConfigError(Exception):
    """Raised when a user-supplied config file cannot be loaded or parsed."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` values onto a copy of ``base``."""
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(config_path: Path | None) -> dict[str, Any]:
    """Load configuration from JSON file, merging over built-in defaults."""
    if config_path is None:
        return deepcopy(DEFAULT_CONFIG)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Failed to parse config '{config_path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file '{config_path}' must contain a JSON object.")
    return _deep_merge(DEFAULT_CONFIG, data)


def _effective_watchlist_path(cli_path: str | None, config: dict[str, Any]) -> Path:
    """Resolve watchlist path from CLI override, config, or default."""
    if cli_path:
        return Path(cli_path).expanduser()
    cfg_path = config.get("watchlist_path")
    if cfg_path:
        return Path(str(cfg_path)).expanduser()
    return resolve_watchlist_path(None)


def _handle_ingest(args: argparse.Namespace) -> int:
    result = ingest_file(Path(args.input))
    metrics = compute_metrics(result.alerts, [])

    print(f"Source File    : {args.input}")
    print(f"Detected Format: {result.source_format}")
    print(f"Alerts Parsed  : {len(result.alerts)} (warnings: {result.warnings})")
    if metrics.shift_start and metrics.shift_end:
        print(f"Time Range     : {metrics.shift_start} -> {metrics.shift_end}")
    else:
        print("Time Range     : N/A")
    print(
        "Severity Counts: "
        f"CRITICAL={metrics.severity_counts['critical']}  "
        f"HIGH={metrics.severity_counts['high']}  "
        f"MEDIUM={metrics.severity_counts['medium']}  "
        f"LOW={metrics.severity_counts['low']}"
    )
    if result.warning_messages:
        for msg in result.warning_messages[:5]:
            print(f"  [warn] {msg}", file=sys.stderr)
    return 0


def _handle_report(args: argparse.Namespace, config: dict[str, Any]) -> int:
    result = ingest_file(Path(args.input))
    incidents = group_alerts(result.alerts)
    wl_path = _effective_watchlist_path(args.watchlist, config)

    if args.auto_watch:
        threshold = str(
            config.get("severity_thresholds", {}).get("watchlist_auto_add", "critical")
        )
        added = auto_watch_incidents(
            incidents,
            threshold=threshold,
            added_by=args.analyst,
            path=wl_path,
        )
        if added:
            print(
                f"Auto-added {len(added)} IOC(s) to watchlist ({wl_path}).",
                file=sys.stderr,
            )

    entries = list_entries(path=wl_path, active_only=True)
    watchlist_hits = apply_watchlist(incidents, entries)
    metrics = compute_metrics(result.alerts, incidents, watchlist_hits=watchlist_hits)

    fmt = args.format
    if fmt == "terminal":
        print(
            generate_terminal_summary(
                incidents=incidents,
                metrics=metrics,
                watchlist_entries=entries,
                shift_name=args.shift,
                outgoing_analyst=args.analyst,
                incoming_analyst=args.incoming,
            )
        )
        return 0

    if fmt == "html":
        out_path = Path(args.output) if args.output else Path("handover_report.html")
        content = generate_html_report(
            incidents=incidents,
            metrics=metrics,
            watchlist_entries=entries,
            shift_name=args.shift,
            outgoing_analyst=args.analyst,
            incoming_analyst=args.incoming,
            config=config,
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        print(f"HTML report written to: {out_path}")
        return 0

    if fmt == "md":
        content = generate_markdown_report(
            incidents=incidents,
            metrics=metrics,
            watchlist_entries=entries,
            shift_name=args.shift,
            outgoing_analyst=args.analyst,
            incoming_analyst=args.incoming,
            config=config,
        )
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"Markdown report written to: {out_path}")
        else:
            print(content)
        return 0

    if fmt == "all":
        base = Path(args.output) if args.output else Path("handover_report")
        html_path = base if base.suffix.lower() == ".html" else base.with_suffix(".html")
        md_path = base.with_suffix(".md")

        html_content = generate_html_report(
            incidents=incidents,
            metrics=metrics,
            watchlist_entries=entries,
            shift_name=args.shift,
            outgoing_analyst=args.analyst,
            incoming_analyst=args.incoming,
            config=config,
        )
        md_content = generate_markdown_report(
            incidents=incidents,
            metrics=metrics,
            watchlist_entries=entries,
            shift_name=args.shift,
            outgoing_analyst=args.analyst,
            incoming_analyst=args.incoming,
            config=config,
        )
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_content, encoding="utf-8")
        md_path.write_text(md_content, encoding="utf-8")

        print(
            generate_terminal_summary(
                incidents=incidents,
                metrics=metrics,
                watchlist_entries=entries,
                shift_name=args.shift,
                outgoing_analyst=args.analyst,
                incoming_analyst=args.incoming,
            )
        )
        print(f"HTML report written to: {html_path}")
        print(f"Markdown report written to: {md_path}")
        return 0

    return 1


def _handle_watch(args: argparse.Namespace, config: dict[str, Any]) -> int:
    wl_path = _effective_watchlist_path(args.watchlist, config)

    if args.watch_action == "list":
        entries = list_entries(path=wl_path, active_only=not args.all)
        if not entries:
            print(f"Watchlist is empty ({wl_path}).")
            return 0
        for entry in entries:
            print(
                f"[{entry.status.upper()}] {entry.ioc} ({entry.type}) "
                f"- {entry.reason} | by {entry.added_by} @ {entry.added_at}"
            )
        return 0

    if args.watch_action == "add":
        entry, created = add_entry(
            ioc=args.ioc,
            entry_type=args.type,
            reason=args.reason,
            added_by=args.added_by,
            source_incident=args.incident,
            path=wl_path,
        )
        verb = "Added" if created else "Updated active"
        print(f"{verb} watchlist entry: {entry.ioc} ({entry.type}) -> {wl_path}")
        return 0

    if args.watch_action == "resolve":
        resolved = resolve_entry(ioc=args.ioc, path=wl_path)
        if resolved:
            print(f"Resolved watchlist entry: {args.ioc}")
            return 0
        print(f"Error: No active watchlist entry found for '{args.ioc}'.", file=sys.stderr)
        return 1

    return 1


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="shiftsentinel",
        description="ShiftSentinel — SOC shift handover report generator.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to JSON configuration file (merges over built-in defaults).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # report subcommand
    report_p = subparsers.add_parser(
        "report",
        help="Generate a shift handover report from alert data.",
        description="Ingest alerts, group into incidents, apply watchlist, and generate reports.",
    )
    report_p.add_argument("--input", "-i", required=True, help="Path to alert file (.json or .csv).")
    report_p.add_argument(
        "--format",
        "-f",
        choices=("html", "md", "terminal", "all"),
        default="terminal",
        help="Output report format (default: terminal).",
    )
    report_p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (used for html, md, and all formats).",
    )
    report_p.add_argument(
        "--shift",
        default="Unspecified",
        help="Shift name, e.g. Morning, Evening, Night (default: Unspecified).",
    )
    report_p.add_argument(
        "--analyst",
        default="On-duty Analyst",
        help="Outgoing analyst name (default: On-duty Analyst).",
    )
    report_p.add_argument(
        "--incoming",
        default="Incoming Analyst",
        help="Incoming analyst name (default: Incoming Analyst).",
    )
    report_p.add_argument(
        "--watchlist",
        default=None,
        help="Override watchlist JSON path.",
    )
    report_p.add_argument(
        "--auto-watch",
        action="store_true",
        help="Automatically add source IPs of critical incidents to the watchlist.",
    )

    # ingest subcommand
    ingest_p = subparsers.add_parser(
        "ingest",
        help="Parse an alert file and print a quick ingestion summary.",
        description="Validate and summarize an alert input file without generating a full report.",
    )
    ingest_p.add_argument("--input", "-i", required=True, help="Path to alert file (.json or .csv).")

    # watch subcommand
    watch_p = subparsers.add_parser(
        "watch",
        help="Manage the persistent carry-over IOC watchlist.",
        description="List, add, or resolve IOCs on the persistent carry-over watchlist.",
    )
    watch_p.add_argument("--watchlist", default=None, help="Override watchlist JSON path.")
    watch_sub = watch_p.add_subparsers(dest="watch_action", required=True)

    watch_list = watch_sub.add_parser("list", help="List watchlist entries.")
    watch_list.add_argument(
        "--all",
        action="store_true",
        help="Include resolved entries in addition to active ones.",
    )

    watch_add = watch_sub.add_parser("add", help="Add an IOC to the watchlist.")
    watch_add.add_argument("--ioc", required=True, help="IOC value (IP, domain, hash, user, host).")
    watch_add.add_argument(
        "--type",
        choices=WATCHLIST_TYPES,
        default="ip",
        help="IOC type (default: ip).",
    )
    watch_add.add_argument("--reason", required=True, help="Reason for tracking this IOC.")
    watch_add.add_argument(
        "--added-by",
        default="On-duty Analyst",
        help="Analyst adding the entry.",
    )
    watch_add.add_argument(
        "--incident",
        default="",
        help="Optional source incident title.",
    )

    watch_resolve = watch_sub.add_parser("resolve", help="Mark an active watchlist IOC as resolved.")
    watch_resolve.add_argument("--ioc", required=True, help="IOC value to resolve.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point returning process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(Path(args.config) if args.config else None)
        if args.command == "ingest":
            return _handle_ingest(args)
        if args.command == "report":
            return _handle_report(args, config)
        if args.command == "watch":
            return _handle_watch(args, config)
    except (ConfigError, IngestError, WatchlistError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Coloured terminal summary generator with graceful non-TTY degradation."""

from __future__ import annotations

import sys

from .metrics import ShiftMetrics
from .models import Incident, WatchlistEntry

_ANSI: dict[str, str] = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "GREEN": "\033[92m",
    "CYAN": "\033[96m",
    "MAGENTA": "\033[95m",
}

_SEV_ANSI: dict[str, str] = {
    "critical": "RED",
    "high": "YELLOW",
    "medium": "CYAN",
    "low": "GREEN",
}


def _c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_ANSI.get(color, '')}{text}{_ANSI['RESET']}"


def generate_terminal_summary(
    incidents: list[Incident],
    metrics: ShiftMetrics,
    watchlist_entries: list[WatchlistEntry],
    shift_name: str = "Unspecified",
    outgoing_analyst: str = "On-duty Analyst",
    incoming_analyst: str = "Incoming Analyst",
    use_color: bool | None = None,
) -> str:
    """Render a compact terminal shift handover summary."""
    color_enabled = sys.stdout.isatty() if use_color is None else use_color
    active_watchlist = [e for e in watchlist_entries if e.status == "active"]

    lines: list[str] = [
        _c("=" * 72, "CYAN", color_enabled),
        _c(
            f"  ShiftSentinel | {shift_name} Shift | {outgoing_analyst} -> {incoming_analyst}",
            "BOLD",
            color_enabled,
        ),
        _c("=" * 72, "CYAN", color_enabled),
        (
            f"  Alerts: {metrics.total_alerts}  |  Incidents: {metrics.total_incidents}  |  "
            f"CRITICAL={metrics.severity_counts.get('critical', 0)}  "
            f"HIGH={metrics.severity_counts.get('high', 0)}  "
            f"MEDIUM={metrics.severity_counts.get('medium', 0)}  "
            f"LOW={metrics.severity_counts.get('low', 0)}"
        ),
        "",
    ]

    if not incidents:
        lines.append(_c("  [OK] No incidents recorded during this shift.", "GREEN", color_enabled))
    else:
        lines.append(_c("  Top Incidents:", "BOLD", color_enabled))
        for inc in incidents[:5]:
            sev_badge = _c(
                f"[{inc.severity.upper():<8}]",
                _SEV_ANSI.get(inc.severity, "RESET"),
                color_enabled,
            )
            watch_tag = _c(" [WATCHLIST]", "YELLOW", color_enabled) if inc.watchlist_hits else ""
            lines.append(
                f"  {inc.id} {sev_badge} ({inc.alert_count:>2} alerts) {inc.title}{watch_tag}"
            )
        if len(incidents) > 5:
            lines.append(_c(f"  ... and {len(incidents) - 5} more incident(s).", "DIM", color_enabled))

    lines.append("")
    lines.append(
        f"  Watchlist: {len(active_watchlist)} active carry-over IOC(s) "
        f"| {metrics.watchlist_hits} hit(s) this shift"
    )
    lines.append(_c("=" * 72, "CYAN", color_enabled))
    return "\n".join(lines)

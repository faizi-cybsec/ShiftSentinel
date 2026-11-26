"""Markdown shift handover report generator for tickets, wikis, and runbooks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .metrics import ShiftMetrics
from .models import Incident, WatchlistEntry, format_iso_timestamp
from .watchlist import format_age


def _md_escape(text: str) -> str:
    """Escape pipe characters so Markdown table cells stay aligned."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def generate_markdown_report(
    incidents: list[Incident],
    metrics: ShiftMetrics,
    watchlist_entries: list[WatchlistEntry],
    shift_name: str = "Unspecified",
    outgoing_analyst: str = "On-duty Analyst",
    incoming_analyst: str = "Incoming Analyst",
    config: dict[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render a structured Markdown shift handover report."""
    cfg = config or {}
    team_name = str(cfg.get("team_name") or "Security Operations Center")
    organisation = str(cfg.get("organisation") or "").strip()
    team_display = f"{team_name} ({organisation})" if organisation else team_name

    now = generated_at if generated_at is not None else datetime.now(timezone.utc)
    generated_str = format_iso_timestamp(now)
    shift_window = (
        f"{metrics.shift_start} to {metrics.shift_end}"
        if metrics.shift_start and metrics.shift_end
        else "No alerts in window"
    )
    crit_high = (
        metrics.severity_counts.get("critical", 0) + metrics.severity_counts.get("high", 0)
    )
    active_watchlist = [e for e in watchlist_entries if e.status == "active"]

    lines: list[str] = [
        "# ShiftSentinel — Shift Handover Report",
        "",
        f"- **Team:** {team_display}",
        f"- **Shift:** {shift_name}",
        f"- **Generated:** `{generated_str}`",
        f"- **Shift Window:** `{shift_window}`",
        f"- **Outgoing Analyst:** {outgoing_analyst}",
        f"- **Incoming Analyst:** {incoming_analyst}",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total Alerts | {metrics.total_alerts} |",
        f"| Grouped Incidents | {metrics.total_incidents} |",
        f"| Critical + High Alerts | {crit_high} |",
        f"| Watchlist Hits | {metrics.watchlist_hits} |",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Alert Count | Incident Count |",
        "| --- | ---: | ---: |",
    ]
    for sev in ("critical", "high", "medium", "low"):
        lines.append(
            f"| {sev.upper()} | {metrics.severity_counts.get(sev, 0)} | "
            f"{metrics.incident_severity_counts.get(sev, 0)} |"
        )

    lines.extend(["", "## Alerts by Hour (UTC)", ""])
    active_hours = [(h, c) for h, c in sorted(metrics.alerts_per_hour.items()) if c > 0]
    if active_hours:
        lines.append("| Hour (UTC) | Alerts |")
        lines.append("| --- | ---: |")
        for hour, count in active_hours:
            lines.append(f"| `{hour:02d}:00` | {count} |")
    else:
        lines.append("_No hourly alert activity recorded._")

    lines.extend(["", "## Prioritized Incidents", ""])
    if not incidents:
        lines.append("_No incidents recorded during this shift._")
    else:
        lines.append(
            "| ID | Severity | Title | Status | Alerts | First Seen | Last Seen | Source IPs | MITRE | Watchlist |"
        )
        lines.append("| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |")
        for inc in incidents:
            ips = ", ".join(inc.source_ips) if inc.source_ips else "-"
            mitre = ", ".join(inc.mitre_techniques) if inc.mitre_techniques else "-"
            watch_flag = "⚠ WATCHLIST" if inc.watchlist_hits else "-"
            lines.append(
                f"| `{inc.id}` | **{inc.severity.upper()}** | {_md_escape(inc.title)} | "
                f"{inc.status} | {inc.alert_count} | `{inc.first_seen}` | `{inc.last_seen}` | "
                f"`{_md_escape(ips)}` | `{_md_escape(mitre)}` | {watch_flag} |"
            )

    lines.extend(["", "## Top Talkers", "", "### Top Source IPs", ""])
    if metrics.top_source_ips:
        lines.append("| Source IP | Alerts |")
        lines.append("| --- | ---: |")
        for ip, count in metrics.top_source_ips:
            lines.append(f"| `{ip}` | {count} |")
    else:
        lines.append("_No source IP data._")

    lines.extend(["", "### Top Targeted Users", ""])
    if metrics.top_users:
        lines.append("| User | Alerts |")
        lines.append("| --- | ---: |")
        for user, count in metrics.top_users:
            lines.append(f"| `{user}` | {count} |")
    else:
        lines.append("_No targeted user data._")

    lines.extend(["", "## Carry-Over Watchlist", ""])
    if active_watchlist:
        lines.append("| IOC | Type | Reason | Added By | Source Incident | Age |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for entry in active_watchlist:
            age = format_age(entry.added_at, now=now)
            lines.append(
                f"| `{_md_escape(entry.ioc)}` | {entry.type.upper()} | "
                f"{_md_escape(entry.reason)} | {_md_escape(entry.added_by)} | "
                f"{_md_escape(entry.source_incident or '-')} | {age} |"
            )
    else:
        lines.append("_No active carry-over watchlist entries._")

    lines.extend(
        [
            "",
            "## Sign-Off",
            "",
            f"- **Handed over by:** {outgoing_analyst}",
            f"- **Received by:** {incoming_analyst}",
            "",
        ]
    )

    return "\n".join(lines)

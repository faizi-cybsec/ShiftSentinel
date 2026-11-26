"""Pure shift metrics computation functions."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import SEVERITIES, Alert, Incident, parse_iso_timestamp


@dataclass(slots=True)
class ShiftMetrics:
    """Aggregated shift statistics computed from alerts and incidents."""

    total_alerts: int = 0
    total_incidents: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    incident_severity_counts: dict[str, int] = field(default_factory=dict)
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    alerts_per_hour: dict[int, int] = field(default_factory=dict)
    busiest_hour: int | None = None
    busiest_hour_count: int = 0
    watchlist_hits: int = 0
    shift_start: str = ""
    shift_end: str = ""


def count_by_severity(alerts: list[Alert]) -> dict[str, int]:
    """Count alerts per severity level in fixed order."""
    counts = {sev: 0 for sev in SEVERITIES}
    for alert in alerts:
        sev = alert.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def count_incidents_by_severity(incidents: list[Incident]) -> dict[str, int]:
    """Count incidents per severity level in fixed order."""
    counts = {sev: 0 for sev in SEVERITIES}
    for inc in incidents:
        sev = inc.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def top_source_ips(alerts: list[Alert], limit: int = 5) -> list[tuple[str, int]]:
    """Return the top ``limit`` source IPs ordered by alert count descending."""
    counter = Counter(a.source_ip for a in alerts if a.source_ip)
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]


def top_targeted_users(alerts: list[Alert], limit: int = 5) -> list[tuple[str, int]]:
    """Return the top ``limit`` targeted users ordered by alert count descending."""
    counter = Counter(a.user for a in alerts if a.user)
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]


def compute_alerts_per_hour(alerts: list[Alert]) -> dict[int, int]:
    """Bucket alerts into 24 hourly slots (0..23) based on alert timestamp hour."""
    buckets = {hour: 0 for hour in range(24)}
    for alert in alerts:
        dt = parse_iso_timestamp(alert.timestamp)
        buckets[dt.hour] += 1
    return buckets


def compute_metrics(
    alerts: list[Alert],
    incidents: list[Incident],
    watchlist_hits: int = 0,
) -> ShiftMetrics:
    """Compute all shift metrics from normalized alerts and grouped incidents."""
    per_hour = compute_alerts_per_hour(alerts)
    busiest_hour: int | None = None
    busiest_count = 0
    if alerts:
        busiest_hour = max(range(24), key=lambda h: (per_hour[h], -h))
        busiest_count = per_hour[busiest_hour]

    shift_start = ""
    shift_end = ""
    if alerts:
        timestamps = sorted(alerts, key=lambda a: parse_iso_timestamp(a.timestamp))
        shift_start = timestamps[0].timestamp
        shift_end = timestamps[-1].timestamp

    return ShiftMetrics(
        total_alerts=len(alerts),
        total_incidents=len(incidents),
        severity_counts=count_by_severity(alerts),
        incident_severity_counts=count_incidents_by_severity(incidents),
        top_source_ips=top_source_ips(alerts, limit=5),
        top_users=top_targeted_users(alerts, limit=5),
        alerts_per_hour=per_hour,
        busiest_hour=busiest_hour,
        busiest_hour_count=busiest_count,
        watchlist_hits=watchlist_hits,
        shift_start=shift_start,
        shift_end=shift_end,
    )

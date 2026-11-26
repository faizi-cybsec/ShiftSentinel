"""Core data models and timestamp helpers for ShiftSentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
INCIDENT_STATUSES: tuple[str, ...] = ("open", "investigating", "contained", "closed")


def parse_iso_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a timezone-aware datetime (UTC default)."""
    raw = value.strip()
    if not raw:
        raise ValueError("Empty timestamp")
    if raw.endswith("Z") or raw.endswith("z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_iso_timestamp(dt: datetime) -> str:
    """Format a datetime as a timezone-aware ISO 8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@dataclass(slots=True)
class Alert:
    """Normalized internal alert representation produced by all ingest parsers."""

    timestamp: str
    source_ip: str = ""
    dest_ip: str = ""
    host: str = ""
    user: str = ""
    rule_name: str = ""
    severity: str = "low"
    mitre_technique: str = ""
    mitre_tactic: str = ""
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Incident:
    """Grouped security incident aggregated from one or more related alerts."""

    id: str
    title: str
    severity: str
    status: str = "open"
    first_seen: str = ""
    last_seen: str = ""
    alert_count: int = 0
    source_ips: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    sample_descriptions: list[str] = field(default_factory=list)
    watchlist_hits: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WatchlistEntry:
    """Persistent carry-over watchlist IOC entry tracked across shifts."""

    ioc: str
    type: str
    reason: str
    added_by: str
    added_at: str
    source_incident: str = ""
    status: str = "active"

    def to_dict(self) -> dict[str, str]:
        """Serialize entry to a JSON-compatible dictionary."""
        return {
            "ioc": self.ioc,
            "type": self.type,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
            "source_incident": self.source_incident,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WatchlistEntry":
        """Deserialize entry from a dictionary."""
        return cls(
            ioc=str(data.get("ioc", "")).strip(),
            type=str(data.get("type", "ip")).strip().lower() or "ip",
            reason=str(data.get("reason", "")).strip(),
            added_by=str(data.get("added_by", "Unknown")).strip(),
            added_at=str(data.get("added_at", "")).strip(),
            source_incident=str(data.get("source_incident", "")).strip(),
            status=str(data.get("status", "active")).strip().lower() or "active",
        )

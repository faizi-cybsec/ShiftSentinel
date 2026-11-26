"""Persistent carry-over watchlist store for tracking IOCs across SOC shifts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    SEVERITY_RANK,
    Incident,
    WatchlistEntry,
    format_iso_timestamp,
    parse_iso_timestamp,
)

DEFAULT_WATCHLIST_PATH: Path = Path.home() / ".shiftsentinel" / "watchlist.json"
WATCHLIST_TYPES: tuple[str, ...] = ("ip", "domain", "hash", "user", "host")


class WatchlistError(Exception):
    """Raised when the watchlist file cannot be read or written."""


def resolve_watchlist_path(path: Path | None = None) -> Path:
    """Return the effective watchlist JSON path."""
    return path if path is not None else DEFAULT_WATCHLIST_PATH


def load_watchlist(path: Path | None = None) -> list[WatchlistEntry]:
    """Load watchlist entries from disk; returns an empty list if file does not exist."""
    target = resolve_watchlist_path(path)
    if not target.exists():
        return []
    try:
        raw_text = target.read_text(encoding="utf-8")
        data = json.loads(raw_text) if raw_text.strip() else []
    except (OSError, json.JSONDecodeError) as exc:
        raise WatchlistError(f"Failed to load watchlist '{target}': {exc}") from exc

    if not isinstance(data, list):
        raise WatchlistError(f"Watchlist '{target}' must contain a JSON array.")

    entries: list[WatchlistEntry] = []
    for item in data:
        if isinstance(item, dict) and str(item.get("ioc", "")).strip():
            entries.append(WatchlistEntry.from_dict(item))
    return entries


def save_watchlist(entries: list[WatchlistEntry], path: Path | None = None) -> Path:
    """Persist watchlist entries to disk, creating parent directories if needed."""
    target = resolve_watchlist_path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = [entry.to_dict() for entry in entries]
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise WatchlistError(f"Failed to save watchlist '{target}': {exc}") from exc
    return target


def list_entries(path: Path | None = None, active_only: bool = False) -> list[WatchlistEntry]:
    """Return watchlist entries, optionally filtered to active items only."""
    entries = load_watchlist(path)
    if active_only:
        return [e for e in entries if e.status == "active"]
    return entries


def add_entry(
    ioc: str,
    entry_type: str = "ip",
    reason: str = "",
    added_by: str = "On-duty Analyst",
    source_incident: str = "",
    path: Path | None = None,
) -> tuple[WatchlistEntry, bool]:
    """Add an IOC to the watchlist or update an existing active entry.

    Returns ``(entry, created_new)``.
    """
    cleaned_ioc = ioc.strip()
    if not cleaned_ioc:
        raise WatchlistError("IOC value cannot be empty.")

    cleaned_type = entry_type.strip().lower()
    if cleaned_type not in WATCHLIST_TYPES:
        raise WatchlistError(
            f"Invalid watchlist type '{entry_type}'. Must be one of: {', '.join(WATCHLIST_TYPES)}"
        )

    entries = load_watchlist(path)
    now_iso = format_iso_timestamp(datetime.now(timezone.utc))

    for existing in entries:
        if existing.status == "active" and existing.ioc.lower() == cleaned_ioc.lower():
            if reason.strip():
                existing.reason = reason.strip()
            if source_incident.strip() and not existing.source_incident:
                existing.source_incident = source_incident.strip()
            save_watchlist(entries, path)
            return existing, False

    new_entry = WatchlistEntry(
        ioc=cleaned_ioc,
        type=cleaned_type,
        reason=reason.strip() or "Flagged for shift carry-over monitoring",
        added_by=added_by.strip() or "On-duty Analyst",
        added_at=now_iso,
        source_incident=source_incident.strip(),
        status="active",
    )
    entries.append(new_entry)
    save_watchlist(entries, path)
    return new_entry, True


def resolve_entry(ioc: str, path: Path | None = None) -> bool:
    """Mark active watchlist entries matching ``ioc`` as resolved.

    Returns True if at least one entry was updated.
    """
    cleaned_ioc = ioc.strip().lower()
    if not cleaned_ioc:
        raise WatchlistError("IOC value cannot be empty.")

    entries = load_watchlist(path)
    updated = False
    for entry in entries:
        if entry.status == "active" and entry.ioc.lower() == cleaned_ioc:
            entry.status = "resolved"
            updated = True

    if updated:
        save_watchlist(entries, path)
    return updated


def apply_watchlist(incidents: list[Incident], entries: list[WatchlistEntry]) -> int:
    """Flag incidents touching any active watchlist IOC and return total hit count."""
    active = [e for e in entries if e.status == "active" and e.ioc]
    if not active:
        return 0

    total_hits = 0
    for inc in incidents:
        entity_tokens = {
            token.lower()
            for token in (inc.source_ips + inc.hosts + inc.users)
            if token
        }
        text_blob = " ".join([inc.title, *inc.sample_descriptions]).lower()

        hits: list[str] = []
        for entry in active:
            needle = entry.ioc.lower()
            if (needle in entity_tokens or needle in text_blob) and entry.ioc not in hits:
                hits.append(entry.ioc)

        inc.watchlist_hits = hits
        total_hits += len(hits)

    return total_hits


def auto_watch_incidents(
    incidents: list[Incident],
    threshold: str = "critical",
    added_by: str = "On-duty Analyst",
    path: Path | None = None,
) -> list[WatchlistEntry]:
    """Automatically add source IPs of incidents meeting the severity threshold."""
    min_rank = SEVERITY_RANK.get(threshold.strip().lower(), SEVERITY_RANK["critical"])
    added: list[WatchlistEntry] = []

    for inc in incidents:
        if SEVERITY_RANK.get(inc.severity, 0) < min_rank:
            continue
        for ip in inc.source_ips:
            entry, created = add_entry(
                ioc=ip,
                entry_type="ip",
                reason=f"Auto-added from {inc.severity.upper()} incident {inc.id}: {inc.title}",
                added_by=added_by,
                source_incident=inc.title,
                path=path,
            )
            if created:
                added.append(entry)

    return added


def format_age(added_at: str, now: datetime | None = None) -> str:
    """Format the elapsed time since ``added_at`` as a concise human-readable string."""
    if not added_at:
        return "unknown"
    try:
        created = parse_iso_timestamp(added_at)
    except ValueError:
        return "unknown"

    reference = now if now is not None else datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    delta_seconds = max(0, int((reference - created).total_seconds()))
    days, rem = divmod(delta_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60

    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

"""Alert ingestion parsers for LogSentinel JSON, generic JSON, and CSV exports."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Alert, format_iso_timestamp, parse_iso_timestamp


class IngestError(Exception):
    """Raised when an input file cannot be read or parsed."""


@dataclass(slots=True)
class IngestResult:
    """Result of ingesting an alert source file."""

    alerts: list[Alert] = field(default_factory=list)
    warnings: int = 0
    warning_messages: list[str] = field(default_factory=list)
    source_format: str = "unknown"


_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "@timestamp", "event_time", "created_at", "date"),
    "source_ip": ("source_ip", "src_ip", "src", "ip", "client_ip", "remote_ip", "sourceip"),
    "dest_ip": ("dest_ip", "dst_ip", "destination_ip", "dest", "target_ip", "dst"),
    "host": ("host", "hostname", "host_name", "computer", "device", "workstation", "target"),
    "user": ("user", "username", "user_name", "account", "actor", "target_user"),
    "rule_name": (
        "rule_name",
        "rule",
        "rule_title",
        "alert_name",
        "title",
        "signature",
        "name",
        "event_type",
    ),
    "severity": ("severity", "sev", "level", "priority", "risk"),
    "mitre_technique": (
        "mitre_technique",
        "technique",
        "technique_id",
        "mitre_id",
        "attck_technique",
    ),
    "mitre_tactic": ("mitre_tactic", "tactic", "attck_tactic"),
    "description": ("description", "message", "msg", "details", "summary", "reason"),
}

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "p1": "critical",
    "sev1": "critical",
    "high": "high",
    "err": "high",
    "error": "high",
    "p2": "high",
    "sev2": "high",
    "medium": "medium",
    "med": "medium",
    "warn": "medium",
    "warning": "medium",
    "p3": "medium",
    "sev3": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "p4": "low",
    "sev4": "low",
}


def _extract_field(record: dict[str, Any], candidates: tuple[str, ...]) -> str:
    """Return the first non-empty string value matching any candidate key (case-insensitive)."""
    lowered: dict[str, Any] = {str(k).strip().lower(): v for k, v in record.items()}
    for key in candidates:
        if key in lowered and lowered[key] is not None:
            text = str(lowered[key]).strip()
            if text:
                return text
    return ""


def normalize_severity(value: str) -> str:
    """Normalize arbitrary severity labels into low/medium/high/critical."""
    cleaned = value.strip().lower()
    return _SEVERITY_MAP.get(cleaned, "low")


def normalize_alert(record: dict[str, Any]) -> Alert:
    """Convert a raw alert dictionary into a normalized Alert instance."""
    if not isinstance(record, dict):
        raise TypeError("Alert record must be a JSON object or CSV row")

    raw_ts = _extract_field(record, _FIELD_ALIASES["timestamp"])
    if not raw_ts:
        raise ValueError("Missing required timestamp field")
    dt = parse_iso_timestamp(raw_ts)
    iso_ts = format_iso_timestamp(dt)

    rule_name = _extract_field(record, _FIELD_ALIASES["rule_name"])
    if not rule_name:
        raise ValueError("Missing required rule_name/rule field")

    severity = normalize_severity(_extract_field(record, _FIELD_ALIASES["severity"]))

    return Alert(
        timestamp=iso_ts,
        source_ip=_extract_field(record, _FIELD_ALIASES["source_ip"]),
        dest_ip=_extract_field(record, _FIELD_ALIASES["dest_ip"]),
        host=_extract_field(record, _FIELD_ALIASES["host"]),
        user=_extract_field(record, _FIELD_ALIASES["user"]),
        rule_name=rule_name,
        severity=severity,
        mitre_technique=_extract_field(record, _FIELD_ALIASES["mitre_technique"]),
        mitre_tactic=_extract_field(record, _FIELD_ALIASES["mitre_tactic"]),
        description=_extract_field(record, _FIELD_ALIASES["description"]),
        raw=dict(record),
    )


def _parse_records(records: list[Any], source_format: str) -> IngestResult:
    """Normalize a list of raw records, counting and skipping malformed entries."""
    result = IngestResult(source_format=source_format)
    for idx, item in enumerate(records, start=1):
        try:
            alert = normalize_alert(item)
            result.alerts.append(alert)
        except (ValueError, TypeError) as exc:
            result.warnings += 1
            result.warning_messages.append(f"Entry {idx}: {exc}")
    return result


def _looks_like_logsentinel_list(records: list[Any]) -> bool:
    """Heuristic check for a top-level list of LogSentinel detection objects."""
    for item in records:
        if isinstance(item, dict):
            keys = {str(k).strip().lower() for k in item}
            if "rule" in keys or "rule_title" in keys or "alert_id" in keys:
                return True
    return False


def parse_logsentinel_json(data: Any) -> IngestResult:
    """Parse LogSentinel JSON output (object with 'detections'/'alerts' or top-level list)."""
    if isinstance(data, dict):
        if isinstance(data.get("detections"), list):
            return _parse_records(data["detections"], "logsentinel_json")
        if isinstance(data.get("alerts"), list):
            return _parse_records(data["alerts"], "logsentinel_json")
        raise IngestError(
            "LogSentinel JSON object must contain a 'detections' or 'alerts' list."
        )
    if isinstance(data, list):
        return _parse_records(data, "logsentinel_json")
    raise IngestError("JSON root must be an array or an object containing detections.")


def parse_generic_json(data: Any) -> IngestResult:
    """Parse generic JSON alert array."""
    if isinstance(data, list):
        return _parse_records(data, "generic_json")
    if isinstance(data, dict):
        for key in ("alerts", "detections", "events", "records"):
            if isinstance(data.get(key), list):
                return _parse_records(data[key], "generic_json")
    raise IngestError("Generic JSON must be a list of alert objects.")


def parse_json_text(text: str) -> IngestResult:
    """Parse JSON text, auto-detecting LogSentinel vs generic alert format."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid JSON: {exc}") from exc

    if isinstance(data, dict):
        if "detections" in data or "alerts" in data:
            return parse_logsentinel_json(data)
        return parse_generic_json(data)
    if isinstance(data, list):
        if _looks_like_logsentinel_list(data):
            return parse_logsentinel_json(data)
        return parse_generic_json(data)
    raise IngestError("JSON root must be a list or object.")


def parse_csv_text(text: str) -> IngestResult:
    """Parse CSV alert export using csv.DictReader with flexible header mapping."""
    stripped = text.strip()
    if not stripped:
        raise IngestError("CSV file is empty.")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise IngestError("CSV file is missing a header row.")

    records: list[dict[str, Any]] = []
    for row in reader:
        cleaned = {k: v for k, v in row.items() if k is not None}
        records.append(cleaned)
    return _parse_records(records, "csv")


def ingest_file(path: Path) -> IngestResult:
    """Read and parse an alert file, auto-detecting format from its extension."""
    if not path.exists():
        raise IngestError(f"Input file not found: {path}")
    if not path.is_file():
        raise IngestError(f"Input path is not a file: {path}")

    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise IngestError(f"Failed to read '{path}': {exc}") from exc

    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_json_text(text)
    if suffix == ".csv":
        return parse_csv_text(text)

    # Fallback auto-detection for non-standard extensions
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return parse_json_text(text)
    return parse_csv_text(text)

"""Unit tests for alert ingestion parsers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shiftsentinel.ingest import (
    IngestError,
    ingest_file,
    parse_csv_text,
    parse_json_text,
    parse_logsentinel_json,
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestIngest(unittest.TestCase):
    """Tests for LogSentinel JSON, generic JSON, and CSV ingestion."""

    def test_sample_logsentinel_and_csv_parity(self) -> None:
        json_res = ingest_file(SAMPLES_DIR / "logsentinel_report.json")
        csv_res = ingest_file(SAMPLES_DIR / "alerts.csv")

        self.assertEqual(json_res.source_format, "logsentinel_json")
        self.assertEqual(csv_res.source_format, "csv")
        self.assertEqual(json_res.warnings, 0)
        self.assertEqual(csv_res.warnings, 0)
        self.assertEqual(len(json_res.alerts), 52)
        self.assertEqual(len(csv_res.alerts), 52)

        json_rules = [a.rule_name for a in json_res.alerts]
        csv_rules = [a.rule_name for a in csv_res.alerts]
        self.assertEqual(json_rules, csv_rules)

    def test_flexible_field_mapping_variants(self) -> None:
        payload = [
            {
                "time": "2026-11-25T22:10:00Z",
                "src_ip": "203.0.113.55",
                "dst_ip": "10.0.0.5",
                "hostname": "WEB-01",
                "username": "alice",
                "alert_name": "Suspicious Web Request",
                "sev": "crit",
                "technique_id": "T1190",
                "tactic": "Initial Access",
                "message": "SQL injection attempt detected",
            }
        ]
        res = parse_json_text(json.dumps(payload))
        self.assertEqual(len(res.alerts), 1)
        alert = res.alerts[0]
        self.assertEqual(alert.timestamp, "2026-11-25T22:10:00+00:00")
        self.assertEqual(alert.source_ip, "203.0.113.55")
        self.assertEqual(alert.dest_ip, "10.0.0.5")
        self.assertEqual(alert.host, "WEB-01")
        self.assertEqual(alert.user, "alice")
        self.assertEqual(alert.rule_name, "Suspicious Web Request")
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.mitre_technique, "T1190")
        self.assertEqual(alert.mitre_tactic, "Initial Access")
        self.assertEqual(alert.description, "SQL injection attempt detected")

    def test_logsentinel_top_level_list_and_malformed_entries(self) -> None:
        payload = [
            {
                "timestamp": "2026-11-25T23:00:00+00:00",
                "rule": "SSH Brute Force Attempt",
                "severity": "HIGH",
                "source_ip": "192.0.2.10",
            },
            "not-a-dict",
            {"timestamp": "invalid-date", "rule": "Broken"},
            {"timestamp": "2026-11-25T23:05:00Z"},  # missing rule
        ]
        res = parse_logsentinel_json(payload)
        self.assertEqual(len(res.alerts), 1)
        self.assertEqual(res.warnings, 3)

    def test_csv_case_insensitive_headers(self) -> None:
        csv_data = (
            "Time,SRC_IP,Hostname,Username,Rule_Name,Severity,Message\n"
            "2026-11-25T22:30:00Z,198.51.100.12,APP-01,bob,Failed Login,warning,Bad password\n"
        )
        res = parse_csv_text(csv_data)
        self.assertEqual(len(res.alerts), 1)
        self.assertEqual(res.alerts[0].severity, "medium")
        self.assertEqual(res.alerts[0].host, "APP-01")
        self.assertEqual(res.alerts[0].user, "bob")

    def test_missing_file_raises_ingest_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "does_not_exist.json"
            with self.assertRaises(IngestError):
                ingest_file(missing)


if __name__ == "__main__":
    unittest.main()

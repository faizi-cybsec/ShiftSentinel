"""Unit tests for the alert-to-incident grouping engine."""

from __future__ import annotations

import unittest

from shiftsentinel.grouping import group_alerts
from shiftsentinel.models import Alert


class TestGrouping(unittest.TestCase):
    """Tests for alert correlation, merging, sorting, and title generation."""

    def test_merges_same_rule_and_ip_with_max_severity(self) -> None:
        alerts = [
            Alert(
                timestamp="2026-11-25T22:00:00+00:00",
                source_ip="185.92.72.110",
                host="BASTION-01",
                user="root",
                rule_name="SSH Brute Force Attempt",
                severity="medium",
                mitre_technique="T1110",
                description="Failed login 1",
            ),
            Alert(
                timestamp="2026-11-25T22:02:00+00:00",
                source_ip="185.92.72.110",
                host="BASTION-01",
                user="admin",
                rule_name="SSH Brute Force Attempt",
                severity="high",
                mitre_technique="T1110",
                description="Failed login 2",
            ),
        ]
        incidents = group_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.id, "INC-001")
        self.assertEqual(inc.severity, "high")
        self.assertEqual(inc.alert_count, 2)
        self.assertEqual(inc.users, ["root", "admin"])
        self.assertIn("185.92.72.110", inc.title)
        self.assertIn("Multiple failed logins", inc.title)

    def test_merges_across_rules_by_source_ip_and_mitre_technique(self) -> None:
        alerts = [
            Alert(
                timestamp="2026-11-25T23:10:00+00:00",
                source_ip="185.92.72.110",
                host="BASTION-01",
                user="root",
                rule_name="SSH Brute Force Attempt",
                severity="high",
                mitre_technique="T1110",
            ),
            Alert(
                timestamp="2026-11-25T23:25:00+00:00",
                source_ip="185.92.72.110",
                host="BASTION-01",
                user="admin",
                rule_name="SSH Login Success After Brute Force",
                severity="critical",
                mitre_technique="T1110",
            ),
        ]
        incidents = group_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, "critical")
        self.assertEqual(incidents[0].alert_count, 2)

    def test_does_not_merge_empty_source_ip_across_different_rules(self) -> None:
        alerts = [
            Alert(
                timestamp="2026-11-25T22:00:00+00:00",
                source_ip="",
                host="WS-1042",
                rule_name="Malware Detection A",
                severity="high",
                mitre_technique="T1204",
            ),
            Alert(
                timestamp="2026-11-25T22:10:00+00:00",
                source_ip="",
                host="WS-2001",
                rule_name="Malware Detection B",
                severity="medium",
                mitre_technique="T1204",
            ),
        ]
        incidents = group_alerts(alerts)
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].id, "INC-001")
        self.assertEqual(incidents[0].severity, "high")
        self.assertEqual(incidents[0].title, "Malware detection on WS-1042")
        self.assertEqual(incidents[1].id, "INC-002")

    def test_sorting_severity_then_count(self) -> None:
        alerts = [
            Alert(
                timestamp="2026-11-25T22:00:00+00:00",
                source_ip="10.0.0.1",
                rule_name="Low Noise",
                severity="low",
            ),
            Alert(
                timestamp="2026-11-25T22:01:00+00:00",
                source_ip="10.0.0.1",
                rule_name="Low Noise",
                severity="low",
            ),
            Alert(
                timestamp="2026-11-25T22:02:00+00:00",
                source_ip="10.0.0.2",
                rule_name="Critical Alert",
                severity="critical",
            ),
        ]
        incidents = group_alerts(alerts)
        self.assertEqual([i.severity for i in incidents], ["critical", "low"])
        self.assertEqual([i.id for i in incidents], ["INC-001", "INC-002"])


if __name__ == "__main__":
    unittest.main()

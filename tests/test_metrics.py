"""Unit tests for pure shift metrics computation."""

from __future__ import annotations

import unittest

from shiftsentinel.metrics import compute_metrics
from shiftsentinel.models import Alert, Incident


class TestMetrics(unittest.TestCase):
    """Tests for severity counts, top talkers, and hourly bucketing."""

    def test_compute_metrics_on_handbuilt_alerts(self) -> None:
        alerts = [
            Alert(
                timestamp="2026-11-25T23:05:00+00:00",
                source_ip="185.92.72.110",
                user="root",
                rule_name="SSH Brute Force",
                severity="high",
            ),
            Alert(
                timestamp="2026-11-25T23:10:00+00:00",
                source_ip="185.92.72.110",
                user="admin",
                rule_name="SSH Brute Force",
                severity="critical",
            ),
            Alert(
                timestamp="2026-11-25T23:15:00+00:00",
                source_ip="185.92.72.110",
                user="root",
                rule_name="SSH Brute Force",
                severity="high",
            ),
            Alert(
                timestamp="2026-11-26T01:20:00+00:00",
                source_ip="45.142.212.61",
                user="",
                rule_name="Port Scan",
                severity="medium",
            ),
            Alert(
                timestamp="2026-11-26T02:00:00+00:00",
                source_ip="10.20.14.105",
                user="k.wilson",
                rule_name="USB Policy",
                severity="low",
            ),
        ]
        incidents = [
            Incident(id="INC-001", title="SSH", severity="critical", alert_count=3),
            Incident(id="INC-002", title="Scan", severity="medium", alert_count=1),
            Incident(id="INC-003", title="USB", severity="low", alert_count=1),
        ]

        m = compute_metrics(alerts, incidents, watchlist_hits=2)
        self.assertEqual(m.total_alerts, 5)
        self.assertEqual(m.total_incidents, 3)
        self.assertEqual(
            m.severity_counts,
            {"low": 1, "medium": 1, "high": 2, "critical": 1},
        )
        self.assertEqual(m.top_source_ips[0], ("185.92.72.110", 3))
        self.assertEqual(m.top_users[0], ("root", 2))
        self.assertEqual(m.alerts_per_hour[23], 3)
        self.assertEqual(m.alerts_per_hour[1], 1)
        self.assertEqual(m.alerts_per_hour[2], 1)
        self.assertEqual(m.alerts_per_hour[0], 0)
        self.assertEqual(len(m.alerts_per_hour), 24)
        self.assertEqual(m.busiest_hour, 23)
        self.assertEqual(m.busiest_hour_count, 3)
        self.assertEqual(m.watchlist_hits, 2)
        self.assertEqual(m.shift_start, "2026-11-25T23:05:00+00:00")
        self.assertEqual(m.shift_end, "2026-11-26T02:00:00+00:00")

    def test_empty_alerts(self) -> None:
        m = compute_metrics([], [])
        self.assertEqual(m.total_alerts, 0)
        self.assertIsNone(m.busiest_hour)
        self.assertEqual(m.shift_start, "")
        self.assertEqual(m.shift_end, "")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for persistent carry-over watchlist management."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shiftsentinel.models import Incident
from shiftsentinel.watchlist import (
    add_entry,
    apply_watchlist,
    auto_watch_incidents,
    list_entries,
    resolve_entry,
)


class TestWatchlist(unittest.TestCase):
    """Tests for watchlist persistence, matching, and auto-watch."""

    def test_add_list_resolve_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wl_path = Path(tmpdir) / "watchlist.json"

            entry, created = add_entry(
                ioc="185.92.72.110",
                entry_type="ip",
                reason="SSH brute force source",
                added_by="Faizan Ahmed",
                source_incident="INC-001",
                path=wl_path,
            )
            self.assertTrue(created)
            self.assertEqual(entry.status, "active")

            # Adding same active IOC updates rather than duplicating
            _, created_again = add_entry(
                ioc="185.92.72.110",
                entry_type="ip",
                reason="Confirmed compromise source",
                path=wl_path,
            )
            self.assertFalse(created_again)

            active = list_entries(path=wl_path, active_only=True)
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0].reason, "Confirmed compromise source")

            resolved = resolve_entry("185.92.72.110", path=wl_path)
            self.assertTrue(resolved)
            self.assertEqual(len(list_entries(path=wl_path, active_only=True)), 0)
            self.assertEqual(len(list_entries(path=wl_path, active_only=False)), 1)

    def test_apply_watchlist_and_auto_watch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wl_path = Path(tmpdir) / "watchlist.json"
            incidents = [
                Incident(
                    id="INC-001",
                    title="Multiple failed logins from 185.92.72.110 targeting root",
                    severity="critical",
                    source_ips=["185.92.72.110"],
                    hosts=["BASTION-01"],
                    users=["root"],
                    alert_count=19,
                ),
                Incident(
                    id="INC-002",
                    title="External Port Scan",
                    severity="medium",
                    source_ips=["45.142.212.61"],
                    alert_count=12,
                ),
            ]

            added = auto_watch_incidents(
                incidents,
                threshold="critical",
                added_by="Faizan Ahmed",
                path=wl_path,
            )
            self.assertEqual(len(added), 1)
            self.assertEqual(added[0].ioc, "185.92.72.110")

            entries = list_entries(path=wl_path, active_only=True)
            hits = apply_watchlist(incidents, entries)
            self.assertEqual(hits, 1)
            self.assertEqual(incidents[0].watchlist_hits, ["185.92.72.110"])
            self.assertEqual(incidents[1].watchlist_hits, [])


if __name__ == "__main__":
    unittest.main()

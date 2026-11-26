# ShiftSentinel

**Automated SOC shift handover report generator — ingest alert feeds, correlate incidents, track carry-over IOCs, and produce HTML, Markdown, and terminal handover reports using Python's standard library only.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/faizi-cybsec/ShiftSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/faizi-cybsec/ShiftSentinel/actions/workflows/ci.yml)

---

## Why I Built This

In a 24/7 Security Operations Center, the riskiest moment of the day is the shift handover. When an 8-hour night shift ends, open investigations, active brute-force sources, and suspicious hosts must be communicated clearly to the incoming analyst so nothing gets dropped between shifts. ShiftSentinel automates that handover: it turns raw alert exports—including [LogSentinel](https://github.com/faizi-cybsec/LogSentinel) JSON reports—into a structured, sign-off-ready handover package in seconds.

## Features

- **Zero external dependencies:** Pure Python 3.10+ standard library only (`csv`, `json`, `argparse`, `pathlib`, `html`, `unittest`).
- **Multi-format ingestion:** First-class support for LogSentinel JSON reports, generic JSON alert arrays, and CSV exports with flexible, case-insensitive field mapping.
- **Incident correlation:** Groups alerts by `(rule_name, source_ip)` and merges related alerts sharing `(source_ip, mitre_technique)` across rules, assigning prioritized IDs (`INC-001`, `INC-002`, ...).
- **Persistent carry-over watchlist:** Tracks active IOCs (`ip`, `domain`, `hash`, `user`, `host`) across shifts in `~/.shiftsentinel/watchlist.json`, flags matching incidents with `⚠ WATCHLIST`, and optionally auto-adds critical incident IPs (`--auto-watch`).
- **Three report formats:**
  - **HTML (`--format html`):** Self-contained dark-theme SOC report with inline CSS, severity chips, an inline SVG 24-hour alert volume chart, top talkers, carry-over watchlist, and analyst sign-off block.
  - **Markdown (`--format md`):** Clean tables ready to paste into Jira, ServiceNow, or a wiki.
  - **Terminal (`--format terminal`):** Compact ANSI-coloured summary that degrades gracefully when piped.

## Installation

```bash
git clone https://github.com/faizi-cybsec/ShiftSentinel.git
cd ShiftSentinel

# Optional: install as an editable package to expose the `shiftsentinel` command
pip install -e .
```

You can also run it directly without installing anything:

```bash
python -m shiftsentinel.cli --help
```

## Quick Start

### 1. Inspect / Validate Alert Inputs (`ingest`)

```bash
python -m shiftsentinel.cli ingest --input samples/alerts.csv
python -m shiftsentinel.cli ingest --input samples/logsentinel_report.json
```

### 2. Manage the Carry-Over Watchlist (`watch`)

```bash
python -m shiftsentinel.cli watch add --ioc 185.92.72.110 --type ip --reason "SSH brute force + login success on BASTION-01"
python -m shiftsentinel.cli watch list
python -m shiftsentinel.cli watch resolve --ioc 185.92.72.110
```

### 3. Generate Handover Reports (`report`)

```bash
# Terminal summary from LogSentinel JSON
python -m shiftsentinel.cli report --input samples/logsentinel_report.json --format terminal --shift "Night" --analyst "Faizan Ahmed" --incoming "Next Analyst"

# Self-contained HTML report from CSV
python -m shiftsentinel.cli report --input samples/alerts.csv --format html --output handover_report.html --shift "Night" --analyst "Faizan Ahmed" --incoming "Next Analyst" --auto-watch

# Generate HTML + Markdown + Terminal together
python -m shiftsentinel.cli report --input samples/logsentinel_report.json --format all --output handover_report --shift "Night" --analyst "Faizan Ahmed" --incoming "Next Analyst"
```

## Example Terminal Output

```text
========================================================================
  ShiftSentinel | Night Shift | Faizan Ahmed -> Next Analyst
========================================================================
  Alerts: 52  |  Incidents: 11  |  CRITICAL=1  HIGH=23  MEDIUM=20  LOW=8

  Top Incidents:
  INC-001 [CRITICAL] (19 alerts) Multiple failed logins from 185.92.72.110 targeting root, admin [WATCHLIST]
  INC-002 [HIGH    ] ( 3 alerts) Malware detection on WS-1042
  INC-003 [HIGH    ] ( 2 alerts) Privilege escalation on APP-SRV-02 by dev_svc
  INC-004 [MEDIUM  ] (12 alerts) Port scan / reconnaissance from 45.142.212.61 (12 alerts)
  INC-005 [MEDIUM  ] ( 4 alerts) Web Directory Enumeration from 91.240.118.172 (4 alerts)
  ... and 6 more incident(s).

  Watchlist: 1 active carry-over IOC(s) | 1 hit(s) this shift
========================================================================
```

## Report Screenshots

Place rendered HTML report screenshots in the [`docs/`](docs/) directory (for example, `docs/handover_report.png`) and link them here once captured from your browser.

## Project Structure

```text
ShiftSentinel/
├── .github/
│   └── workflows/
│       └── ci.yml                # GitHub Actions unittest + CLI smoke test (Python 3.10–3.12)
├── .gitignore
├── LICENSE                       # MIT License
├── README.md
├── pyproject.toml                # Package metadata and `shiftsentinel` entry point
├── config.example.json           # Example team, shift, threshold, and escalation config
├── docs/
│   └── .gitkeep                  # Screenshot placeholder directory
├── shiftsentinel/
│   ├── __init__.py
│   ├── cli.py                    # argparse CLI (report, ingest, watch)
│   ├── models.py                 # Alert, Incident, and WatchlistEntry dataclasses
│   ├── ingest.py                 # LogSentinel JSON, generic JSON, and CSV parsers
│   ├── grouping.py               # Alert-to-incident correlation engine
│   ├── watchlist.py              # Persistent JSON watchlist store
│   ├── metrics.py                # Pure shift metrics computation
│   ├── report_html.py            # Dark-theme HTML report + inline SVG chart
│   ├── report_md.py              # Markdown handover report
│   └── report_terminal.py        # ANSI-coloured terminal summary
├── samples/
│   ├── logsentinel_report.json   # 52-alert night shift scenario (LogSentinel JSON)
│   └── alerts.csv                # Matching 52-alert night shift scenario (CSV)
└── tests/
    ├── __init__.py
    ├── test_ingest.py
    ├── test_grouping.py
    ├── test_watchlist.py
    └── test_metrics.py
```

## How It Works

1. **Ingest:** Reads `.json` or `.csv` inputs, auto-detecting LogSentinel vs. generic JSON shapes, normalizing timestamps to timezone-aware ISO 8601, and skipping malformed entries with warning counts.
2. **Group:** Clusters alerts sharing `(rule_name, source_ip)` and merges cross-rule activity sharing `(source_ip, mitre_technique)` into prioritized incidents with generated titles.
3. **Watchlist Persistence:** Loads active IOCs from `~/.shiftsentinel/watchlist.json` (or `--watchlist` / config), flags matching incidents, and renders a carry-over section so open items survive shift boundaries.
4. **Metrics & Report:** Computes severity breakdowns, top talkers, and 24-hour UTC alert buckets, then renders HTML, Markdown, or terminal output with analyst sign-off.

## Roadmap

- **v1.1:** Shift-over-shift comparison (delta in alert volume, recurring IPs, and incident resolution velocity).
- **v1.2:** Splunk CSV export profile and optional SMTP email delivery for automated shift-end dispatch.

## MITRE ATT&CK Note

Sample alerts and grouped incidents reference [MITRE ATT&CK](https://attack.mitre.org/) technique and tactic IDs (such as `T1110` Brute Force, `T1548` Abuse Elevation Control Mechanism, `T1204` User Execution, and `T1046` Network Service Discovery) for SOC triage alignment.

## License

Released under the [MIT License](LICENSE). Copyright &copy; 2026 Faizan Ahmed.

## Author

**Faizan Ahmed** — Aspiring SOC Analyst
GitHub: [https://github.com/faizi-cybsec](https://github.com/faizi-cybsec)

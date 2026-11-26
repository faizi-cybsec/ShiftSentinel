"""Self-contained dark-theme HTML shift handover report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .metrics import ShiftMetrics
from .models import Incident, WatchlistEntry, format_iso_timestamp
from .watchlist import format_age

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#e5484d",
    "high": "#f76b15",
    "medium": "#ffb224",
    "low": "#46a758",
}


def _esc(value: Any) -> str:
    """HTML-escape any user-supplied or alert-derived text."""
    return html.escape(str(value), quote=True)


def _render_hourly_svg(alerts_per_hour: dict[int, int]) -> str:
    """Generate an inline SVG 24-hour bar chart of alert volume (no JavaScript)."""
    width = 760
    height = 200
    pad_left = 36
    pad_right = 14
    pad_top = 20
    pad_bottom = 32
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    counts = [alerts_per_hour.get(h, 0) for h in range(24)]
    max_val = max(counts) if any(counts) else 1
    slot_w = plot_w / 24.0
    bar_w = max(8.0, slot_w - 6.0)

    parts: list[str] = [
        (
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            'role="img" aria-label="Alerts per hour (UTC)" '
            'xmlns="http://www.w3.org/2000/svg" style="display:block;max-width:100%;">'
        ),
    ]

    # Horizontal gridlines (0%, 50%, 100%)
    for frac in (0.0, 0.5, 1.0):
        y = pad_top + plot_h * (1.0 - frac)
        label_val = round(max_val * frac)
        parts.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - pad_right}" y2="{y:.1f}" '
            'stroke="#1e2d4a" stroke-width="1" />'
        )
        parts.append(
            f'<text x="{pad_left - 6}" y="{y + 4:.1f}" text-anchor="end" '
            'fill="#8fa3c7" font-size="10" font-family="ui-monospace,Consolas,monospace">'
            f"{label_val}</text>"
        )

    # Bars and hour labels
    for hour in range(24):
        count = counts[hour]
        bar_h = (count / max_val) * plot_h if max_val > 0 else 0.0
        x = pad_left + hour * slot_w + (slot_w - bar_w) / 2.0
        y = pad_top + plot_h - bar_h
        fill = "#3b82f6" if count > 0 else "#1a2742"
        if count == max_val and count > 0:
            fill = "#f76b15"

        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(bar_h, 2.0):.1f}" '
            f'rx="2" fill="{fill}"><title>{hour:02d}:00 - {count} alerts</title></rect>'
        )
        if count > 0:
            parts.append(
                f'<text x="{x + bar_w / 2.0:.1f}" y="{max(11.0, y - 4.0):.1f}" '
                'text-anchor="middle" fill="#cbd5e1" font-size="9" '
                'font-family="ui-monospace,Consolas,monospace">'
                f"{count}</text>"
            )
        if hour % 2 == 0:
            parts.append(
                f'<text x="{x + bar_w / 2.0:.1f}" y="{height - 10}" '
                'text-anchor="middle" fill="#8fa3c7" font-size="10" '
                'font-family="ui-monospace,Consolas,monospace">'
                f"{hour:02d}</text>"
            )

    parts.append("</svg>")
    return "\n".join(parts)


def generate_html_report(
    incidents: list[Incident],
    metrics: ShiftMetrics,
    watchlist_entries: list[WatchlistEntry],
    shift_name: str = "Unspecified",
    outgoing_analyst: str = "On-duty Analyst",
    incoming_analyst: str = "Incoming Analyst",
    config: dict[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render a complete, self-contained dark-theme HTML shift handover report."""
    cfg = config or {}
    team_name = str(cfg.get("team_name") or "Security Operations Center")
    organisation = str(cfg.get("organisation") or "").strip()
    team_display = f"{team_name} — {organisation}" if organisation else team_name

    now = generated_at if generated_at is not None else datetime.now(timezone.utc)
    generated_str = format_iso_timestamp(now)
    shift_window = (
        f"{metrics.shift_start} to {metrics.shift_end}"
        if metrics.shift_start and metrics.shift_end
        else "No alerts in window"
    )

    crit_high_count = (
        metrics.severity_counts.get("critical", 0) + metrics.severity_counts.get("high", 0)
    )
    active_watchlist = [e for e in watchlist_entries if e.status == "active"]

    # Severity breakdown rows
    sev_bars_html: list[str] = []
    max_sev = max(metrics.severity_counts.values()) if metrics.severity_counts else 1
    max_sev = max(max_sev, 1)
    for sev in ("critical", "high", "medium", "low"):
        count = metrics.severity_counts.get(sev, 0)
        pct = round((count / max_sev) * 100) if count > 0 else 0
        color = _SEVERITY_COLORS[sev]
        sev_bars_html.append(
            f'<div class="sev-row">'
            f'<span class="chip chip-{sev}">{_esc(sev.upper())}</span>'
            f'<div class="sev-bar-track"><div class="sev-bar-fill" '
            f'style="width:{pct}%;background:{color};"></div></div>'
            f'<span class="sev-count">{count}</span>'
            f"</div>"
        )

    # Incident table rows
    incident_rows: list[str] = []
    if not incidents:
        incident_rows.append(
            '<tr><td colspan="9" class="empty-cell">No incidents recorded during this shift.</td></tr>'
        )
    else:
        for inc in incidents:
            ips = ", ".join(inc.source_ips) if inc.source_ips else "—"
            mitre = ", ".join(inc.mitre_techniques) if inc.mitre_techniques else "—"
            window = f"{inc.first_seen}<br><span class=\"muted\">&rarr; {inc.last_seen}</span>"
            watch_badge = (
                f'<span class="watch-flag" title="{_esc(", ".join(inc.watchlist_hits))}">'
                "&#9888; WATCHLIST</span>"
                if inc.watchlist_hits
                else '<span class="muted">—</span>'
            )
            incident_rows.append(
                "<tr>"
                f'<td class="mono">{_esc(inc.id)}</td>'
                f'<td><span class="chip chip-{_esc(inc.severity)}">{_esc(inc.severity.upper())}</span></td>'
                f'<td class="inc-title">{_esc(inc.title)}</td>'
                f'<td><span class="status-pill">{_esc(inc.status)}</span></td>'
                f'<td class="mono num">{inc.alert_count}</td>'
                f'<td class="mono small">{window}</td>'
                f'<td class="mono small">{_esc(ips)}</td>'
                f'<td class="mono small">{_esc(mitre)}</td>'
                f"<td>{watch_badge}</td>"
                "</tr>"
            )

    # Top talkers tables
    ip_rows = "".join(
        f'<tr><td class="mono">{_esc(ip)}</td><td class="mono num">{cnt}</td></tr>'
        for ip, cnt in metrics.top_source_ips
    ) or '<tr><td colspan="2" class="empty-cell">No source IP data.</td></tr>'

    user_rows = "".join(
        f'<tr><td class="mono">{_esc(user)}</td><td class="mono num">{cnt}</td></tr>'
        for user, cnt in metrics.top_users
    ) or '<tr><td colspan="2" class="empty-cell">No targeted user data.</td></tr>'

    # Watchlist table rows
    watchlist_rows: list[str] = []
    if not active_watchlist:
        watchlist_rows.append(
            '<tr><td colspan="6" class="empty-cell">No active carry-over watchlist items.</td></tr>'
        )
    else:
        for entry in active_watchlist:
            age = format_age(entry.added_at, now=now)
            watchlist_rows.append(
                "<tr>"
                f'<td class="mono">{_esc(entry.ioc)}</td>'
                f'<td><span class="type-pill">{_esc(entry.type.upper())}</span></td>'
                f"<td>{_esc(entry.reason)}</td>"
                f"<td>{_esc(entry.added_by)}</td>"
                f'<td class="small">{_esc(entry.source_incident or "—")}</td>'
                f'<td class="mono">{_esc(age)}</td>'
                "</tr>"
            )

    busiest_text = (
        f"{metrics.busiest_hour:02d}:00 UTC ({metrics.busiest_hour_count} alerts)"
        if metrics.busiest_hour is not None
        else "N/A"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShiftSentinel — Shift Handover Report ({_esc(shift_name)})</title>
<style>
  :root {{
    --bg: #0b1220;
    --surface: #111a2e;
    --surface-alt: #16223b;
    --border: #1e2d4a;
    --text: #e2e8f0;
    --muted: #8fa3c7;
    --accent: #3b82f6;
    --critical: #e5484d;
    --high: #f76b15;
    --medium: #ffb224;
    --low: #46a758;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 28px 20px 48px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Arial, sans-serif;
    line-height: 1.5;
    font-size: 14px;
  }}
  .container {{
    max-width: 1200px;
    margin: 0 auto;
  }}
  .header-card {{
    background: linear-gradient(135deg, #111a2e 0%, #16223b 100%);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px 24px;
    margin-bottom: 16px;
  }}
  .header-top {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
  }}
  h1 {{
    margin: 0 0 6px;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.01em;
    color: #f8fafc;
  }}
  .subtitle {{
    color: var(--muted);
    font-size: 13px;
  }}
  .shift-badge {{
    background: rgba(59, 130, 246, 0.16);
    color: #93c5fd;
    border: 1px solid rgba(59, 130, 246, 0.35);
    padding: 5px 12px;
    border-radius: 999px;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 10px 18px;
    margin-top: 16px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
    font-size: 13px;
  }}
  .meta-label {{
    color: var(--muted);
    margin-right: 6px;
  }}
  .signoff-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 14px;
    margin-bottom: 18px;
  }}
  .signoff-pill {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
    margin-bottom: 18px;
  }}
  .kpi-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 18px;
  }}
  .kpi-label {{
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .kpi-value {{
    font-size: 28px;
    font-weight: 700;
    margin-top: 4px;
    color: #f8fafc;
  }}
  .kpi-value.warn {{ color: var(--critical); }}
  .kpi-value.watch {{ color: var(--medium); }}
  .panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 18px;
  }}
  .panel h2 {{
    margin: 0 0 14px;
    font-size: 15px;
    font-weight: 600;
    color: #f1f5f9;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .split-grid {{
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 18px;
    margin-bottom: 18px;
  }}
  .two-col {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 18px;
    margin-bottom: 18px;
  }}
  @media (max-width: 860px) {{
    .split-grid {{ grid-template-columns: 1fr; }}
  }}
  .sev-row {{
    display: grid;
    grid-template-columns: 88px 1fr 40px;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }}
  .sev-bar-track {{
    height: 10px;
    background: var(--surface-alt);
    border-radius: 999px;
    overflow: hidden;
  }}
  .sev-bar-fill {{
    height: 100%;
    border-radius: 999px;
  }}
  .sev-count {{
    text-align: right;
    font-family: ui-monospace, Consolas, monospace;
    font-weight: 600;
  }}
  .chip {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.04em;
    color: #0b1220;
    text-align: center;
  }}
  .chip-critical {{ background: var(--critical); color: #fff; }}
  .chip-high {{ background: var(--high); color: #fff; }}
  .chip-medium {{ background: var(--medium); color: #0b1220; }}
  .chip-low {{ background: var(--low); color: #0b1220; }}
  .status-pill, .type-pill {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    background: var(--surface-alt);
    border: 1px solid var(--border);
    color: var(--muted);
    text-transform: uppercase;
  }}
  .watch-flag {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    background: rgba(255, 178, 36, 0.16);
    color: var(--medium);
    border: 1px solid rgba(255, 178, 36, 0.45);
    white-space: nowrap;
  }}
  .table-wrap {{
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th, td {{
    padding: 10px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  th {{
    color: var(--muted);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: var(--surface-alt);
  }}
  tbody tr:hover {{
    background: rgba(255, 255, 255, 0.02);
  }}
  .mono {{
    font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  }}
  .small {{ font-size: 12px; }}
  .num {{ text-align: right; }}
  .muted {{ color: var(--muted); }}
  .inc-title {{ font-weight: 600; color: #f8fafc; }}
  .empty-cell {{
    text-align: center;
    color: var(--muted);
    padding: 18px;
  }}
  .signoff-footer {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 18px;
  }}
  .sig-line {{
    border-bottom: 1px dashed var(--muted);
    padding-bottom: 6px;
    margin-top: 8px;
    font-weight: 600;
    color: #f8fafc;
  }}
</style>
</head>
<body>
<div class="container">
  <header class="header-card">
    <div class="header-top">
      <div>
        <h1>ShiftSentinel &mdash; Shift Handover Report</h1>
        <div class="subtitle">{_esc(team_display)}</div>
      </div>
      <span class="shift-badge">{_esc(shift_name)} Shift</span>
    </div>
    <div class="meta-grid">
      <div><span class="meta-label">Generated:</span><span class="mono">{_esc(generated_str)}</span></div>
      <div><span class="meta-label">Shift Window:</span><span class="mono">{_esc(shift_window)}</span></div>
      <div><span class="meta-label">Busiest Hour:</span><span class="mono">{_esc(busiest_text)}</span></div>
    </div>
  </header>

  <section class="signoff-row">
    <div class="signoff-pill">
      <span class="meta-label">Outgoing Analyst</span>
      <strong>{_esc(outgoing_analyst)}</strong>
    </div>
    <div class="signoff-pill">
      <span class="meta-label">Incoming Analyst</span>
      <strong>{_esc(incoming_analyst)}</strong>
    </div>
  </section>

  <section class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Total Alerts</div>
      <div class="kpi-value">{metrics.total_alerts}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Grouped Incidents</div>
      <div class="kpi-value">{metrics.total_incidents}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Critical + High Alerts</div>
      <div class="kpi-value warn">{crit_high_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Watchlist Hits</div>
      <div class="kpi-value watch">{metrics.watchlist_hits}</div>
    </div>
  </section>

  <section class="split-grid">
    <div class="panel" style="margin-bottom:0;">
      <h2>Severity Breakdown</h2>
      {"".join(sev_bars_html)}
    </div>
    <div class="panel" style="margin-bottom:0;">
      <h2>Alerts by Hour (UTC)</h2>
      {_render_hourly_svg(metrics.alerts_per_hour)}
    </div>
  </section>

  <section class="panel">
    <h2>Prioritized Incidents</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Status</th>
            <th class="num">Alerts</th>
            <th>First &ndash; Last Seen</th>
            <th>Source IPs</th>
            <th>MITRE</th>
            <th>Watchlist</th>
          </tr>
        </thead>
        <tbody>
          {"".join(incident_rows)}
        </tbody>
      </table>
    </div>
  </section>

  <section class="two-col">
    <div class="panel" style="margin-bottom:0;">
      <h2>Top Source IPs</h2>
      <table>
        <thead><tr><th>Source IP</th><th class="num">Alerts</th></tr></thead>
        <tbody>{ip_rows}</tbody>
      </table>
    </div>
    <div class="panel" style="margin-bottom:0;">
      <h2>Top Targeted Users</h2>
      <table>
        <thead><tr><th>Username</th><th class="num">Alerts</th></tr></thead>
        <tbody>{user_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>Carry-Over Watchlist (Active IOCs: {len(active_watchlist)})</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>IOC</th>
            <th>Type</th>
            <th>Reason</th>
            <th>Added By</th>
            <th>Source Incident</th>
            <th>Age</th>
          </tr>
        </thead>
        <tbody>
          {"".join(watchlist_rows)}
        </tbody>
      </table>
    </div>
  </section>

  <footer class="signoff-footer">
    <div>
      <div class="meta-label">Handed over by:</div>
      <div class="sig-line">{_esc(outgoing_analyst)}</div>
    </div>
    <div>
      <div class="meta-label">Received by:</div>
      <div class="sig-line">{_esc(incoming_analyst)}</div>
    </div>
  </footer>
</div>
</body>
</html>
"""

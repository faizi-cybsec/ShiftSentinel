"""Alert-to-incident correlation and grouping engine."""

from __future__ import annotations

from collections import OrderedDict

from .models import SEVERITY_RANK, Alert, Incident, parse_iso_timestamp


def _unique_preserve_order(values: list[str]) -> list[str]:
    """Return unique non-empty strings while preserving first-seen order."""
    seen: dict[str, None] = {}
    for val in values:
        cleaned = val.strip()
        if cleaned and cleaned not in seen:
            seen[cleaned] = None
    return list(seen.keys())


def _generate_title(
    rule_names: list[str],
    source_ips: list[str],
    hosts: list[str],
    users: list[str],
    alert_count: int,
) -> str:
    """Generate a human-readable incident title from rule keywords and entities."""
    combined_rules = " ".join(rule_names).lower()
    primary_rule = rule_names[0] if rule_names else "Security Alert"
    ip_str = source_ips[0] if source_ips else ""
    host_str = hosts[0] if hosts else ""
    users_str = ", ".join(users[:3])
    if len(users) > 3:
        users_str += f" (+{len(users) - 3} more)"

    if (
        "failed login" in combined_rules
        or "brute force" in combined_rules
        or "bruteforce" in combined_rules
        or ("ssh" in combined_rules and "fail" in combined_rules)
    ):
        if ip_str and users_str:
            return f"Multiple failed logins from {ip_str} targeting {users_str}"
        if ip_str:
            return f"Multiple failed logins from {ip_str}"
        if users_str:
            return f"Multiple failed logins targeting {users_str}"
        return f"Multiple failed logins ({alert_count} alerts)"

    if (
        "malware" in combined_rules
        or "trojan" in combined_rules
        or "ransomware" in combined_rules
        or "virus" in combined_rules
    ):
        if host_str:
            return f"Malware detection on {host_str}"
        if ip_str:
            return f"Malware detection involving {ip_str}"
        return f"Malware detection ({alert_count} alerts)"

    if "privilege escalation" in combined_rules or "sudo" in combined_rules or "privesc" in combined_rules:
        if host_str and users_str:
            return f"Privilege escalation on {host_str} by {users_str}"
        if host_str:
            return f"Privilege escalation on {host_str}"
        if users_str:
            return f"Privilege escalation by {users_str}"
        return f"Privilege escalation ({alert_count} alerts)"

    if "port scan" in combined_rules or "recon" in combined_rules or "scan" in combined_rules:
        if ip_str:
            return f"Port scan / reconnaissance from {ip_str} ({alert_count} alerts)"
        return f"Port scan / reconnaissance ({alert_count} alerts)"

    if ip_str:
        return f"{primary_rule} from {ip_str} ({alert_count} alerts)"
    if host_str:
        return f"{primary_rule} on {host_str} ({alert_count} alerts)"
    return f"{primary_rule} ({alert_count} alerts)"


def group_alerts(alerts: list[Alert]) -> list[Incident]:
    """Group alerts into prioritized incidents.

    Grouping rules:
    1. Alerts sharing ``(rule_name, source_ip)`` are grouped together.
    2. Groups sharing a non-empty ``(source_ip, mitre_technique)`` pair across
       different rules are merged into a single incident.
    3. Incidents are sorted by severity (critical first), then alert_count
       descending, then first_seen ascending, and assigned sequential IDs.
    """
    if not alerts:
        return []

    # Step 1: Primary grouping by (rule_name, source_ip)
    primary_groups: OrderedDict[tuple[str, str], list[Alert]] = OrderedDict()
    for alert in alerts:
        key = (alert.rule_name, alert.source_ip)
        primary_groups.setdefault(key, []).append(alert)

    # Step 2: Merge groups sharing non-empty (source_ip, mitre_technique)
    clusters: list[list[Alert]] = list(primary_groups.values())
    parent = list(range(len(clusters)))

    def find(idx: int) -> int:
        while parent[idx] != idx:
            parent[idx] = parent[parent[idx]]
            idx = parent[idx]
        return idx

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    pair_owner: dict[tuple[str, str], int] = {}
    for idx, group in enumerate(clusters):
        for alert in group:
            if alert.source_ip and alert.mitre_technique:
                pair = (alert.source_ip, alert.mitre_technique)
                if pair in pair_owner:
                    union(pair_owner[pair], idx)
                else:
                    pair_owner[pair] = idx

    merged_buckets: OrderedDict[int, list[Alert]] = OrderedDict()
    for idx, group in enumerate(clusters):
        root = find(idx)
        merged_buckets.setdefault(root, []).extend(group)

    # Step 3: Build Incident objects
    incidents: list[Incident] = []
    for bucket in merged_buckets.values():
        sorted_alerts = sorted(bucket, key=lambda a: parse_iso_timestamp(a.timestamp))
        highest_sev = max(
            (a.severity for a in sorted_alerts),
            key=lambda s: SEVERITY_RANK.get(s, 0),
        )
        # Prioritize rule names from highest severity alerts for title generation
        prioritized_rules = _unique_preserve_order(
            [
                a.rule_name
                for a in sorted(
                    sorted_alerts,
                    key=lambda x: -SEVERITY_RANK.get(x.severity, 0),
                )
            ]
        )
        source_ips = _unique_preserve_order([a.source_ip for a in sorted_alerts])
        hosts = _unique_preserve_order([a.host for a in sorted_alerts])
        users = _unique_preserve_order([a.user for a in sorted_alerts])
        mitre_techniques = _unique_preserve_order([a.mitre_technique for a in sorted_alerts])
        descriptions = _unique_preserve_order([a.description for a in sorted_alerts])[:3]

        title = _generate_title(
            rule_names=prioritized_rules,
            source_ips=source_ips,
            hosts=hosts,
            users=users,
            alert_count=len(sorted_alerts),
        )

        incidents.append(
            Incident(
                id="",
                title=title,
                severity=highest_sev,
                status="open",
                first_seen=sorted_alerts[0].timestamp,
                last_seen=sorted_alerts[-1].timestamp,
                alert_count=len(sorted_alerts),
                source_ips=source_ips,
                hosts=hosts,
                users=users,
                mitre_techniques=mitre_techniques,
                sample_descriptions=descriptions,
            )
        )

    # Step 4: Sort by severity descending, alert_count descending, first_seen ascending
    incidents.sort(
        key=lambda inc: (
            -SEVERITY_RANK.get(inc.severity, 0),
            -inc.alert_count,
            parse_iso_timestamp(inc.first_seen),
        )
    )

    # Step 5: Assign sequential IDs
    for idx, inc in enumerate(incidents, start=1):
        inc.id = f"INC-{idx:03d}"

    return incidents

"""
Digital forensics component.

Turns the raw event/alert stores into the artefacts an investigator produces:

  * timeline()         -- a normalised, time-ordered super-timeline of activity
  * collect_artifacts()-- IOCs grouped by type (hosts, accounts, IPs, files...)
  * chain_of_custody() -- an evidence register with hashes
  * forensic_report()  -- a court-/command-ready Markdown report

Designed to read the same JSONL the live engine writes, so a report can be
generated after the fact from ./data.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .store import STORE, EVENTS_FILE, ALERTS_FILE


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _load_jsonl(path: str) -> List[Dict]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def load_events(from_disk: bool = False) -> List[Dict]:
    return _load_jsonl(EVENTS_FILE) if from_disk else STORE.events(limit=100000)


def load_alerts(from_disk: bool = False) -> List[Dict]:
    return _load_jsonl(ALERTS_FILE) if from_disk else STORE.alerts(limit=100000)


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #
def _norm_time(rec: Dict) -> str:
    return rec.get("timestamp") or rec.get("detected_at") or rec.get("ingested_at", "")


def timeline(from_disk: bool = False, limit: int = 500) -> List[Dict]:
    """Time-ordered super-timeline merging events and alerts."""
    rows: List[Dict] = []
    for e in load_events(from_disk):
        rows.append({
            "time": _norm_time(e),
            "kind": "event",
            "source": e.get("source", "n/a"),
            "host": e.get("host") or e.get("dst_ip", "n/a"),
            "user": e.get("user", "n/a"),
            "detail": e.get("message", ""),
            "ref": e.get("_id", ""),
        })
    for a in load_alerts(from_disk):
        rows.append({
            "time": _norm_time(a),
            "kind": "ALERT",
            "source": a.get("rule_id", "n/a"),
            "host": a.get("host", "n/a"),
            "user": a.get("user", "n/a"),
            "detail": f"[{a.get('severity','').upper()}] {a.get('summary','')}",
            "ref": a.get("_id", ""),
        })
    rows.sort(key=lambda r: r["time"])
    return rows[-limit:]


# --------------------------------------------------------------------------- #
# Artifact / IOC collection
# --------------------------------------------------------------------------- #
def collect_artifacts(from_disk: bool = False) -> Dict:
    events = load_events(from_disk)
    alerts = load_alerts(from_disk)

    src_ips = Counter()
    accounts = Counter()
    hosts = Counter()
    files = set()
    hashes = set()
    techniques = Counter()
    commands = []

    for e in events:
        if e.get("src_ip"):
            src_ips[e["src_ip"]] += 1
        if e.get("user"):
            accounts[e["user"]] += 1
        if e.get("host"):
            hosts[e["host"]] += 1
        if e.get("file"):
            files.add(e["file"])
        if e.get("sha256"):
            hashes.add(e["sha256"])
        if e.get("command_line") and any(
            t in e["command_line"].lower()
            for t in ("powershell", "winpeas", "iex", "-enc")
        ):
            commands.append(e["command_line"][:160])

    for a in alerts:
        for t in a.get("mitre_techniques", []):
            techniques[t] += 1

    return {
        "suspicious_ips": src_ips.most_common(10),
        "involved_accounts": accounts.most_common(10),
        "affected_hosts": hosts.most_common(10),
        "files_of_interest": sorted(files),
        "file_hashes": sorted(hashes),
        "suspicious_commands": commands[:10],
        "mitre_techniques": techniques.most_common(),
        "event_total": len(events),
        "alert_total": len(alerts),
    }


# --------------------------------------------------------------------------- #
# Chain of custody / evidence register
# --------------------------------------------------------------------------- #
def _sha256_file(path: str) -> str:
    if not os.path.exists(path):
        return "0" * 64
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def chain_of_custody(case_id: str, analyst: str = "SOC Analyst") -> List[Dict]:
    now = datetime.now(timezone.utc).isoformat()
    register = []
    for label, path in (("Raw event log (JSONL)", EVENTS_FILE),
                        ("Alert log (JSONL)", ALERTS_FILE)):
        register.append({
            "evidence_id": f"{case_id}-{len(register)+1:03d}",
            "description": label,
            "path": path,
            "sha256": _sha256_file(path),
            "collected_by": analyst,
            "collected_at": now,
            "status": "sealed",
        })
    return register


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def forensic_report(case_id: Optional[str] = None, analyst: str = "SOC Analyst",
                    from_disk: bool = False) -> str:
    case_id = case_id or "CASE-" + datetime.now().strftime("%Y%m%d-%H%M")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    arts = collect_artifacts(from_disk)
    alerts = load_alerts(from_disk)
    tl = timeline(from_disk, limit=40)
    coc = chain_of_custody(case_id, analyst)

    sev_counts = Counter(a.get("severity") for a in alerts)
    top_alerts = sorted(alerts, key=lambda a: a.get("detected_at", ""))[:15]

    lines: List[str] = []
    add = lines.append

    add(f"# Digital Forensics & Incident Report — {case_id}")
    add("")
    add("> **CLASSIFICATION: UNCLASSIFIED // FOR TRAINING USE**  ")
    add("> Cyber Defense SOC Lab — synthetic data, generated for demonstration.")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add(f"| Case ID | `{case_id}` |")
    add(f"| Lead Analyst | {analyst} |")
    add(f"| Report Generated | {now} |")
    add(f"| Events Analysed | {arts['event_total']} |")
    add(f"| Alerts Triaged | {arts['alert_total']} |")
    add(f"| Severity Breakdown | "
        f"CRIT {sev_counts.get('critical',0)} / HIGH {sev_counts.get('high',0)} / "
        f"MED {sev_counts.get('medium',0)} / LOW {sev_counts.get('low',0)} |")
    add("")

    add("## 1. Executive Summary")
    add("")
    if alerts:
        add(f"During the monitoring period the SOC detection pipeline triaged "
            f"**{arts['alert_total']} alerts** across **{arts['event_total']} "
            f"normalised events**. The activity is consistent with a multi-stage "
            f"intrusion: credential access (password spraying), discovery (network "
            f"scanning), execution (obfuscated PowerShell), privilege escalation, "
            f"and a malware delivery attempt. The leading source of malicious "
            f"activity was "
            f"`{arts['suspicious_ips'][0][0] if arts['suspicious_ips'] else 'n/a'}`.")
    else:
        add("No alerts were present in the analysed dataset. Run a simulation "
            "(`python -m soclab simulate --all`) to populate the case.")
    add("")

    add("## 2. Indicators of Compromise (IOCs)")
    add("")
    add("### Suspicious source IPs")
    add("| IP | Event count |\n|---|---|")
    for ip, c in arts["suspicious_ips"]:
        add(f"| `{ip}` | {c} |")
    add("")
    add("### Accounts involved")
    add("| Account | Event count |\n|---|---|")
    for u, c in arts["involved_accounts"]:
        add(f"| `{u}` | {c} |")
    add("")
    add("### Affected hosts")
    add("| Host | Event count |\n|---|---|")
    for h, c in arts["affected_hosts"]:
        add(f"| `{h}` | {c} |")
    add("")
    if arts["file_hashes"]:
        add("### File artefacts & hashes")
        for f in arts["files_of_interest"]:
            add(f"- `{f}`")
        for h in arts["file_hashes"]:
            add(f"  - SHA-256 `{h}`")
        add("")
    if arts["suspicious_commands"]:
        add("### Suspicious command lines")
        for cmd in arts["suspicious_commands"]:
            add(f"- `{cmd}`")
        add("")

    add("## 3. MITRE ATT&CK Techniques Observed")
    add("")
    add("| Technique | Alert hits |\n|---|---|")
    for tech, c in arts["mitre_techniques"]:
        add(f"| {tech} | {c} |")
    add("")

    add("## 4. Alert Detail")
    add("")
    add("| Time (UTC) | Sev | Rule | Host | Summary |")
    add("|---|---|---|---|---|")
    for a in top_alerts:
        add(f"| {a.get('detected_at','')[:19]} | {a.get('severity','').upper()} | "
            f"{a.get('rule_id','')} | {a.get('host','')} | {a.get('summary','')} |")
    add("")

    add("## 5. Investigation Timeline (latest 40 entries)")
    add("")
    add("| Time | Type | Source | Host | User | Detail |")
    add("|---|---|---|---|---|---|")
    for r in tl:
        detail = (r["detail"] or "").replace("|", "/")[:90]
        add(f"| {r['time'][:19]} | {r['kind']} | {r['source']} | {r['host']} | "
            f"{r['user']} | {detail} |")
    add("")

    add("## 6. Chain of Custody")
    add("")
    add("| Evidence ID | Description | SHA-256 | Collected By | Collected At | Status |")
    add("|---|---|---|---|---|---|")
    for ev in coc:
        add(f"| {ev['evidence_id']} | {ev['description']} | `{ev['sha256'][:16]}…` | "
            f"{ev['collected_by']} | {ev['collected_at'][:19]} | {ev['status']} |")
    add("")

    add("## 7. Findings & Recommendations")
    add("")
    add("1. **Containment** — block the identified source IP(s) at the perimeter "
        "and isolate affected workstations from the network.")
    add("2. **Credential hygiene** — force password resets for every account that "
        "appeared in failed-logon clusters; enforce MFA on all remote access.")
    add("3. **Privilege review** — remove excess token privileges "
        "(SeDebug/SeImpersonate) from non-tier-0 service accounts.")
    add("4. **Hardening** — enable PowerShell ScriptBlock + Module logging estate-"
        "wide; deploy the provided Sysmon config to all endpoints.")
    add("5. **Detection tuning** — promote the validated lab rules into the "
        "production Wazuh ruleset; add the observed IOCs to threat-intel watchlists.")
    add("")
    add("---")
    add(f"*Report produced by the Cyber Defense SOC Lab forensics module on {now}. "
        "All data is synthetic and generated for training.*")
    return "\n".join(lines)


def write_forensic_report(out_path: str, **kw) -> str:
    report = forensic_report(**kw)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    return out_path

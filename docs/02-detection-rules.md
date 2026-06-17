# Detection Rules

The SOC Lab ships **eight** detection rules (SOC-001 … SOC-008), defined once in [`../soclab/rules.py`](../soclab/rules.py) and consumed by both the live detection engine and the Wazuh exporter. Each rule carries a description, MITRE ATT&CK mapping, detection logic, data sources, a sample log, the expected alert, and a Wazuh rule ID.

Detection style matters here: rules are either **stateless** (fire on a single matching event — e.g. privilege escalation) or **stateful** (correlate multiple events in a sliding time window keyed by an entity — e.g. brute force by source IP). Stateful correlation with a cooldown is what separates a usable SOC rule from an alert cannon.

| ID | Name | Severity | Type | Wazuh ID |
|---|---|---|---|---|
| SOC-001 | Brute Force / Password Spraying | HIGH | stateful (≥5 / 60s by IP) | 100100 |
| SOC-002 | Port Scan / Network Recon | MEDIUM | stateful (≥15 ports / 30s) | 100200 |
| SOC-003 | Privilege Escalation | HIGH | stateless | 100300 |
| SOC-004 | Suspicious PowerShell | HIGH | stateless | 100400 |
| SOC-005 | Malware Execution (EICAR) | CRITICAL | stateless | 100500 |
| SOC-006 | Repeated Failed Logins (account) | MEDIUM | stateful (≥3 / 120s by user) | 100600 |
| SOC-007 | Lateral Movement | HIGH | stateful (≥2 hosts / 300s) | 100700 |
| SOC-008 | Unauthorized Account Creation | CRITICAL | stateless | 100800 |

---

## SOC-001 — Brute Force / Password Spraying
**Severity:** HIGH · **Wazuh:** 100100

**Description.** Detects high-volume failed authentication from a single source — classic brute force — and the spray variant where one password is tried against many accounts.

**MITRE ATT&CK.** T1110.001 Brute Force, T1110.003 Password Spraying · Tactic TA0006 Credential Access.

**Detection logic.** Count failed logons (Windows Event ID 4625 / Linux `sshd` "Failed password") grouped by source IP within a 60-second window. Five or more failures raises the alert. A spray is specifically recognised when the same source hits five or more *distinct* usernames.

**Data sources.** Windows Security 4625; Linux `/var/log/auth.log`.

**Sample log.**
```json
{"source":"WinEventLog:Security","event_id":4625,"host":"WIN-CLIENT01",
 "user":"j.doe","src_ip":"10.10.20.66","logon_type":3,"status":"0xC000006A",
 "message":"An account failed to log on. Status: bad password."}
```

**Expected alert.** `HIGH — Brute force: 5+ failed logons from 10.10.20.66 in 60s`

---

## SOC-002 — Port Scan / Network Reconnaissance
**Severity:** MEDIUM · **Wazuh:** 100200

**Description.** Detects a host probing many TCP services in a short interval — the reconnaissance that precedes exploitation.

**MITRE ATT&CK.** T1046 Network Service Discovery, T1595 Active Scanning · Tactics TA0007 Discovery, TA0043 Reconnaissance.

**Detection logic.** Group firewall/flow `connection_attempt` events by source IP within 30 seconds; if the source touches 15 or more *distinct* destination ports, raise a scan alert.

**Data sources.** Firewall flow logs; Zeek `conn.log`; Linux iptables.

**Sample log.**
```json
{"source":"Firewall:flow","action":"connection_attempt","src_ip":"10.10.20.66",
 "dst_ip":"10.10.10.10","dst_port":3389,"proto":"tcp","message":"SYN to 10.10.10.10:3389"}
```

**Expected alert.** `MEDIUM — Port scan: 15+ ports from 10.10.20.66 on 10.10.10.10`

---

## SOC-003 — Privilege Escalation (Special Privileges Assigned)
**Severity:** HIGH · **Wazuh:** 100300

**Description.** Detects sensitive privileges being granted to an account that is not an approved administrator — a hallmark of token abuse and escalation.

**MITRE ATT&CK.** T1078 Valid Accounts, T1548 Abuse Elevation Control · Tactic TA0004 Privilege Escalation.

**Detection logic.** Fire when Event ID 4672 (special privileges assigned) is granted to an account *not* on the approved-admin allowlist, or when a `sudo` session escalates a standard user to root.

**Data sources.** Windows Security 4672; Linux `sudo` / `auth.log`.

**Sample log.**
```json
{"source":"WinEventLog:Security","event_id":4672,"host":"WIN-DC01",
 "user":"svc_backup","src_ip":"10.10.10.50","privileges":"SeDebugPrivilege, SeTcbPrivilege",
 "message":"Special privileges assigned to new logon."}
```

**Expected alert.** `HIGH — Priv-esc: SeDebugPrivilege granted to non-admin svc_backup`

---

## SOC-004 — Suspicious PowerShell Activity
**Severity:** HIGH · **Wazuh:** 100400

**Description.** Detects PowerShell invoked with obfuscation and download-cradle patterns characteristic of fileless attacks.

**MITRE ATT&CK.** T1059.001 PowerShell, T1027 Obfuscated Files, T1105 Ingress Tool Transfer · Tactics TA0002 Execution, TA0005 Defense Evasion.

**Detection logic.** Inspect process-creation command lines where the image is `powershell.exe` or `pwsh.exe`. Match against an obfuscation/download token list: `-enc`, `IEX`, `DownloadString`, `-nop`, `hidden`, `FromBase64String`, and similar.

**Data sources.** Sysmon Event ID 1; Windows Security 4688; PowerShell ScriptBlock 4104.

**Sample log.**
```json
{"source":"WinEventLog:Sysmon","event_id":1,"host":"WIN-CLIENT01","user":"j.doe",
 "image":"C:\\Windows\\System32\\powershell.exe",
 "command_line":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3...",
 "parent_image":"C:\\Windows\\System32\\cmd.exe"}
```

**Expected alert.** `HIGH — Suspicious PowerShell (encoded + hidden) on WIN-CLIENT01`

---

## SOC-005 — Malware Execution / EICAR Detection
**Severity:** CRITICAL · **Wazuh:** 100500

**Description.** Detects known-bad files and AV/EDR malware verdicts. The lab uses the harmless EICAR test signature so the full malware-response chain can be validated safely.

**MITRE ATT&CK.** T1204 User Execution, T1059 Command & Scripting, T1105 Ingress Tool Transfer · Tactics TA0002 Execution, TA0005 Defense Evasion.

**Detection logic.** Fire on (a) AV/EDR `malware_detected` events, (b) a Sysmon Event ID 11 file-create of an EICAR/known-bad hash, or (c) a process image launched from `\Temp\` or `\AppData\` via a LOLBin.

**Data sources.** AV/EDR alerts; Sysmon Event ID 1/11; VirusTotal hash lookups.

**EICAR reference hash (SHA-256).** `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`

**Expected alert.** `CRITICAL — Malware EICAR-Test-File on WIN-CLIENT01 (quarantined)`

---

## SOC-006 — Repeated Failed Login Attempts (single account)
**Severity:** MEDIUM · **Wazuh:** 100600

**Description.** Catches slow, targeted password guessing aimed at one account that deliberately stays under the brute-force-by-IP threshold.

**MITRE ATT&CK.** T1110 Brute Force · Tactic TA0006 Credential Access.

**Detection logic.** Group 4625 / `sshd` failures by *username* within 120 seconds; three or more failures for one account raises a medium alert. This complements SOC-001 (which groups by IP) so an attacker cannot evade both by rotating source or target alone.

**Data sources.** Windows Security 4625; Linux `/var/log/auth.log`.

**Expected alert.** `MEDIUM — 3+ failed logins for account 'administrator'`

---

## SOC-007 — Lateral Movement (remote logon / service install)
**Severity:** HIGH · **Wazuh:** 100700

**Description.** Detects an account hopping between hosts or a PsExec-style service install used to pivot through the network.

**MITRE ATT&CK.** T1021.002 SMB/Admin Shares, T1570 Lateral Tool Transfer, T1569.002 Service Execution · Tactic TA0008 Lateral Movement.

**Detection logic.** Correlate successful network logons (4624, logon_type 3) by the same user across two or more distinct hosts within 300 seconds, OR a 7045 service install whose name/path looks like PsExec (`PSEXESVC`) or a random eight-character string.

**Data sources.** Windows Security 4624/7045; Sysmon Event ID 18 (named pipes).

**Expected alert.** `HIGH — Lateral movement: svc_backup network-logon to 2+ hosts`

---

## SOC-008 — Unauthorized Account Creation / Privileged Group Change
**Severity:** CRITICAL · **Wazuh:** 100800

**Description.** Detects backdoor accounts and unauthorized elevation of group membership — common persistence and privilege-escalation techniques.

**MITRE ATT&CK.** T1136.002 Create Account: Domain, T1098 Account Manipulation · Tactics TA0003 Persistence, TA0004 Privilege Escalation.

**Detection logic.** Fire immediately on 4720 (user created) or 4728/4732 (added to a privileged group), unless the actor is the approved IAM service account *and* the target group is on the allowlist.

**Data sources.** Windows Security 4720/4728/4732; Linux `useradd`.

**Expected alert.** `CRITICAL — Unauthorized account 'backdoor_svc' created by j.doe`

---

## From rule to Wazuh

Run `python -m soclab export-wazuh` to regenerate [`../config/wazuh/local_rules.xml`](../config/wazuh/local_rules.xml). Each SOC-00X rule becomes a Wazuh `<rule>` with the correct level, `frequency`/`timeframe` for stateful rules, `<mitre>` technique IDs, and a tactic group — a deployable ruleset derived from the exact same source of truth the lab's engine uses.

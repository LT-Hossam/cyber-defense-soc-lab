# Attack Simulation Scenarios

The lab includes five end-to-end attack scenarios defined in [`../soclab/scenarios.py`](../soclab/scenarios.py). Each one emits realistic *log telemetry* that drives the detection engine — there is **no functional exploit or malware code**. Run them all with `python -m soclab simulate --all`, a single one with `python -m soclab simulate --scenario <key>`, or click **RUN FULL SIMULATION** in the console.

Scenario keys: `spray`, `nmap`, `powershell`, `privesc`, `malware`.

Each scenario below lists its objective, attack steps, the telemetry it generates, the detection that fires, and the analyst's investigation procedure.

---

## Scenario 1 — Password Spraying Attack
**Key:** `spray` · **Triggers:** SOC-001, SOC-006 · **MITRE:** T1110.003 Password Spraying (TA0006 Credential Access)

**Objective.** Gain a foothold by trying one common password across many domain accounts, staying under per-account lockout limits.

**Attack steps.**
1. Attacker enumerates valid usernames (OSINT / LDAP null session).
2. A single password (e.g. `Summer2025!`) is tried once per account.
3. Low-and-slow timing avoids account-lockout thresholds.
4. One weak account (`t.brown`) authenticates successfully.

**Generated logs.** A burst of Event ID 4625 failures from `10.10.20.66` against multiple usernames, followed by a 4624 success for `t.brown`.

**Detection process.** SOC-001 correlates five or more failures from one source IP within 60 seconds and recognises the spray pattern (many distinct usernames). SOC-006 independently flags accounts hit repeatedly.

**Analyst investigation procedure.**
1. Pivot on `src_ip 10.10.20.66` — confirm it is the Kali host, not a user.
2. Build a timeline of 4625 events; count distinct target accounts.
3. Identify the 4624 success immediately after the failures (`t.brown`).
4. Check what `t.brown`'s session did next (process creation, logons).
5. Force a password reset for `t.brown`; block the source IP at the firewall.

---

## Scenario 2 — Nmap Reconnaissance
**Key:** `nmap` · **Triggers:** SOC-002 · **MITRE:** T1046 Network Service Discovery, T1595 Active Scanning (TA0007 Discovery)

**Objective.** Map the attack surface of a target host by scanning for open TCP services prior to exploitation.

**Attack steps.**
1. Attacker runs an Nmap SYN scan: `nmap -sS -p- 10.10.10.20`.
2. Half-open SYN probes hit a wide range of TCP ports.
3. Open ports reply SYN/ACK; the firewall logs every probe.
4. Service/version detection follows on the open ports.

**Generated logs.** Twenty `connection_attempt` flow records from `10.10.20.66` to distinct ports on `10.10.10.20`.

**Detection process.** SOC-002 groups connection attempts by source IP over 30 seconds; crossing 15 distinct destination ports raises the scan alert.

**Analyst investigation procedure.**
1. Confirm a single source touched many ports in a short window.
2. Determine which ports answered (true exposure) versus filtered.
3. Correlate with any follow-on exploit attempts on the open services.
4. Tighten firewall ACLs; ensure the red-team segment is isolated.

---

## Scenario 3 — Suspicious PowerShell Execution
**Key:** `powershell` · **Triggers:** SOC-004 · **MITRE:** T1059.001 PowerShell, T1027 Obfuscated Files, T1105 Ingress Tool Transfer (TA0002 Execution)

**Objective.** Execute a fileless, in-memory payload using an encoded, hidden PowerShell download cradle.

**Attack steps.**
1. The initial-access account (`t.brown`) opens a hidden PowerShell.
2. The command line uses `-enc` (Base64) and `-w hidden` to evade casual review.
3. A `Net.WebClient` download cradle pulls a stage from the attacker host.
4. The payload runs in memory (fileless) to avoid disk-based AV.

**Generated logs.** A Sysmon Event ID 1 process-create with an encoded, hidden PowerShell command line, parented by `cmd.exe`.

**Detection process.** SOC-004 inspects PowerShell command lines for obfuscation/download tokens and fires on the encoded + hidden combination.

**Analyst investigation procedure.**
1. Decode the Base64 `-enc` blob to recover the real command.
2. Pull Sysmon Event ID 3 to see if the host beaconed to `10.10.20.66`.
3. Pull 4104 ScriptBlock logs for the full deobfuscated script.
4. Isolate the host; hunt the same cradle pattern across the estate.

---

## Scenario 4 — Privilege Escalation
**Key:** `privesc` · **Triggers:** SOC-003 · **MITRE:** T1078 Valid Accounts, T1548 Abuse Elevation Control, T1134 Access Token Manipulation (TA0004 Privilege Escalation)

**Objective.** Elevate from a standard user to SYSTEM/admin by abusing a mis-scoped service account and token privileges.

**Attack steps.**
1. Attacker runs a local enumeration tool from a Temp directory.
2. Discovers `svc_backup` holds `SeImpersonate`/`SeDebug` privileges.
3. Abuses the token to obtain elevated context (potato-style).
4. Event ID 4672 records the sensitive privileges being granted.

**Generated logs.** A Sysmon process-create of an enumeration tool from `\Temp\`, followed by a 4672 special-privilege assignment to the non-admin `svc_backup`.

**Detection process.** SOC-003 fires because 4672 granted sensitive privileges to an account outside the admin allowlist.

**Analyst investigation procedure.**
1. Identify the non-admin account receiving `SeDebug`/`SeImpersonate`.
2. Trace the parent process tree back to initial access.
3. Review why `svc_backup` holds those privileges (mis-config).
4. Remove excess privileges; rotate the service credential.

---

## Scenario 5 — Malware Simulation (EICAR)
**Key:** `malware` · **Triggers:** SOC-005 · **MITRE:** T1204 User Execution, T1105 Ingress Tool Transfer (TA0002 Execution)

**Objective.** Validate end-to-end malware detection and response using the harmless EICAR industry test file — **no real malware is involved**.

**Attack steps.**
1. A lure (`invoice_2025.exe`) is written to the user's Temp directory.
2. The file contains the EICAR test string — recognised by all AV/EDR.
3. Sysmon Event ID 11 records the file create; EDR raises a detection.
4. The artifact is quarantined; the SOC validates the response chain.

**Generated logs.** A Sysmon Event ID 11 file-create plus an EDR `malware_detected` verdict, both carrying the EICAR signature and reference SHA-256.

**Detection process.** SOC-005 fires CRITICAL on the EICAR signature / known-bad hash, immediately escalating the console's DEFCON readiness.

**Analyst investigation procedure.**
1. Confirm the EDR verdict and that the file was quarantined.
2. Hash the artifact and check it against threat intel / VirusTotal.
3. Determine the delivery vector (download, email, lateral copy).
4. Sweep the estate for the same hash; confirm no execution occurred.

---

## Putting it together

Running all five scenarios produces a coherent **multi-stage intrusion narrative**: credential access (spray) → discovery (scan) → execution (PowerShell) → privilege escalation → malware delivery. The forensic report (see [`04-forensics.md`](04-forensics.md)) reconstructs exactly this storyline from the raw events, which is what makes the lab a realistic investigation exercise rather than a set of disconnected alerts.

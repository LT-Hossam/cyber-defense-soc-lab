# Playbook — Privilege Escalation & Unauthorized Account Changes

**Triggering detections:** SOC-003 (HIGH), SOC-008 (CRITICAL)
**MITRE ATT&CK:** T1078 Valid Accounts, T1548 Abuse Elevation Control, T1134 Access Token Manipulation, T1136.002 Create Account: Domain (TA0004 Privilege Escalation, TA0003 Persistence)
**Classification:** UNCLASSIFIED // FOR TRAINING USE

---

## When this fires
A non-administrative principal was granted sensitive privileges (Windows EventID 4672 — `SeDebugPrivilege`, `SeImpersonatePrivilege`, etc.), captured by SOC-003; **and/or** an account was created or added to a privileged group (4720/4728/4732/4756), captured by SOC-008. In the lab this maps to the privilege-escalation scenario where `svc_backup` is abused for token impersonation, and to unauthorized account-creation events.

## 1. Identification
- [ ] Identify the principal that received the sensitive privileges and whether it should ever hold them.
- [ ] For account changes: confirm who created/modified the account, the target account, and the group involved (Domain Admins, Enterprise Admins, etc.).
- [ ] Trace the **parent process tree** back toward initial access (e.g., enumeration tool launched from a Temp directory).
- [ ] Correlate with preceding detections (brute force, suspicious PowerShell, malware) to reconstruct the kill chain.
- [ ] Determine whether the elevated context was used to take further action.

## 2. Containment
- [ ] Disable the affected/abused account(s) and any newly created account.
- [ ] Force-logoff active sessions for the principal that gained privileges.
- [ ] If a service account (e.g. `svc_backup`) was abused, disable it and isolate the host where impersonation occurred.
- [ ] Revoke Kerberos tickets / tokens for the affected principals.

## 3. Eradication
- [ ] Remove unauthorized accounts and reverse unauthorized group memberships.
- [ ] Strip excess privileges from over-permissioned service accounts (remove `SeImpersonate`/`SeDebug` where not required).
- [ ] Rotate credentials for any abused service account and any account that operated on the host.
- [ ] Remove any persistence the elevated context may have established.

## 4. Recovery
- [ ] Re-create legitimately needed accounts with least-privilege scoping.
- [ ] Validate privileged-group membership against the approved baseline.
- [ ] Restore affected hosts from known-good images if elevation led to further compromise.
- [ ] Heighten monitoring on the affected accounts and Domain Controllers.

## 5. Lessons Learned
- [ ] Why did a non-admin principal hold sensitive privileges? Fix the mis-configuration at source.
- [ ] Are privileged-group changes gated by approval and alerting? Confirm SOC-008 coverage.
- [ ] Review service-account hardening (gMSA, constrained delegation, tiered admin model).
- [ ] Tune SOC-003/SOC-008 to suppress known-good administrative activity without losing coverage.

## Investigation queries (conceptual)
- 4672 events grouped by `user`, filtered to non-administrative principals.
- 4720/4728/4732/4756 (account create / privileged group add) over the window, by `subject` (who did it).
- Process tree for the principal around the 4672 timestamp (Sysmon ID 1 parent/child).

## Key indicators to record
| Field | Value |
|---|---|
| Host | e.g. `WIN-SRV02` |
| Escalated principal | e.g. `svc_backup` |
| Privileges granted | e.g. `SeImpersonate`, `SeDebug` |
| Account created / group changed | account + group (if any) |
| Performed by | subject account |
| Time observed | start–end |
| Evidence IDs | from the forensic report |

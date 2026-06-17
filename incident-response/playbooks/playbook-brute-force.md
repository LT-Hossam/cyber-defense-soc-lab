# Playbook — Brute Force / Password Spraying

**Triggering detections:** SOC-001 (HIGH), SOC-006 (MEDIUM)
**MITRE ATT&CK:** T1110 Brute Force, T1110.003 Password Spraying (TA0006 Credential Access)
**Classification:** UNCLASSIFIED // FOR TRAINING USE

---

## When this fires
A single source IP produced ≥5 failed logons in 60s (SOC-001), and/or one account was hit ≥3 times in 120s (SOC-006). In the lab this maps to the password-spray scenario from `10.10.20.66`.

## 1. Identification
- [ ] Confirm the source IP and whether it belongs to a user, a service, or an unknown/attacker host.
- [ ] Count distinct target accounts. Many accounts + one password = **spray**; one account + many passwords = **targeted brute force**.
- [ ] Check for a **successful** logon (4624) from the same source immediately after the failures — this is the indicator of an actual compromise.
- [ ] Classify severity: any success → treat as confirmed compromise (HIGH+).

## 2. Containment
- [ ] Block the source IP at the firewall / conditional-access layer.
- [ ] If an account authenticated successfully, disable or force-logoff that session.
- [ ] Apply/confirm account-lockout policy on the targeted accounts.

## 3. Eradication
- [ ] Force a password reset for any account that authenticated, and for any account that may have been guessed.
- [ ] Review whether the successful account performed further actions (process creation, lateral logons) and chain to the relevant playbook if so.
- [ ] Revoke active tokens/sessions for affected accounts.

## 4. Recovery
- [ ] Restore normal access for legitimately locked-out users.
- [ ] Confirm telemetry from the source IP has ceased.
- [ ] Monitor the affected accounts closely for re-authentication attempts.

## 5. Lessons Learned
- [ ] Was MFA enforced? If not, this is the primary remediation.
- [ ] Were lockout thresholds appropriate (low enough to slow spray, high enough to avoid self-DoS)?
- [ ] Tune SOC-001/SOC-006 thresholds if false positives/negatives were observed.

## Investigation queries (conceptual)
- All 4625 by `src_ip` over the window → distinct `user` count.
- First 4624 success by `src_ip` after the failure burst.
- Post-success activity for the compromised account (4688 / Sysmon ID 1).

## Key indicators to record
| Field | Value |
|---|---|
| Source IP | e.g. `10.10.20.66` |
| Targeted accounts | list |
| Compromised account | e.g. `t.brown` (if any) |
| Time window | start–end |
| Evidence IDs | from the forensic report |

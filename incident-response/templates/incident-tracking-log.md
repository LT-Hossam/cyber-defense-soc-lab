# Incident Tracking Log

**Classification:** UNCLASSIFIED // FOR TRAINING USE
Master register of all incidents handled by the SOC. One row per case. Detailed write-ups live in individual incident reports (`incident-report-template.md`).

| Case ID | Date opened (UTC) | Severity | Triggering rule(s) | Summary | Affected host(s) | Affected account(s) | Status | Lead analyst | Date closed (UTC) | Report link |
|---|---|---|---|---|---|---|---|---|---|---|
| CASE-20260616-001 | 2026-06-16 19:10 | HIGH | SOC-001 | Password spray from 10.10.20.66 against domain accounts | WIN-DC01 | multiple | Contained | Tier-2 | | reports/sample-forensic-report.md |
| CASE-YYYYMMDD-002 | | | | | | | Open | | | |
| CASE-YYYYMMDD-003 | | | | | | | Open | | | |

---

## Status definitions
- **Open** — under active investigation, not yet contained.
- **Contained** — threat isolated; eradication/recovery in progress.
- **Eradicated** — threat removed; recovery and validation in progress.
- **Closed** — recovery complete, lessons learned recorded.

## Severity definitions
- **Critical** — confirmed compromise, privileged access, or malware execution with estate-wide risk.
- **High** — strong indicator of compromise or successful escalation on one host/account.
- **Medium** — suspicious activity requiring investigation; no confirmed compromise.
- **Low** — anomalous but likely benign; recorded for trend analysis.

## SLA targets (training defaults)
| Severity | Acknowledge | Contain |
|---|---|---|
| Critical | 15 min | 1 hour |
| High | 30 min | 4 hours |
| Medium | 2 hours | 1 business day |
| Low | 1 business day | best effort |

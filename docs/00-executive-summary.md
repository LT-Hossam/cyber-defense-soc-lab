# Executive Summary

**Project:** Cyber Defense SOC Lab
**Classification:** UNCLASSIFIED // FOR TRAINING USE
**Audience:** Hiring managers, security leadership, programme stakeholders

---

## The one-paragraph version

Cyber Defense SOC Lab is a self-contained Security Operations Center simulation that demonstrates the complete defensive (blue-team) lifecycle: telemetry collection, detection engineering, alert triage, attack simulation, digital forensics, and incident response. It runs end-to-end on a single laptop with one dependency, yet ships the same production configuration (Wazuh, Sysmon, Elastic) used in a live enterprise. Every detection is mapped to the MITRE ATT&CK framework, and the system is fronted by a tactical command console that mirrors how a real SOC watch floor operates.

## The problem it addresses

Most security portfolios are either (a) screenshots of someone else's tooling, or (b) write-ups with no runnable artifact behind them. A reviewer cannot verify the candidate can actually *engineer detections, correlate events, and run an investigation*. This project closes that gap: a reviewer clones the repository, runs one command, and watches the full pipeline operate against simulated adversary activity.

## What it demonstrates

- **Detection engineering** — eight MITRE-mapped rules with stateful, sliding-window correlation rather than naive single-event matching.
- **Threat detection coverage** — brute force, password spraying, port scanning, privilege escalation, suspicious PowerShell, malware execution, repeated failed logins, lateral movement, and unauthorized account creation.
- **Attack simulation** — five realistic, *benign* scenarios that exercise the detection pipeline without any functional malware or exploit code.
- **Digital forensics** — automated timeline reconstruction, IOC and artifact collection, SHA-256 chain-of-custody, and court-ready reporting.
- **Incident response** — a structured five-phase workflow (Identify, Contain, Eradicate, Recover, Lessons Learned) with reusable playbooks and templates.
- **Operations** — a live console with a DEFCON-style readiness posture, threat radar, and analyst triage workflow.

## Safety and integrity

The project contains **no malware and no working exploit code**. Attack scenarios generate realistic *log telemetry* so the defensive engine has activity to detect. The malware scenario uses the **EICAR** industry-standard test signature — a harmless string every antivirus product recognises specifically for safe validation. All data is synthetic. This makes the project safe to run, share publicly, and present to any audience.

## Outcome

The result is a single artifact that a candidate can demonstrate live in an interview, walk through file-by-file, and discuss at depth across SIEM engineering, threat hunting, forensics, Active Directory security, and incident response — the exact competency areas national cyber, military, and intelligence security teams hire for.

## Key facts

| Item | Detail |
|---|---|
| Detection rules | 8, all MITRE ATT&CK–mapped |
| Attack scenarios | 5, fully benign synthetic telemetry |
| Runtime dependency | Flask only (pure-Python core) |
| Deployment configs | Wazuh, Sysmon, Filebeat, Winlogbeat, Elastic |
| Time to first detection | < 1 minute from clone |
| Data | 100% synthetic, training-safe |

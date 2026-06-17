# Final Project Report

**Project:** Cyber Defense SOC Lab
**Classification:** UNCLASSIFIED // FOR TRAINING USE
**Document type:** Consolidated final report

---

## 1. Abstract

Cyber Defense SOC Lab is a self-contained Security Operations Center simulation that demonstrates the complete defensive cybersecurity lifecycle — telemetry collection, detection engineering, alert triage, attack simulation, digital forensics, and incident response — in a single runnable artifact. It executes on a single machine with one dependency (Flask) while shipping the production configuration (Wazuh, Sysmon, Elastic/Beats) required to run the identical detection logic against a live enterprise. Every detection is mapped to MITRE ATT&CK, and the system is operated through a tactical command console modelled on a real SOC watch floor.

## 2. Objectives and scope

The project set out to build, in one cohesive package: a simulated enterprise network; a detection capability covering the major attack classes; realistic but safe attack simulations; a forensics capability that produces defensible reports; a structured incident-response workflow; and an operator interface — all documented to a professional standard and deployable to real tooling. The scope explicitly **excludes** any functional offensive code; adversary activity is represented purely as telemetry.

## 3. System overview

The environment models the `CYBERLAB.LOCAL` domain: a Windows domain controller running Active Directory, a Windows member server, Linux web host, two Windows clients, a Wazuh SIEM, and a Kali attacker. Telemetry flows endpoint → log shipper → SIEM → detection engine → store → console, mirroring a production pipeline. See [`01-architecture.md`](01-architecture.md) and [`diagrams/architecture.svg`](diagrams/architecture.svg).

## 4. Detection capability

Eight rules (SOC-001…SOC-008) cover brute force and password spraying, port scanning, privilege escalation, suspicious PowerShell, malware execution, repeated failed logins, lateral movement, and unauthorized account creation. Rules are stateless (single-event) or stateful (sliding-window correlation keyed by an entity, with a cooldown to suppress alert storms). All are MITRE-mapped and exportable to a deployable Wazuh ruleset from the same source definitions. Full detail in [`02-detection-rules.md`](02-detection-rules.md).

## 5. Attack simulation

Five scenarios — password spraying, Nmap reconnaissance, suspicious PowerShell, privilege escalation, and EICAR malware — emit realistic log events that exercise the detection pipeline end-to-end. Run together they form a coherent multi-stage intrusion (credential access → discovery → execution → escalation → delivery). The malware scenario uses the harmless EICAR test signature. Full detail in [`03-attack-scenarios.md`](03-attack-scenarios.md).

## 6. Digital forensics

The forensics module reconstructs an event timeline, extracts indicators of compromise (IPs, accounts, hosts, files, hashes, commands, techniques), maintains a SHA-256 chain-of-custody, and assembles a structured forensic report with a classification banner and evidence-linked conclusions. A sample report ships in [`../reports/sample-forensic-report.md`](../reports/sample-forensic-report.md). Full detail in [`04-forensics.md`](04-forensics.md).

## 7. Incident response

A five-phase workflow (Identify, Contain, Eradicate, Recover, Lessons Learned), aligned to NIST SP 800-61 / SANS PICERL, is implemented with reusable playbooks and templates and surfaced live in the console's Incidents view. Full detail in [`06-incident-response.md`](06-incident-response.md).

## 8. Operator interface

The tactical console presents six live views (Overview, Threats, Incidents, User Activity, Detections, Forensics) with an animated threat radar and a DEFCON-style readiness gauge that escalates with severity. Design and view-by-view detail in [`05-dashboards.md`](05-dashboards.md).

## 9. Verification

The application was tested end-to-end: the CLI runs all five scenarios and raises the expected alerts; the server starts and every API endpoint responds; the console serves and renders; the Wazuh export produces valid XML; and the forensic report generates cleanly. A pytest suite ([`../tests/`](../tests/)) asserts that each scenario triggers its expected detection, guarding against regressions.

## 10. Results

From a single command, the lab produces a populated SOC: a full multi-stage intrusion detected across the eight rules, an escalated readiness posture, a populated user-activity and IOC picture, and a generated forensic report — all from synthetic, training-safe data, with no external services required.

## 11. Skills demonstrated

SIEM engineering, threat hunting, incident response, digital forensics, Active Directory security, security monitoring, detection engineering, and software engineering. The component-by-component mapping is in [`10-resume-value.md`](10-resume-value.md).

## 12. Limitations and future work

The lab models telemetry rather than capturing it from live hosts (by design, for portability and safety); detections operate on the modelled event shapes. Natural extensions: behavioural/UEBA baselining for anomaly detection, additional data sources (DNS, proxy, cloud audit), automated response actions, an expanded rule set, and continuous-integration execution of the detection test suite.

## 13. Conclusion

The project delivers a complete, technically accurate, and safe demonstration of defensive SOC operations in a form a reviewer can run, inspect, and discuss at depth. It evidences the precise competencies that cybersecurity, government, military, and intelligence security teams hire for — and does so in a single, coherent, runnable artifact.

---

## Appendix — repository map

| Area | Path |
|---|---|
| Application package | `soclab/` |
| Detection rules | `soclab/rules.py` |
| Detection engine | `soclab/detection_engine.py` |
| Attack scenarios | `soclab/scenarios.py` |
| Forensics | `soclab/forensics.py` |
| Tactical console | `soclab/web/` |
| Production configs | `config/` |
| Documentation | `docs/` |
| Incident response | `incident-response/` |
| Sample report | `reports/sample-forensic-report.md` |
| Tests | `tests/` |

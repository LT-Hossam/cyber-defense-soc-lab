# Resume Value

How to talk about this project on a CV and in interviews — and exactly which component proves each skill. The point of the lab is that every claim you make is *demonstrable on screen*, not asserted on paper.

---

## One-line résumé bullet

> Built **Cyber Defense SOC Lab**, a runnable SOC simulation with 8 MITRE ATT&CK–mapped detection rules, a stateful correlation engine, 5 attack scenarios, automated digital-forensic reporting, and a 5-phase incident-response workflow, fronted by a live tactical console — deployable to Wazuh, Sysmon, and Elastic.

---

## Skills-to-component map

| Skill area | Demonstrated by | What you can say in an interview |
|---|---|---|
| **SIEM engineering** | `rules.py`, `detection_engine.py`, `wazuh_export.py`, `config/wazuh/` | "I wrote eight detection rules with stateful, sliding-window correlation and export them to a deployable Wazuh ruleset from a single source of truth." |
| **Threat hunting** | MITRE mapping on every rule, `forensics.collect_artifacts()`, the IOC board | "I pivot across IPs, accounts, hosts, hashes, and ATT&CK techniques to reconstruct a multi-stage intrusion from raw telemetry." |
| **Incident response** | `incident-response/` playbooks & templates, the Incidents view | "I run the full PICERL/NIST lifecycle — identify, contain, eradicate, recover, lessons learned — with reusable playbooks." |
| **Digital forensics** | `forensics.py`, the timeline, SHA-256 chain-of-custody, the sample report | "I produce hash-verified, court-ready forensic reports where every conclusion traces to a specific piece of evidence." |
| **Active Directory security** | 4625/4672/4720/4728/4732/4624 modelling, SOC-003/007/008 | "I detect privilege escalation, lateral movement, and unauthorized account creation from AD audit events, with an admin allowlist to cut false positives." |
| **Security monitoring** | the tactical console, DEFCON readiness, alert triage workflow | "I built a live watch-floor console with severity-based readiness scoring and a full triage drawer for each alert." |
| **Detection engineering** | stateless vs stateful rules, thresholds, cooldowns | "I understand why naive single-event rules create alert storms, so I correlate in time windows keyed by the right entity." |
| **Software engineering** | clean Python package, CLI, Flask API, tests | "It's a real, tested, dependency-light application — not a notebook — with a CLI and an API." |

---

## Why this stands out for government / military / intelligence roles

These employers screen hard for *demonstrable* blue-team capability and disciplined process. This project hits the exact criteria:

- **MITRE ATT&CK fluency** — every detection and scenario is mapped, which is the common language of national-security cyber teams.
- **Evidence discipline** — chain-of-custody and classification banners (`UNCLASSIFIED // FOR TRAINING USE`) show you understand handling and reporting rigour.
- **Process maturity** — a structured IR lifecycle with playbooks and templates, not ad-hoc firefighting.
- **Operational mindset** — readiness posture, triage prioritisation, and a watch-floor UI mirror how a real SOC/CSOC runs.
- **Safety and judgement** — choosing EICAR and synthetic telemetry over live malware shows exactly the risk awareness these roles require.

---

## Interview talking points

- **Walk the file tree.** Open `rules.py`, show one stateful rule, then show the same rule as Wazuh XML — "same source of truth, lab and production."
- **Run it live.** `simulate --all`, then narrate the intrusion from the console: spray → scan → PowerShell → escalation → malware.
- **Show the investigation.** Pivot on the attacker IP in User Activity; generate a forensic report; point at an evidence ID and its hash.
- **Discuss tuning.** Explain the admin allowlist and the cooldown — concrete false-positive reduction, which is what senior reviewers probe for.
- **Talk trade-offs.** Why simulation over six VMs; why benign telemetry; what you'd add next (e.g. UEBA baselining, more data sources).

---

## Suggested CV phrasing variants

**Detection-engineering focus:**
> Designed 8 MITRE ATT&CK–mapped detections with stateful time-window correlation and an admin-allowlist false-positive control; exported them as a deployable Wazuh ruleset.

**Forensics/IR focus:**
> Automated digital-forensic reporting (timeline, IOC extraction, SHA-256 chain-of-custody) and codified a 5-phase incident-response workflow with playbooks and templates.

**Full-stack/SOC focus:**
> Built and shipped a runnable SOC platform — detection engine, attack simulation, forensics, and a live tactical console — in a dependency-light Python codebase with CLI, API, and tests.

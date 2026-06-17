# Cyber Defense SOC Lab

> **A self-contained, runnable Security Operations Center (SOC) simulation** — detection engineering, attack simulation, digital forensics, and incident response in one portfolio-grade package, fronted by a tactical command-console UI.

`UNCLASSIFIED // FOR TRAINING USE` · MITRE ATT&CK–mapped · Pure-Python core · Ships with production Wazuh / Sysmon / Elastic configs

---

## What this is

Cyber Defense SOC Lab demonstrates the full blue-team lifecycle the way a real SOC operates it: telemetry comes in, a detection engine triages it against MITRE ATT&CK–mapped rules, alerts escalate a DEFCON-style readiness posture, an analyst investigates, and a court-ready forensic report comes out the other end.

It is built so a reviewer can clone it and have it **running in under a minute on any laptop** — no virtual machines, no SIEM cluster, no internet. The entire enterprise (a Windows AD domain, Linux servers, clients, and a Kali attacker) is simulated in software using **benign synthetic telemetry**. At the same time, the repository ships the **real production configuration** (Wazuh rules, Sysmon config, Elastic/Beats pipelines) you would deploy in a live environment, so it doubles as a deployment reference.

> **Safety note.** This project contains **no malware and no functional exploit code**. Attack "simulations" emit realistic-looking *log events* so the defensive engine has something to detect. The malware scenario uses the harmless, industry-standard **EICAR** test string — the same file every antivirus vendor uses to validate detection.

---

## Capabilities at a glance

| Area | What's implemented |
|---|---|
| **Detection engineering** | 8 detection rules (SOC-001…SOC-008), each mapped to MITRE ATT&CK, with sliding-window stateful correlation |
| **Attack simulation** | 5 end-to-end scenarios: password spray, Nmap recon, suspicious PowerShell, privilege escalation, EICAR malware |
| **Digital forensics** | Event timeline, IOC/artifact collection, chain-of-custody (SHA-256), full Markdown forensic reports |
| **Incident response** | 5-phase IR workflow (Identify → Contain → Eradicate → Recover → Lessons Learned) with playbooks & templates |
| **Tactical UI** | Live command console with animated threat radar, DEFCON readiness gauge, six operational views |
| **Production configs** | Wazuh `local_rules.xml`, Sysmon config, Filebeat/Winlogbeat/Elastic pipelines |

---

## Quick start

### Option A — one command (recommended)

**Linux / macOS**
```bash
git clone <your-repo-url> cyber-defense-soc-lab
cd cyber-defense-soc-lab
./run.sh
```

**Windows (PowerShell)**
```powershell
git clone <your-repo-url> cyber-defense-soc-lab
cd cyber-defense-soc-lab
.\run.ps1
```

The launcher creates a virtual environment, installs Flask, primes the engine with a full attack simulation, and opens the console.

Then browse to **http://127.0.0.1:8000**.

### Option B — manual (full control)

```bash
# 1. create + activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1

# 2. install the single dependency
pip install -r requirements.txt

# 3. (optional) fire all five attack scenarios so the console opens with data
python -m soclab simulate --all

# 4. launch the tactical console
python -m soclab serve --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** and click **RUN FULL SIMULATION** in the top bar to watch detections fire live.

> Requires **Python 3.9+**. The only dependency is Flask.

---

## Command-line interface

Everything the UI does is also available headlessly — useful for CI, demos, or screenshots.

```bash
python -m soclab simulate --all                  # run every attack scenario
python -m soclab simulate --scenario powershell  # run a single scenario
python -m soclab rules                            # print the detection catalogue
python -m soclab forensics --report reports/case.md --simulate-first
python -m soclab export-wazuh                     # regenerate Wazuh rules XML
python -m soclab serve                            # launch the web console
```

Scenario keys: `spray`, `nmap`, `powershell`, `privesc`, `malware`.

---

## The tactical console

Six operational views, all driven by live data polled every few seconds:

- **Overview** — threat radar, KPI deck, severity distribution, top MITRE techniques, live event ticker, DEFCON readiness.
- **Threats** — filterable alert queue; click any alert for a full triage drawer (MITRE mapping, evidence, sample event, recommended response).
- **Incidents** — the five-phase IR workflow with live incident cards.
- **User Activity** — per-account and per-source-IP behavioural tables.
- **Detections** — one-click attack-scenario launcher and the full rule catalogue.
- **Forensics** — IOC board, event timeline, and on-demand forensic report generation.

The aesthetic is a deliberate departure from the generic "hacker green on black" — NATO signal-amber and phosphor-green on gunmetal, HUD typography, CRT scanlines, and an animated radar sweep that positions threat blips by severity.

---

## Repository structure

```
cyber-defense-soc-lab/
├── soclab/                     # application package
│   ├── rules.py                # 8 MITRE-mapped detection rules
│   ├── detection_engine.py     # stateful sliding-window correlation engine
│   ├── store.py                # thread-safe event/alert store (JSONL-backed)
│   ├── log_generator.py        # simulated enterprise + benign telemetry
│   ├── scenarios.py            # 5 attack simulation scenarios
│   ├── forensics.py            # timeline, IOCs, chain-of-custody, reports
│   ├── wazuh_export.py         # rules.py -> Wazuh local_rules.xml
│   ├── server.py               # Flask API + console host
│   ├── cli.py                  # command-line entrypoint
│   └── web/                    # tactical single-page console (HTML/CSS/JS)
├── config/                     # production deployment configs
│   ├── wazuh/local_rules.xml   # generated Wazuh detection rules
│   ├── sysmon/sysmon-config.xml
│   ├── elastic/  filebeat/  winlogbeat/
├── docs/                       # full documentation set (00–12) + diagrams
├── incident-response/          # playbooks + IR templates
├── reports/                    # sample forensic report
├── tests/                      # pytest detection-coverage suite
├── run.sh / run.ps1 / Makefile
└── requirements.txt
```

---

## Documentation

The `docs/` directory contains the full written deliverable set:

| File | Contents |
|---|---|
| `00-executive-summary.md` | One-page brief for non-technical stakeholders |
| `01-architecture.md` | Environment design + component roles (diagram in `docs/diagrams/`) |
| `02-detection-rules.md` | All 8 rules: logic, MITRE, sample logs, expected alerts |
| `03-attack-scenarios.md` | All 5 scenarios: objective, steps, logs, detection, investigation |
| `04-forensics.md` | Forensic methodology and report walkthrough |
| `05-dashboards.md` | Dashboard design + console view guide |
| `06-incident-response.md` | IR workflow, playbooks, templates |
| `07-deployment-guide.md` | Production deployment (Wazuh + Elastic + Sysmon) |
| `08-user-manual.md` | Running and operating the lab |
| `09-soc-analyst-guide.md` | Day-in-the-life analyst runbook |
| `10-resume-value.md` | Skills-to-component mapping for your CV / interviews |
| `11-presentation-outline.md` | PowerPoint / briefing deck outline |
| `12-final-project-report.md` | Consolidated final report |

---

## How this maps to real SOC skills

| Skill area | Where it shows up |
|---|---|
| **SIEM engineering** | Detection rules, the correlation engine, exportable Wazuh rules |
| **Threat hunting** | MITRE ATT&CK mapping, IOC pivoting, the forensics module |
| **Incident response** | The five-phase IR module, playbooks, and templates |
| **Digital forensics** | Timeline reconstruction, chain-of-custody, evidence reports |
| **Active Directory security** | 4625/4672/4720 event modelling, privilege-escalation detection |
| **Security monitoring** | The live console, readiness scoring, and alert triage workflow |

See `docs/10-resume-value.md` for the full breakdown.

---

## License

Released under the [MIT License](LICENSE). Synthetic data only; intended for training, demonstration, and portfolio use.

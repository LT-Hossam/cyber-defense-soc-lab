# Presentation Outline

A ready-to-build slide deck for presenting the Cyber Defense SOC Lab to an interview panel, security team, or programme review. Suggested length: **14–16 slides, ~15 minutes**, leaving time for a live demo and questions. Speaker notes are written as what to *say*; build each slide in your tool of choice.

Design to match the project: gunmetal background, signal-amber headings, phosphor-green accents, mono captions, `UNCLASSIFIED // FOR TRAINING USE` footer.

---

### Slide 1 — Title
**Cyber Defense SOC Lab** · *A runnable Security Operations Center simulation*
Your name, role target, date. Footer banner.
> *Say:* "I built a SOC you can run in under a minute — let me show you the whole blue-team lifecycle in one project."

### Slide 2 — The problem
Most security portfolios can't be verified — screenshots or write-ups with nothing runnable behind them.
> *Say:* "I wanted something a reviewer could clone and watch operate, not take on faith."

### Slide 3 — What it is
One sentence + the capability table (detection, simulation, forensics, IR, console, configs).
> *Say:* "Detection engineering through to forensic reporting, plus the production configs you'd actually deploy."

### Slide 4 — Architecture
The `architecture.svg` diagram. Three zones: adversary, enterprise, SOC.
> *Say:* "A simulated AD enterprise, a Kali attacker, and a Wazuh/Elastic detection pipeline — all in software, with real configs shipped alongside."

### Slide 5 — Safety by design
Benign synthetic telemetry; EICAR not real malware; 100% synthetic data.
> *Say:* "No exploit code, no malware — the judgement call these roles screen for."

### Slide 6 — Detection engineering
The 8-rule table; contrast stateless vs stateful correlation.
> *Say:* "Eight MITRE-mapped rules. The interesting ones correlate over time windows so they don't become an alert cannon."

### Slide 7 — One rule, end to end
Show SOC-001 in `rules.py`, then the same rule as Wazuh XML.
> *Say:* "Single source of truth — what I test in the lab is what runs in Wazuh."

### Slide 8 — Attack simulation
The five scenarios as a kill-chain: spray → scan → PowerShell → escalation → malware.
> *Say:* "Each emits realistic telemetry; together they tell one multi-stage intrusion story."

### Slide 9 — LIVE DEMO
Switch to the console. Click **RUN FULL SIMULATION**. Narrate the readiness escalation and radar.
> *Say:* "Watch DEFCON move from 5 to 2 as the critical malware alert lands."

### Slide 10 — Triage & investigation
In the demo: open the malware alert's triage drawer; pivot on the attacker IP in User Activity.
> *Say:* "This is the analyst loop — observe, triage, pivot, decide."

### Slide 11 — Digital forensics
Generate a report live; show the timeline and a hash-verified evidence ID.
> *Say:* "From raw logs to a court-ready report where every conclusion traces to evidence."

### Slide 12 — Incident response
The five-phase workflow; the playbooks and templates.
> *Say:* "A disciplined PICERL lifecycle, not ad-hoc firefighting."

### Slide 13 — Skills demonstrated
The skills-to-component map from [`10-resume-value.md`](10-resume-value.md).
> *Say:* "Every claim here is something I just showed you on screen."

### Slide 14 — Tech stack & deployment
Python · Flask · Wazuh · Sysmon · Elastic · MITRE ATT&CK. How the configs deploy.
> *Say:* "Dependency-light to run, production-real to deploy."

### Slide 15 — What's next
Roadmap: UEBA baselining, more data sources, automated response actions, detection unit tests in CI.
> *Say:* "Here's how I'd mature it toward a real detection-engineering pipeline."

### Slide 16 — Close / Q&A
Repo link, contact. Footer banner.
> *Say:* "Happy to walk any file or rerun any part of the demo."

---

## Demo checklist (run before presenting)
```bash
python -m soclab simulate --all     # confirm 6 alerts
python -m soclab serve              # confirm console loads
# pre-open: Overview, Threats, User Activity, Forensics
```
Have a backup screenshot set in case live demo isn't possible. Keep the terminal font large.

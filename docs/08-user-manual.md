# User Manual

How to operate the Cyber Defense SOC Lab — both the command line and the tactical console.

---

## Starting the lab

```bash
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
python -m soclab serve               # console at http://127.0.0.1:8000
```

Add `--port 8001` to change the port, or `--no-baseline` to stop the background benign-traffic generator.

---

## Command-line interface

The CLI exposes everything the console does, for demos, CI, and screenshots.

### `serve` — launch the console
```bash
python -m soclab serve [--host 127.0.0.1] [--port 8000] [--no-baseline]
```

### `simulate` — run attack scenarios
```bash
python -m soclab simulate --all                  # all five scenarios
python -m soclab simulate --scenario spray       # one scenario
```
Scenario keys: `spray`, `nmap`, `powershell`, `privesc`, `malware`.

### `rules` — print the detection catalogue
```bash
python -m soclab rules
```
Lists all eight rules with severity, MITRE mapping, logic, threshold, and Wazuh ID.

### `forensics` — generate a forensic report
```bash
python -m soclab forensics --report reports/case.md --analyst "Your Name" --simulate-first
```
`--simulate-first` runs a full intrusion before reporting; omit `--report` to print to the terminal.

### `export-wazuh` — regenerate the Wazuh ruleset
```bash
python -m soclab export-wazuh [--out config/wazuh/local_rules.xml]
```

---

## Using the console

### Top command bar
- **Readiness indicator** — the current DEFCON posture (5 Normal → 2 Active Intrusion).
- **RUN FULL SIMULATION** — fires all five attack scenarios; watch alerts and the radar populate.
- **RESET** — clears all events and alerts back to a clean baseline.
- **Status dot + clock** — live service health and time.

### Navigation rail
Six views, each with a live badge count:

1. **Overview** — radar, KPIs, severity bars, top MITRE techniques, live ticker.
2. **Threats** — the alert queue; filter by severity, click a row for full triage.
3. **Incidents** — the five-phase IR workflow and incident cards.
4. **User Activity** — per-account and per-IP behaviour tables.
5. **Detections** — scenario launcher + the full rule catalogue.
6. **Forensics** — IOC board, timeline, and report generation.

### Triage workflow
1. An alert appears in **Threats** (and a blip on the radar).
2. Click it to open the triage drawer: MITRE mapping, evidence IDs, the raw sample event, and recommended actions.
3. Update its status as you work it (e.g. acknowledged / investigating / closed).
4. For a real incident, generate a forensic report from the **Forensics** view.

---

## A five-minute guided tour

```bash
python -m soclab serve
```
1. Open the console — note the calm DEFCON 5 baseline.
2. Click **RUN FULL SIMULATION**. Watch the readiness gauge escalate as the CRITICAL malware alert lands, and blips appear on the radar.
3. Go to **Threats**, sort/filter by severity, and open the malware alert to read its MITRE mapping and recommended response.
4. Go to **User Activity** — see `10.10.20.66` (the attacker) and `t.brown` (the compromised account) rise to the top.
5. Go to **Forensics**, generate a report, and read the reconstructed intrusion timeline.
6. Click **RESET** to return to baseline.

That tour is the same flow you would walk an interviewer through.

---

## Data and persistence

Runtime telemetry is written to `data/events.jsonl` and `data/alerts.jsonl` (git-ignored). The forensics module can read these back, so a report reflects everything observed in the session. **RESET** or `make clean` clears them.

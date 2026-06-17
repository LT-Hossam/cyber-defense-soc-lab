# Dashboards

The tactical console is the lab's SOC watch floor. It is a single-page application served by Flask ([`../soclab/web/`](../soclab/web/)) that polls the API every few seconds and renders six operational views. This document maps the four required dashboards onto those views and explains how to read each one.

> **Live, not static.** These are not screenshots of a third-party tool — every panel is driven by the lab's own API (`/api/stats`, `/api/alerts`, `/api/events`, `/api/forensics/artifacts`). Click **RUN FULL SIMULATION** to populate them.

---

## Visual language

The console deliberately avoids the generic "green-on-black hacker" look. The palette is operational:

- **Signal amber** `#f0b429` — HUD accents, headings, primary controls.
- **Phosphor green** `#3ddc84` — secure / nominal / online states.
- **Hostile red** `#ff4d4d` — critical alerts and active intrusion.
- **Amber/yellow/orange** — high/medium severity grading.
- **Gunmetal** `#0a0f0e` — background, with CRT scanlines and a faint grid.

Typography pairs **Rajdhani** (HUD display) with **Share Tech Mono** (data). The signature element is an **animated radar sweep** that positions threat blips by severity (critical near the centre, low at the rim) with a **DEFCON-style readiness gauge** that escalates 5 → 2 as severity rises.

---

## 1. Security Overview Dashboard → *Overview view*

The mission picture at a glance:

- **Threat radar** — animated sweep; each blip is an open alert positioned by severity.
- **Readiness gauge** — DEFCON 5 (Normal) down to DEFCON 2 (Active Intrusion), computed from the current severity mix.
- **KPI deck** — total events, open alerts, open incidents, distinct MITRE techniques observed.
- **Severity distribution** — critical/high/medium/low bars.
- **Top MITRE techniques** — the techniques seen most across current alerts.
- **Live event ticker** — the most recent telemetry scrolling in real time.

*Read it to answer:* "What is our posture right now, and is anything on fire?"

## 2. Threat Dashboard → *Threats view*

The alert queue:

- Every open alert as a row: rule ID, severity, host, account, summary, time.
- Severity filtering to focus the queue.
- Click any alert to open the **triage drawer**: MITRE tactics/techniques, supporting evidence IDs, the raw sample event, and recommended response actions.

*Read it to answer:* "What needs an analyst's attention, and what do I do about it?"

## 3. Incident Dashboard → *Incidents view*

The response picture:

- The five-phase IR workflow (Identify → Contain → Eradicate → Recover → Lessons Learned) rendered as a live progression.
- Incident cards grouping related alerts into a single tracked case.

*Read it to answer:* "What incidents are open and where are they in the response lifecycle?"

## 4. User Activity Dashboard → *Users view*

The behavioural picture:

- Per-account table: event volume, associated hosts, anomalies.
- Per-source-IP table: which addresses are generating activity, ranked.

*Read it to answer:* "Which identities and addresses are driving this activity?" — the core question in any credential-abuse or insider investigation.

---

## Supporting views

- **Detections view** — one-click launcher for each attack scenario plus the full rule catalogue, so you can demonstrate detection coverage on demand.
- **Forensics view** — the IOC board, interactive timeline, and on-demand forensic-report generation.

---

## Implementation steps (how the dashboards are built)

1. **Backend** — `server.py` exposes JSON endpoints. `/api/stats` computes the severity mix, MITRE technique ranking, and the DEFCON readiness level server-side.
2. **Polling** — `app.js` fetches the endpoints on a short interval and diffs the results into the DOM (no page reloads).
3. **Radar** — `renderRadar()` places each alert blip at a radius derived from its severity and a deterministic angle derived from its alert ID, so the picture is stable between polls.
4. **Styling** — `styles.css` defines the palette as CSS variables, the CRT/grid overlays, the radar `@keyframes sweep`, and responsive breakpoints; it honours `prefers-reduced-motion`.
5. **Triage drawer** — selecting an alert renders its full detail (MITRE, evidence, sample event, response guidance) in a slide-in panel.

## Reproducing dashboard screenshots

```bash
python -m soclab simulate --all      # populate with a full intrusion
python -m soclab serve               # launch the console
# open http://127.0.0.1:8000 and capture each view
```

Because the simulation is deterministic in structure, the dashboards always tell the same coherent multi-stage story — ideal for a portfolio screenshot set or a live interview walkthrough.

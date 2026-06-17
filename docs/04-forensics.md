# Digital Forensics

The forensics module ([`../soclab/forensics.py`](../soclab/forensics.py)) turns raw detection data into an investigation: a timeline, a set of indicators, a chain-of-custody register, and a court-/command-ready report. It reads from the live event store or from the persisted JSONL in `data/`.

Generate a report from a fresh simulation:
```bash
python -m soclab forensics --report reports/sample-forensic-report.md --analyst "SOC Analyst — Tier 2" --simulate-first
```
A pre-generated example ships at [`../reports/sample-forensic-report.md`](../reports/sample-forensic-report.md).

---

## The four capabilities

### 1. Log analysis
Every event the engine ingests is normalised and stored. The forensics layer reads that store back and segments it by source IP, account, host, file, hash, command line, and MITRE technique — the dimensions an analyst actually pivots on. This is the difference between "a pile of logs" and "evidence."

### 2. Timeline creation
`timeline()` orders all events chronologically and annotates each with its host, user, source, and a short description. A reconstructed timeline is the spine of any investigation: it establishes sequence (spray *before* the successful logon, enumeration *before* the privilege grant) and therefore causality. The console's Forensics view renders the same timeline interactively.

### 3. Artifact collection
`collect_artifacts()` extracts the indicators of compromise:

| IOC class | Example |
|---|---|
| Suspicious source IPs | `10.10.20.66` (the attacker) |
| Involved accounts | `t.brown`, `svc_backup`, `administrator` |
| Affected hosts | `WIN-CLIENT01`, `WIN-DC01` |
| Files of interest | `…\Temp\invoice_2025.exe` |
| File hashes | the EICAR SHA-256 |
| Suspicious commands | the encoded PowerShell cradle |
| MITRE techniques | the full set observed across the incident |

These are ranked by frequency so the analyst sees the most active indicators first.

### 4. Evidence documentation
`chain_of_custody()` produces a custody register where each evidence item is assigned an ID (`E0000001`, …) and a **SHA-256 integrity hash** of its content. Alerts reference the evidence IDs that support them, so a reviewer can trace every conclusion in the report back to a specific, hash-verified event. This is what makes the output defensible rather than anecdotal.

---

## The forensic report

`forensic_report()` assembles the full Markdown document. Its structure:

1. **Header** — case ID, lead analyst, generation time, event/alert counts, severity breakdown, and the `UNCLASSIFIED // FOR TRAINING USE` classification banner.
2. **Executive summary** — a plain-language account of the intrusion narrative and the leading source of malicious activity.
3. **Indicators of Compromise** — the ranked IOC tables described above.
4. **Alert detail** — each triaged alert with its rule, severity, MITRE mapping, and supporting evidence IDs.
5. **Timeline** — the chronological event reconstruction.
6. **Chain of custody** — the hash-verified evidence register.
7. **Recommendations** — containment, eradication, and recovery actions tied to what was observed.

The case ID is derived from the date (`CASE-YYYYMMDD-HHMM`), and the report is fully deterministic given the same input events — so it regenerates cleanly in CI or a live demo.

---

## Why this matters for the role

Forensic reporting is where SOC work meets accountability: incident records feed legal, regulatory, and (in government/military contexts) command reporting lines. Demonstrating that you can move from raw telemetry to a hash-verified, MITRE-mapped, decision-ready report — automatically — is exactly the capability that separates a log-watcher from an investigator.

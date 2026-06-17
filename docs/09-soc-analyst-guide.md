# SOC Analyst Guide

A day-in-the-life runbook for operating this SOC the way a tier-1/tier-2 analyst would. It assumes the console is running (`python -m soclab serve`).

---

## The analyst's loop

A SOC analyst repeats one loop: **observe → triage → investigate → respond → document**. The lab is built around exactly this loop.

```
Overview (posture) → Threats (queue) → triage drawer (decide)
   → investigate (pivot) → Incidents/IR (respond) → Forensics (document)
```

---

## 1. Observe — read the posture
Start every shift on the **Overview** view:
- What is the **DEFCON readiness**? DEFCON 5 is a quiet board; DEFCON 2 means an active intrusion is in progress.
- Scan the **severity distribution** and the **radar** — critical blips sit near the centre.
- Glance at **top MITRE techniques** to see *what kind* of activity dominates.

## 2. Triage — work the queue
Move to **Threats**. For each open alert, decide quickly:
- **True positive or false positive?** Use the sample event in the triage drawer.
- **Severity correct?** CRITICAL (malware, account creation) jumps the queue.
- **Related to an existing case?** If several alerts share a source IP or account, they are one incident, not many.

Triage priority order: CRITICAL → HIGH → MEDIUM, and within a tier, anything touching Tier-0 assets (the domain controller, admin accounts) first.

## 3. Investigate — pivot on indicators
The core analyst skill is pivoting. The richest pivots here:

| Pivot on | Reveals |
|---|---|
| **Source IP** (`10.10.20.66`) | every action by the same adversary host |
| **Account** (`t.brown`, `svc_backup`) | the blast radius of a compromised identity |
| **Host** (`WIN-CLIENT01`) | everything that happened on a target |
| **MITRE technique** | other activity in the same attack stage |
| **File hash** | other hosts where the same artifact appears |

Use **User Activity** for IP/account pivots and **Forensics → timeline** to establish sequence. The question you are always answering: *what happened before this, and what happened after?*

## 4. Respond — follow the playbook
Once an alert is a confirmed incident, switch to the **Incidents** view and follow the matching playbook in [`../incident-response/playbooks/`](../incident-response/playbooks/):
- Brute force / spray → reset the affected credential, block the source IP.
- Suspicious PowerShell / malware → isolate the host, confirm quarantine, hunt the pattern estate-wide.
- Privilege escalation / account creation → strip excess privileges, disable backdoor accounts, rotate service credentials.

Work the five phases in order: Identify → Contain → Eradicate → Recover → Lessons Learned.

## 5. Document — make it defensible
Generate a forensic report from the **Forensics** view (or `python -m soclab forensics --report …`). Record the case in the incident-report template. Every conclusion should trace to an evidence ID with a SHA-256 hash — that is what makes your write-up hold up to review.

---

## Worked example — the full intrusion

After **RUN FULL SIMULATION**, an analyst would read it as one story:

1. **SOC-001 (HIGH)** — spray from `10.10.20.66` against many accounts → credential access underway.
2. **SOC-006 (MEDIUM)** — `administrator` hit repeatedly → targeted guessing.
3. **SOC-002 (MEDIUM)** — the same source scans `WIN-SRV02` → discovery.
4. **SOC-004 (HIGH)** — encoded, hidden PowerShell on `WIN-CLIENT01` by `t.brown` → execution; `t.brown` is the foothold.
5. **SOC-003 (HIGH)** — `svc_backup` granted `SeDebug`/`SeImpersonate` → privilege escalation.
6. **SOC-005 (CRITICAL)** — EICAR artifact on `WIN-CLIENT01` → malware delivery; DEFCON escalates.

**Conclusion:** one adversary (`10.10.20.66`), one foothold account (`t.brown`), one escalation path (`svc_backup`), progressing through credential access → discovery → execution → escalation → delivery. **Contain** `WIN-CLIENT01`, **reset** `t.brown`, **strip** `svc_backup` privileges, **block** the source IP — then document and review.

---

## Habits that separate good analysts

- **Pivot, don't tunnel.** One alert is a thread; pull it until you see the whole picture.
- **Sequence is everything.** A success *after* a flood of failures is a compromise, not a coincidence.
- **Write as you go.** Evidence IDs and hashes captured during the investigation, not after.
- **Tune the source.** Every false positive is a chance to improve a rule — close the loop in Lessons Learned.

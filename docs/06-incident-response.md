# Incident Response

The lab implements the incident-response lifecycle the way frameworks like **NIST SP 800-61** and the **SANS PICERL** model define it, condensed into five operational phases. Reusable playbooks live in [`../incident-response/playbooks/`](../incident-response/playbooks/) and templates in [`../incident-response/templates/`](../incident-response/templates/).

The console's **Incidents view** renders these phases live, advancing as an analyst works an alert from detection to closure.

---

## The five phases

### 1. Identification
Confirm that an alert is a true incident, classify its severity, and open a case. Inputs are the detection engine's alerts and the analyst's triage. Outputs are a declared incident, an assigned severity, and an initial scope (which hosts, accounts, and data are involved). *Key question: what happened, and how bad is it?*

### 2. Containment
Stop the spread without destroying evidence. Short-term containment isolates affected hosts and blocks the attacker's source; long-term containment applies temporary controls (credential resets, firewall rules) while the investigation continues. *Key question: how do we stop this getting worse right now?*

### 3. Eradication
Remove the adversary's foothold: delete malware and backdoor accounts, close the exploited weakness (e.g. strip the over-scoped `svc_backup` privileges), and revoke compromised credentials. *Key question: how do we get the attacker out and keep them out?*

### 4. Recovery
Return affected systems to validated, monitored production. Restore from known-good state where needed, confirm clean telemetry, and watch closely for re-compromise. *Key question: how do we safely resume operations?*

### 5. Lessons Learned
Run a post-incident review within a fixed window of closure. Capture the timeline, root cause, what worked, what didn't, and concrete improvements — including new or tuned detections. *Key question: how do we make the next one less likely and easier to catch?*

---

## Playbooks

Scenario-specific runbooks that take an analyst from alert to closure. Each one names the triggering detection, the immediate actions, the investigation steps, and the containment/eradication/recovery actions specific to that threat.

| Playbook | Triggering detection |
|---|---|
| [`playbook-brute-force.md`](../incident-response/playbooks/playbook-brute-force.md) | SOC-001 / SOC-006 |
| [`playbook-malware.md`](../incident-response/playbooks/playbook-malware.md) | SOC-005 |
| [`playbook-privilege-escalation.md`](../incident-response/playbooks/playbook-privilege-escalation.md) | SOC-003 / SOC-008 |

## Templates

Fill-in documents that standardise how incidents are recorded and communicated:

| Template | Purpose |
|---|---|
| [`incident-report-template.md`](../incident-response/templates/incident-report-template.md) | The formal record of a single incident |
| [`incident-tracking-log.md`](../incident-response/templates/incident-tracking-log.md) | The running queue of all incidents and their status |

---

## Severity and response targets

| Severity | Example detections | Target response start |
|---|---|---|
| CRITICAL | SOC-005 malware, SOC-008 account creation | Immediate |
| HIGH | SOC-001 brute force, SOC-003 priv-esc, SOC-004 PowerShell, SOC-007 lateral | Within minutes |
| MEDIUM | SOC-002 scan, SOC-006 repeated logins | Same shift |

These targets are illustrative service levels for the lab; a real programme would align them to its own SLAs and the criticality of the assets involved.

---

## How it ties together

An alert in the **Threats view** becomes a case in the **Incidents view**; the analyst follows the matching **playbook**, records findings in the **incident report template**, and — for anything reaching evidence handling — the **forensics module** supplies the hash-verified timeline and chain of custody. That closed loop, from detection to documented closure, is the deliverable employers in regulated and national-security environments most want to see.

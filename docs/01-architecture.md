# Environment Architecture

**Domain:** `CYBERLAB.LOCAL`
**Diagram:** [`diagrams/architecture.svg`](diagrams/architecture.svg)

This document describes the simulated enterprise the SOC Lab defends, the role of every component, and how telemetry flows from the endpoints to the analyst's screen.

---

## Design philosophy

A production SOC environment normally requires six or more virtual machines, a SIEM cluster, and a network fabric — impractical for a portfolio reviewer to stand up. The SOC Lab solves this two ways:

1. **Simulated enterprise (default).** Every host, user, and adversary action is modelled in software. The detection pipeline is real; the telemetry is synthetic. This is what runs when you execute the project.
2. **Production reference (shipped configs).** The `config/` directory contains the actual Wazuh rules, Sysmon configuration, and Beats/Elastic pipelines you would deploy on real hardware. The simulated rules and the production rules are kept in lockstep — `python -m soclab export-wazuh` regenerates the Wazuh XML directly from the same rule definitions the engine uses.

The result is a project that *runs* like a lab and *documents* like a deployment.

---

## The simulated enterprise

### Network segments

| Segment | Range | Purpose |
|---|---|---|
| Server / management | `10.10.10.0/24` | Domain controller, servers, SIEM |
| Client / user | `10.10.20.0/24` | Workstations and the red-team host |

### Inventory

| Host | IP | Role |
|---|---|---|
| `WIN-DC01` | `10.10.10.10` | Windows Server — Domain Controller |
| `WIN-SRV02` | `10.10.10.20` | Windows Server — member / file server |
| `LNX-WEB01` | `10.10.10.40` | Linux Server — web/app host |
| `WIN-SIEM` | `10.10.10.50` | Wazuh SIEM manager |
| `WIN-CLIENT01` | `10.10.20.30` | Windows Client — workstation |
| `WIN-CLIENT02` | `10.10.20.31` | Windows Client — workstation |
| `KALI` (attacker) | `10.10.20.66` | Adversary / red-team workstation |

---

## Component roles

### Windows Server (`WIN-DC01`)
The domain controller and authority for identity. It runs **Active Directory**, DNS, and Group Policy. It is the highest-value target in the environment — compromise here means domain dominance. From a detection standpoint it is the richest source of authentication telemetry: failed logons (Event ID 4625), special-privilege assignment (4672), account creation (4720), and privileged group changes (4728/4732).

### Active Directory
The identity backbone. It defines users, groups, the admin allowlist, and authentication policy. The lab models AD security events directly — the privilege-escalation and unauthorized-account-creation detections key off AD's audit events. Protecting AD (Tier-0 assets, privileged group membership, service-account hygiene) is the single most important Active Directory security discipline this project demonstrates.

### Windows Client (`WIN-CLIENT01`, `WIN-CLIENT02`)
Domain-joined user workstations. These are the primary *execution surface* — where phishing payloads run, where PowerShell cradles fire, and where malware lands. They emit process-creation events (Security 4688, Sysmon Event ID 1), PowerShell script-block logs (4104), and file-create events (Sysmon Event ID 11).

### Linux Server (`LNX-WEB01`)
A web/application host representing the non-Windows attack surface. It contributes `sshd` authentication telemetry (`/var/log/auth.log`) and `sudo` escalation events, so the brute-force and privilege-escalation detections cover both operating systems rather than Windows alone.

### Attacker Machine — Kali Linux (`10.10.20.66`)
The adversary workstation. In the simulation it is the *source* of all malicious activity: password spraying, Nmap scanning, encoded PowerShell delivery, privilege-escalation tooling, and the EICAR malware drop. Every scenario's telemetry carries this source IP, which is the analyst's primary pivot point during investigation. **No real offensive tooling is executed** — the host only emits the log events such activity would produce.

### SIEM Platform — Wazuh (`WIN-SIEM`)
The detection brain. In production, Wazuh ingests logs from every host (via Wazuh agents and Winlogbeat), normalises them through decoders, and evaluates them against the ruleset in `local_rules.xml`. The SOC Lab's Python **detection engine** mirrors this behaviour in software, and `wazuh_export.py` emits a real, deployable Wazuh ruleset from the same rule definitions — so what you test in the lab is what you would run in Wazuh.

### Sysmon
A Windows system-monitoring agent that provides far deeper endpoint visibility than the default audit policy: full process trees with hashes (Event ID 1), network connections (Event ID 3), file creation (Event ID 11), and named-pipe activity (Event ID 18). Sysmon is what makes the suspicious-PowerShell and malware detections precise. The trimmed, production-grade configuration ships in [`../config/sysmon/sysmon-config.xml`](../config/sysmon/sysmon-config.xml).

### Elastic Stack
Storage, search, and visualisation. **Filebeat** and **Winlogbeat** ship logs into Elasticsearch; **Kibana** provides long-term search and dashboarding. In the lab, the tactical console plays the role Kibana would in production. Reference pipeline configs live under `config/filebeat`, `config/winlogbeat`, and `config/elastic`.

### Network Monitoring
A perimeter firewall / network TAP feeding flow records and connection-attempt logs into the SIEM. This is the data source behind the port-scan detection (SOC-002) — a host touching many distinct ports in a short window is visible only at the network layer.

---

## Telemetry flow

```
[ Endpoints / Servers / Linux / Firewall ]
        │   Sysmon + Windows Event Logs + flow logs
        ▼
[ Winlogbeat / Filebeat / Wazuh agent ]   ── log shipping ──►
        ▼
[ Wazuh SIEM ]  decoders + local_rules.xml
        ▼
[ Detection Engine ]  stateful sliding-window correlation
        ▼  MITRE-mapped alerts
[ Elastic Stack ]  index / search
        ▼
[ Tactical Console ]  radar · DEFCON readiness · triage · forensics · IR
```

The detection engine raises an alert, the alert escalates the DEFCON-style readiness posture, the analyst triages it in the console, and — if it is a real incident — the forensics and incident-response modules take over. That full path is what the rest of this documentation walks through.

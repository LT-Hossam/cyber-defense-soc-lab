# Deployment Guide

This guide covers two deployment modes: running the **lab simulation** (what a reviewer does) and standing up the **production reference** (how the same detections run against real telemetry).

---

## Part A — Run the lab (simulation)

### Prerequisites
- Python 3.9 or newer
- `pip`
- A modern browser

### Steps

```bash
# 1. clone
git clone <your-repo-url> cyber-defense-soc-lab
cd cyber-defense-soc-lab

# 2. virtual environment
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1

# 3. install (Flask is the only dependency)
pip install -r requirements.txt

# 4. prime with a full attack simulation (optional but recommended)
python -m soclab simulate --all

# 5. launch the tactical console
python -m soclab serve --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. Or use the one-command launcher: `./run.sh` (Linux/macOS) or `.\run.ps1` (Windows).

### Verifying the install
```bash
python -m soclab rules            # should print 8 rules
python -m soclab simulate --all   # should raise 6 alerts
curl -s http://127.0.0.1:8000/api/health   # {"status":"online", ...}
```

---

## Part B — Production reference deployment

This is how you would run the *same* detection logic against a live enterprise. The lab ships the configs; this section explains where they go.

### B.1 Sysmon (Windows endpoints)
Install Sysmon with the provided configuration on every Windows host to get deep process/network/file telemetry:
```powershell
sysmon64.exe -accepteula -i config\sysmon\sysmon-config.xml
# update an existing install:
sysmon64.exe -c config\sysmon\sysmon-config.xml
```
The config (see [`../config/sysmon/sysmon-config.xml`](../config/sysmon/sysmon-config.xml)) focuses on the high-signal events the detections rely on: process creation (ID 1), network connections (ID 3), and file creation (ID 11).

### B.2 Wazuh (SIEM manager)
Deploy the generated ruleset on the Wazuh manager:
```bash
# regenerate from the source-of-truth rules if needed
python -m soclab export-wazuh

# copy onto the manager and restart
sudo cp config/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```
Install the **Wazuh agent** on each Windows/Linux host so its logs reach the manager. The eight SOC-00X rules (Wazuh IDs 100100–100800) will then evaluate live traffic.

### B.3 Beats → Elastic (search & visualisation)
- **Winlogbeat** on Windows hosts ships Security and Sysmon channels — see [`../config/winlogbeat/`](../config/winlogbeat/).
- **Filebeat** on Linux hosts ships `auth.log`/syslog — see [`../config/filebeat/`](../config/filebeat/).
- **Elasticsearch + Kibana** index and visualise — see [`../config/elastic/`](../config/elastic/).

### B.4 Windows audit policy
For the AD-centric detections (4625/4672/4720/4728/4732/4624/7045) to be present, enable the matching advanced audit policies on the domain — logon, account management, and privilege use — via Group Policy. The detection rules document ([`02-detection-rules.md`](02-detection-rules.md)) lists the exact event IDs each rule consumes.

---

## Configuration reference

| Path | Deploys to | Purpose |
|---|---|---|
| `config/sysmon/sysmon-config.xml` | every Windows host | endpoint telemetry |
| `config/wazuh/local_rules.xml` | `/var/ossec/etc/rules/` on the manager | detection rules |
| `config/winlogbeat/` | Windows hosts | ship Windows/Sysmon logs |
| `config/filebeat/` | Linux hosts | ship auth/syslog |
| `config/elastic/` | Elastic node | index & visualise |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `port already in use` | run with `--port 8001` (or any free port) |
| no alerts in the console | click **RUN FULL SIMULATION**, or run `python -m soclab simulate --all` |
| `flask` not found | activate the venv, then `pip install -r requirements.txt` |
| console loads but is empty | the API runs at the same origin — confirm the server log shows requests to `/api/stats` |

The lab is intentionally dependency-light so it runs in restricted environments where only Python is available.

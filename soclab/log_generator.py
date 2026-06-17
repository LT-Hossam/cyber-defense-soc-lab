"""
Log generator for the simulated enterprise.

Produces normalised events that look like what Winlogbeat / Sysmon / Filebeat
would ship into a SIEM. Two flavours:

  * baseline traffic  -- benign day-to-day activity (the "noise" a SOC lives in)
  * attack telemetry  -- emitted by scenarios.py

Everything here is synthetic. The only "malware" indicator used is the EICAR
test signature (https://www.eicar.org/) — an industry-standard, completely
harmless string that every AV recognises, used precisely so detection can be
demonstrated without any real malicious code.
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Dict, List


# --------------------------------------------------------------------------- #
# Simulated enterprise inventory
# --------------------------------------------------------------------------- #
DOMAIN = "CYBERLAB.LOCAL"

HOSTS = {
    "WIN-DC01":      {"ip": "10.10.10.10", "os": "Windows Server 2022", "role": "Domain Controller / AD DS / DNS"},
    "WIN-SRV02":     {"ip": "10.10.10.20", "os": "Windows Server 2022", "role": "File / Application Server"},
    "WIN-CLIENT01":  {"ip": "10.10.20.30", "os": "Windows 11",          "role": "Workstation (Finance)"},
    "WIN-CLIENT02":  {"ip": "10.10.20.31", "os": "Windows 11",          "role": "Workstation (HR)"},
    "LNX-WEB01":     {"ip": "10.10.10.40", "os": "Ubuntu 22.04",        "role": "Linux Web / Reverse Proxy"},
    "WIN-SIEM":      {"ip": "10.10.10.50", "os": "Ubuntu 22.04",        "role": "Wazuh Manager / Elastic"},
}

USERS = ["j.doe", "a.smith", "m.khan", "r.patel", "s.nguyen", "l.garcia",
         "t.brown", "administrator", "svc_backup", "svc_sql", "svc_iam"]

ATTACKER = {"ip": "10.10.20.66", "host": "KALI-ATTACKER", "label": "Kali Linux (RED TEAM)"}

COMMON_PROCS = [
    "C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\winword.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\teams.exe",
]


def _ts(offset: float = 0.0) -> str:
    return datetime.fromtimestamp(time.time() + offset, tz=timezone.utc).isoformat()


def _host(name: str) -> Dict:
    return HOSTS.get(name, {"ip": "0.0.0.0", "os": "unknown", "role": "unknown"})


# --------------------------------------------------------------------------- #
# Baseline (benign) events
# --------------------------------------------------------------------------- #
def successful_logon(host: str = None, user: str = None) -> Dict:
    host = host or random.choice([h for h in HOSTS if h.startswith("WIN")])
    user = user or random.choice([u for u in USERS if not u.startswith("svc")])
    return {
        "timestamp": _ts(), "source": "WinEventLog:Security", "event_id": 4624,
        "host": host, "host_ip": _host(host)["ip"], "user": user,
        "src_ip": _host(host)["ip"], "logon_type": random.choice([2, 7, 11]),
        "auth_package": "Kerberos", "domain": DOMAIN,
        "message": f"An account was successfully logged on ({user}).",
    }


def benign_process(host: str = None, user: str = None) -> Dict:
    host = host or random.choice([h for h in HOSTS if h.startswith("WIN")])
    user = user or random.choice([u for u in USERS if not u.startswith("svc")])
    image = random.choice(COMMON_PROCS)
    return {
        "timestamp": _ts(), "source": "WinEventLog:Sysmon", "event_id": 1,
        "host": host, "host_ip": _host(host)["ip"], "user": user,
        "image": image, "command_line": image,
        "parent_image": "C:\\Windows\\explorer.exe",
        "message": f"Process created: {image}",
    }


def benign_traffic() -> Dict:
    host = random.choice(list(HOSTS))
    dst = random.choice([h for h in HOSTS if h != host])
    return {
        "timestamp": _ts(), "source": "Firewall:flow", "action": "connection_allowed",
        "src_ip": _host(host)["ip"], "dst_ip": _host(dst)["ip"],
        "dst_port": random.choice([80, 443, 445, 389, 53, 3389, 22]),
        "proto": "tcp", "message": "Allowed established connection.",
    }


def benign_linux_login() -> Dict:
    user = random.choice(["root", "deploy", "ubuntu", "m.khan"])
    return {
        "timestamp": _ts(), "source": "Linux:auth", "action": "ssh_success",
        "host": "LNX-WEB01", "host_ip": "10.10.10.40", "user": user,
        "src_ip": _host("WIN-CLIENT01")["ip"],
        "message": f"Accepted password for {user} from 10.10.20.30 port 51022 ssh2",
    }


def baseline_batch(n: int = 12) -> List[Dict]:
    """A small batch of mixed benign events."""
    generators = [successful_logon, benign_process, benign_traffic,
                  benign_traffic, benign_linux_login, successful_logon]
    return [random.choice(generators)() for _ in range(n)]


def inventory() -> Dict:
    """Static description of the simulated estate for the dashboard / docs."""
    return {
        "domain": DOMAIN,
        "hosts": [{"name": k, **v} for k, v in HOSTS.items()],
        "users": USERS,
        "attacker": ATTACKER,
        "networks": [
            {"cidr": "10.10.10.0/24", "zone": "Server VLAN (trusted)"},
            {"cidr": "10.10.20.0/24", "zone": "Client VLAN (user)"},
            {"cidr": "10.10.99.0/24", "zone": "DMZ / red-team segment"},
        ],
    }

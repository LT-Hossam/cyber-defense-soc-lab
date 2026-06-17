"""
SOC Lab API + dashboard server.

A single Flask app that:
  * serves the tactical dashboard (soclab/web/index.html + static assets)
  * exposes a small REST API the dashboard polls
  * runs an optional background thread that drips benign baseline traffic so the
    console always has a live pulse

No external services required — pure Python + Flask.
"""

from __future__ import annotations

import os
import threading
import time
from collections import Counter
from typing import Dict

from flask import Flask, jsonify, request, send_from_directory

from . import log_generator as gen
from .detection_engine import ENGINE, ingest
from .scenarios import all_scenarios, get_scenario, SCENARIO_ORDER
from .rules import rule_catalogue
from .store import STORE
from .forensics import timeline, collect_artifacts, forensic_report

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

app = Flask(__name__, static_folder=None)

# --------------------------------------------------------------------------- #
# Background baseline traffic (keeps the console alive)
# --------------------------------------------------------------------------- #
_bg_stop = threading.Event()


def _baseline_loop(interval: float = 3.0):
    while not _bg_stop.is_set():
        for ev in gen.baseline_batch(n=4):
            ingest(ev)
        _bg_stop.wait(interval)


def start_baseline():
    t = threading.Thread(target=_baseline_loop, daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------- #
# Static / dashboard
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(WEB_DIR, "static"), filename)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/health")
def health():
    return jsonify({"status": "online", "service": "Cyber Defense SOC Lab",
                    "version": "1.0.0"})


@app.route("/api/inventory")
def inventory():
    return jsonify(gen.inventory())


@app.route("/api/rules")
def rules():
    return jsonify(rule_catalogue())


@app.route("/api/scenarios")
def scenarios():
    # metadata only (strip the bulky events)
    out = []
    for s in all_scenarios():
        out.append({k: v for k, v in s.items() if k != "events"})
    return jsonify(out)


@app.route("/api/stats")
def stats():
    alerts = STORE.alerts(limit=100000)
    sev = Counter(a.get("severity") for a in alerts)
    status = Counter(a.get("status") for a in alerts)
    by_rule = Counter(a.get("rule_name") for a in alerts)
    tech = Counter()
    for a in alerts:
        for t in a.get("mitre_techniques", []):
            tech[t.split()[0]] += 1
    # readiness: more open criticals/highs -> higher DEFCON-style posture
    crit = sev.get("critical", 0)
    high = sev.get("high", 0)
    if crit > 0:
        readiness = "DEFCON 2 — ACTIVE INTRUSION"
        readiness_level = 2
    elif high > 0:
        readiness = "DEFCON 3 — ELEVATED THREAT"
        readiness_level = 3
    elif sev.get("medium", 0) > 0:
        readiness = "DEFCON 4 — INCREASED WATCH"
        readiness_level = 4
    else:
        readiness = "DEFCON 5 — NORMAL READINESS"
        readiness_level = 5
    return jsonify({
        "events": STORE.event_count(),
        "alerts": STORE.alert_count(),
        "severity": dict(sev),
        "status": dict(status),
        "by_rule": by_rule.most_common(8),
        "techniques": tech.most_common(10),
        "open_incidents": status.get("open", 0),
        "readiness": readiness,
        "readiness_level": readiness_level,
    })


@app.route("/api/events")
def events():
    limit = int(request.args.get("limit", 60))
    source = request.args.get("source")
    return jsonify(STORE.events(limit=limit, source=source))


@app.route("/api/alerts")
def alerts():
    limit = int(request.args.get("limit", 60))
    severity = request.args.get("severity")
    status = request.args.get("status")
    return jsonify(STORE.alerts(limit=limit, severity=severity, status=status))


@app.route("/api/alerts/<alert_id>/status", methods=["POST"])
def set_alert_status(alert_id):
    body = request.get_json(force=True, silent=True) or {}
    new = body.get("status", "investigating")
    updated = STORE.update_alert_status(alert_id, new)
    if not updated:
        return jsonify({"error": "alert not found"}), 404
    return jsonify(updated)


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """Fire one or all attack scenarios; returns the alerts raised."""
    body = request.get_json(force=True, silent=True) or {}
    which = body.get("scenario", "all")
    raised = []
    fired_scenarios = []
    keys = SCENARIO_ORDER if which == "all" else [which]
    for key in keys:
        if key not in SCENARIO_ORDER:
            return jsonify({"error": f"unknown scenario '{key}'"}), 400
        sc = get_scenario(key)
        fired_scenarios.append(sc["name"])
        for ev in sc["events"]:
            raised.extend(ingest(ev))
    return jsonify({"scenarios": fired_scenarios,
                    "alerts_raised": len(raised),
                    "alerts": raised})


@app.route("/api/timeline")
def api_timeline():
    return jsonify(timeline(limit=int(request.args.get("limit", 200))))


@app.route("/api/forensics/report")
def api_report():
    analyst = request.args.get("analyst", "SOC Analyst")
    return jsonify({"markdown": forensic_report(analyst=analyst)})


@app.route("/api/forensics/artifacts")
def api_artifacts():
    return jsonify(collect_artifacts())


@app.route("/api/reset", methods=["POST"])
def reset():
    STORE.clear()
    return jsonify({"status": "cleared"})


# --------------------------------------------------------------------------- #
def create_app(seed: bool = True, baseline: bool = True) -> Flask:
    if seed:
        # prime the console with a little history so it's never empty
        for ev in gen.baseline_batch(n=30):
            ingest(ev)
    if baseline:
        start_baseline()
    return app


def run(host: str = "127.0.0.1", port: int = 8000, baseline: bool = True):
    create_app(seed=True, baseline=baseline)
    print("=" * 64)
    print("  CYBER DEFENSE SOC LAB  —  tactical console online")
    print(f"  ▶  http://{host}:{port}")
    print("=" * 64)
    app.run(host=host, port=port, debug=False, threaded=True)

"""
Test suite for the Cyber Defense SOC Lab.

Runs fully offline against isolated, non-persisting stores so the live
data/ ring buffers are never touched. Verifies that:
  * the rule catalogue is well-formed,
  * every attack scenario raises the detections it claims to,
  * the forensics module produces a usable report,
  * the Flask API answers on its core routes.

Run:  python -m pytest -q
"""

import pytest

from soclab.rules import RULES, RULES_BY_ID, rule_catalogue
from soclab.store import Store
from soclab.detection_engine import DetectionEngine
from soclab.scenarios import all_scenarios, get_scenario, SCENARIO_ORDER


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def fresh_engine() -> DetectionEngine:
    """An engine bound to a private, non-persisting store."""
    return DetectionEngine(store=Store(persist=False))


def run_scenario(key: str):
    """Feed one scenario's events through a clean engine, collect rule IDs."""
    engine = fresh_engine()
    fired = set()
    for event in get_scenario(key)["events"]:
        for alert in engine.process(event):
            fired.add(alert["rule_id"])
    return fired


# --------------------------------------------------------------------------- #
# rule catalogue
# --------------------------------------------------------------------------- #
def test_eight_rules_present():
    assert len(RULES) == 8
    expected = {f"SOC-{n:03d}" for n in range(1, 9)}
    assert set(RULES_BY_ID) == expected


def test_every_rule_has_mitre_and_logic():
    for rule in RULES:
        assert rule.mitre_tactics, f"{rule.id} missing tactics"
        assert rule.mitre_techniques, f"{rule.id} missing techniques"
        assert rule.detection_logic.strip()
        assert rule.severity in {"low", "medium", "high", "critical"}


def test_catalogue_is_serialisable():
    cat = rule_catalogue()
    assert len(cat) == 8
    for entry in cat:
        # must be plain JSON-friendly types
        assert isinstance(entry["id"], str)
        assert isinstance(entry["mitre_techniques"], list)


# --------------------------------------------------------------------------- #
# scenarios -> detections
# --------------------------------------------------------------------------- #
def test_scenario_order_matches_registry():
    assert set(SCENARIO_ORDER) == {s_key for s_key in SCENARIO_ORDER}
    assert len(all_scenarios()) == len(SCENARIO_ORDER) == 5


@pytest.mark.parametrize("key", SCENARIO_ORDER)
def test_scenario_raises_expected_rules(key):
    scenario = get_scenario(key)
    fired = run_scenario(key)
    expected = set(scenario["expected_rules"])
    missing = expected - fired
    assert not missing, f"{key}: expected {expected}, missing {missing}, got {fired}"


def test_password_spray_is_high():
    engine = fresh_engine()
    severities = []
    for event in get_scenario("spray")["events"]:
        for alert in engine.process(event):
            if alert["rule_id"] == "SOC-001":
                severities.append(alert["severity"])
    assert "high" in severities


def test_malware_is_critical():
    engine = fresh_engine()
    found = False
    for event in get_scenario("malware")["events"]:
        for alert in engine.process(event):
            if alert["rule_id"] == "SOC-005":
                assert alert["severity"] == "critical"
                found = True
    assert found


def test_alerts_carry_mitre_and_evidence():
    engine = fresh_engine()
    saw_alert = False
    for event in get_scenario("privesc")["events"]:
        for alert in engine.process(event):
            saw_alert = True
            assert alert["mitre_techniques"]
            assert "summary" in alert and alert["summary"]
            assert "rule_name" in alert
    assert saw_alert


# --------------------------------------------------------------------------- #
# forensics  (reads the global in-memory STORE)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def loaded_global_store():
    """Clear the global STORE, disable disk persistence, ingest all scenarios."""
    from soclab.store import STORE
    from soclab.detection_engine import ENGINE
    prev_persist = STORE._persist
    STORE._persist = False
    STORE.clear()
    for scenario in all_scenarios():
        for event in scenario["events"]:
            ENGINE.process(event)
    yield STORE
    STORE.clear()
    STORE._persist = prev_persist


def test_forensics_report_contains_case_id(loaded_global_store):
    from soclab import forensics
    report = forensics.forensic_report(analyst="pytest")
    assert "CASE-" in report
    assert ("MITRE" in report) or ("ATT&CK" in report)


def test_collect_artifacts_returns_iocs(loaded_global_store):
    from soclab import forensics
    arts = forensics.collect_artifacts()
    assert isinstance(arts, dict)
    # scenarios should surface accounts, hosts, and MITRE techniques
    assert arts["alert_total"] >= 1
    assert any(arts.get(k) for k in ("involved_accounts", "affected_hosts",
                                     "mitre_techniques", "file_hashes"))


# --------------------------------------------------------------------------- #
# server / API
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client():
    from soclab.server import create_app
    app = create_app(seed=False, baseline=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json().get("status") in {"online", "ok"}


def test_rules_endpoint(client):
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    assert len(resp.get_json()) == 8


def test_simulate_then_alerts(client):
    sim = client.post("/api/simulate", json={"scenario": "all"})
    assert sim.status_code == 200
    alerts = client.get("/api/alerts")
    assert alerts.status_code == 200
    assert len(alerts.get_json()) >= 1


def test_index_and_static_served(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200

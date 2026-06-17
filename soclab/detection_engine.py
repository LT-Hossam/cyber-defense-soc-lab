"""
Detection engine.

Streams normalised events past the rule catalogue and produces alerts. Supports
two rule shapes:

  * stateless  (threshold == 1): a single matching event fires immediately.
  * stateful   (threshold  > 1): matching events are bucketed by a correlation
    key inside a sliding time window; the alert fires when the bucket reaches the
    threshold, then the bucket is reset to avoid alert storms.

This mirrors how real SIEM correlation works (Wazuh `frequency`/`timeframe`,
Elastic threshold rules) while staying small enough to read in one sitting.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Deque, Dict, List, Tuple
from collections import deque

from .rules import DetectionRule, all_rules
from .store import Store, STORE, utcnow_iso


def _event_ts(event: Dict) -> float:
    """Epoch seconds for an event, tolerant of ISO strings or epoch floats."""
    ts = event.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


class DetectionEngine:
    """Evaluates the rule catalogue against an event stream."""

    def __init__(self, store: Store = STORE):
        self.store = store
        self.rules: List[DetectionRule] = all_rules()
        # buckets[(rule_id, key)] -> deque of (ts, event) inside the window
        self._buckets: Dict[Tuple[str, str], Deque[Tuple[float, Dict]]] = \
            defaultdict(deque)
        # last-fire cooldown so a saturated bucket doesn't re-alert every event
        self._cooldown: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------ #
    def process(self, event: Dict) -> List[Dict]:
        """Run one event past every rule. Returns any alerts raised."""
        alerts: List[Dict] = []
        ts = _event_ts(event)

        for rule in self.rules:
            try:
                if not rule.match(event):
                    continue
            except Exception:
                # A faulty predicate must never crash ingestion.
                continue

            key = (rule.id, rule.group_by(event))

            if rule.threshold <= 1:
                alerts.append(self._raise(rule, [event]))
                continue

            # stateful: maintain a sliding window bucket
            bucket = self._buckets[key]
            bucket.append((ts, event))
            cutoff = ts - rule.window_seconds
            while bucket and bucket[0][0] < cutoff:
                bucket.popleft()

            if len(bucket) >= rule.threshold:
                last = self._cooldown.get(key, 0)
                if ts - last >= rule.window_seconds:
                    contributing = [ev for (_, ev) in bucket]
                    alerts.append(self._raise(rule, contributing))
                    self._cooldown[key] = ts
                    bucket.clear()

        return alerts

    # ------------------------------------------------------------------ #
    def _raise(self, rule: DetectionRule, events: List[Dict]) -> Dict:
        pivot = events[-1]
        # Build a concise, analyst-friendly summary.
        distinct_users = sorted({e.get("user", "") for e in events if e.get("user")})
        distinct_ports = sorted({e.get("dst_port") for e in events
                                 if e.get("dst_port") is not None})
        alert = {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
            "host": pivot.get("host") or pivot.get("dst_ip") or "n/a",
            "src_ip": pivot.get("src_ip", "n/a"),
            "user": pivot.get("user", "n/a"),
            "event_count": len(events),
            "summary": self._summarise(rule, pivot, len(events),
                                       distinct_users, distinct_ports),
            "evidence": [e.get("_id") for e in events if e.get("_id")][-25:],
            "sample_event": pivot,
            "wazuh_rule_id": rule.wazuh_rule_id,
            "detected_at": utcnow_iso(),
        }
        return self.store.add_alert(alert)

    @staticmethod
    def _summarise(rule, pivot, n, users, ports) -> str:
        if rule.id == "SOC-001":
            extra = f" across {len(users)} accounts" if len(users) > 1 else ""
            return (f"{n} failed authentications from {pivot.get('src_ip')}"
                    f"{extra} within {rule.window_seconds}s")
        if rule.id == "SOC-002":
            return (f"{n} connection attempts to {len(ports)} distinct ports "
                    f"on {pivot.get('dst_ip')} from {pivot.get('src_ip')}")
        if rule.id == "SOC-003":
            return (f"Special privileges ({pivot.get('privileges','elevated')}) "
                    f"assigned to {pivot.get('user')} on {pivot.get('host')}")
        if rule.id == "SOC-004":
            return (f"Suspicious PowerShell on {pivot.get('host')} by "
                    f"{pivot.get('user')}: {pivot.get('command_line','')[:90]}")
        if rule.id == "SOC-005":
            sig = pivot.get("signature") or pivot.get("file") or "suspicious binary"
            return f"Malware indicator '{sig}' on {pivot.get('host')} ({pivot.get('user')})"
        if rule.id == "SOC-006":
            return (f"{n} failed logins targeting account '{pivot.get('user')}' "
                    f"within {rule.window_seconds}s")
        if rule.id == "SOC-007":
            return (f"Lateral movement: {pivot.get('user')} network-logged-on to "
                    f"{n} hosts (latest {pivot.get('host')})")
        if rule.id == "SOC-008":
            actor = pivot.get("actor", "unknown")
            return (f"Account/group change for '{pivot.get('user')}' by {actor} "
                    f"on {pivot.get('host')}")
        return f"{rule.name}: {n} events"


# Shared engine instance for the running server.
ENGINE = DetectionEngine()


def ingest(event: Dict) -> List[Dict]:
    """Store an event and run detection on it. Returns raised alerts."""
    STORE.add_event(event)
    return ENGINE.process(event)

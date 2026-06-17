"""
Lightweight event + alert store for the SOC lab.

In a production SOC these live in Elasticsearch / OpenSearch. For a portable lab
that must run on any laptop with zero external services, we keep an in-memory
ring buffer with optional append-only JSONL persistence to ./data so the
forensics tooling and the dashboard can both read the same ground truth.
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.jsonl")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Thread-safe store for normalised events and generated alerts."""

    def __init__(self, max_events: int = 20000, max_alerts: int = 5000,
                 persist: bool = True):
        self._events: Deque[Dict] = deque(maxlen=max_events)
        self._alerts: Deque[Dict] = deque(maxlen=max_alerts)
        self._lock = threading.RLock()
        self._persist = persist
        self._event_seq = 0
        self._alert_seq = 0
        if persist:
            os.makedirs(DATA_DIR, exist_ok=True)

    # -- events ----------------------------------------------------------- #
    def add_event(self, event: Dict) -> Dict:
        with self._lock:
            self._event_seq += 1
            event.setdefault("_id", f"E{self._event_seq:07d}")
            event.setdefault("ingested_at", utcnow_iso())
            self._events.append(event)
            if self._persist:
                self._append(EVENTS_FILE, event)
            return event

    def events(self, limit: int = 200, source: Optional[str] = None) -> List[Dict]:
        with self._lock:
            data = list(self._events)
        if source:
            data = [e for e in data if e.get("source") == source]
        return data[-limit:][::-1]

    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    # -- alerts ----------------------------------------------------------- #
    def add_alert(self, alert: Dict) -> Dict:
        with self._lock:
            self._alert_seq += 1
            alert.setdefault("_id", f"A{self._alert_seq:06d}")
            alert.setdefault("created_at", utcnow_iso())
            alert.setdefault("status", "open")
            self._alerts.append(alert)
            if self._persist:
                self._append(ALERTS_FILE, alert)
            return alert

    def alerts(self, limit: int = 200, severity: Optional[str] = None,
               status: Optional[str] = None) -> List[Dict]:
        with self._lock:
            data = list(self._alerts)
        if severity:
            data = [a for a in data if a.get("severity") == severity]
        if status:
            data = [a for a in data if a.get("status") == status]
        return data[-limit:][::-1]

    def alert_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def update_alert_status(self, alert_id: str, status: str) -> Optional[Dict]:
        with self._lock:
            for a in self._alerts:
                if a.get("_id") == alert_id:
                    a["status"] = status
                    a["updated_at"] = utcnow_iso()
                    return a
        return None

    # -- maintenance ------------------------------------------------------ #
    def clear(self):
        with self._lock:
            self._events.clear()
            self._alerts.clear()
            self._event_seq = 0
            self._alert_seq = 0
            if self._persist:
                for f in (EVENTS_FILE, ALERTS_FILE):
                    try:
                        open(f, "w").close()
                    except OSError:
                        pass

    def _append(self, path: str, record: Dict):
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass


# A single process-wide store the server, engine and generator all share.
STORE = Store()

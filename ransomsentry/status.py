"""Live status shared with the dashboard via logs/status.json (written atomically)."""
import json, os, threading, time
from collections import deque
from pathlib import Path

STATUS_FILE = Path(__file__).resolve().parents[1] / "logs" / "status.json"


class Status:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"state": "starting", "started_at": time.time(), "ml_prob": None,
                     "rule_score": 0, "events_per_window": 0, "files_shadowed": 0, "config": {}}
        self._alerts = deque(maxlen=50)       # newest first
        self._ml = deque(maxlen=120)          # [time, probability]
        self._incidents = deque(maxlen=20)

    def update(self, **kw):
        with self.lock:
            self.data.update(kw)

    def add_alert(self, severity, signal, detail, path):
        with self.lock:
            self._alerts.appendleft({"t": time.time(), "severity": severity,
                                     "signal": signal, "detail": detail, "path": path})

    def add_ml(self, p: float):
        with self.lock:
            self.data["ml_prob"] = p
            self._ml.append([time.time(), p])

    def add_incident(self, report: dict):
        with self.lock:
            self._incidents.appendleft({"t": time.time(), **report})

    def write(self):
        with self.lock:
            snap = {**self.data, "alerts": list(self._alerts), "ml_history": list(self._ml),
                    "incidents": list(self._incidents), "updated_at": time.time()}
        STATUS_FILE.parent.mkdir(exist_ok=True)
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap, default=str), encoding="utf-8")
        for _ in range(10):                   # Windows: reader may briefly lock the file
            try:
                os.replace(tmp, STATUS_FILE)
                return
            except PermissionError:
                time.sleep(0.02)

    def start(self, interval: float = 0.5):
        def loop():
            while True:
                try:
                    self.write()
                except Exception:
                    pass
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()


STATUS = Status()
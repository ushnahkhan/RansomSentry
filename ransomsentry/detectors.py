import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from ransomsentry import config
from ransomsentry.monitor import FileEvent


@dataclass
class Alert:
    signal: str
    severity: str      # LOW / MEDIUM / HIGH / CRITICAL
    detail: str
    path: str
    weight: int


class RuleDetector:
    WEIGHTS = {"entropy_jump": 3, "ext_change": 3, "high_rate": 4,
               "ransom_note": 6, "canary": 100}

    def __init__(self, canary_paths: set[str] = frozenset()):
        self.canaries = {c.lower() for c in canary_paths}
        self.events = deque()        # timestamps of recent file events
        self.signals = deque()       # (timestamp, weight) of recent alerts
        self.last_rate_alert = 0.0

    # ---------- helpers ----------
    def _trim(self, now):
        w = config.RATE_WINDOW_SEC
        while self.events and now - self.events[0] > w:
            self.events.popleft()
        while self.signals and now - self.signals[0][0] > w:
            self.signals.popleft()

    def _alert(self, out, signal, severity, detail, path):
        a = Alert(signal, severity, detail, path, self.WEIGHTS[signal])
        self.signals.append((time.time(), a.weight))
        out.append(a)

    # ---------- main entry ----------
    def process(self, ev: FileEvent) -> list[Alert]:
        now = ev.timestamp
        self._trim(now)
        self.events.append(now)
        out: list[Alert] = []
        paths = {ev.path.lower()} | ({ev.dest_path.lower()} if ev.dest_path else set())

        # d) canary touched -> instant critical
        if paths & self.canaries:
            self._alert(out, "canary", "CRITICAL", f"canary file touched ({ev.kind})", ev.path)

        # a) entropy jump (plaintext -> encrypted)
        b, a = ev.entropy_before, ev.entropy_after
        if ev.kind in ("modified", "moved") and b is not None and a is not None:
            if a >= config.ENTROPY_HIGH and a - b >= config.ENTROPY_JUMP:
                self._alert(out, "entropy_jump", "HIGH", f"entropy {b:.2f} -> {a:.2f}", ev.path)

        # c) suspicious extension change
        if ev.kind == "moved" and ev.dest_path:
            src, dst = Path(ev.path), Path(ev.dest_path)
            if dst.suffix.lower() in config.SUSPICIOUS_EXTS:
                self._alert(out, "ext_change", "HIGH", f"{src.name} -> {dst.name}", ev.path)
            elif dst.name.startswith(src.name + "."):
                self._alert(out, "ext_change", "MEDIUM", f"extension appended: {dst.name}", ev.path)

        # c) ransom note created
        if ev.kind == "created" and Path(ev.path).name.lower() in config.RANSOM_NOTE_NAMES:
            self._alert(out, "ransom_note", "HIGH", "possible ransom note created", ev.path)

        # b) burst of file activity
        if len(self.events) > config.RATE_THRESHOLD and now - self.last_rate_alert > config.RATE_WINDOW_SEC:
            self.last_rate_alert = now
            self._alert(out, "high_rate", "MEDIUM",
                        f"{len(self.events)} file events in {config.RATE_WINDOW_SEC}s", ev.path)
        return out

    def threat_score(self) -> int:
        return sum(w for _, w in self.signals)

    def is_malicious(self) -> bool:
        return self.threat_score() >= config.SCORE_THRESHOLD
    def first_signal_time(self) -> float:
        return self.signals[0][0] if self.signals else time.time()

    def reset(self):
        self.events.clear()
        self.signals.clear()
        self.last_rate_alert = 0.0
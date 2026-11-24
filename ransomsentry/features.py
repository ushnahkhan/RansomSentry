import threading, time
from collections import deque
from pathlib import Path
import numpy as np

FEATURES = ["n_events", "write_rate", "create_ratio", "modify_ratio", "delete_ratio",
            "rename_ratio", "ext_change_ratio", "unique_files", "mean_entropy_after",
            "max_entropy_after", "frac_high_entropy", "mean_entropy_delta", "frac_entropy_jump"]


class FeatureExtractor:
    """Turns the file events of the last `window` seconds into one feature vector."""
    def __init__(self, window: float = 2.0):
        self.window = window
        self.events = deque()
        self.lock = threading.Lock()

    def add(self, ev):
        with self.lock:
            self.events.append(ev)

    def compute(self, now: float | None = None):
        now = now or time.time()
        with self.lock:
            while self.events and now - self.events[0].timestamp > self.window:
                self.events.popleft()
            evs = list(self.events)
        if not evs:
            return None

        n = len(evs)
        kinds = [e.kind for e in evs]
        mod, cre = kinds.count("modified"), kinds.count("created")
        dele, mov = kinds.count("deleted"), kinds.count("moved")
        ext_changes = sum(1 for e in evs if e.kind == "moved" and e.dest_path
                          and Path(e.dest_path).suffix.lower() != Path(e.path).suffix.lower())
        after = [e.entropy_after for e in evs if e.entropy_after is not None]
        deltas = [e.entropy_after - e.entropy_before for e in evs
                  if e.entropy_after is not None and e.entropy_before is not None]
        files = {(e.dest_path or e.path).lower() for e in evs}

        return {
            "n_events": n,
            "write_rate": (mod + cre) / self.window,
            "create_ratio": cre / n,
            "modify_ratio": mod / n,
            "delete_ratio": dele / n,
            "rename_ratio": mov / n,
            "ext_change_ratio": ext_changes / n,
            "unique_files": len(files),
            "mean_entropy_after": float(np.mean(after)) if after else 0.0,
            "max_entropy_after": float(max(after)) if after else 0.0,
            "frac_high_entropy": sum(a >= 7.5 for a in after) / len(after) if after else 0.0,
            "mean_entropy_delta": float(np.mean(deltas)) if deltas else 0.0,
            "frac_entropy_jump": sum(d >= 2.0 for d in deltas) / len(deltas) if deltas else 0.0,
        }
import threading, time
from ransomsentry import config, alerts, responder
from ransomsentry.backup import ShadowBackup
from ransomsentry.canary import plant_canaries
from ransomsentry.classifier import Classifier
from ransomsentry.detectors import Alert, RuleDetector
from ransomsentry.features import FeatureExtractor
from ransomsentry.monitor import start_monitor
from collections import deque
from ransomsentry.status import STATUS


def run():
    agent_start = time.time()
    canaries = plant_canaries(config.PROTECTED_DIRS) if config.CANARIES_ENABLED else set()
    backup = ShadowBackup(config.PROTECTED_DIRS)
    backup.snapshot()
    det = RuleDetector(canaries)
    fx = FeatureExtractor(window=2.0)
    clf = Classifier() if config.ML_ENABLED else None
    if clf is not None and not clf.available:
        alerts.info("[ml] no model found - run tools\\train.py first. Using rules only.")
        clf = None
    tracker = responder.IOTracker()
    tracker.start()
    STATUS.update(config={"protected": [str(d) for d in config.PROTECTED_DIRS],
                          "rules": config.RULES_ENABLED, "ml": clf is not None,
                          "canaries": config.CANARIES_ENABLED},
                  files_shadowed=len(backup.hashes))
    STATUS.start()
    state = {"busy": False, "source": "", "ml_prob": None}
    lock = threading.Lock()

    def _respond(first_signal: float):
        detected_at = time.time()
        alerts.detected(det.threat_score())
        procs, why = responder.find_culprits(tracker, first_signal, agent_start)
        killed = responder.kill(procs) if procs else ["nothing killed"]
        killed_at = time.time()
        time.sleep(0.5)
        restored = backup.restore_all()
        p = state["ml_prob"]
        alerts.incident({
            "verdict by": state["source"],
            "ML probability (last window)": f"{p:.2f}" if p is not None else "-",
            "detection time (s)": round(detected_at - first_signal, 3),
            "time to kill (s)": round(killed_at - first_signal, 3) if procs else "-",
            "culprit": why,
            "action": "; ".join(killed),
            "files damaged & restored": len(restored),
            "restored": ", ".join(x.split("\\")[-1] for x in restored[:15])
                        + (" ..." if len(restored) > 15 else ""),
        })
        time.sleep(1.0)

    def respond(first_signal: float):
        try:
            _respond(first_signal)
        except Exception as e:
            alerts.info(f"[response error] {e!r}")
        finally:
            STATUS.update(state="watching")
            det.reset()
            fx.clear()                      # don't let our own restore look like an attack
            state["busy"] = False
            alerts.info("[monitor] back to watching")

    def trigger(first_signal: float, source: str):
        with lock:
            if state["busy"]:
                return
            state["busy"] = True
            state["source"] = source
        threading.Thread(target=respond, args=(first_signal,), daemon=True).start()
    def safe_to_backup(ev) -> bool:
        if det.threat_score() > 0:                        # anything suspicious in the last 5 s
            return False
        if (state["ml_prob"] or 0) >= 0.5:                # ML is uneasy
            return False
        b, a = ev.entropy_before, ev.entropy_after
        if a is not None and b is not None and a - b >= 1.0:   # file became much more random
            return False
        return True
    def on_event(ev):
        if state["busy"]:
            return
        fx.add(ev)
        found = det.process(ev)            # always run: also decides what is safe to back up
        for a in found:
            alerts.alert(a)
        if not found and ev.kind in ("created", "modified") and safe_to_backup(ev):
            backup.backup_file(ev.path)
        if config.RULES_ENABLED and det.is_malicious():
            trigger(det.first_signal_time(), f"rules (score {det.threat_score()})")

    obs = start_monitor(on_event)
    STATUS.update(state="watching")
    alerts.info(f"RansomSentry running - rules {'ON' if config.RULES_ENABLED else 'OFF'}, "
                f"ML {'ON' if clf else 'OFF'} - Ctrl+C to stop")

    recent_p, ml_first = deque(maxlen=3), None
    try:
        while True:
            time.sleep(1)
            STATUS.update(rule_score=det.threat_score())
            if clf is None or state["busy"]:
                recent_p.clear(); ml_first = None
                continue
            f = fx.compute()
            if not f:
                STATUS.add_ml(0.0); STATUS.update(events_per_window=0)
                recent_p.clear(); ml_first = None
                continue
            p = clf.probability(f)
            STATUS.add_ml(p); STATUS.update(events_per_window=f["n_events"])   
            state["ml_prob"] = p
            recent_p.append(p)
            if config.ML_DEBUG:
                alerts.info(f"[ml] p={p:.2f} events={f['n_events']} rename={f['rename_ratio']:.2f} "
                            f"ext={f['ext_change_ratio']:.2f} dEnt={f['mean_entropy_delta']:.2f} "
                            f"entAfter={f['mean_entropy_after']:.2f} create={f['create_ratio']:.2f}")
            high = sum(x >= config.ML_THRESHOLD for x in recent_p)
            if p >= config.ML_THRESHOLD:
                if ml_first is None:
                    ml_first = fx.oldest()
                alerts.alert(Alert("ml_classifier", "HIGH",
                                   f"Random Forest: ransomware probability {p:.2f} "
                                   f"({high}/{config.ML_CONSECUTIVE} of last 3 windows)", "-", 0))
            if high >= config.ML_CONSECUTIVE:
                trigger(ml_first or fx.oldest(), f"ML classifier (p={p:.2f})")
                recent_p.clear(); ml_first = None
            elif high == 0:
                ml_first = None
    except KeyboardInterrupt:
        STATUS.update(state="stopped"); STATUS.write()
        obs.stop()
    obs.join()


if __name__ == "__main__":
    run()
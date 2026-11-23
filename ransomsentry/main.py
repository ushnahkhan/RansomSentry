import threading, time
from collections import deque
from ransomsentry import config, alerts, responder
from ransomsentry.backup import ShadowBackup
from ransomsentry.canary import plant_canaries
from ransomsentry.detectors import RuleDetector
from ransomsentry.monitor import start_monitor


def run():
    agent_start = time.time()
    canaries = plant_canaries(config.PROTECTED_DIRS) if config.CANARIES_ENABLED else set()
    backup = ShadowBackup(config.PROTECTED_DIRS)
    backup.snapshot()
    det = RuleDetector(canaries)
    tracker = responder.IOTracker()
    tracker.start()
    recent_events = deque(maxlen=5000)          # timestamps of ALL file events
    state = {"busy": False}

    def _respond(first_signal: float):
        detected_at = time.time()
        alerts.detected(det.threat_score())
        procs, why = responder.find_culprits(tracker, first_signal, agent_start)        
        killed = responder.kill(procs) if procs else ["nothing killed"]
        killed_at = time.time()
        time.sleep(0.5)
        restored = backup.restore_all()
        alerts.incident({
            "detection time (s)": round(detected_at - first_signal, 3),
            "time to kill (s)": round(killed_at - first_signal, 3) if procs else "-",
            "culprit": why,
            "action": "; ".join(killed),
            "files damaged & restored": len(restored),
            "restored": ", ".join(p.split("\\")[-1] for p in restored[:15])
                        + (" ..." if len(restored) > 15 else ""),
        })
        time.sleep(1.0)

    def respond(first_signal: float):
        try:
            _respond(first_signal)
        except Exception as e:
            alerts.info(f"[response error] {e!r}")
        finally:
            det.reset()
            state["busy"] = False
            alerts.info("[monitor] back to watching")

    def on_event(ev):
        recent_events.append(ev.timestamp)       # always record, even while responding
        if state["busy"]:
            return
        found = det.process(ev)
        for a in found:
            alerts.alert(a)
        if not found and ev.kind in ("created", "modified"):
            backup.backup_file(ev.path)
        if det.is_malicious():
            state["busy"] = True
            threading.Thread(target=respond, args=(det.first_signal_time(),), daemon=True).start()

    obs = start_monitor(on_event)
    alerts.info("RansomSentry running - Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()


if __name__ == "__main__":
    run()
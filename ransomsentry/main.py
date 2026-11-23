import time
from ransomsentry import config
from ransomsentry.canary import plant_canaries
from ransomsentry.detectors import RuleDetector
from ransomsentry.monitor import start_monitor


def run():
    canaries = plant_canaries(config.PROTECTED_DIRS) if config.CANARIES_ENABLED else set()
    det = RuleDetector(canaries)
    state = {"detected_at": None}

    def on_event(ev):
        for a in det.process(ev):
            print(f"[{a.severity:8}] {a.signal:12} {a.detail}  ({a.path})")
        if det.is_malicious() and state["detected_at"] is None:
            state["detected_at"] = time.time()
            print(f"\n>>> RANSOMWARE DETECTED  (threat score {det.threat_score()}) <<<\n")
            # Day 3: kill process + restore files here

    obs = start_monitor(on_event)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()


if __name__ == "__main__":
    run()
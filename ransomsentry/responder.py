import os, threading, time
from collections import deque
import psutil

# never kill these
WHITELIST = {"explorer.exe", "code.exe", "svchost.exe", "msmpeng.exe", "searchindexer.exe",
             "searchprotocolhost.exe", "searchfilterhost.exe", "onedrive.exe", "conhost.exe",
             "system", "registry", "csrss.exe", "winlogon.exe", "lsass.exe", "dwm.exe",
             "runtimebroker.exe", "taskmgr.exe", "vboxtray.exe", "vboxservice.exe",
             "msedge.exe", "git.exe", "claude.exe"}

TRUSTED_DIRS = (r"c:\windows", r"c:\program files", r"c:\program files (x86)")

_me = psutil.Process()
_SAFE_PIDS = {os.getpid(), _me.ppid(), 0, 4}
_MY_USER = _me.username()


class IOTracker(threading.Thread):
    """Samples I/O operation counts of user processes ~4x/second, keeps ~15 s of history."""
    def __init__(self, interval: float = 0.25, history_sec: float = 15):
        super().__init__(daemon=True)
        self.interval = interval
        self.history = deque(maxlen=int(history_sec / interval))   # (time, {pid: io_ops})
        self.eligible = {}            # pid -> Process (or None if we must ignore it)
        self.lock = threading.Lock()

    def _get(self, pid):
        if pid in self.eligible:
            return self.eligible[pid]
        proc = None
        try:
            p = psutil.Process(pid)
            if (pid not in _SAFE_PIDS and p.name().lower() not in WHITELIST
                    and p.username() == _MY_USER):
                proc = p
        except psutil.Error:
            pass
        self.eligible[pid] = proc     # cache: name/user checked only once per process
        return proc

    def _sample(self):
        snap = {}
        for pid in psutil.pids():
            p = self._get(pid)
            if p is None:
                continue
            try:
                io = p.io_counters()
                snap[pid] = io.read_count + io.write_count
            except psutil.Error:
                self.eligible.pop(pid, None)
        return snap

    def run(self):
        while True:
            t, s = time.time(), self._sample()
            with self.lock:
                self.history.append((t, s))
            time.sleep(self.interval)

    def window(self, since: float):
        with self.lock:
            return [h for h in self.history if h[0] >= since]


def _value_at(h, pid, T):
    """Last known I/O count of pid at or before time T (None if process didn't exist yet)."""
    v = None
    for t, s in h:
        if t > T:
            break
        if pid in s:
            v = s[pid]
    return v


def _score(tracker, first_signal, agent_start, base_sec=5.0):
    a_start = first_signal - 0.5             # attack window starts just before first alert
    b_start = a_start - base_sec             # baseline window before that
    h = tracker.window(b_start - 1.0)
    if len(h) < 2 or h[-1][0] - a_start < 0.4:
        return None
    t_now, last = h[-1]
    dur = t_now - a_start
    best = None
    for pid, v_now in last.items():
        v_a, v_b = _value_at(h, pid, a_start), _value_at(h, pid, b_start)
        ops = v_now - (v_a if v_a is not None else 0)
        rate = ops / dur                                       # ops/s during attack
        base = (v_a - v_b) / base_sec if (v_a is not None and v_b is not None) else 0.0
        if ops < 10 or rate < 3 * (base + 1):                  # needs a clear jump
            continue
        p = tracker.eligible.get(pid)
        try:
            exe = (p.exe() or "").lower()
            new = p.create_time() >= agent_start
        except (psutil.Error, AttributeError):
            continue
        untrusted = not exe.startswith(TRUSTED_DIRS)
        lift = rate - base
        score = min(lift / 10, 2.0) + (1 if new else 0) + (1 if untrusted else 0)
        if best is None or score > best["score"]:
            best = dict(score=score, rate=rate, base=base, proc=p, new=new, untrusted=untrusted)
    return best


def find_culprits(tracker, first_signal: float, agent_start: float, tries: int = 4):
    """Kill only a process whose I/O suddenly jumped when the attack began."""
    best = None
    for _ in range(tries):
        time.sleep(0.4)
        best = _score(tracker, first_signal, agent_start)
        if best and best["score"] >= 2.5:
            why = (f"I/O jumped {best['base']:.0f} -> {best['rate']:.0f} ops/s, "
                   f"{'new' if best['new'] else 'old'} process, "
                   f"{'user-writable' if best['untrusted'] else 'trusted'} path, "
                   f"score {best['score']:.2f}")
            return [best["proc"]], why
    if best:
        return [], f"no confident culprit (best score {best['score']:.2f})"
    return [], "no confident culprit (no process with an I/O jump)"


def kill(procs) -> list[str]:
    results = []
    for p in procs:
        try:
            p.suspend()
            desc = f"{p.name()} (PID {p.pid}) {' '.join(p.cmdline())[:100]}"
            for c in p.children(recursive=True):
                c.kill()
            p.kill()
            results.append(f"KILLED {desc}")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            results.append(f"FAILED PID {p.pid}: {e}")
    return results
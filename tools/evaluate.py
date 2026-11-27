import argparse, csv, hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path
import pandas as pd
import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ransomsentry import config
from ransomsentry.canary import CANARY_NAMES

PY = sys.executable
TEST = Path(r"C:\TestDocs")
CLEAN = Path(r"C:\LabData\testdocs_clean")
SEVENZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
MANIFEST = ROOT / "simulator" / "keys" / "TestDocs_manifest.json"
LOG = Path(config.LOG_FILE)
AGENT_OUT = ROOT / "logs" / "eval_agent.txt"
RUNS_CSV = ROOT / "data" / "eval_runs.csv"
SUMMARY = ROOT / "data" / "eval_summary.md"
FIELDS = ["mode", "kind", "scenario", "detected", "incidents", "verdict", "detection_s", "kill_s",
          "correct_kill", "killed_something", "files_hit", "files_lost", "timed_out"]

MODES = {
    "full":       {"RS_RULES": "1", "RS_ML": "1", "RS_CANARIES": "1"},
    "no_canary":  {"RS_RULES": "1", "RS_ML": "1", "RS_CANARIES": "0"},
    "rules_only": {"RS_RULES": "1", "RS_ML": "0", "RS_CANARIES": "0"},
    "ml_only":    {"RS_RULES": "0", "RS_ML": "1", "RS_CANARIES": "0"},
}

def sim(*a):    return [PY, "simulator/safe_sim.py", "encrypt", str(TEST), *a]
def ps(c):      return ["powershell", "-NoProfile", "-Command", c]
def benign(n):  return [PY, "tools/benign.py", n, str(TEST)]

ATTACKS = {
    "sim_fast":    sim(),
    "sim_medium":  sim("--delay", "0.05"),
    "sim_slow":    sim("--delay", "0.3"),
    "partial_512": sim("--partial", "512", "--delay", "0.05"),
    "partial_1k":  sim("--partial", "1024", "--delay", "0.05"),
    "partial_4k":  sim("--partial", "4096", "--delay", "0.05"),
    "no_note":     sim("--no-note", "--delay", "0.05"),
}
EVASIONS = {
    "no_rename":         sim("--no-rename", "--delay", "0.05"),
    "no_rename_partial": sim("--no-rename", "--partial", "1024", "--delay", "0.05"),
    "very_slow":         sim("--delay", "2"),
}
BENIGN = {
    "copy":        ps(r"New-Item -ItemType Directory C:\TestDocs\copytest -Force | Out-Null; Copy-Item C:\LabData\source\* C:\TestDocs\copytest\ -Force"),
    "zip":         ps(r"Compress-Archive C:\TestDocs\*.txt C:\TestDocs\backup.zip -Force"),
    "unzip":       ps(r"Expand-Archive C:\LabData\LabArchive.zip C:\TestDocs\extracted -Force"),
    "bulk_rename": benign("bulk_rename"),
    "edit":        benign("edit"),
    "gzip_rotate": benign("gzip_rotate"),
    "download":    benign("download"),
}
if SEVENZIP.exists():
    BENIGN["7z_add"] = [str(SEVENZIP), "a", r"C:\TestDocs\arch.7z", r"C:\TestDocs\*.txt"]


def plan(repeats):
    p = []
    for n, c in ATTACKS.items():
        p.append(("full", "attack", n, c, repeats, 60))
        p.append(("no_canary", "attack", n, c, repeats, 60))
    for n in ("sim_medium", "partial_1k"):
        p.append(("rules_only", "attack", n, ATTACKS[n], repeats, 60))
        p.append(("ml_only", "attack", n, ATTACKS[n], repeats, 60))
    for n, c in EVASIONS.items():
        p.append(("no_canary", "evasion", n, c, repeats, 45))
    for n, c in BENIGN.items():
        p.append(("full", "benign", n, c, repeats, 60))
    return p


# ---------- test folder handling ----------
def sha(p: Path):
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None

def make_clean_copy():
    if CLEAN.exists():
        return
    if any(p.suffix == ".locked" for p in TEST.iterdir()):
        sys.exit("C:\\TestDocs still has .locked files - decrypt it first.")
    CLEAN.mkdir(parents=True)
    for p in TEST.iterdir():
        if p.is_file() and p.name not in CANARY_NAMES and p.name != "HOW_TO_DECRYPT.txt":
            shutil.copy2(p, CLEAN / p.name)
    print(f"[eval] saved clean reference copy: {len(list(CLEAN.iterdir()))} files")

def reset_testdocs():
    for _ in range(10):
        try:
            if TEST.exists():
                shutil.rmtree(TEST)
            break
        except OSError:
            time.sleep(1)
    shutil.copytree(CLEAN, TEST)
    MANIFEST.unlink(missing_ok=True)


# ---------- one run ----------
def run_one(mode, kind, name, cmd, timeout, clean_hashes):
    reset_testdocs()
    log_pos = LOG.stat().st_size if LOG.exists() else 0
    env = {**os.environ, **MODES[mode], "RS_ML_DEBUG": "0",
           "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
    AGENT_OUT.parent.mkdir(exist_ok=True)
    out = open(AGENT_OUT, "w", encoding="utf-8")
    agent = subprocess.Popen([PY, "-m", "ransomsentry.main"], cwd=ROOT, env=env,
                             stdout=out, stderr=subprocess.STDOUT)
    t0 = time.time()
    while "RansomSentry running" not in AGENT_OUT.read_text(encoding="utf-8", errors="ignore"):
        if time.time() - t0 > 90 or agent.poll() is not None:
            agent.kill(); out.close()
            raise RuntimeError("agent did not start - see logs\\eval_agent.txt")
        time.sleep(0.5)
    time.sleep(5)                                  # let the I/O tracker build history

    tout = open(ROOT / "logs" / "eval_target.txt", "w", encoding="utf-8")
    target = subprocess.Popen(cmd, cwd=ROOT, stdout=tout, stderr=subprocess.STDOUT,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    start, timed_out = time.time(), False
    sim_pids = {target.pid}                        # launcher + the real python child it starts
    while target.poll() is None:
        try:
            sim_pids |= {c.pid for c in psutil.Process(target.pid).children(recursive=True)}
        except psutil.Error:
            pass
        if time.time() - start > timeout:
            target.kill(); timed_out = True
            break
        time.sleep(0.2)
    time.sleep(6)                                  # let the agent finish kill + restore
    agent.kill(); agent.wait(); out.close()
    tout.close()

    incidents = []
    if LOG.exists():
        with open(LOG, encoding="utf-8", errors="ignore") as f:
            f.seek(log_pos)
            for line in f:
                if "INCIDENT " in line:
                    try:
                        incidents.append(json.loads(line.split("INCIDENT ", 1)[1]))
                    except json.JSONDecodeError:
                        pass
    inc = incidents[0] if incidents else {}
    action = inc.get("action", "")
    row = dict(mode=mode, kind=kind, scenario=name,
               detected=int(bool(incidents)), incidents=len(incidents),
               verdict=inc.get("verdict by", ""),
               detection_s=inc.get("detection time (s)", ""),
               kill_s=inc.get("time to kill (s)", ""),
               correct_kill=int(any(f"(PID {p})" in action for p in sim_pids)),               killed_something=int("KILLED" in action),
               files_hit="", files_lost="", timed_out=int(timed_out))
    if kind != "benign":
        try:
            row["files_hit"] = len(json.loads(MANIFEST.read_text())["files"])
        except Exception:
            row["files_hit"] = 0
        row["files_lost"] = sum(1 for n, h in clean_hashes.items() if sha(TEST / n) != h)
    return row


# ---------- summary tables ----------
def fmt(v, d=2):
    return "-" if pd.isna(v) else f"{v:.{d}f}"

def summarize():
    df = pd.read_csv(RUNS_CSV)
    for c in ("detection_s", "kill_s", "files_hit", "files_lost"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["verdict"] = df["verdict"].astype(object).where(df["verdict"].notna(), "").astype(str)    
    L = ["# RansomSentry evaluation results", "",
         "## Attacks and evasions", "",
         "| Mode | Scenario | Runs | Detected | Avg detection (s) | Avg time to kill (s) "
         "| Avg files hit | Avg files lost | Correct kill | Verdict by |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    att = df[df.kind != "benign"]
    for (mode, sc), g in att.groupby(["mode", "scenario"], sort=False):
        v = g["verdict"].map(lambda s: s.split(" (")[0] if s else "none").value_counts()
        verdicts = ", ".join(f"{k} x{n}" for k, n in v.items())
        L.append(f"| {mode} | {sc} | {len(g)} | {g.detected.mean():.0%} | {fmt(g.detection_s.mean())} "
                 f"| {fmt(g.kill_s.mean())} | {fmt(g.files_hit.mean(), 1)} | {fmt(g.files_lost.mean(), 1)} "
                 f"| {g.correct_kill.mean():.0%} | {verdicts} |")
    ben = df[df.kind == "benign"]
    L += ["", "## Benign workloads (false positives)", "",
          "| Scenario | Runs | False alarms | Process killed |", "|---|---|---|---|"]
    for sc, g in ben.groupby("scenario", sort=False):
        L.append(f"| {sc} | {len(g)} | {int(g.detected.sum())} | {int(g.killed_something.sum())} |")
    if len(ben):
        L.append(f"\n**Overall false-positive rate: {ben.detected.mean():.1%} "
                 f"({int(ben.detected.sum())}/{len(ben)} benign runs)**")
    SUMMARY.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--only", default="", help="comma-separated mode:scenario, e.g. full:sim_medium")
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args()
    if a.summary_only:
        summarize(); sys.exit()

    make_clean_copy()
    clean_hashes = {p.name: sha(p) for p in CLEAN.iterdir()}
    items = plan(a.repeats)
    if a.only:
        wanted = set(a.only.split(","))
        items = [it for it in items if f"{it[0]}:{it[2]}" in wanted]
    total = sum(it[4] for it in items)
    print(f"[eval] {total} runs planned (~{total * 30 // 60} min)")

    RUNS_CSV.parent.mkdir(exist_ok=True)
    new = not RUNS_CSV.exists()
    i = 0
    with open(RUNS_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for mode, kind, name, cmd, reps, timeout in items:
            for _ in range(reps):
                i += 1
                row = run_one(mode, kind, name, cmd, timeout, clean_hashes)
                w.writerow(row); f.flush()
                print(f"[eval] {i}/{total} {mode:10} {name:18} detected={row['detected']} "
                      f"t={row['detection_s']} hit={row['files_hit']} lost={row['files_lost']} "
                      f"verdict={row['verdict']}")
    reset_testdocs()
    summarize()
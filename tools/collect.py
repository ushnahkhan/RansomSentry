"""
Collect a labelled behaviour dataset for the RansomSentry classifier.
Run from C:\\RansomSentry with the venv active. Do NOT run ransomsentry.main at the same time.
    python tools\\collect.py --repeats 5
    python tools\\collect.py --only sim_medium,copy --repeats 1      (quick test)
"""
import argparse, csv, os, random, shutil, subprocess, sys, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ransomsentry.monitor import start_monitor
from ransomsentry.features import FeatureExtractor, FEATURES

LAB = Path(r"C:\Sandbox")
LABDATA = Path(r"C:\LabData")
SOURCE = LABDATA / "source"
ARCHIVE = LABDATA / "LabArchive.zip"
ARCHIVE_7Z = LABDATA / "LabArchive.7z"
SEVENZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
KEYS = ROOT / "simulator" / "keys"
OUT = ROOT / "data" / "dataset.csv"
PY = sys.executable
WORDS = ("the of and to in is was for on with as by at from report budget client invoice "
         "project meeting update payment schedule review quarter revenue team notes").split()


def ps(cmd: str):
    return ["powershell", "-NoProfile", "-Command", cmd]

def sim(*args):
    return [PY, "simulator/safe_sim.py", "encrypt", str(LAB), *args]

SCENARIOS = {
    # ---------- ransomware (label 1) ----------
    "sim_fast":     (1, sim()),
    "sim_medium":   (1, sim("--delay", "0.05")),
    "sim_slow":     (1, sim("--delay", "0.3")),
    "sim_partial":  (1, sim("--partial", "1024", "--delay", "0.02")),
    "sim_nonote":   (1, sim("--no-note", "--delay", "0.01")),
    # ---------- benign (label 0) ----------
    "copy":         (0, ps(r"New-Item -ItemType Directory C:\Sandbox\copy -Force | Out-Null; Copy-Item C:\LabData\source\* C:\Sandbox\copy\ -Force")),    "robocopy":     (0, ["robocopy", str(SOURCE), r"C:\Sandbox\backup", "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP"]),
    "zip":          (0, ps(r"Compress-Archive C:\Sandbox\* C:\Sandbox\archive.zip -Force")),
    "unzip":        (0, ps(r"Expand-Archive C:\LabData\LabArchive.zip C:\Sandbox\extracted -Force")),    "delete":       (0, ps(r"Remove-Item C:\Sandbox\*.txt")),
    "edit":         (0, [PY, "tools/benign.py", "edit"]),
    "download":     (0, [PY, "tools/benign.py", "download"]),
    "resave":       (0, [PY, "tools/benign.py", "resave"]),
    "gzip_rotate":  (0, [PY, "tools/benign.py", "gzip_rotate"]),
    "git_clone":    (0, ["git", "clone", "--depth", "1", "https://github.com/psf/requests", r"C:\Sandbox\requests"]),
}
if SEVENZIP.exists():
    SCENARIOS["7z_add"] = (0, [str(SEVENZIP), "a", r"C:\Sandbox\arch.7z", r"C:\Sandbox\*"])
    SCENARIOS["7z_extract"] = (0, [str(SEVENZIP), "x", str(ARCHIVE_7Z), r"-oC:\Sandbox\x7", "-y"])


# ---------- lab setup ----------
def build_files(folder: Path, seed: int):
    rng = random.Random(seed)
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(50):
        text = " ".join(rng.choices(WORDS, k=rng.randint(400, 6000)))
        (folder / f"doc_{i}.txt").write_text(text)
    for i in range(10):
        rows = "\n".join(f"{rng.randint(1,9999)},{rng.choice(WORDS)},{rng.random():.4f}" for _ in range(500))
        (folder / f"data_{i}.csv").write_text(rows)
    for i in range(10):
        (folder / f"photo_{i}.jpg").write_bytes(os.urandom(rng.randint(20_000, 100_000)))
    for i in range(10):
        with zipfile.ZipFile(folder / f"letter_{i}.docx", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("word/document.xml", " ".join(rng.choices(WORDS, k=3000)))

def prepare_sources():
    LABDATA.mkdir(exist_ok=True)
    if not SOURCE.exists():
        build_files(SOURCE, seed=999)
    if not ARCHIVE.exists():
        with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as z:
            for p in SOURCE.iterdir():
                z.write(p, p.name)
    if SEVENZIP.exists() and not ARCHIVE_7Z.exists():
        subprocess.run([str(SEVENZIP), "a", str(ARCHIVE_7Z), str(SOURCE / "*")], stdout=subprocess.DEVNULL)

def reset_lab(seed: int):
    if LAB.exists():
        shutil.rmtree(LAB, ignore_errors=True)
    build_files(LAB, seed)
    (KEYS / "Sandbox_manifest.json").unlink(missing_ok=True)


# ---------- recording ----------
def record(name, label, cmd, run_id, step=1.0, settle=2.0, timeout=120):
    reset_lab(seed=run_id)
    fx = FeatureExtractor(window=2.0)
    obs = start_monitor(fx.add, folders=[LAB])
    time.sleep(1.0)
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows, start, done_at = [], time.time(), None
    while True:
        time.sleep(step)
        f = fx.compute()
        if f:
            rows.append({**f, "label": label, "scenario": name, "run": run_id})
        if done_at is None and proc.poll() is not None:
            done_at = time.time()
        if done_at and time.time() - done_at > settle:
            break
        if time.time() - start > timeout:
            proc.kill()
            break
    obs.stop(); obs.join()
    return rows

def save(rows):
    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with open(OUT, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FEATURES + ["label", "scenario", "run"])
        if new:
            w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--only", default="", help="comma-separated scenario names")
    a = ap.parse_args()
    names = [n for n in SCENARIOS if not a.only or n in a.only.split(",")]
    prepare_sources()
    run_id = int(time.time()) % 100000
    for r in range(a.repeats):
        for name in names:
            label, cmd = SCENARIOS[name]
            run_id += 1
            rows = record(name, label, cmd, run_id)
            save(rows)
            print(f"[collect] round {r+1}/{a.repeats}  {name:12} label={label}  windows={len(rows)}")
    print(f"[collect] done -> {OUT}")
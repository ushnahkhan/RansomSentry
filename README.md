# RansomSentry

**Behaviour-based ransomware early detection and response for Windows 10/11.**

RansomSentry watches protected folders, detects ransomware by *what it does* (mass high-entropy rewrites, suspicious renames, ransom notes, touched decoy files) instead of by signatures, kills the responsible process within about a second, and restores the damaged files from a shadow backup.

> **Safety:** all testing must be done inside a virtual machine with snapshots. The included simulator really encrypts files (test folders only, with the key kept). Never run it on a real machine.

---

## Results (87 automated runs, see `data/eval_summary.md`)

| Measure | Target | Result |
|---|---|---|
| Detection rate, standard attacks | – | **100%** (63/63) |
| Detection time | < 3 s | **0.00–0.25 s** (rules), **1.5–1.7 s** (ML only) |
| Files lost | < 10 | **0** in all standard attacks |
| Correct process killed | – | **100%** |
| False-positive rate (8 benign tools) | low | **0%** (0/24) |
| Classifier accuracy (5-fold grouped CV) | – | **99.8%** |

Known limits: in-place partial encryption without renaming, and very slow attackers.

---

## How it works

```
file event ─► monitor (watchdog) ─► head entropy (first 4 KB)
                                     │
               ┌─────────────────────┴─────────────────────┐
               ▼                                           ▼
     Rule engine (5 s window)                  Random Forest (2 s windows)
     entropy jump · rename to .locked          13 behaviour features
     high write rate · ransom note · canary    "2 of last 3 windows ≥ 0.8"
               └──────────── rules OR ML ──────────────────┘
                                     ▼
          Responder: find process whose I/O suddenly jumped ─► kill
                                     ▼
          Shadow backup: restore damaged files ─► alerts + incident log
```

| Component | File |
|---|---|
| File monitor | `ransomsentry/monitor.py` |
| Entropy | `ransomsentry/entropy.py` |
| Rule detectors | `ransomsentry/detectors.py` |
| Canary (decoy) files | `ransomsentry/canary.py` |
| ML features / classifier | `ransomsentry/features.py`, `ransomsentry/classifier.py` |
| Process attribution + kill | `ransomsentry/responder.py` |
| Shadow backup / restore | `ransomsentry/backup.py` |
| Alerts + logging | `ransomsentry/alerts.py` → `logs/incidents.log` |
| Agent entry point | `ransomsentry/main.py` |
| Settings | `ransomsentry/config.py` |

---

## Setup

**Requirements:** Windows 10/11 VM (VirtualBox recommended), Python 3.11, Git.

```powershell
git clone https://github.com/ushnahkhan/RansomSentry.git
cd RansomSentry
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create the test folders and some test files:

```powershell
mkdir C:\TestDocs, C:\Sandbox
1..20  | % { "Normal document number $_. " * 300 | Out-File "C:\TestDocs\doc$_.txt" }
1..300 | % { "Normal document number $_. " * 300 | Out-File "C:\TestDocs\report$_.txt" }
```

Train the model (the trained model is not stored in the repo):

```powershell
python tools\collect.py --repeats 5     # build data/dataset.csv (~45 min), skip if it exists
python tools\train.py                   # creates models/rf.joblib + data/metrics.txt
```

📸 Take a VM snapshot before testing.

---

## Usage

**Run the agent** (protects `C:\TestDocs`):

```powershell
python -m ransomsentry.main
```

**Attack it with the safe simulator** (second terminal, wait ~5 s after "RansomSentry running"):

```powershell
python simulator\safe_sim.py encrypt C:\TestDocs --delay 0.05
```

Options: `--delay S` (speed), `--partial N` (encrypt only the first N bytes), `--no-rename`, `--no-note`.
The simulator refuses any folder except `C:\Sandbox` and `C:\TestDocs`.

**Undo the simulator** (if anything is left encrypted):

```powershell
python simulator\safe_sim.py decrypt C:\TestDocs
```

**Live dashboard (optional bonus):**

```powershell
python dashboard\app.py        # then open http://127.0.0.1:5000
```

**Switch detection layers** with environment variables (`1` = on, `0` = off):
`RS_RULES`, `RS_ML`, `RS_CANARIES`, `RS_ML_DEBUG`.

---

## Reproducing the evaluation

```powershell
python tools\evaluate.py --repeats 3      # ~45 min, results in data\eval_summary.md
```

---

## Repository layout

```
ransomsentry/   agent source code
simulator/      safe ransomware simulator (AES-256-CTR, key kept)
tools/          dataset collection, training, evaluation, benign workloads
dashboard/      optional read-only web dashboard (localhost only)
data/           dataset.csv, metrics.txt, eval_runs.csv, eval_summary.md
```

## Scope

User-mode agent for Windows only. Out of scope: Linux/macOS, kernel drivers, whole-disk/MBR ransomware, real malware samples, network detection.

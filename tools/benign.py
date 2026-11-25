"""Benign heavy-write workloads used as negative (label 0) training data. Works on C:\\Sandbox only."""
import gzip, os, random, sys, time
from pathlib import Path

LAB = Path(r"C:\Sandbox")
WORDS = "meeting report budget client invoice project update schedule review notes".split()


def edit():          # someone typing / saving documents
    files = list(LAB.glob("*.txt"))
    for _ in range(40):
        with open(random.choice(files), "a") as f:
            f.write(" ".join(random.choices(WORDS, k=50)) + "\n")
        time.sleep(0.1)

def download():      # browser saving new compressed files (photos, zips)
    for i in range(30):
        (LAB / f"download_{i}.bin").write_bytes(os.urandom(random.randint(50_000, 300_000)))
        time.sleep(0.05)

def resave():        # photo editor re-saving images in place (already high entropy)
    for p in list(LAB.glob("*.jpg")) + list(LAB.glob("*.docx")):
        p.write_bytes(os.urandom(p.stat().st_size))
        time.sleep(0.05)

def gzip_rotate():   # log rotation: compress each file to .gz and delete original (hard case!)
    for p in list(LAB.glob("*.txt")):
        with open(p, "rb") as src, gzip.open(str(p) + ".gz", "wb") as dst:
            dst.write(src.read())
        p.unlink()
        time.sleep(0.02)

def bulk_rename():   # user/tool renaming many files, e.g. .txt -> .md (hard case: extension change)
    for p in list(LAB.glob("*.txt")):
        p.rename(p.with_suffix(".md"))
        time.sleep(0.01)
if __name__ == "__main__":
    {"edit": edit, "download": download, "resave": resave, "gzip_rotate": gzip_rotate,
     "bulk_rename": bulk_rename}[sys.argv[1]]()
import random
from pathlib import Path

# "!" sorts first and "zzz" last, so attacks going in either order hit a canary early
CANARY_NAMES = ["!Financial_Report_2026.docx", "000_Passwords_backup.txt", "zzz_Tax_Records.pdf"]

WORDS = "invoice account budget salary quarter report client payment total tax revenue".split()

def plant_canaries(folders) -> set[str]:
    paths = set()
    for folder in folders:
        for name in CANARY_NAMES:
            p = Path(folder) / name
            if not p.exists():
                text = " ".join(random.choice(WORDS) for _ in range(4000))
                p.write_text(text)          # low-entropy plaintext, looks real
            paths.add(str(p).lower())
    print(f"[canary] {len(paths)} canary files in place")
    return paths
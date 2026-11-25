"""
SAFE ransomware simulator for testing RansomSentry.
- Only runs on the folders in ALLOWED_ROOTS.
- Saves the key + per-file info BEFORE encrypting, so everything is recoverable.
- `decrypt` mode restores all files and verifies them with SHA-256.
"""
import argparse, hashlib, json, os, secrets, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALLOWED_ROOTS = [Path(r"C:\Sandbox").resolve(), Path(r"C:\TestDocs").resolve()]
KEY_DIR = Path(r"C:\RansomSentry\simulator\keys")
EXT = ".locked"
NOTE = "HOW_TO_DECRYPT.txt"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def aes_ctr(key, nonce):
    return Cipher(algorithms.AES(key), modes.CTR(nonce))

def check_target(folder: str) -> Path:
    t = Path(folder).resolve()
    if t not in ALLOWED_ROOTS:
        sys.exit(f"REFUSED: {t} is not an allowed test folder. Allowed: {ALLOWED_ROOTS}")
    return t

def manifest_path(target: Path) -> Path:
    return KEY_DIR / f"{target.name}_manifest.json"

def save_manifest(mpath: Path, manifest: dict):
    tmp = mpath.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=1))
    for _ in range(40):                 # Windows: antivirus/indexer may briefly lock the file
        try:
            os.replace(tmp, mpath)      # atomic swap
            return
        except PermissionError:
            time.sleep(0.05)
    os.replace(tmp, mpath)              # last try; raises if still locked         # atomic: the manifest is never half-written
def encrypt(target: Path, delay: float, partial: int | None, note: bool):
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    mpath = manifest_path(target)
    if mpath.exists():
        sys.exit(f"Manifest {mpath} already exists - run decrypt first.")

    key = secrets.token_bytes(32)                     # AES-256
    manifest = {"key": key.hex(), "files": {}}
    files = sorted(p for p in target.rglob("*")
                   if p.is_file() and not p.name.endswith(EXT) and p.name != NOTE)
    print(f"[sim] PID {os.getpid()} - encrypting {len(files)} files in {target}")

    for p in files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        nonce = secrets.token_bytes(16)
        n = len(data) if partial is None else min(partial, len(data))
        dest = p.with_name(p.name + EXT)

        # 1) record everything needed to undo, BEFORE touching the file
        manifest["files"][str(dest)] = {"orig": str(p), "nonce": nonce.hex(),
                                        "n": n, "sha256": sha256(data)}
        save_manifest(mpath, manifest)
        # 2) overwrite in place, then rename (typical ransomware behaviour)
        enc = aes_ctr(key, nonce).encryptor()
        p.write_bytes(enc.update(data[:n]) + enc.finalize() + data[n:])
        p.rename(dest)
        print(f"[sim] encrypted {p.name}")
        if delay:
            time.sleep(delay)

    if note:
        (target / NOTE).write_text(
            "*** SIMULATION ONLY ***\nFiles were encrypted by the RansomSentry test simulator.\n"
            f"Restore with: python simulator\\safe_sim.py decrypt {target}\n")
    print("[sim] finished")


def decrypt(target: Path):
    mpath = manifest_path(target)
    if not mpath.exists():
        sys.exit("No manifest found - nothing to decrypt.")
    m = json.loads(mpath.read_text())
    key = bytes.fromhex(m["key"])
    restored = 0

    for dest, info in m["files"].items():
        dest, orig = Path(dest), Path(info["orig"])
        cur = dest if dest.exists() else (orig if orig.exists() else None)
        if cur is None:
            print(f"[sim] missing: {orig.name}")
            continue
        data = cur.read_bytes()
        if sha256(data) != info["sha256"]:           # still encrypted -> decrypt
            dec = aes_ctr(key, bytes.fromhex(info["nonce"])).decryptor()
            n = info["n"]
            data = dec.update(data[:n]) + dec.finalize() + data[n:]
            if sha256(data) != info["sha256"]:
                print(f"[sim] WARNING could not verify {orig.name}")
                continue
        orig.write_bytes(data)
        if cur != orig:
            cur.unlink()
        restored += 1

    (target / NOTE).unlink(missing_ok=True)
    mpath.rename(KEY_DIR / f"{target.name}_manifest_{int(time.time())}.done.json")
    print(f"[sim] restored {restored}/{len(m['files'])} files")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SAFE ransomware simulator (test folders only)")
    ap.add_argument("mode", choices=["encrypt", "decrypt"])
    ap.add_argument("folder")
    ap.add_argument("--delay", type=float, default=0, help="seconds between files (slow mode)")
    ap.add_argument("--partial", type=int, default=None, help="only encrypt first N bytes")
    ap.add_argument("--no-note", action="store_true")
    a = ap.parse_args()
    t = check_target(a.folder)
    if a.mode == "encrypt":
        encrypt(t, a.delay, a.partial, not a.no_note)
    else:
        decrypt(t)
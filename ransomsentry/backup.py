import hashlib, shutil
from pathlib import Path
from ransomsentry import config


def _sha(path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


class ShadowBackup:
    def __init__(self, folders, backup_dir=config.BACKUP_DIR):
        self.folders = [Path(f) for f in folders]
        self.root = Path(backup_dir)
        self.hashes = {}                    # lower(path) -> (original path, sha256)

    def _shadow_path(self, path) -> Path | None:
        p = Path(path)
        for f in self.folders:
            try:
                return self.root / f.name / p.relative_to(f)
            except ValueError:
                continue
        return None

    def backup_file(self, path):
        p = Path(path)
        sp = self._shadow_path(p)
        try:
            if (sp is None or not p.is_file()
                    or p.suffix.lower() in config.SUSPICIOUS_EXTS
                    or p.stat().st_size > config.BACKUP_MAX_MB * 1024 * 1024):
                return
            sp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, sp)
            self.hashes[str(p).lower()] = (str(p), _sha(sp))
        except OSError:
            pass

    def snapshot(self):
        for f in self.folders:
            for p in f.rglob("*"):
                if p.is_file():
                    self.backup_file(p)
        print(f"[backup] shadow copies of {len(self.hashes)} files in {self.root}")

    def restore_all(self) -> list[str]:
        """Restore every file whose content changed or vanished; remove ransomware leftovers."""
        restored = []
        for orig, h in list(self.hashes.values()):
            op, sp = Path(orig), self._shadow_path(orig)
            if not sp or not sp.exists():
                continue
            if op.exists() and _sha(op) == h:
                continue                    # untouched
            try:
                shutil.copy2(sp, op)
                restored.append(orig)
            except OSError:
                pass
        # delete .locked files and ransom notes that weren't there before
        for f in self.folders:
            for p in f.rglob("*"):
                if not p.is_file() or str(p).lower() in self.hashes:
                    continue
                if p.suffix.lower() in config.SUSPICIOUS_EXTS or p.name.lower() in config.RANSOM_NOTE_NAMES:
                    try:
                        p.unlink()
                    except OSError:
                        pass
        return restored
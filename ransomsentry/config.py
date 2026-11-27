from pathlib import Path

PROTECTED_DIRS = [Path(r"C:\TestDocs")]
BACKUP_DIR     = Path(r"C:\RansomSentry\.shadow")
LOG_FILE       = Path(r"C:\RansomSentry\logs\incidents.log")

ENTROPY_HIGH      = 7.5
ENTROPY_JUMP      = 2.0
RATE_WINDOW_SEC   = 5
RATE_THRESHOLD    = 20
SUSPICIOUS_EXTS   = {".locked", ".encrypted", ".crypt", ".enc", ".ransom"}
RANSOM_NOTE_NAMES = {"readme.txt", "how_to_decrypt.txt", "restore_files.txt"}
SCORE_THRESHOLD   = 10     # threat score that means "ransomware"
BACKUP_MAX_MB = 50      # don't shadow-copy files bigger than this
ML_THRESHOLD    = 0.8      # probability needed per window
ML_CONSECUTIVE  = 2        # this many high windows in a row -> 
import os

def _flag(name: str, default: bool) -> bool:
    """Read an on/off setting from environment variable RS_<name> (used by tools\\evaluate.py)."""
    v = os.environ.get("RS_" + name)
    return default if v is None else v == "1"

CANARIES_ENABLED = _flag("CANARIES", True)
RULES_ENABLED    = _flag("RULES", True)
ML_ENABLED       = _flag("ML", True)
ML_DEBUG         = _flag("ML_DEBUG", False)
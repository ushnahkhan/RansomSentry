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
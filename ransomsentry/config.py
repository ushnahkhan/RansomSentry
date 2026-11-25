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
CANARIES_ENABLED  = True
BACKUP_MAX_MB = 50      # don't shadow-copy files bigger than this
RULES_ENABLED   = True     # rule-based verdicts
ML_ENABLED      = True     # Random Forest verdicts
ML_THRESHOLD    = 0.8      # probability needed per window
ML_CONSECUTIVE  = 2        # this many high windows in a row -> 
ML_DEBUG = True    # print every ML probability + key features
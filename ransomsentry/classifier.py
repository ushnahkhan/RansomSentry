from pathlib import Path
import joblib
import pandas as pd
from ransomsentry.features import FEATURES

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "rf.joblib"


class Classifier:
    def __init__(self, path: Path = MODEL_PATH):
        self.model = joblib.load(path) if path.exists() else None
        if self.model is not None:
            self.model.n_jobs = 1
            self.probability({f: 0.0 for f in FEATURES})   # warm-up: load code paths now, not mid-attack         # one window per second: single thread is faster

    @property
    def available(self) -> bool:
        return self.model is not None

    def probability(self, feats: dict) -> float:
        """Probability (0-1) that this 2-second window is ransomware."""
        return float(self.model.predict_proba(pd.DataFrame([feats])[FEATURES])[0][1])
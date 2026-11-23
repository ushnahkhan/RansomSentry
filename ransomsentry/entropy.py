import numpy as np

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-(probs * np.log2(probs)).sum())

def file_entropy(path, max_bytes: int = 64 * 1024):
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(max_bytes))
    except OSError:
        return None
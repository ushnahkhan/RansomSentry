"""RansomSentry live dashboard (read-only).
Run:  python dashboard\\app.py     then open  http://127.0.0.1:5000
"""
import json, time
from pathlib import Path
from flask import Flask, jsonify, send_from_directory

ROOT = Path(__file__).resolve().parents[1]
STATUS_FILE = ROOT / "logs" / "status.json"
LOG_FILE = ROOT / "logs" / "incidents.log"
app = Flask(__name__)


@app.get("/")
def index():
    return send_from_directory(Path(__file__).parent, "index.html")


@app.get("/api/status")
def status():
    for _ in range(5):
        try:
            data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
            break
        except (OSError, json.JSONDecodeError):
            time.sleep(0.05)
    else:
        return jsonify({"state": "offline"})
    if time.time() - data.get("updated_at", 0) > 3:      # agent not writing -> offline
        data["state"] = "offline"
    return jsonify(data)


@app.get("/api/history")
def history():
    out = []
    if LOG_FILE.exists():
        for line in LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "INCIDENT " in line:
                try:
                    out.append({"time": line[:19], **json.loads(line.split("INCIDENT ", 1)[1])})
                except json.JSONDecodeError:
                    pass
    return jsonify(out[-50:][::-1])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)     # localhost only
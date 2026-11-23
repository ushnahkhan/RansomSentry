import json, logging
from rich.console import Console
from rich.panel import Panel
from rich.markup import escape
from ransomsentry import config

console = Console()
config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
log = logging.getLogger("ransomsentry")
log.setLevel(logging.INFO)
_h = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_h)

STYLE = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}


def info(msg: str):
    console.print(f"[dim]{escape(msg)}[/dim]")
    log.info(msg)

def alert(a):
    console.print(f"[{STYLE[a.severity]}]{a.severity:8}[/] {a.signal:12} "
                  f"{escape(a.detail)}  [dim]{escape(a.path)}[/dim]")
    log.warning("%s %s %s %s", a.severity, a.signal, a.detail, a.path)

def detected(score: int):
    console.print(Panel(f"RANSOMWARE DETECTED  -  threat score {score}\nResponding...",
                        style="bold white on red"))
    log.critical("RANSOMWARE DETECTED score=%s", score)

def incident(report: dict):
    body = "\n".join(f"{k}: {v}" for k, v in report.items())
    console.print(Panel(escape(body), title="Incident report", border_style="red"))
    log.critical("INCIDENT %s", json.dumps(report, default=str))
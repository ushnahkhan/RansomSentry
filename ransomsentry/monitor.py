import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ransomsentry.config import PROTECTED_DIRS
from ransomsentry.entropy import file_entropy


@dataclass
class FileEvent:
    kind: str                       # created / modified / moved / deleted
    path: str
    dest_path: Optional[str] = None # for renames
    entropy_before: Optional[float] = None
    entropy_after: Optional[float] = None
    timestamp: float = field(default_factory=time.time)


class EntropyCache:
    """Remembers each file's last known entropy so we can detect a JUMP."""
    def __init__(self):
        self.values = {}

    def scan(self, folders):
        for folder in folders:
            for p in Path(folder).rglob("*"):
                if p.is_file():
                    self.values[str(p)] = file_entropy(p)
        print(f"[baseline] cached entropy for {len(self.values)} files")

    def update(self, path):
        before = self.values.get(path)
        after = file_entropy(path)
        if after is not None:          # don't overwrite with None if the file vanished
            self.values[path] = after
        return before, after

    def move(self, src, dest):
        before = self.values.pop(src, None)
        after = file_entropy(dest)
        self.values[dest] = after
        return before, after


class SentryHandler(FileSystemEventHandler):
    def __init__(self, cache: EntropyCache, callback: Callable[[FileEvent], None]):
        self.cache = cache
        self.callback = callback

    def on_created(self, e):
        if e.is_directory: return
        _, after = self.cache.update(e.src_path)
        self.callback(FileEvent("created", e.src_path, entropy_after=after))

    def on_modified(self, e):
        if e.is_directory: return
        before, after = self.cache.update(e.src_path)
        self.callback(FileEvent("modified", e.src_path, None, before, after))

    def on_moved(self, e):
        if e.is_directory: return
        before, after = self.cache.move(e.src_path, e.dest_path)
        self.callback(FileEvent("moved", e.src_path, e.dest_path, before, after))

    def on_deleted(self, e):
        if e.is_directory: return
        before = self.cache.values.pop(e.src_path, None)
        self.callback(FileEvent("deleted", e.src_path, entropy_before=before))


def start_monitor(callback, folders=PROTECTED_DIRS):
    cache = EntropyCache()
    cache.scan(folders)
    observer = Observer()
    handler = SentryHandler(cache, callback)
    for folder in folders:
        observer.schedule(handler, str(folder), recursive=True)
    observer.start()
    print(f"[monitor] watching: {', '.join(map(str, folders))}")
    return observer


if __name__ == "__main__":
    def show(ev: FileEvent):
        b = f"{ev.entropy_before:.2f}" if ev.entropy_before is not None else "-"
        a = f"{ev.entropy_after:.2f}" if ev.entropy_after is not None else "-"
        extra = f" -> {ev.dest_path}" if ev.dest_path else ""
        print(f"{ev.kind:9} {ev.path}{extra}   entropy {b} -> {a}")

    obs = start_monitor(show)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
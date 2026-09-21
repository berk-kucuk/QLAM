import os
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

# Don't rescan the same path more than once within this window — editors and
# temp files fire a burst of modify events for a single logical change.
_DEBOUNCE_SECONDS = 5.0

_QUARANTINE_DIR = str(Path.home() / ".local" / "share" / "Qlam" / "quarantine")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


DEFAULT_WATCH_PATHS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "Desktop"),
    "/tmp",
]


class _ThreatHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._callback(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._callback(event.src_path)


class RealtimeProtection(QObject):
    threat_detected = pyqtSignal(str, str)   # path, threat_name
    status_changed = pyqtSignal(bool)         # is_active
    scan_error = pyqtSignal(str)

    def __init__(self, scan_engine, parent=None):
        super().__init__(parent)
        self._engine = scan_engine
        self._observer = None
        self._active = False
        self._watched_paths: list[str] = list(DEFAULT_WATCH_PATHS)
        self._pending: set[str] = set()
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_active(self) -> bool:
        return self._active

    def start(self, paths: list[str] | None = None):
        if not WATCHDOG_AVAILABLE:
            self.scan_error.emit("watchdog library not available for real-time protection.")
            return
        if self._active:
            return
        if paths:
            self._watched_paths = paths

        # Prefer the clamd daemon (signatures stay resident → near-instant
        # per-file scans). Falls back to clamscan transparently if unavailable.
        try:
            self._engine.connect_daemon()
        except Exception:
            pass

        self._observer = Observer()
        handler = _ThreatHandler(self._on_file_event)
        for path in self._watched_paths:
            if os.path.isdir(path):
                self._observer.schedule(handler, path, recursive=True)
        self._observer.start()
        self._active = True
        self.status_changed.emit(True)

    def stop(self):
        if not self._active or self._observer is None:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None
        self._active = False
        self.status_changed.emit(False)

    def set_watched_paths(self, paths: list[str]):
        was_active = self._active
        if was_active:
            self.stop()
        self._watched_paths = paths
        if was_active:
            self.start()

    def _should_handle(self, filepath: str) -> bool:
        base = os.path.basename(filepath)
        if base.startswith("."):
            return False  # hidden / editor swap / partial-download files
        if filepath.startswith(_QUARANTINE_DIR):
            return False  # never rescan files we just isolated
        if not os.path.isfile(filepath):
            return False  # gone already, or a directory
        if not self._engine._should_scan(filepath):
            return False  # too large (respects the max-file-size setting)
        now = time.time()
        last = self._recent.get(filepath)
        if last is not None and (now - last) < _DEBOUNCE_SECONDS:
            return False  # scanned very recently — ignore the modify-storm
        self._recent[filepath] = now
        # Keep the debounce map from growing unbounded on busy watch dirs.
        if len(self._recent) > 512:
            cutoff = now - _DEBOUNCE_SECONDS
            self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        return True

    def _on_file_event(self, filepath: str):
        with self._lock:
            if filepath in self._pending or not self._should_handle(filepath):
                return
            self._pending.add(filepath)

        try:
            result = self._engine._scan_single(filepath)
            if result.infected:
                self.threat_detected.emit(filepath, result.threat)
        except Exception:
            pass
        finally:
            with self._lock:
                self._pending.discard(filepath)

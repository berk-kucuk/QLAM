import os
import subprocess
import threading
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal

try:
    import pyclamd
    PYCLAMD_AVAILABLE = True
except ImportError:
    PYCLAMD_AVAILABLE = False


class ScanResult:
    def __init__(self, path: str, infected: bool, threat: str = "", scan_time: float = 0.0):
        self.path = path
        self.infected = infected
        self.threat = threat
        self.scan_time = scan_time
        self.timestamp = datetime.now()


class ScanStats:
    def __init__(self):
        self.total_files = 0
        self.infected_files = 0
        self.scanned_files = 0
        self.errors = 0
        self.start_time = datetime.now()
        self.end_time = None
        self.threats: list[ScanResult] = []

    def duration_seconds(self) -> float:
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()


class ScanEngine(QThread):
    file_scanned = pyqtSignal(str, bool, str)   # path, infected, threat_name
    scan_progress = pyqtSignal(int, int, str)    # current, total, current_file
    scan_finished = pyqtSignal(object)           # ScanStats
    scan_error = pyqtSignal(str)
    engine_status = pyqtSignal(str, bool)        # message, is_daemon

    def __init__(self, parent=None):
        super().__init__(parent)
        self._abort = threading.Event()
        self._clamd = None
        self._use_daemon = False
        self._scan_targets: list[str] = []
        self._recursive = True
        self._max_file_size_mb = 100
        self._scan_archives = True
        self._scan_options: dict = {}

    # ── Engine initialization ─────────────────────────────────────────────

    def connect_daemon(self) -> bool:
        if not PYCLAMD_AVAILABLE:
            return False
        try:
            cd = pyclamd.ClamdUnixSocket()
            cd.ping()
            self._clamd = cd
            self._use_daemon = True
            self.engine_status.emit(f"clamd daemon connected: {cd.version()}", True)
            return True
        except Exception:
            pass
        try:
            cd = pyclamd.ClamdNetworkSocket()
            cd.ping()
            self._clamd = cd
            self._use_daemon = True
            self.engine_status.emit(f"clamd daemon connected (TCP): {cd.version()}", True)
            return True
        except Exception:
            self._use_daemon = False
            self._clamd = None
            self.engine_status.emit("clamd not available — using clamscan fallback", False)
            return False

    def daemon_available(self) -> bool:
        if self._clamd is None:
            return False
        try:
            self._clamd.ping()
            return True
        except Exception:
            self._use_daemon = False
            self._clamd = None
            return False

    # ── Public API ────────────────────────────────────────────────────────

    def start_scan(self, targets: list[str], recursive: bool = True):
        self._abort.clear()
        self._scan_targets = targets
        self._recursive = recursive
        self.start()

    def abort(self):
        self._abort.set()

    def set_option(self, key: str, value):
        self._scan_options[key] = value

    # ── Thread entry ──────────────────────────────────────────────────────

    def run(self):
        stats = ScanStats()
        files = self._collect_files(self._scan_targets, self._recursive)
        stats.total_files = len(files)

        self.connect_daemon()

        for i, filepath in enumerate(files):
            if self._abort.is_set():
                break
            self.scan_progress.emit(i + 1, stats.total_files, filepath)
            result = self._scan_single(filepath)
            stats.scanned_files += 1
            if result.infected:
                stats.infected_files += 1
                stats.threats.append(result)
            self.file_scanned.emit(result.path, result.infected, result.threat)

        stats.end_time = datetime.now()
        self.scan_finished.emit(stats)

    # ── Internal helpers ──────────────────────────────────────────────────

    def _collect_files(self, targets: list[str], recursive: bool) -> list[str]:
        files = []
        for target in targets:
            p = Path(target)
            if p.is_file():
                files.append(str(p))
            elif p.is_dir():
                if recursive:
                    for root, dirs, fnames in os.walk(p):
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        for fname in fnames:
                            fp = os.path.join(root, fname)
                            if self._should_scan(fp):
                                files.append(fp)
                else:
                    for item in p.iterdir():
                        if item.is_file() and self._should_scan(str(item)):
                            files.append(str(item))
        return files

    def _should_scan(self, path: str) -> bool:
        try:
            size = os.path.getsize(path)
            if size > self._max_file_size_mb * 1024 * 1024:
                return False
        except OSError:
            return False
        return True

    def _scan_single(self, filepath: str) -> ScanResult:
        if self._use_daemon and self._clamd:
            return self._scan_with_daemon(filepath)
        return self._scan_with_clamscan(filepath)

    def _scan_with_daemon(self, filepath: str) -> ScanResult:
        try:
            result = self._clamd.scan_file(filepath)
            if result is None:
                return ScanResult(filepath, False)
            # result = {filepath: ('FOUND', 'ThreatName')} or {filepath: ('OK', None)}
            status, threat = result.get(filepath, ('OK', None))
            if status == 'FOUND':
                return ScanResult(filepath, True, threat or "Unknown")
            return ScanResult(filepath, False)
        except Exception as e:
            return self._scan_with_clamscan(filepath)

    def _scan_with_clamscan(self, filepath: str) -> ScanResult:
        try:
            cmd = ["clamscan", "--no-summary"]
            if not self._scan_archives:
                cmd.append("--no-archive-scan")
            cmd.append(filepath)
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            # Return code 1 = virus found, 0 = clean, 2 = error
            if proc.returncode == 1:
                for line in proc.stdout.splitlines():
                    if "FOUND" in line:
                        parts = line.rsplit(":", 1)
                        threat = parts[-1].strip().replace(" FOUND", "")
                        return ScanResult(filepath, True, threat)
                return ScanResult(filepath, True, "Unknown")
            return ScanResult(filepath, False)
        except subprocess.TimeoutExpired:
            return ScanResult(filepath, False)
        except Exception:
            return ScanResult(filepath, False)

    # ── Quick scan paths ──────────────────────────────────────────────────

    @staticmethod
    def quick_scan_paths() -> list[str]:
        home = str(Path.home())
        return [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, ".local/share"),
            "/tmp",
            "/var/tmp",
        ]

    @staticmethod
    def full_scan_paths() -> list[str]:
        return ["/"]

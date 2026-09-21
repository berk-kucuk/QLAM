import os
import subprocess
import tempfile
import threading
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal

# Pseudo-filesystems and volatile dirs that must never be walked/scanned during
# a full ("/") scan — they are not real files and scanning them wastes time or
# hangs.
_SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"}

# Qlam's own quarantine store — never rescan files we've already isolated.
_QUARANTINE_DIR = Path.home() / ".local" / "share" / "Qlam" / "quarantine"

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
        self._proc: subprocess.Popen | None = None

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
        # Kill the running clamscan immediately so a big scan stops at once.
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass

    def set_option(self, key: str, value):
        self._scan_options[key] = value

    # ── Thread entry ──────────────────────────────────────────────────────

    def run(self):
        stats = ScanStats()
        files = self._collect_files(self._scan_targets, self._recursive)
        stats.total_files = len(files)

        self.connect_daemon()

        if files:
            if self._use_daemon and self._clamd:
                # Daemon holds the signatures resident, so per-file scanning is
                # already fast (no DB reload per call).
                self._scan_daemon_loop(files, stats)
            else:
                # No daemon: run ONE clamscan over the whole file list. clamscan
                # loads the ~175 MB signature DB once instead of once per file,
                # which is the difference between seconds and many minutes.
                self._scan_clamscan_batch(files, stats)

        stats.end_time = datetime.now()
        self.scan_finished.emit(stats)

    def _scan_daemon_loop(self, files: list[str], stats: ScanStats) -> None:
        for i, filepath in enumerate(files):
            if self._abort.is_set():
                break
            result = self._scan_with_daemon(filepath)
            stats.scanned_files += 1
            if result.infected:
                stats.infected_files += 1
                stats.threats.append(result)
                self.file_scanned.emit(result.path, True, result.threat)
            if i % 15 == 0 or result.infected or i + 1 == stats.total_files:
                self.scan_progress.emit(i + 1, stats.total_files, filepath)

    def _scan_clamscan_batch(self, files: list[str], stats: ScanStats) -> None:
        fd, listpath = tempfile.mkstemp(prefix="qlam-scan-", suffix=".list")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(files))

            cmd = [
                "clamscan", "--stdout", "--no-summary",
                f"--max-filesize={self._max_file_size_mb}M",
                f"--max-scansize={self._max_file_size_mb}M",
                f"--scan-archive={'yes' if self._scan_archives else 'no'}",
                f"--file-list={listpath}",
            ]
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, bufsize=1,
                )
            except Exception as e:
                self.scan_error.emit(str(e))
                return

            count = 0
            for line in self._proc.stdout:
                if self._abort.is_set():
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.endswith(" FOUND"):
                    path, _, verdict = line.rpartition(": ")
                    threat = verdict[:-len(" FOUND")].strip() or "Unknown"
                    count += 1
                    stats.scanned_files += 1
                    stats.infected_files += 1
                    stats.threats.append(ScanResult(path, True, threat))
                    self.scan_progress.emit(count, stats.total_files, path)
                    self.file_scanned.emit(path, True, threat)
                elif line.endswith(": OK"):
                    count += 1
                    stats.scanned_files += 1
                    if count % 15 == 0 or count == stats.total_files:
                        self.scan_progress.emit(count, stats.total_files, line[:-len(": OK")])
                elif line.endswith(" ERROR"):
                    count += 1
                    stats.scanned_files += 1
                    stats.errors += 1
        finally:
            proc = self._proc
            if proc is not None:
                try:
                    proc.wait(timeout=30)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            self._proc = None
            try:
                os.remove(listpath)
            except OSError:
                pass

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
                        # Prune hidden dirs, pseudo-filesystems and Qlam's own
                        # quarantine store (never rescan quarantined files).
                        dirs[:] = [
                            d for d in dirs
                            if not d.startswith('.')
                            and os.path.join(root, d) not in _SKIP_DIRS
                            and not os.path.join(root, d).startswith(str(_QUARANTINE_DIR))
                        ]
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

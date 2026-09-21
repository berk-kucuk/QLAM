import os
import shutil
import stat
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

# sigtool's "Build time:" value has changed format across ClamAV releases, so
# try each known layout in turn instead of assuming one.
_BUILD_TIME_FORMATS = (
    "%d %b %Y %H:%M %z",       # 1.x: "21 Jul 2026 06:23 +0000"
    "%d %b %Y %H:%M:%S %z",
    "%d %b %Y %H-%M-%S %z",    # older builds
)

_DB_DIRS = ("/var/lib/clamav", "/usr/local/share/clamav", "/usr/share/clamav")

# Where freshclam is allowed to live, in preference order.
#
# SECURITY: this binary is executed AS ROOT through pkexec, so it must never be
# resolved from PATH. shutil.which reads os.environ["PATH"], which the user (and
# anything running as the user) controls: dropping ~/.local/bin/freshclam was
# enough to have it run as root the next time someone clicked "Update Database"
# and typed their own password at a prompt they were expecting. pkexec normally
# sanitises PATH for the program it launches, but that does not help when the
# path has already been baked into the script text handed to it.
#
# Root-owned system directories only, and the file is checked to be a real,
# executable, root-owned file before it is used.
_FRESHCLAM_PATHS = ("/usr/bin/freshclam", "/usr/local/bin/freshclam")


def _resolve_freshclam() -> str | None:
    """Return a trustworthy absolute path to freshclam, or None.

    "Trustworthy" here means: a regular file (not a symlink into somewhere the
    user can write), executable, and owned by root. A freshclam that a normal
    user can replace is a root shell waiting for the next update click, so it
    is refused rather than run.
    """
    for path in _FRESHCLAM_PATHS:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_uid != 0:
            continue
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        if not os.access(path, os.X_OK):
            continue
        return path
    return None


class DatabaseInfo:
    def __init__(self):
        self.main_version: str = "Unknown"
        self.daily_version: str = "Unknown"
        self.bytecode_version: str = "Unknown"
        self.main_date: datetime | None = None
        self.daily_date: datetime | None = None
        self.db_path: str = ""
        self.clamav_version: str = "Unknown"

    def is_outdated(self) -> bool:
        if self.daily_date is None:
            return True
        return (datetime.now() - self.daily_date).days > 3


def _parse_build_time(value: str) -> datetime | None:
    for fmt in _BUILD_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return None


def _parse_db_dir(db_dir: str, info: DatabaseInfo) -> None:
    targets = {
        "main.cvd":     ("main_version",     "main_date"),
        "main.cld":     ("main_version",     "main_date"),
        "daily.cvd":    ("daily_version",    "daily_date"),
        "daily.cld":    ("daily_version",    "daily_date"),
        "bytecode.cvd": ("bytecode_version", None),
        "bytecode.cld": ("bytecode_version", None),
    }
    for fname, (ver_attr, date_attr) in targets.items():
        fpath = os.path.join(db_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            r = subprocess.run(["sigtool", "--info", fpath],
                               capture_output=True, text=True, timeout=15)
            got_date = False
            for line in r.stdout.splitlines():
                if line.startswith("Version:"):
                    setattr(info, ver_attr, line.split(":", 1)[1].strip())
                if date_attr and line.startswith("Build time:"):
                    dt = _parse_build_time(line.split(":", 1)[1].strip())
                    if dt is not None:
                        setattr(info, date_attr, dt)
                        got_date = True
            # If sigtool ran but we couldn't read a build time, fall back to the
            # file mtime so freshness detection still works.
            if date_attr and not got_date:
                setattr(info, date_attr,
                        datetime.fromtimestamp(os.path.getmtime(fpath)))
        except Exception:
            try:
                if date_attr:
                    setattr(info, date_attr,
                            datetime.fromtimestamp(os.path.getmtime(fpath)))
                setattr(info, ver_attr, f"~{os.path.getsize(fpath) // 1024} KB")
            except Exception:
                pass


def _fetch_info() -> DatabaseInfo:
    info = DatabaseInfo()
    try:
        r = subprocess.run(["clamscan", "--version"],
                           capture_output=True, text=True, timeout=10)
        info.clamav_version = r.stdout.strip().split("\n")[0]
    except Exception:
        pass

    for db_dir in _DB_DIRS:
        if os.path.isdir(db_dir):
            info.db_path = db_dir
            _parse_db_dir(db_dir, info)
            break
    return info


class _InfoWorker(QThread):
    done = pyqtSignal(object)

    def run(self):
        self.done.emit(_fetch_info())


class _UpdateWorker(QThread):
    output = pyqtSignal(str)
    result = pyqtSignal(bool, str)

    def run(self):
        freshclam = _resolve_freshclam()
        if not freshclam:
            self.result.emit(
                False,
                "freshclam was not found in a system location "
                f"({' or '.join(_FRESHCLAM_PATHS)}). Install clamav.")
            return

        pkexec = shutil.which("pkexec")
        if not pkexec:
            self.result.emit(
                False, "pkexec not found. Install polkit or run: sudo freshclam")
            return

        # Run the whole sequence as a single inline script passed to `sh -c`.
        # This avoids writing an executable to a world-writable, predictable
        # path in /tmp (which would be a local privilege-escalation vector via
        # a symlink/TOCTOU race, since the script is then executed as root).
        #   1. stop clamav-freshclam so it releases the log-file lock
        #   2. run freshclam once
        #   3. restart the service afterwards
        # freshclam comes from _resolve_freshclam(), which only ever returns a
        # root-owned binary in a fixed system directory — never anything found
        # on PATH, because this string runs as root.
        script = (
            "systemctl stop clamav-freshclam 2>/dev/null || true\n"
            f"'{freshclam}' --verbose --stdout\n"
            "RET=$?\n"
            "systemctl start clamav-freshclam 2>/dev/null || true\n"
            "exit $RET\n"
        )

        try:
            proc = subprocess.Popen(
                [pkexec, "/bin/sh", "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.output.emit(line)
            proc.wait(timeout=300)

            code = proc.returncode
            if code == 0:
                self.result.emit(True, "Database updated successfully.")
            elif code == 40:
                self.result.emit(True, "Database is already up to date.")
            elif code in (126, 127):
                self.result.emit(False, "Authentication failed or cancelled.")
            else:
                self.result.emit(False, f"Update failed (exit code {code}).")
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            self.result.emit(False, "Update timed out after 5 minutes.")
        except Exception as e:
            self.result.emit(False, str(e))


class DatabaseManager(QObject):
    update_started  = pyqtSignal()
    update_output   = pyqtSignal(str)
    update_finished = pyqtSignal(bool, str)
    info_loaded     = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._info_worker: _InfoWorker | None = None
        self._update_worker: _UpdateWorker | None = None

    def load_info(self):
        if self._info_worker is not None and self._info_worker.isRunning():
            return
        worker = _InfoWorker(self)
        worker.done.connect(self.info_loaded)
        self._info_worker = worker
        worker.start()

    def is_updating(self) -> bool:
        return self._update_worker is not None and self._update_worker.isRunning()

    def run_update(self):
        if self.is_updating():
            return
        self.update_started.emit()
        worker = _UpdateWorker(self)
        worker.output.connect(self.update_output)
        worker.result.connect(self.update_finished)
        self._update_worker = worker
        worker.start()

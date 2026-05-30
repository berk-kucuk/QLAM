import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


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


class DatabaseManager(QThread):
    update_started  = pyqtSignal()
    update_output   = pyqtSignal(str)
    update_finished = pyqtSignal(bool, str)
    info_loaded     = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._action = "info"

    def load_info(self):
        self._action = "info"
        self.start()

    def run_update(self):
        self._action = "update"
        self.update_started.emit()
        self.start()

    def run(self):
        if self._action == "info":
            self.info_loaded.emit(self._fetch_info())
        elif self._action == "update":
            self._do_update()

    # ── Info ──────────────────────────────────────────────────

    def _fetch_info(self) -> DatabaseInfo:
        info = DatabaseInfo()
        try:
            r = subprocess.run(["clamscan", "--version"],
                               capture_output=True, text=True, timeout=10)
            info.clamav_version = r.stdout.strip().split("\n")[0]
        except Exception:
            pass

        for db_dir in ["/var/lib/clamav", "/usr/local/share/clamav", "/usr/share/clamav"]:
            if os.path.isdir(db_dir):
                info.db_path = db_dir
                self._parse_db_dir(db_dir, info)
                break
        return info

    def _parse_db_dir(self, db_dir: str, info: DatabaseInfo):
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
                for line in r.stdout.splitlines():
                    if line.startswith("Version:"):
                        setattr(info, ver_attr, line.split(":", 1)[1].strip())
                    if date_attr and line.startswith("Build time:"):
                        try:
                            dt = datetime.strptime(
                                line.split(":", 1)[1].strip(), "%d %b %Y %H-%M-%S %z"
                            )
                            setattr(info, date_attr, dt.replace(tzinfo=None))
                        except Exception:
                            pass
            except Exception:
                try:
                    if date_attr:
                        setattr(info, date_attr,
                                datetime.fromtimestamp(os.path.getmtime(fpath)))
                    setattr(info, ver_attr, f"~{os.path.getsize(fpath)//1024} KB")
                except Exception:
                    pass

    # ── Update ────────────────────────────────────────────────

    def _do_update(self):
        freshclam = shutil.which("freshclam")
        if not freshclam:
            self.update_finished.emit(False, "freshclam not found. Install clamav.")
            return

        pkexec = shutil.which("pkexec")
        if not pkexec:
            self.update_finished.emit(
                False,
                "pkexec not found. Install polkit or run: sudo freshclam"
            )
            return

        # Build a helper script that:
        #   1. Stops clamav-freshclam service (if running) to release the log lock
        #   2. Runs freshclam once
        #   3. Restarts the service afterwards
        # All in one pkexec call → one auth dialog only.
        script = (
            "#!/bin/sh\n"
            "systemctl stop clamav-freshclam 2>/dev/null || true\n"
            f"{freshclam} --verbose --stdout\n"
            "RET=$?\n"
            "systemctl start clamav-freshclam 2>/dev/null || true\n"
            "exit $RET\n"
        )
        script_path = "/tmp/qlam_update_helper.sh"
        with open(script_path, "w") as f:
            f.write(script)
        os.chmod(script_path, 0o755)

        try:
            proc = subprocess.Popen(
                [pkexec, "/bin/sh", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.update_output.emit(line)
            proc.wait(timeout=300)

            if proc.returncode == 0:
                self.update_finished.emit(True, "Database updated successfully.")
            elif proc.returncode == 40:
                self.update_finished.emit(True, "Database is already up to date.")
            elif proc.returncode == 126:
                self.update_finished.emit(False, "Authentication cancelled.")
            elif proc.returncode == 127:
                self.update_finished.emit(False, "freshclam not found.")
            else:
                self.update_finished.emit(
                    False, f"Update failed (exit code {proc.returncode})."
                )

        except subprocess.TimeoutExpired:
            self.update_finished.emit(False, "Update timed out after 5 minutes.")
        except Exception as e:
            self.update_finished.emit(False, str(e))
        finally:
            try:
                os.remove(script_path)
            except OSError:
                pass

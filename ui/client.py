"""D-Bus client for qlamd (org.maze.Qlam1).

The GUI does no scanning of its own: everything goes through the daemon,
which runs as root and keeps protecting the system whether or not this
window is open. Complex replies are JSON strings.

Calls that may show a polkit password prompt (scans, quarantine actions,
settings) are made asynchronously so the window never freezes while the
user types their password.
"""
from __future__ import annotations

import json
import os

from PyQt6.QtCore import QMetaType, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtDBus import (
    QDBusArgument, QDBusConnection, QDBusInterface, QDBusMessage,
    QDBusPendingCallWatcher, QDBusPendingReply, QDBusServiceWatcher, QDBusUnixFileDescriptor,
)

SERVICE = "org.maze.Qlam1"
PATH = "/org/maze/Qlam1"
IFACE = "org.maze.Qlam1"

# Long enough for a polkit prompt the user takes their time with.
_AUTH_TIMEOUT_MS = 5 * 60 * 1000


def _u32(n: int) -> QDBusArgument:
    return QDBusArgument(int(n), QMetaType.Type.UInt.value)


def _strlist(items: list[str]) -> QDBusArgument:
    return QDBusArgument(list(items), QMetaType.Type.QStringList.value)


class QlamClient(QObject):
    """Thin wrapper around the daemon's API with Qt signals for its events."""

    connected_changed = pyqtSignal(bool)
    status_changed = pyqtSignal(dict)
    threat = pyqtSignal(dict)                 # an event for this user
    scan_progress = pyqtSignal(str, int, int)  # id, files, detections
    scan_finished = pyqtSignal(dict)           # scan record

    def __init__(self, session_bus: bool = False, parent=None):
        super().__init__(parent)
        self.uid = os.getuid()
        self.bus = QDBusConnection.sessionBus() if session_bus else QDBusConnection.systemBus()
        self.iface = QDBusInterface(SERVICE, PATH, IFACE, self.bus, self)
        self.iface.setTimeout(20_000)
        self._watchers: set[QDBusPendingCallWatcher] = set()
        self.status: dict = {}
        self.connected = False
        # Scan ids started by (or visible to) this user; progress signals for
        # anyone else's scans are ignored.
        self.my_scans: set[str] = set()

        for name, slot in (
            ("StatusChanged", self._on_status_signal),
            ("ThreatDetected", self._on_threat_signal),
            ("ScanProgress", self._on_progress_signal),
            ("ScanFinished", self._on_finished_signal),
        ):
            self.bus.connect(SERVICE, PATH, IFACE, name, slot)

        self._svc = QDBusServiceWatcher(
            SERVICE, self.bus, QDBusServiceWatcher.WatchModeFlag.WatchForOwnerChange, self)
        self._svc.serviceOwnerChanged.connect(lambda *_: self.refresh_status())

    # ── Calls ─────────────────────────────────────────────────────────────

    def _call(self, method: str, *args):
        """Synchronous call for quick reads. Returns (ok, value | error)."""
        reply = self.iface.call(method, *args)
        if reply.type() == QDBusMessage.MessageType.ErrorMessage:
            return False, reply.errorMessage()
        out = reply.arguments()
        return True, (out[0] if out else None)

    def _call_async(self, method: str, *args, done=None, fail=None):
        """Asynchronous call; `done(value)` or `fail(message)` on completion."""
        msg = QDBusMessage.createMethodCall(SERVICE, PATH, IFACE, method)
        msg.setArguments(list(args))
        pending = self.bus.asyncCall(msg, _AUTH_TIMEOUT_MS)
        watcher = QDBusPendingCallWatcher(pending, self)
        self._watchers.add(watcher)

        def finished(w: QDBusPendingCallWatcher):
            self._watchers.discard(w)
            w.deleteLater()
            reply = QDBusPendingReply(w).reply()
            if reply.type() == QDBusMessage.MessageType.ErrorMessage:
                if fail:
                    fail(_friendly(reply.errorName(), reply.errorMessage()))
            elif done:
                out = reply.arguments()
                done(out[0] if out else None)

        watcher.finished.connect(finished)

    def _json(self, method: str, *args, default=None):
        ok, value = self._call(method, *args)
        self._set_connected(ok)
        if not ok or not isinstance(value, str):
            return default
        try:
            return json.loads(value)
        except ValueError:
            return default

    def _set_connected(self, ok: bool):
        if ok != self.connected:
            self.connected = ok
            self.connected_changed.emit(ok)

    def refresh_status(self) -> dict:
        status = self._json("Status", default={}) or {}
        self.status = status
        self.my_scans.update((status.get("user") or {}).get("running_scans") or [])
        self.status_changed.emit(status)
        return status

    def events(self, limit: int = 200) -> list[dict]:
        return self._json("Events", _u32(limit), default=[]) or []

    def scans(self, limit: int = 50) -> list[dict]:
        return self._json("Scans", _u32(limit), default=[]) or []

    def quarantine(self) -> list[dict]:
        return self._json("Quarantine", default=[]) or []

    def start_scan(self, kind: str, paths: list[str] | None = None, done=None, fail=None):
        def started(scan_id):
            self.my_scans.add(str(scan_id))
            if done:
                done(scan_id)
        self._call_async("StartScan", kind, _strlist(paths or []), done=started, fail=fail)

    def cancel_scan(self, scan_id: str):
        self._call_async("CancelScan", scan_id)

    def quarantine_event(self, event_id: int, done=None, fail=None):
        self._call_async("QuarantineEvent", str(event_id), done=done, fail=fail)

    def trust_event(self, event_id: int, done=None, fail=None):
        self._call_async("TrustEvent", str(event_id), done=done, fail=fail)

    def delete_quarantine(self, qid: str, done=None, fail=None):
        self._call_async("DeleteQuarantine", qid, done=done, fail=fail)

    def restore_quarantine(self, qid: str, dest: str, done=None, fail=None):
        """Restore into `dest`, which is opened here with the user's own
        permissions — the daemon never writes into user paths as root."""
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            if fail:
                fail(f"{dest} already exists. Choose another location.")
            return
        except OSError as e:
            if fail:
                fail(f"Cannot create {dest}: {e.strerror}")
            return
        arg = QDBusUnixFileDescriptor(fd)
        os.close(fd)  # the QDBusUnixFileDescriptor holds its own duplicate

        def failed(msg):
            try:
                if os.path.getsize(dest) == 0:
                    os.unlink(dest)
            except OSError:
                pass
            if fail:
                fail(msg)

        self._call_async("RestoreQuarantine", qid, arg, done=done, fail=failed)

    def set_option(self, name: str, value: bool, done=None, fail=None):
        self._call_async("SetOption", name, bool(value), done=done, fail=fail)

    def update_signatures(self, done=None, fail=None):
        self._call_async("UpdateSignatures", done=done, fail=fail)

    # ── Signals from the daemon ───────────────────────────────────────────

    @pyqtSlot(QDBusMessage)
    def _on_status_signal(self, _msg: QDBusMessage):
        self.refresh_status()

    @pyqtSlot(QDBusMessage)
    def _on_threat_signal(self, msg: QDBusMessage):
        args = msg.arguments()
        if len(args) < 2:
            return
        event_id, uid = int(args[0]), int(args[1])
        # Signals reach every process on the bus; only look at our own.
        if uid != self.uid and self.uid != 0:
            return
        for ev in self.events(50):
            if ev.get("id") == event_id:
                self.threat.emit(ev)
                break
        self.refresh_status()

    @pyqtSlot(QDBusMessage)
    def _on_progress_signal(self, msg: QDBusMessage):
        args = msg.arguments()
        if len(args) >= 3 and str(args[0]) in self.my_scans:
            self.scan_progress.emit(str(args[0]), int(args[1]), int(args[2]))

    @pyqtSlot(QDBusMessage)
    def _on_finished_signal(self, msg: QDBusMessage):
        args = msg.arguments()
        if not args:
            return
        scan_id = str(args[0])
        if scan_id not in self.my_scans:
            return
        self.my_scans.discard(scan_id)
        for rec in self.scans(20):
            if rec.get("id") == scan_id:
                self.scan_finished.emit(rec)
                break
        self.refresh_status()


def _friendly(name: str, message: str) -> str:
    if name.endswith("AccessDenied") or "not authorized" in message:
        return "Permission was not granted."
    if name.endswith("ServiceUnknown") or name.endswith("NoReply"):
        return "The Qlam service is not running. Start it with: sudo systemctl enable --now qlamd"
    return message.removeprefix("Call failed: ")

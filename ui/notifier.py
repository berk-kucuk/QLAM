"""Desktop notifications with action buttons (org.freedesktop.Notifications).

Qt's tray balloon has no buttons; a warning is only useful if the user can act
on it right there, so this talks to the notification server directly and
falls back to the tray balloon when there is none.
"""
from __future__ import annotations

from PyQt6.QtCore import QMetaType, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtDBus import QDBusArgument, QDBusConnection, QDBusInterface, QDBusMessage

_SVC = "org.freedesktop.Notifications"
_PATH = "/org/freedesktop/Notifications"


class Notifier(QObject):
    # (event_id, action key) — action key is one of the ids passed to notify()
    action = pyqtSignal(int, str)

    def __init__(self, fallback=None, parent=None):
        super().__init__(parent)
        self._fallback = fallback  # callable(title, body, critical)
        self._bus = QDBusConnection.sessionBus()
        self._iface = QDBusInterface(_SVC, _PATH, _SVC, self._bus, self)
        self._by_notification: dict[int, int] = {}
        self._bus.connect(_SVC, _PATH, _SVC, "ActionInvoked", self._on_action)
        self._bus.connect(_SVC, _PATH, _SVC, "NotificationClosed", self._on_closed)

    def notify(self, event_id: int, title: str, body: str,
               actions: list[tuple[str, str]], critical: bool = False) -> None:
        flat: list[str] = []
        for key, label in actions:
            flat += [key, label]
        hints = {
            "urgency": QDBusArgument(2 if critical else 1, QMetaType.Type.UChar.value),
            "desktop-entry": "qlam",
        }
        reply = self._iface.call(
            "Notify",
            "Qlam",
            QDBusArgument(0, QMetaType.Type.UInt.value),
            "qlam",
            title,
            body,
            QDBusArgument(flat, QMetaType.Type.QStringList.value),
            hints,
            0 if critical else 15000,  # critical warnings stay until dismissed
        )
        if reply.type() == QDBusMessage.MessageType.ErrorMessage or not reply.arguments():
            if self._fallback:
                self._fallback(title, body, critical)
            return
        self._by_notification[int(reply.arguments()[0])] = event_id

    @pyqtSlot(QDBusMessage)
    def _on_action(self, msg: QDBusMessage):
        args = msg.arguments()
        if len(args) < 2:
            return
        nid, key = int(args[0]), str(args[1])
        event_id = self._by_notification.pop(nid, None)
        if event_id is not None:
            self.action.emit(event_id, key)

    @pyqtSlot(QDBusMessage)
    def _on_closed(self, msg: QDBusMessage):
        args = msg.arguments()
        if args:
            self._by_notification.pop(int(args[0]), None)

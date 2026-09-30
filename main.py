#!/usr/bin/env python3
"""Qlam — desktop client for the qlamd antivirus service.

    qlam            open the window
    qlam --tray     start in the tray (used at login) to show warnings
    qlam --session  talk to a development qlamd on the session bus
"""
import os
import sys
import traceback
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtClassInfo, pyqtSlot
from PyQt6.QtDBus import QDBusConnection, QDBusInterface
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox

from ui.theme import get_stylesheet, theme

BASE_DIR = Path(__file__).resolve().parent
LOGOS_DIR = BASE_DIR / "Logos"
RESOURCES_DIR = BASE_DIR / "resources"

_GUI_SERVICE = "org.maze.QlamGui"


@pyqtClassInfo("D-Bus Interface", _GUI_SERVICE)
class _Instance(QObject):
    """Lets a second `qlam` launch bring up the running one instead of
    starting another tray icon."""

    def __init__(self, window):
        super().__init__(window)
        self._window = window

    @pyqtSlot()
    def Show(self):
        self._window.show_window()


def _report_exception(exc_type, exc, tb):
    """PyQt6 aborts the whole app (qFatal) on an exception escaping a slot
    unless sys.excepthook is replaced. A bug in one button must not take the
    window down: log it, tell the user, carry on."""
    traceback.print_exception(exc_type, exc, tb)
    app = QApplication.instance()
    if app is not None and not issubclass(exc_type, KeyboardInterrupt):
        QMessageBox.warning(None, "Qlam", f"Something went wrong: {exc}\n\nDetails are in the log.")


def main():
    sys.excepthook = _report_exception
    os.environ.setdefault("RESOURCE_NAME", "qlam")
    tray_only = "--tray" in sys.argv
    session_bus = "--session" in sys.argv

    app = QApplication(sys.argv)
    app.setApplicationName("Qlam")
    app.setApplicationDisplayName("Qlam")
    app.setOrganizationName("Qlam")
    app.setDesktopFileName("qlam")
    app.setQuitOnLastWindowClosed(False)

    bus = QDBusConnection.sessionBus()
    if not bus.registerService(_GUI_SERVICE):
        if not tray_only:
            QDBusInterface(_GUI_SERVICE, "/", _GUI_SERVICE, bus).call("Show")
        return 0

    logo = LOGOS_DIR / "qlam.png"
    if logo.exists():
        app.setWindowIcon(QIcon(str(logo)))
    font = QFont("Inter", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)
    app.setStyleSheet(get_stylesheet(theme.name, RESOURCES_DIR))
    theme.changed.connect(lambda _p: app.setStyleSheet(get_stylesheet(theme.name, RESOURCES_DIR)))

    from ui.main_window import MainWindow
    window = MainWindow(session_bus=session_bus)
    instance = _Instance(window)
    bus.registerObject("/", instance, QDBusConnection.RegisterOption.ExportAllSlots)
    if not tray_only or window.tray is None:
        window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
import sys
import os
from pathlib import Path

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon

from ui.main_window import MainWindow
from ui.theme import theme, get_stylesheet

BASE_DIR = Path(__file__).parent
LOGOS_DIR = BASE_DIR / "Logos"
RESOURCES_DIR = BASE_DIR / "resources"


def main():
    os.environ.setdefault("QT_QPA_PLATFORM", "xcb")
    # Force the X11 WM_CLASS instance name (res_name) to "qlam". Without
    # this Qt derives it from argv[0] ("main.py"), so the dock/taskbar
    # can't match the window to qlam.desktop and shows a second, generic
    # icon. Must be set before QApplication is constructed.
    os.environ.setdefault("RESOURCE_NAME", "qlam")

    tray_only = "--tray" in sys.argv

    app = QApplication(sys.argv)
    app.setApplicationName("Qlam")
    app.setApplicationDisplayName("Qlam Antivirus")
    app.setOrganizationName("Qlam")
    # Ties the window to qlam.desktop so the dock/taskbar uses our own
    # icon instead of showing a second, generic one (Wayland app_id /
    # X11 WM_CLASS). Must match the .desktop basename and StartupWMClass.
    app.setDesktopFileName("qlam")
    app.setQuitOnLastWindowClosed(False)

    logo_path = LOGOS_DIR / "qlam.png"
    if logo_path.exists():
        app.setWindowIcon(QIcon(str(logo_path)))

    font = QFont("Inter", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    # Apply the current theme and re-apply on every toggle.
    app.setStyleSheet(get_stylesheet(theme.name, RESOURCES_DIR))
    theme.changed.connect(
        lambda _p: app.setStyleSheet(get_stylesheet(theme.name, RESOURCES_DIR))
    )

    window = MainWindow()
    if not tray_only:
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

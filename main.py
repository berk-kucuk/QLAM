#!/usr/bin/env python3
import sys
import os
from pathlib import Path

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon

from ui.main_window import MainWindow

BASE_DIR = Path(__file__).parent
LOGOS_DIR = BASE_DIR / "Logos"


def load_stylesheet() -> str:
    qss_path = BASE_DIR / "resources" / "style.qss"
    if not qss_path.exists():
        return ""
    with open(qss_path) as f:
        content = f.read()
    # Replace relative resource paths with absolute paths
    content = content.replace(
        "url(resources/", f"url({BASE_DIR / 'resources'}/"
    )
    return content


def main():
    os.environ.setdefault("QT_QPA_PLATFORM", "xcb")

    app = QApplication(sys.argv)
    app.setApplicationName("Qlam")
    app.setApplicationDisplayName("Qlam Antivirus")
    app.setOrganizationName("Qlam")
    app.setQuitOnLastWindowClosed(False)

    logo_path = LOGOS_DIR / "qlam.png"
    if logo_path.exists():
        app.setWindowIcon(QIcon(str(logo_path)))

    font = QFont("Inter", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    stylesheet = load_stylesheet()
    if stylesheet:
        app.setStyleSheet(stylesheet)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

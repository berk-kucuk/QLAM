"""Main window, tray icon and notifications."""
from __future__ import annotations

from pathlib import Path

import qtawesome as qta
from PyQt6.QtCore import QEvent, QSize, Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QPushButton,
    QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from ui.alerts_page import AlertsPage, is_open
from ui.client import QlamClient
from ui.notifier import Notifier
from ui.overview_page import OverviewPage
from ui.quarantine_page import QuarantinePage
from ui.scan_page import ScanPage
from ui.settings_page import SettingsPage
from ui.theme import load_prefs, save_theme, theme
from ui.titlebar import ResizeGrips, TitleBar
from ui.widgets import headline, level, short_path

_LOGOS = Path(__file__).resolve().parent.parent / "Logos"

_NAV = [
    ("overview", "fa5s.shield-alt", "Overview"),
    ("findings", "fa5s.exclamation-circle", "Findings"),
    ("scan", "fa5s.search", "Scan"),
    ("quarantine", "fa5s.lock", "Quarantine"),
    ("settings", "fa5s.cog", "Settings"),
]


class _NavButton(QPushButton):
    def __init__(self, icon: str, text: str, parent=None):
        super().__init__(parent)
        self.setObjectName("NavButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.icon_name = icon
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 12, 0)
        lay.setSpacing(12)
        self.ic = QLabel()
        self.ic.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.tx = QLabel(text)
        self.tx.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.badge = QLabel()
        self.badge.setObjectName("NavBadge")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setFixedHeight(18)
        self.badge.setMinimumWidth(18)
        self.badge.hide()
        lay.addWidget(self.ic)
        lay.addWidget(self.tx, 1)
        lay.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_active(self, on: bool):
        self.setProperty("active", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        p = theme.p
        color = p["nav_active_tx"] if on else p["text_mid"]
        self.ic.setPixmap(qta.icon(self.icon_name, color=color).pixmap(QSize(15, 15)))
        self.tx.setStyleSheet(f"color: {color}; font-weight: {600 if on else 500}; background: transparent;")

    def set_badge(self, n: int):
        self.badge.setText(str(n) if n < 100 else "99+")
        self.badge.setVisible(n > 0)


class MainWindow(QMainWindow):
    def __init__(self, session_bus: bool = False):
        super().__init__()
        self.setWindowTitle("Qlam")
        # Qlam draws its own title bar (ui/titlebar.py) instead of the window
        # manager's, so it looks the same on every desktop.
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setMinimumSize(1000, 660)
        self.resize(1180, 760)

        self.client = QlamClient(session_bus, self)
        self._events: list[dict] = []
        self._build()
        self._setup_tray()
        self.notifier = Notifier(fallback=self._tray_message, parent=self)
        self.notifier.action.connect(self._notification_action)

        c = self.client
        c.status_changed.connect(self._on_status)
        c.connected_changed.connect(lambda _ok: self._on_status(c.status))
        c.threat.connect(self._on_threat)
        c.scan_finished.connect(lambda _r: self.refresh_lists())
        theme.changed.connect(lambda _p: self._retint())

        self._nav_to("overview")
        c.refresh_status()
        self.refresh_lists()
        # Signals cover changes; this only catches a daemon restart or a
        # missed signal, so it can be slow.
        self._poll = QTimer(self)
        self._poll.timeout.connect(self._periodic)
        self._poll.start(60_000)

    # ── Layout ────────────────────────────────────────────────────────────

    def _build(self):
        frame = QWidget()
        frame.setObjectName("WindowFrame")
        self.setCentralWidget(frame)
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(1, 1, 1, 1)  # room for the 1px window border
        outer.setSpacing(0)
        self.titlebar = TitleBar(self)
        self.titlebar.theme_toggled.connect(self._toggle_theme)
        outer.addWidget(self.titlebar)
        body = QWidget()
        outer.addWidget(body, 1)
        lay = QHBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        side = QWidget()
        side.setObjectName("Sidebar")
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 18, 14, 16)
        sl.setSpacing(4)

        self.nav: dict[str, _NavButton] = {}
        for key, icon, text in _NAV:
            b = _NavButton(icon, text)
            b.clicked.connect(lambda _c=False, k=key: self._nav_to(k))
            self.nav[key] = b
            sl.addWidget(b)
        sl.addStretch(1)
        self.footer = QLabel()
        self.footer.setObjectName("AppVersion")
        self.footer.setWordWrap(True)
        sl.addWidget(self.footer)
        lay.addWidget(side)

        self.stack = QStackedWidget()
        self.stack.setObjectName("ContentArea")
        self.overview = OverviewPage()
        self.findings = AlertsPage(self.client)
        self.scan = ScanPage(self.client)
        self.quarantine = QuarantinePage(self.client)
        self.settings = SettingsPage(self.client)
        self.pages = {
            "overview": self.overview, "findings": self.findings, "scan": self.scan,
            "quarantine": self.quarantine, "settings": self.settings,
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        lay.addWidget(self.stack, 1)

        o = self.overview
        o.go_alerts.connect(lambda: self._nav_to("findings"))
        o.go_scan.connect(lambda: self._nav_to("scan"))
        o.go_settings.connect(lambda: self._nav_to("settings"))
        o.quick_scan.connect(self.quick_scan)
        o.update_signatures.connect(self._update_signatures)
        self.scan.show_findings.connect(lambda: self._nav_to("findings"))
        self.findings.changed.connect(self._after_decision)
        self.quarantine.changed.connect(self._after_decision)
        self._frame = frame
        self._grips = ResizeGrips(self)
        self._retint()

    # ── Window chrome ─────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._grips.place()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            # A maximized window has no border and can't be resized.
            maximized = self.isMaximized() or self.isFullScreen()
            # ("maximized" itself is a read-only QWidget property.)
            self._frame.setProperty("winstate", "max" if maximized else "normal")
            self._frame.style().unpolish(self._frame)
            self._frame.style().polish(self._frame)
            self._frame.layout().setContentsMargins(*([0] * 4 if maximized else [1] * 4))
            self._grips.place()
            self.titlebar.retint()

    def _toggle_theme(self):
        theme.toggle()
        save_theme(theme.name)
        self.settings.sync_theme()

    def _retint(self):
        for k, b in self.nav.items():
            b.set_active(self.stack.currentWidget() is self.pages.get(k))

    def _nav_to(self, key: str):
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        for k, b in self.nav.items():
            b.set_active(k == key)
        if key == "quarantine":
            self.quarantine.refresh()
        elif key == "scan":
            self.scan.refresh()
        elif key == "findings":
            self.refresh_lists()

    # ── Data ──────────────────────────────────────────────────────────────

    def refresh_lists(self):
        self._events = self.client.events(300)
        self.overview.set_events(self._events)
        self.findings.set_events(self._events)
        self.nav["findings"].set_badge(self.findings.open_count())

    def _periodic(self):
        self.client.refresh_status()
        if self.isVisible():
            self.refresh_lists()

    def _after_decision(self):
        self.client.refresh_status()
        self.refresh_lists()
        if self.stack.currentWidget() is self.quarantine:
            self.quarantine.refresh()

    def _on_status(self, st: dict):
        ok = self.client.connected
        self.overview.set_status(st, ok)
        self.settings.set_status(st if ok else {})
        rt = st.get("realtime", {}) if ok else {}
        open_n = int(st.get("user", {}).get("open_findings", 0)) if ok else 0
        if not ok:
            self.titlebar.set_status("Service not running", "warn")
        elif open_n:
            self.titlebar.set_status(f"{open_n} to review", "bad")
        elif rt.get("active"):
            self.titlebar.set_status("Protected", "good")
        else:
            self.titlebar.set_status("Real-time protection off", "warn")
        if not ok:
            self.footer.setText("Service not running")
        elif rt.get("active"):
            self.footer.setText(f"Real-time protection on\nQlam {st.get('version', '')}")
        else:
            self.footer.setText(f"Real-time protection off\nQlam {st.get('version', '')}")
        self._update_tray(st, ok)

    # ── Actions ───────────────────────────────────────────────────────────

    def quick_scan(self):
        self._nav_to("scan")
        self.show_window()
        self.scan.start("quick")

    def _update_signatures(self):
        self.client.update_signatures(fail=lambda m: QMessageBox.warning(self, "Qlam", m))

    def show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def show_finding(self, event_id: int):
        self.show_window()
        self._nav_to("findings")
        self.findings.select_event(event_id)

    # ── Notifications ─────────────────────────────────────────────────────

    def _on_threat(self, ev: dict):
        self.refresh_lists()
        kind, lvl = ev.get("kind"), level(ev)
        if kind == "safety-pause":
            self.notifier.notify(ev["id"], "Qlam paused automatic blocking", ev.get("action", ""), [], True)
            return
        if ev.get("resolution") and kind != "quarantined":
            return
        if lvl == "notice" and not load_prefs().get("notify_notices", False):
            return
        where = short_path(ev.get("path", ""), 70)
        if kind == "quarantined":
            self.notifier.notify(ev["id"], "Qlam moved known malware to quarantine",
                                 f"{ev.get('detection')}\n{where}", [("default", "Details")], False)
            return
        body = f"{ev.get('detection')}\n{where}\nNothing has been changed. Choose what to do."
        actions = [("default", "Details")]
        if ev.get("sha256") and is_open(ev):
            actions.insert(0, ("quarantine", "Move to quarantine"))
        self.notifier.notify(ev["id"], f"Qlam: {headline(ev)}", body, actions, lvl == "danger")

    def _notification_action(self, event_id: int, key: str):
        if key == "quarantine":
            self.client.quarantine_event(
                event_id, done=lambda _r: self._after_decision(),
                fail=lambda m: (self.show_finding(event_id), QMessageBox.warning(self, "Qlam", m)))
        else:
            self.show_finding(event_id)

    def _tray_message(self, title: str, body: str, critical: bool):
        if self.tray:
            icon = QSystemTrayIcon.MessageIcon.Critical if critical else QSystemTrayIcon.MessageIcon.Warning
            self.tray.showMessage(title, body, icon, 10000)

    # ── Tray ──────────────────────────────────────────────────────────────

    def _setup_tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self._app_icon())
        self.tray.setToolTip("Qlam")
        menu = QMenu()
        menu.addAction("Open Qlam", self.show_window)
        menu.addAction("Quick scan", self.quick_scan)
        menu.addSeparator()
        menu.addAction("Quit", QApplication.instance().quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda r: self.show_window() if r == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def _app_icon(self) -> QIcon:
        p = _LOGOS / "qlam.png"
        return QIcon(str(p)) if p.exists() else qta.icon("fa5s.shield-alt")

    def _update_tray(self, st: dict, ok: bool):
        if not self.tray:
            return
        open_n = int(st.get("user", {}).get("open_findings", 0)) if ok else 0
        rt_on = ok and st.get("realtime", {}).get("active")
        if not ok:
            tip = "Qlam: service not running"
        elif open_n:
            tip = f"Qlam: {open_n} finding(s) to review"
        elif rt_on:
            tip = "Qlam: protected"
        else:
            tip = "Qlam: real-time protection off"
        self.tray.setToolTip(tip)
        if open_n:
            self.tray.setIcon(qta.icon("fa5s.exclamation-triangle", color=theme.p["bad"]))
        else:
            self.tray.setIcon(self._app_icon())

    def closeEvent(self, event):
        # With a tray the app keeps running to show warnings; protection
        # itself lives in the daemon and never depended on this window.
        if self.tray and self.tray.isVisible():
            event.ignore()
            self.hide()
        else:
            event.accept()
            QApplication.instance().quit()

from pathlib import Path

import qtawesome as qta
from PyQt6.QtCore import Qt, QTimer, QSize, QTime
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame, QSizeGrip,
    QSystemTrayIcon, QMenu, QApplication, QMessageBox,
)

_BASE = Path(__file__).parent.parent
_LOGOS = _BASE / "Logos"

from core.scan_engine import ScanEngine
from core.database_manager import DatabaseManager
from core.quarantine_manager import QuarantineManager
from core.history_manager import HistoryManager
from core.realtime_protection import RealtimeProtection

from ui.dashboard_page import DashboardPage
from ui.scan_page import ScanPage
from ui.quarantine_page import QuarantinePage
from ui.history_page import HistoryPage
from ui.settings_page import SettingsPage
from ui.theme import theme, save_theme


class _TitleBar(QWidget):
    """Draggable custom title bar. Uses startSystemMove() for Wayland/X11."""

    def __init__(self, window: QMainWindow):
        super().__init__(window)
        self._window = window
        self.setObjectName("TitleBar")
        self.setFixedHeight(48)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self._window.windowHandle()
            if handle:
                handle.startSystemMove()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._window._toggle_maximize()
        super().mouseDoubleClickEvent(event)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Qlam — Antivirus")
        self.setMinimumSize(1080, 700)
        self.resize(1200, 780)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)

        # Core components
        self._scan_engine = ScanEngine(self)
        self._db_manager = DatabaseManager(self)
        self._quarantine_mgr = QuarantineManager()
        self._history_mgr = HistoryManager()

        self._current_scan_type = "quick"
        self._current_targets: list[str] = []

        self._build_ui()
        self._connect_signals()
        self._setup_tray()
        self._init_data()

        theme.changed.connect(self._apply_theme)
        self._apply_theme(theme.p)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_titlebar())

        body = QWidget()
        layout = QHBoxLayout(body)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())

        self._stack = QStackedWidget()
        self._stack.setObjectName("ContentArea")
        layout.addWidget(self._stack)
        outer.addWidget(body, 1)

        # Pages
        self._dashboard = DashboardPage()
        self._scan_page = ScanPage()
        self._quarantine_page = QuarantinePage(self._quarantine_mgr)
        self._history_page = HistoryPage(self._history_mgr)
        self._settings_page = SettingsPage(self._db_manager)

        for page in (self._dashboard, self._scan_page, self._quarantine_page,
                     self._history_page, self._settings_page):
            self._stack.addWidget(page)

        self._realtime = RealtimeProtection(self._scan_engine, self)
        self._nav_to(0)

        # A discreet resize grip in the bottom-right corner (frameless window).
        self._grip = QSizeGrip(central)
        self._grip.setFixedSize(16, 16)

        # Timer for time-based scheduled scans (checks every minute)
        self._sched_timer = QTimer(self)
        self._sched_timer.timeout.connect(self._check_scheduled_scan)
        self._sched_timer.start(60_000)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_grip"):
            self._grip.move(self.width() - self._grip.width() - 2,
                            self.height() - self._grip.height() - 2)

    def _build_titlebar(self) -> _TitleBar:
        bar = _TitleBar(self)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 0, 0)
        lay.setSpacing(12)

        # Brand — horizontal logo, tinted to the theme's text colour so it
        # stays legible on both dark and light backgrounds (text fallback).
        self._brand = QLabel()
        self._brand_src = QPixmap(str(_LOGOS / "qlam_transparent_hortizental.png"))
        if self._brand_src.isNull():
            self._brand.setText("QLAM")
            self._brand.setObjectName("BrandName")
        lay.addWidget(self._brand)

        lay.addStretch()

        # Global protection status pill
        self._status_pill = QLabel("Checking…")
        self._status_pill.setObjectName("StatusPill")
        lay.addWidget(self._status_pill)

        lay.addStretch()

        # Theme toggle
        self._theme_btn = QPushButton()
        self._theme_btn.setObjectName("IconToggle")
        self._theme_btn.setToolTip("Toggle light / dark theme")
        self._theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._theme_btn.clicked.connect(self._toggle_theme)
        lay.addWidget(self._theme_btn)

        lay.addSpacing(6)

        # Window controls
        self._min_btn = QPushButton("─")
        self._min_btn.setObjectName("WinBtn")
        self._min_btn.setToolTip("Minimize")
        self._min_btn.clicked.connect(self.showMinimized)
        lay.addWidget(self._min_btn)

        self._max_btn = QPushButton("□")
        self._max_btn.setObjectName("WinBtn")
        self._max_btn.setToolTip("Maximize / Restore")
        self._max_btn.clicked.connect(self._toggle_maximize)
        lay.addWidget(self._max_btn)

        self._close_btn = QPushButton("✕")
        self._close_btn.setObjectName("WinClose")
        self._close_btn.setToolTip("Minimize to tray")
        self._close_btn.clicked.connect(self.hide)
        lay.addWidget(self._close_btn)

        return bar

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(12, 18, 12, 18)
        lay.setSpacing(2)

        heading = QLabel("MENU")
        heading.setObjectName("NavHeading")
        heading.setContentsMargins(8, 0, 0, 6)
        lay.addWidget(heading)

        # Navigation buttons
        self._nav_buttons: list[QPushButton] = []
        pages = [
            ("fa5s.home",       "Dashboard",  0),
            ("fa5s.search",     "Scan",       1),
            ("fa5s.lock",       "Quarantine", 2),
            ("fa5s.history",    "History",    3),
            ("fa5s.cog",        "Settings",   4),
        ]
        for icon_name, label, index in pages:
            btn = QPushButton(f"   {label}")
            btn.setObjectName("NavButton")
            btn.setProperty("active", "false")
            btn.setIconSize(QSize(16, 16))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, i=index: self._nav_to(i))
            self._nav_buttons.append(btn)
            lay.addWidget(btn)
        self._nav_icon_names = [p[0] for p in pages]

        lay.addStretch()

        # Bottom status block
        sep = QFrame()
        sep.setObjectName("SidebarSep")
        sep.setFixedHeight(1)
        lay.addWidget(sep)
        lay.addSpacing(12)

        self._rt_status_label = QLabel()
        self._rt_status_label.setWordWrap(True)
        lay.addWidget(self._rt_status_label)
        lay.addSpacing(4)

        self._db_status_label = QLabel("DB: checking…")
        lay.addWidget(self._db_status_label)
        lay.addSpacing(8)

        ver = QLabel("ClamAV powered · v1.2.1")
        ver.setObjectName("AppVersion")
        lay.addWidget(ver)

        self._rt_active = False
        return sidebar

    # ── Theme ─────────────────────────────────────────────────────────────

    def _toggle_theme(self):
        theme.toggle()
        save_theme(theme.name)

    def _tint_brand(self):
        """Recolour the (single-colour) logo to the current text colour,
        preserving its alpha, so it reads on either background."""
        if self._brand_src.isNull():
            return
        src = self._brand_src.scaledToHeight(
            22, Qt.TransformationMode.SmoothTransformation)
        tinted = QPixmap(src.size())
        tinted.fill(Qt.GlobalColor.transparent)
        painter = QPainter(tinted)
        painter.drawPixmap(0, 0, src)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        painter.fillRect(tinted.rect(), QColor(theme.p["text"]))
        painter.end()
        self._brand.setPixmap(tinted)

    def _apply_theme(self, p: dict):
        """Re-apply Python-painted colours (nav icons, status labels, pill,
        theme button) after a stylesheet swap."""
        self._tint_brand()
        self._theme_btn.setIcon(
            qta.icon("fa5s.sun" if theme.name == "dark" else "fa5s.moon",
                     color=p["text_mid"])
        )
        self._refresh_nav_icons()
        self._set_rt_label(self._rt_active)
        self._refresh_db_label()
        self._update_status_pill()

    def _refresh_nav_icons(self):
        p = theme.p
        current = self._stack.currentIndex()
        for i, btn in enumerate(self._nav_buttons):
            active = i == current
            color = p["nav_active_tx"] if active else p["text_mid"]
            btn.setIcon(qta.icon(self._nav_icon_names[i], color=color))

    def _set_rt_label(self, active: bool):
        p = theme.p
        color = p["good"] if active else p["text_dim"]
        state = "on" if active else "off"
        self._rt_status_label.setText(f"⬤  Real-time: {state}")
        self._rt_status_label.setStyleSheet(
            f"font-size: 11px; color: {color}; padding: 0 4px;")

    def _refresh_db_label(self):
        p = theme.p
        text, color = getattr(self, "_db_state", ("DB: checking…", p["text_dim"]))
        # Re-resolve colour from semantic role so it tracks the theme.
        if "outdated" in text:
            color = p["warn"]
        elif "up to date" in text:
            color = p["text_mid"]
        else:
            color = p["text_dim"]
        self._db_status_label.setText(text)
        self._db_status_label.setStyleSheet(
            f"font-size: 11px; color: {color}; padding: 0 4px;")

    def _update_status_pill(self):
        p = theme.p
        if self._rt_active:
            self._status_pill.setText("●  Protected")
            self._status_pill.setStyleSheet(
                f"background-color: {p['good_soft']}; border: 1px solid {p['good_border']};"
                f" border-radius: 13px; padding: 4px 14px; font-size: 12px;"
                f" font-weight: 600; color: {p['good']};")
        else:
            self._status_pill.setText("●  Real-time off")
            self._status_pill.setStyleSheet(
                f"background-color: {p['surface']}; border: 1px solid {p['border']};"
                f" border-radius: 13px; padding: 4px 14px; font-size: 12px;"
                f" font-weight: 600; color: {p['text_mid']};")

    # ── Signal connections ────────────────────────────────────────────────

    def _connect_signals(self):
        self._dashboard.quick_scan_requested.connect(
            lambda: self._start_scan_from_dashboard("quick"))
        self._dashboard.full_scan_requested.connect(
            lambda: self._start_scan_from_dashboard("full"))
        self._dashboard.update_requested.connect(self._run_update)
        self._dashboard.realtime_toggled.connect(self._on_dashboard_rt_toggle)

        self._scan_page.scan_requested.connect(self._on_scan_requested)
        self._scan_page.abort_requested.connect(self._scan_engine.abort)

        self._scan_engine.file_scanned.connect(self._on_file_scanned)
        self._scan_engine.scan_progress.connect(self._on_scan_progress)
        self._scan_engine.scan_finished.connect(self._on_scan_finished)

        self._db_manager.info_loaded.connect(self._on_db_info)
        # After a successful signature update, reload the DB info so the
        # dashboard badge / sidebar status reflect the new version.
        self._db_manager.update_finished.connect(self._on_db_update_finished)

        self._settings_page.settings_changed.connect(self._on_settings_changed)

        self._realtime.threat_detected.connect(self._on_rt_threat)
        self._realtime.status_changed.connect(self._on_rt_status)

    # ── Tray ──────────────────────────────────────────────────────────────

    def _setup_tray(self):
        self._tray = QSystemTrayIcon(self)
        logo = _LOGOS / "qlam.png"
        if logo.exists():
            self._tray.setIcon(QIcon(str(logo)))
        else:
            self._tray.setIcon(QIcon.fromTheme("security-high"))
        menu = QMenu()
        menu.addAction("Open Qlam", self.show)
        menu.addAction("Quick Scan", lambda: self._start_scan_from_dashboard("quick"))
        menu.addSeparator()
        menu.addAction("Quit", QApplication.quit)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self._tray.showMessage(
            "Qlam", "Running in the background. Double-click tray icon to restore.",
            QSystemTrayIcon.MessageIcon.Information, 2000
        )

    # ── Window controls ───────────────────────────────────────────────────

    def _toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            self._max_btn.setText("□")
        else:
            self.showMaximized()
            self._max_btn.setText("❐")

    # ── Data initialization ───────────────────────────────────────────────

    def _init_data(self):
        self._db_manager.load_info()
        self._refresh_dashboard_stats()
        settings = self._settings_page.get_settings()
        self._on_settings_changed(settings)

    def _refresh_dashboard_stats(self):
        last = self._history_mgr.last_scan()
        self._dashboard.update_stats(
            self._history_mgr.total_scans(),
            self._history_mgr.total_threats(),
            self._quarantine_mgr.count(),
            last.timestamp_dt if last else None,
        )

    # ── Navigation ────────────────────────────────────────────────────────

    def _nav_to(self, index: int):
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            active = i == index
            btn.setProperty("active", "true" if active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self._refresh_nav_icons()

        if index == 2:
            self._quarantine_page.refresh()
        elif index == 3:
            self._history_page.refresh()

    # ── Scan orchestration ────────────────────────────────────────────────

    def _start_scan_from_dashboard(self, scan_type: str):
        targets = (
            ScanEngine.quick_scan_paths() if scan_type == "quick"
            else ScanEngine.full_scan_paths()
        )
        self._nav_to(1)
        self._scan_page.start_with(scan_type, targets)

    def _on_scan_requested(self, scan_type: str, targets: list[str], recursive: bool):
        if self._scan_engine.isRunning():
            return
        self._current_scan_type = scan_type
        self._current_targets = targets
        self._scan_engine.start_scan(targets, recursive)

    def _on_scan_progress(self, current: int, total: int, filepath: str):
        self._scan_page.update_progress(current, total, filepath)

    def _on_file_scanned(self, path: str, infected: bool, threat: str):
        self._scan_page.on_file_scanned(path, infected, threat)
        if infected:
            settings = self._settings_page.get_settings()
            if settings.get("auto_quarantine", True):
                self._quarantine_mgr.quarantine_file(path, threat)

    def _on_scan_finished(self, stats):
        self._scan_page.finish_scan_ui(stats)
        threats = [{"path": t.path, "threat": t.threat} for t in stats.threats]
        self._history_mgr.add_record(
            self._current_scan_type, self._current_targets,
            stats.scanned_files, stats.infected_files,
            stats.duration_seconds(), threats,
        )
        self._refresh_dashboard_stats()
        self._quarantine_page.refresh()

        if stats.infected_files > 0:
            settings = self._settings_page.get_settings()
            if settings.get("notify_on_threat", True):
                self._tray.showMessage(
                    "Qlam — Threat Detected",
                    f"{stats.infected_files} threat(s) found and quarantined.",
                    QSystemTrayIcon.MessageIcon.Warning, 5000
                )

    # ── DB info ───────────────────────────────────────────────────────────

    def _on_db_info(self, db_info):
        self._dashboard.update_db_info(db_info)
        if db_info.is_outdated():
            self._db_state = ("⬤  DB: outdated", theme.p["warn"])
        else:
            self._db_state = ("⬤  DB: up to date", theme.p["text_mid"])
        self._refresh_db_label()

    def _run_update(self):
        self._nav_to(4)
        self._settings_page._run_update()

    def _on_db_update_finished(self, success: bool, message: str):
        if success:
            self._db_manager.load_info()

    # ── Real-time protection ──────────────────────────────────────────────

    def _on_dashboard_rt_toggle(self, enabled: bool):
        if enabled:
            from core.realtime_protection import DEFAULT_WATCH_PATHS
            settings = self._settings_page.get_settings()
            paths = settings.get("realtime_paths") or DEFAULT_WATCH_PATHS
            self._realtime.set_watched_paths(paths)
            self._realtime.start(paths)
        else:
            self._realtime.stop()

    def _on_rt_status(self, active: bool):
        self._rt_active = active
        self._dashboard.set_realtime_active(active)
        self._set_rt_label(active)
        self._update_status_pill()
        # Keep the Settings checkbox / persisted flag in sync with reality so
        # the two views can never disagree.
        self._settings_page.set_realtime_enabled(active)

    def _on_rt_threat(self, path: str, threat: str):
        self._tray.showMessage(
            "Qlam — Real-time Protection",
            f"Threat detected: {path}\n{threat}",
            QSystemTrayIcon.MessageIcon.Critical, 8000
        )
        self._quarantine_mgr.quarantine_file(path, threat)
        self._quarantine_page.refresh()
        self._refresh_dashboard_stats()

    # ── Settings ──────────────────────────────────────────────────────────

    def _on_settings_changed(self, settings: dict):
        self._scan_engine._max_file_size_mb = settings.get("max_file_size_mb", 100)
        self._scan_engine._scan_archives = settings.get("scan_archives", True)

        rt_enabled = settings.get("realtime_enabled", False)
        rt_paths = settings.get("realtime_paths", [])
        if rt_enabled and rt_paths:
            self._realtime.set_watched_paths(rt_paths)
            if not self._realtime.is_active():
                self._realtime.start(rt_paths)
        else:
            self._realtime.stop()

        if settings.get("scheduled_scan_enabled") and \
                settings.get("scheduled_scan_trigger") == "startup" and \
                not hasattr(self, "_startup_scan_done"):
            self._startup_scan_done = True
            scan_type = settings.get("scheduled_scan_type", "quick")
            QTimer.singleShot(10_000, lambda: self._start_scan_from_dashboard(scan_type))

    def _check_scheduled_scan(self):
        settings = self._settings_page.get_settings()
        if not settings.get("scheduled_scan_enabled"):
            return
        if settings.get("scheduled_scan_trigger") != "time":
            return
        target = settings.get("scheduled_scan_time", "02:00")
        now = QTime.currentTime()
        h, m = (int(x) for x in target.split(":"))
        if now.hour() == h and now.minute() == m:
            if not self._scan_engine.isRunning():
                scan_type = settings.get("scheduled_scan_type", "quick")
                self._start_scan_from_dashboard(scan_type)
                self._tray.showMessage(
                    "Qlam — Scheduled Scan",
                    f"Scheduled {scan_type} scan started.",
                    QSystemTrayIcon.MessageIcon.Information, 4000
                )

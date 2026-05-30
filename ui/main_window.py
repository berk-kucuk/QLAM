from pathlib import Path

import qtawesome as qta
from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame,
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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Qlam — Antivirus")
        self.setMinimumSize(1100, 700)
        self.resize(1200, 760)

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

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        layout.addWidget(sidebar)

        # Content stack
        self._stack = QStackedWidget()
        self._stack.setObjectName("ContentArea")
        layout.addWidget(self._stack)

        # Pages
        self._dashboard = DashboardPage()
        self._scan_page = ScanPage()
        self._quarantine_page = QuarantinePage(self._quarantine_mgr)
        self._history_page = HistoryPage(self._history_mgr)
        self._settings_page = SettingsPage(self._db_manager)

        self._stack.addWidget(self._dashboard)
        self._stack.addWidget(self._scan_page)
        self._stack.addWidget(self._quarantine_page)
        self._stack.addWidget(self._history_page)
        self._stack.addWidget(self._settings_page)

        self._realtime = RealtimeProtection(self._scan_engine, self)
        self._nav_to(0)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(12, 0, 12, 20)
        lay.setSpacing(2)

        # App logo area — horizontal logo image
        logo_container = QWidget()
        logo_container.setFixedHeight(72)
        logo_lay = QVBoxLayout(logo_container)
        logo_lay.setContentsMargins(12, 20, 12, 4)
        logo_lay.setSpacing(0)

        horiz_logo = _LOGOS / "qlam_transparent_hortizental.png"
        logo_label = QLabel()
        if horiz_logo.exists():
            pix = QPixmap(str(horiz_logo))
            # Scale to fit sidebar width (176px), keep aspect ratio
            pix = pix.scaledToWidth(156, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pix)
        else:
            logo_label.setText("Qlam")
            logo_label.setStyleSheet("color: #fff; font-size: 20px; font-weight: 700;")
        logo_lay.addWidget(logo_label)
        lay.addWidget(logo_container)

        ver_label = QLabel("ClamAV powered · v1.0")
        ver_label.setObjectName("AppVersion")
        lay.addWidget(ver_label)
        lay.addSpacing(12)

        # Thin separator
        sep = QFrame()
        sep.setObjectName("SidebarSep")
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a1a1a; border: none;")
        lay.addWidget(sep)
        lay.addSpacing(10)

        # Navigation buttons
        self._nav_buttons: list[QPushButton] = []
        dim = "#525252"
        pages = [
            ("fa5s.home",         "Dashboard",  0),
            ("fa5s.shield-alt",   "Scan",       1),
            ("fa5s.lock",         "Quarantine", 2),
            ("fa5s.history",      "History",    3),
            ("fa5s.cog",          "Settings",   4),
        ]
        for icon_name, label, index in pages:
            btn = QPushButton(f"  {label}")
            btn.setObjectName("NavButton")
            btn.setProperty("active", "false")
            btn.setIcon(qta.icon(icon_name, color=dim))
            btn.setIconSize(QSize(15, 15))
            btn.clicked.connect(lambda _, i=index, ic=icon_name: self._nav_to(i))
            self._nav_buttons.append(btn)
            lay.addWidget(btn)
        self._nav_icon_names = [p[0] for p in pages]

        lay.addStretch()

        # Bottom status indicators
        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #1a1a1a; border: none;")
        lay.addWidget(sep2)
        lay.addSpacing(12)

        self._rt_status_label = QLabel()
        self._rt_status_label.setWordWrap(True)
        self._rt_status_label.setStyleSheet("font-size: 11px; color: #525252; padding: 0 4px;")
        lay.addWidget(self._rt_status_label)
        self._set_rt_label(False)

        self._db_status_label = QLabel("DB: checking...")
        self._db_status_label.setStyleSheet("font-size: 11px; color: #525252; padding: 0 4px;")
        lay.addWidget(self._db_status_label)

        return sidebar

    def _set_rt_label(self, active: bool):
        if active:
            self._rt_status_label.setText("⬤  Real-time: on")
            self._rt_status_label.setStyleSheet("font-size: 11px; color: #22c55e; padding: 0 4px;")
        else:
            self._rt_status_label.setText("⬤  Real-time: off")
            self._rt_status_label.setStyleSheet("font-size: 11px; color: #525252; padding: 0 4px;")

    # ── Signal connections ────────────────────────────────────────────────

    def _connect_signals(self):
        # Dashboard actions
        self._dashboard.quick_scan_requested.connect(
            lambda: self._start_scan_from_dashboard("quick")
        )
        self._dashboard.full_scan_requested.connect(
            lambda: self._start_scan_from_dashboard("full")
        )
        self._dashboard.update_requested.connect(self._run_update)

        # Scan page
        self._scan_page.scan_requested.connect(self._on_scan_requested)
        self._scan_page.abort_requested.connect(self._scan_engine.abort)

        # Scan engine
        self._scan_engine.file_scanned.connect(self._on_file_scanned)
        self._scan_engine.scan_progress.connect(self._on_scan_progress)
        self._scan_engine.scan_finished.connect(self._on_scan_finished)

        # DB manager
        self._db_manager.info_loaded.connect(self._on_db_info)

        # Settings
        self._settings_page.settings_changed.connect(self._on_settings_changed)

        # Real-time
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
        # Minimize to tray instead of quitting
        event.ignore()
        self.hide()
        self._tray.showMessage(
            "Qlam", "Running in the background. Double-click tray icon to restore.",
            QSystemTrayIcon.MessageIcon.Information, 2000
        )

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
            icon_color = "#ffffff" if active else "#525252"
            btn.setIcon(qta.icon(self._nav_icon_names[i], color=icon_color))
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        if index == 2:
            self._quarantine_page.refresh()
        elif index == 3:
            self._history_page.refresh()

    # ── Scan orchestration ────────────────────────────────────────────────

    def _start_scan_from_dashboard(self, scan_type: str):
        from core.scan_engine import ScanEngine
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
        threats = [
            {"path": t.path, "threat": t.threat} for t in stats.threats
        ]
        self._history_mgr.add_record(
            self._current_scan_type,
            self._current_targets,
            stats.scanned_files,
            stats.infected_files,
            stats.duration_seconds(),
            threats,
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
            self._db_status_label.setText("⬤  DB: outdated")
            self._db_status_label.setStyleSheet("font-size: 11px; color: #f97316; padding: 0 4px;")
        else:
            self._db_status_label.setText("⬤  DB: up to date")
            self._db_status_label.setStyleSheet("font-size: 11px; color: #525252; padding: 0 4px;")

    def _run_update(self):
        self._nav_to(4)
        self._settings_page._run_update()

    # ── Real-time protection ──────────────────────────────────────────────

    def _on_rt_status(self, active: bool):
        self._dashboard.set_realtime_active(active)
        self._set_rt_label(active)

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

        rt_paths = settings.get("realtime_paths", [])
        if rt_paths:
            self._realtime.set_watched_paths(rt_paths)
            if not self._realtime.is_active():
                self._realtime.start(rt_paths)
        else:
            self._realtime.stop()

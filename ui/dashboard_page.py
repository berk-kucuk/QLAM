from datetime import datetime

import qtawesome as qta
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QGridLayout, QSizePolicy,
)


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", sub: str = "",
                 accent: str = "#ffffff", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(108)
        lay = QVBoxLayout(self)
        lay.setSpacing(3)
        lay.setContentsMargins(18, 14, 18, 14)

        self._title = QLabel(title)
        self._title.setObjectName("CardTitle")
        lay.addWidget(self._title)

        lay.addSpacing(2)

        self._value = QLabel(value)
        self._value.setObjectName("CardValue")
        self._value.setStyleSheet(f"color: {accent}; font-size: 26px; font-weight: 700;")
        lay.addWidget(self._value)

        self._sub = QLabel(sub)
        self._sub.setObjectName("CardSub")
        lay.addWidget(self._sub)

        lay.addStretch()

    def set_value(self, value: str):
        self._value.setText(value)

    def set_sub(self, sub: str):
        self._sub.setText(sub)


class DashboardPage(QWidget):
    quick_scan_requested = pyqtSignal()
    full_scan_requested = pyqtSignal()
    update_requested = pyqtSignal()
    realtime_toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rt_active = False
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 0, 32, 32)
        root.setSpacing(0)

        # ── Header ───────────────────────────────────────────────────────
        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("System security overview")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)

        # ── Protection status banner ──────────────────────────────────────
        self._banner = QFrame()
        self._banner.setObjectName("StatusBanner")
        banner_lay = QHBoxLayout(self._banner)
        banner_lay.setContentsMargins(20, 16, 20, 16)
        banner_lay.setSpacing(14)

        self._dot = QLabel()
        self._dot.setFixedSize(10, 10)
        self._dot.setStyleSheet(
            "background-color: #22c55e; border-radius: 5px;"
        )
        banner_lay.addWidget(self._dot)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        self._status_title = QLabel("Protected")
        self._status_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #22c55e;")
        self._status_desc = QLabel("Real-time protection is active")
        self._status_desc.setStyleSheet("font-size: 12px; color: #525252;")
        text_col.addWidget(self._status_title)
        text_col.addWidget(self._status_desc)
        banner_lay.addLayout(text_col)

        banner_lay.addStretch()

        self._rt_btn = QPushButton("Turn Off")
        self._rt_btn.setObjectName("GhostButton")
        self._rt_btn.setFixedWidth(90)
        self._rt_btn.clicked.connect(self._toggle_rt)
        banner_lay.addWidget(self._rt_btn)

        root.addWidget(self._banner)
        root.addSpacing(20)

        # ── Stat cards ────────────────────────────────────────────────────
        self._card_scans = StatCard("Total Scans", "0", "all time")
        self._card_threats = StatCard("Threats Found", "0", "all time", "#ef4444")
        self._card_quarantine = StatCard("Quarantined", "0", "files isolated")
        self._card_last = StatCard("Last Scan", "Never", "—")

        grid = QGridLayout()
        grid.setSpacing(12)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.addWidget(self._card_scans, 0, 0)
        grid.addWidget(self._card_threats, 0, 1)
        grid.addWidget(self._card_quarantine, 0, 2)
        grid.addWidget(self._card_last, 0, 3)
        root.addLayout(grid)
        root.addSpacing(28)

        # ── Actions ───────────────────────────────────────────────────────
        actions_label = QLabel("Actions")
        actions_label.setObjectName("CardTitle")
        root.addWidget(actions_label)
        root.addSpacing(10)

        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        quick = QPushButton("  Quick Scan")
        quick.setObjectName("PrimaryButton")
        quick.setMinimumHeight(42)
        quick.setMinimumWidth(140)
        quick.setIcon(qta.icon("fa5s.bolt", color="#ffffff"))
        quick.setIconSize(QSize(14, 14))
        quick.clicked.connect(self.quick_scan_requested)
        action_row.addWidget(quick)

        full = QPushButton("  Full System Scan")
        full.setMinimumHeight(42)
        full.setMinimumWidth(160)
        full.setIcon(qta.icon("fa5s.shield-alt", color="#a3a3a3"))
        full.setIconSize(QSize(14, 14))
        full.clicked.connect(self.full_scan_requested)
        action_row.addWidget(full)

        update = QPushButton("  Update Definitions")
        update.setMinimumHeight(42)
        update.setMinimumWidth(160)
        update.setIcon(qta.icon("fa5s.sync-alt", color="#a3a3a3"))
        update.setIconSize(QSize(14, 14))
        update.clicked.connect(self.update_requested)
        action_row.addWidget(update)

        action_row.addStretch()
        root.addLayout(action_row)
        root.addSpacing(28)

        # ── DB info ───────────────────────────────────────────────────────
        db_frame = QFrame()
        db_frame.setObjectName("Card")
        db_lay = QVBoxLayout(db_frame)
        db_lay.setContentsMargins(18, 14, 18, 14)
        db_lay.setSpacing(8)

        db_row = QHBoxLayout()
        db_icon_lbl = QLabel()
        db_icon_lbl.setPixmap(
            qta.icon("fa5s.database", color="#3b82f6").pixmap(QSize(18, 18))
        )
        db_row.addWidget(db_icon_lbl)

        db_text = QVBoxLayout()
        db_text.setSpacing(2)
        db_head = QLabel("Virus Definitions")
        db_head.setStyleSheet("font-weight: 600; color: #fafafa; font-size: 13px;")
        db_text.addWidget(db_head)
        self._db_label = QLabel("Loading...")
        self._db_label.setObjectName("CardSub")
        db_text.addWidget(self._db_label)
        db_row.addLayout(db_text)
        db_row.addStretch()

        self._db_badge = QLabel("Checking")
        self._db_badge.setStyleSheet(
            "background-color: #141414; color: #525252; border-radius: 10px;"
            "padding: 3px 10px; font-size: 11px; font-weight: 600;"
        )
        db_row.addWidget(self._db_badge)
        db_lay.addLayout(db_row)
        root.addWidget(db_frame)

        root.addStretch()

    # ── Public update API ─────────────────────────────────────────────────

    def update_stats(self, total_scans: int, total_threats: int,
                     quarantine_count: int, last_scan_dt: datetime | None):
        self._card_scans.set_value(str(total_scans))
        self._card_threats.set_value(str(total_threats))
        self._card_quarantine.set_value(str(quarantine_count))
        if last_scan_dt:
            self._card_last.set_value(last_scan_dt.strftime("%b %d"))
            self._card_last.set_sub(last_scan_dt.strftime("%H:%M"))
        else:
            self._card_last.set_value("Never")

    def update_db_info(self, db_info):
        version_parts = []
        if db_info.daily_version and db_info.daily_version != "Unknown":
            version_parts.append(f"Daily v{db_info.daily_version}")
        if db_info.main_version and db_info.main_version != "Unknown":
            version_parts.append(f"Main v{db_info.main_version}")

        version_str = "  ·  ".join(version_parts) if version_parts else "Unknown"
        clamav = db_info.clamav_version.split("/")[0] if db_info.clamav_version != "Unknown" else ""
        self._db_label.setText(f"{clamav}  ·  {version_str}" if clamav else version_str)

        if db_info.is_outdated():
            self._db_badge.setText("Outdated")
            self._db_badge.setStyleSheet(
                "background-color: #1a0a00; color: #f97316; border-radius: 10px;"
                "padding: 3px 10px; font-size: 11px; font-weight: 600; border: 1px solid #7c2d12;"
            )
        else:
            self._db_badge.setText("Up to date")
            self._db_badge.setStyleSheet(
                "background-color: #052e16; color: #22c55e; border-radius: 10px;"
                "padding: 3px 10px; font-size: 11px; font-weight: 600; border: 1px solid #14532d;"
            )

    def set_realtime_active(self, active: bool):
        self._rt_active = active
        if active:
            self._banner.setObjectName("StatusBanner")
            self._dot.setStyleSheet("background-color: #22c55e; border-radius: 5px;")
            self._status_title.setText("Protected")
            self._status_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #22c55e;")
            self._status_desc.setText("Real-time protection is active")
            self._rt_btn.setText("Turn Off")
        else:
            self._banner.setObjectName("StatusBannerDanger")
            self._dot.setStyleSheet("background-color: #ef4444; border-radius: 5px;")
            self._status_title.setText("Unprotected")
            self._status_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #ef4444;")
            self._status_desc.setText("Real-time protection is disabled")
            self._rt_btn.setText("Turn On")
        # Force QSS repaint
        self._banner.style().unpolish(self._banner)
        self._banner.style().polish(self._banner)

    def _toggle_rt(self):
        self._rt_active = not self._rt_active
        self.set_realtime_active(self._rt_active)
        self.realtime_toggled.emit(self._rt_active)

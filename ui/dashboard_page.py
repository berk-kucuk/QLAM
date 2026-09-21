from datetime import datetime

import qtawesome as qta
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QGridLayout,
)

from ui.theme import theme


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", sub: str = "",
                 semantic: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(110)
        self._semantic = semantic  # palette role for the value colour, or None
        lay = QVBoxLayout(self)
        lay.setSpacing(3)
        lay.setContentsMargins(18, 16, 18, 16)

        self._title = QLabel(title)
        self._title.setObjectName("CardTitle")
        lay.addWidget(self._title)
        lay.addSpacing(4)

        self._value = QLabel(value)
        self._value.setObjectName("CardValue")
        lay.addWidget(self._value)

        self._sub = QLabel(sub)
        self._sub.setObjectName("CardSub")
        lay.addWidget(self._sub)
        lay.addStretch()

        self._apply_value_color()

    def _apply_value_color(self):
        if self._semantic:
            self._value.setStyleSheet(
                f"color: {theme.p[self._semantic]}; font-size: 26px; font-weight: 700;")
        else:
            self._value.setStyleSheet("")

    def set_value(self, value: str):
        self._value.setText(value)

    def set_sub(self, sub: str):
        self._sub.setText(sub)

    def apply_theme(self):
        self._apply_value_color()


class DashboardPage(QWidget):
    quick_scan_requested = pyqtSignal()
    full_scan_requested = pyqtSignal()
    update_requested = pyqtSignal()
    realtime_toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rt_active = False
        self._build_ui()
        theme.changed.connect(lambda _p: self._apply_theme())
        self._apply_theme()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 24, 32, 32)
        root.setSpacing(0)

        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("System security overview")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)
        root.addSpacing(22)

        # ── Protection status banner ──────────────────────────────────────
        self._banner = QFrame()
        self._banner.setObjectName("Card")
        banner_lay = QHBoxLayout(self._banner)
        banner_lay.setContentsMargins(20, 18, 20, 18)
        banner_lay.setSpacing(16)

        self._shield_icon = QLabel()
        banner_lay.addWidget(self._shield_icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(3)
        self._status_title = QLabel("Protected")
        self._status_desc = QLabel("Real-time protection is active")
        self._status_desc.setObjectName("Muted")
        text_col.addWidget(self._status_title)
        text_col.addWidget(self._status_desc)
        banner_lay.addLayout(text_col)
        banner_lay.addStretch()

        self._rt_btn = QPushButton("Turn Off")
        self._rt_btn.setObjectName("GhostButton")
        self._rt_btn.setFixedWidth(96)
        self._rt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._rt_btn.clicked.connect(self._toggle_rt)
        banner_lay.addWidget(self._rt_btn)

        root.addWidget(self._banner)
        root.addSpacing(20)

        # ── Stat cards ────────────────────────────────────────────────────
        self._card_scans = StatCard("TOTAL SCANS", "0", "all time")
        self._card_threats = StatCard("THREATS FOUND", "0", "all time")
        self._card_quarantine = StatCard("QUARANTINED", "0", "files isolated")
        self._card_last = StatCard("LAST SCAN", "Never", "—")

        grid = QGridLayout()
        grid.setSpacing(14)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.addWidget(self._card_scans, 0, 0)
        grid.addWidget(self._card_threats, 0, 1)
        grid.addWidget(self._card_quarantine, 0, 2)
        grid.addWidget(self._card_last, 0, 3)
        root.addLayout(grid)
        root.addSpacing(28)

        # ── Actions ───────────────────────────────────────────────────────
        actions_label = QLabel("QUICK ACTIONS")
        actions_label.setObjectName("SectionLabel")
        root.addWidget(actions_label)
        root.addSpacing(12)

        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        self._quick_btn = QPushButton("   Quick Scan")
        self._quick_btn.setObjectName("PrimaryButton")
        self._quick_btn.setMinimumHeight(44)
        self._quick_btn.setMinimumWidth(150)
        self._quick_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._quick_btn.setIconSize(QSize(14, 14))
        self._quick_btn.clicked.connect(self.quick_scan_requested)
        action_row.addWidget(self._quick_btn)

        self._full_btn = QPushButton("   Full System Scan")
        self._full_btn.setMinimumHeight(44)
        self._full_btn.setMinimumWidth(170)
        self._full_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._full_btn.setIconSize(QSize(14, 14))
        self._full_btn.clicked.connect(self.full_scan_requested)
        action_row.addWidget(self._full_btn)

        self._update_btn = QPushButton("   Update Definitions")
        self._update_btn.setMinimumHeight(44)
        self._update_btn.setMinimumWidth(170)
        self._update_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_btn.setIconSize(QSize(14, 14))
        self._update_btn.clicked.connect(self.update_requested)
        action_row.addWidget(self._update_btn)

        action_row.addStretch()
        root.addLayout(action_row)
        root.addSpacing(28)

        # ── DB info ───────────────────────────────────────────────────────
        db_frame = QFrame()
        db_frame.setObjectName("Card")
        db_lay = QVBoxLayout(db_frame)
        db_lay.setContentsMargins(20, 16, 20, 16)
        db_lay.setSpacing(8)

        db_row = QHBoxLayout()
        db_row.setSpacing(12)
        self._db_icon_lbl = QLabel()
        db_row.addWidget(self._db_icon_lbl)

        db_text = QVBoxLayout()
        db_text.setSpacing(2)
        db_head = QLabel("Virus Definitions")
        db_head.setObjectName("Strong")
        db_text.addWidget(db_head)
        self._db_label = QLabel("Loading…")
        self._db_label.setObjectName("CardSub")
        db_text.addWidget(self._db_label)
        db_row.addLayout(db_text)
        db_row.addStretch()

        self._db_badge = QLabel("Checking")
        db_row.addWidget(self._db_badge)
        db_lay.addLayout(db_row)
        root.addWidget(db_frame)

        root.addStretch()

    # ── Theming ───────────────────────────────────────────────────────────

    def _apply_theme(self):
        p = theme.p
        for c in (self._card_scans, self._card_threats,
                  self._card_quarantine, self._card_last):
            c.apply_theme()
        self._quick_btn.setIcon(qta.icon("fa5s.bolt", color=p["accent_text"]))
        self._full_btn.setIcon(qta.icon("fa5s.shield-alt", color=p["text"]))
        self._update_btn.setIcon(qta.icon("fa5s.sync-alt", color=p["text"]))
        self._db_icon_lbl.setPixmap(
            qta.icon("fa5s.database", color=p["text_mid"]).pixmap(QSize(18, 18)))
        self.set_realtime_active(self._rt_active)
        self._refresh_db_badge()

    # ── Public update API ─────────────────────────────────────────────────

    def update_stats(self, total_scans: int, total_threats: int,
                     quarantine_count: int, last_scan_dt: datetime | None):
        self._card_scans.set_value(str(total_scans))
        self._card_threats.set_value(str(total_threats))
        self._card_threats._semantic = "bad" if total_threats > 0 else None
        self._card_threats.apply_theme()
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
        self._db_outdated = db_info.is_outdated()
        self._refresh_db_badge()

    def _refresh_db_badge(self):
        p = theme.p
        outdated = getattr(self, "_db_outdated", None)
        if outdated is None:
            self._db_badge.setText("Checking")
            self._db_badge.setStyleSheet(
                f"background-color: {p['elevated']}; color: {p['text_mid']};"
                f" border-radius: 10px; padding: 3px 12px; font-size: 11px; font-weight: 600;")
        elif outdated:
            self._db_badge.setText("Outdated")
            self._db_badge.setStyleSheet(
                f"background-color: {p['surface']}; color: {p['warn']};"
                f" border: 1px solid {p['border2']}; border-radius: 10px;"
                f" padding: 3px 12px; font-size: 11px; font-weight: 600;")
        else:
            self._db_badge.setText("Up to date")
            self._db_badge.setStyleSheet(
                f"background-color: {p['good_soft']}; color: {p['good']};"
                f" border: 1px solid {p['good_border']}; border-radius: 10px;"
                f" padding: 3px 12px; font-size: 11px; font-weight: 600;")

    def set_realtime_active(self, active: bool):
        p = theme.p
        self._rt_active = active
        if active:
            self._shield_icon.setPixmap(
                qta.icon("fa5s.shield-alt", color=p["good"]).pixmap(QSize(30, 30)))
            self._status_title.setText("Protected")
            self._status_title.setStyleSheet(
                f"font-size: 16px; font-weight: 700; color: {p['good']};")
            self._status_desc.setText("Real-time protection is active")
            self._rt_btn.setText("Turn Off")
        else:
            self._shield_icon.setPixmap(
                qta.icon("fa5s.shield-alt", color=p["bad"]).pixmap(QSize(30, 30)))
            self._status_title.setText("Unprotected")
            self._status_title.setStyleSheet(
                f"font-size: 16px; font-weight: 700; color: {p['bad']};")
            self._status_desc.setText("Real-time protection is disabled")
            self._rt_btn.setText("Turn On")

    def _toggle_rt(self):
        # Emit intent only — the real protection status (status_changed) drives
        # the UI via set_realtime_active(), so the button never disagrees with
        # whether protection actually started.
        self.realtime_toggled.emit(not self._rt_active)

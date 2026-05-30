import json
from pathlib import Path

import qtawesome as qta
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QTextEdit, QMessageBox, QScrollArea,
    QFrame, QSizePolicy, QLineEdit, QComboBox, QTimeEdit,
)
from PyQt6.QtCore import QTime

from core.database_manager import DatabaseManager

SETTINGS_FILE = Path.home() / ".local" / "share" / "Qlam" / "settings.json"
AUTOSTART_FILE = Path.home() / ".config" / "autostart" / "qlam.desktop"

DEFAULTS = {
    "max_file_size_mb": 100,
    "scan_archives": True,
    "follow_symlinks": False,
    "recursive_scan": True,
    "auto_quarantine": True,
    "realtime_enabled": False,
    "realtime_paths": [
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop"),
        "/tmp",
    ],
    "notify_on_threat": True,
    "autostart": False,
    "scheduled_scan_enabled": False,
    "scheduled_scan_type": "quick",
    "scheduled_scan_trigger": "startup",
    "scheduled_scan_time": "02:00",
}

_LABEL = "color: #a3a3a3; font-size: 13px;"
_SECTION = "color: #ffffff; font-size: 13px; font-weight: 600;"
_DIM = "color: #525252; font-size: 12px;"


def _section_card(title: str, icon_name: str) -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setObjectName("Card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(20, 16, 20, 18)
    lay.setSpacing(14)

    header = QHBoxLayout()
    header.setSpacing(10)
    icon_lbl = QLabel()
    icon_lbl.setPixmap(qta.icon(icon_name, color="#3b82f6").pixmap(QSize(15, 15)))
    header.addWidget(icon_lbl)
    title_lbl = QLabel(title)
    title_lbl.setStyleSheet(_SECTION)
    header.addWidget(title_lbl)
    header.addStretch()
    lay.addLayout(header)

    sep = QFrame()
    sep.setFixedHeight(1)
    sep.setStyleSheet("background-color: #1e1e1e; border: none;")
    lay.addWidget(sep)

    return card, lay


class _NumberInput(QLineEdit):
    """Plain text input for numeric values with validation."""
    def __init__(self, min_val: int, max_val: int, suffix: str = "", parent=None):
        super().__init__(parent)
        self._min = min_val
        self._max = max_val
        self._suffix = suffix
        self._value = min_val
        self.setFixedWidth(110)
        self.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.editingFinished.connect(self._on_edited)
        self._refresh()

    def value(self) -> int:
        return self._value

    def setValue(self, v: int):
        self._value = max(self._min, min(self._max, v))
        self._refresh()

    def _on_edited(self):
        try:
            text = self.text().replace(self._suffix, "").strip()
            self._value = max(self._min, min(self._max, int(text)))
        except ValueError:
            pass
        self._refresh()

    def _refresh(self):
        self.setText(f"{self._value}{self._suffix}")


def _row(lay: QVBoxLayout, label: str, widget: QWidget, hint: str = ""):
    row = QHBoxLayout()
    row.setSpacing(16)
    lbl = QLabel(label)
    lbl.setStyleSheet(_LABEL)
    lbl.setFixedWidth(180)
    row.addWidget(lbl)
    row.addWidget(widget)
    row.addStretch()
    lay.addLayout(row)
    if hint:
        hint_lbl = QLabel(hint)
        hint_lbl.setStyleSheet(_DIM)
        hint_lbl.setContentsMargins(196, 0, 0, 0)
        lay.addWidget(hint_lbl)


class SettingsPage(QWidget):
    settings_changed = pyqtSignal(dict)

    def __init__(self, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self._db_manager = db_manager
        self._settings = self._load()
        self._build_ui()
        self._apply_to_ui()

        db_manager.update_output.connect(self._on_update_output)
        db_manager.update_finished.connect(self._on_update_finished)

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        root = QVBoxLayout(content)
        root.setContentsMargins(32, 0, 32, 32)
        root.setSpacing(14)

        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("Scan behavior, real-time protection and database updates")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)

        # ── Scan Options card ─────────────────────────────────────────────
        card1, c1 = _section_card("Scan Options", "fa5s.sliders-h")

        self._max_size_spin = _NumberInput(1, 4096, " MB")
        _row(c1, "Max file size", self._max_size_spin,
             "Files larger than this are skipped")

        self._archives_chk = QCheckBox("Scan inside archives  (zip, tar, gz...)")
        self._archives_chk.setStyleSheet(_LABEL)
        c1.addWidget(self._archives_chk)

        self._symlinks_chk = QCheckBox("Follow symbolic links")
        self._symlinks_chk.setStyleSheet(_LABEL)
        c1.addWidget(self._symlinks_chk)

        self._recursive_chk = QCheckBox("Recursive directory scanning")
        self._recursive_chk.setStyleSheet(_LABEL)
        c1.addWidget(self._recursive_chk)

        self._auto_quarantine_chk = QCheckBox("Automatically quarantine detected threats")
        self._auto_quarantine_chk.setStyleSheet(_LABEL)
        c1.addWidget(self._auto_quarantine_chk)

        root.addWidget(card1)

        # ── Notifications card ────────────────────────────────────────────
        card2, c2 = _section_card("Notifications", "fa5s.bell")

        self._notify_chk = QCheckBox("Show desktop notification when a threat is detected")
        self._notify_chk.setStyleSheet(_LABEL)
        c2.addWidget(self._notify_chk)

        root.addWidget(card2)

        # ── Autostart card ────────────────────────────────────────────────
        card_auto, c_auto = _section_card("System Startup", "fa5s.power-off")

        self._autostart_chk = QCheckBox(
            "Launch Qlam automatically when the system starts  (runs in system tray)"
        )
        self._autostart_chk.setStyleSheet(_LABEL)
        c_auto.addWidget(self._autostart_chk)

        root.addWidget(card_auto)

        # ── Scheduled Scan card ───────────────────────────────────────────
        card_sched, c_sched = _section_card("Scheduled Scan", "fa5s.calendar-alt")

        self._sched_enabled_chk = QCheckBox("Enable scheduled automatic scan")
        self._sched_enabled_chk.setStyleSheet(_LABEL)
        self._sched_enabled_chk.toggled.connect(self._on_sched_toggled)
        c_sched.addWidget(self._sched_enabled_chk)

        # Scan type row
        stype_row = QHBoxLayout()
        stype_lbl = QLabel("Scan type:")
        stype_lbl.setStyleSheet(_LABEL)
        stype_lbl.setFixedWidth(120)
        stype_row.addWidget(stype_lbl)
        self._sched_type_combo = QComboBox()
        self._sched_type_combo.addItems(["Quick Scan", "Full Scan"])
        self._sched_type_combo.setFixedWidth(140)
        stype_row.addWidget(self._sched_type_combo)
        stype_row.addStretch()
        c_sched.addLayout(stype_row)

        # Trigger row
        trig_row = QHBoxLayout()
        trig_lbl = QLabel("Run:")
        trig_lbl.setStyleSheet(_LABEL)
        trig_lbl.setFixedWidth(120)
        trig_row.addWidget(trig_lbl)
        self._sched_trigger_combo = QComboBox()
        self._sched_trigger_combo.addItems(["On system startup", "At a specific time"])
        self._sched_trigger_combo.setFixedWidth(200)
        self._sched_trigger_combo.currentIndexChanged.connect(self._on_trigger_changed)
        trig_row.addWidget(self._sched_trigger_combo)
        trig_row.addStretch()
        c_sched.addLayout(trig_row)

        # Time picker (only visible when "At a specific time" is selected)
        time_row = QHBoxLayout()
        time_lbl = QLabel("Time:")
        time_lbl.setStyleSheet(_LABEL)
        time_lbl.setFixedWidth(120)
        time_row.addWidget(time_lbl)
        self._sched_time_edit = QTimeEdit()
        self._sched_time_edit.setDisplayFormat("HH:mm")
        self._sched_time_edit.setFixedWidth(90)
        self._sched_time_edit.setStyleSheet(
            "QTimeEdit { background-color: #0c0c0c; border: 1px solid #262626;"
            " border-radius: 6px; color: #fafafa; padding: 5px 8px; }"
            "QTimeEdit::up-button, QTimeEdit::down-button { width: 0; }"
        )
        time_row.addWidget(self._sched_time_edit)
        time_row.addStretch()
        self._time_row_widget = QWidget()
        self._time_row_widget.setLayout(time_row)
        c_sched.addWidget(self._time_row_widget)

        root.addWidget(card_sched)

        # ── Real-time Paths card ──────────────────────────────────────────
        card3, c3 = _section_card("Real-time Protection — Watched Paths", "fa5s.eye")

        self._rt_enabled_chk = QCheckBox("Enable real-time protection")
        self._rt_enabled_chk.setStyleSheet(_LABEL)
        self._rt_enabled_chk.toggled.connect(self._on_rt_enabled_toggled)
        c3.addWidget(self._rt_enabled_chk)

        hint = QLabel("One path per line. Qlam monitors these directories for new or modified files.")
        hint.setStyleSheet(_DIM)
        hint.setWordWrap(True)
        c3.addWidget(hint)

        self._rt_paths_edit = QTextEdit()
        self._rt_paths_edit.setFixedHeight(96)
        self._rt_paths_edit.setStyleSheet(
            "background-color: #080808; border: 1px solid #262626; border-radius: 8px;"
            "color: #a3a3a3; font-family: monospace; font-size: 12px; padding: 8px;"
        )
        c3.addWidget(self._rt_paths_edit)

        root.addWidget(card3)

        # ── Virus Database card ───────────────────────────────────────────
        card4, c4 = _section_card("Virus Database", "fa5s.database")

        update_row = QHBoxLayout()
        self._update_btn = QPushButton("  Update Now")
        self._update_btn.setObjectName("PrimaryButton")
        self._update_btn.setIcon(qta.icon("fa5s.sync-alt", color="#ffffff"))
        self._update_btn.setIconSize(QSize(13, 13))
        self._update_btn.setFixedWidth(150)
        self._update_btn.clicked.connect(lambda: self._run_update())
        update_row.addWidget(self._update_btn)

        self._update_status = QLabel("Runs freshclam to fetch the latest signatures")
        self._update_status.setStyleSheet(_DIM)
        update_row.addWidget(self._update_status)
        update_row.addStretch()
        c4.addLayout(update_row)

        self._update_log = QTextEdit()
        self._update_log.setReadOnly(True)
        self._update_log.setFixedHeight(110)
        self._update_log.setStyleSheet(
            "background-color: #080808; border: 1px solid #1e1e1e; border-radius: 8px;"
            "color: #a3a3a3; font-family: monospace; font-size: 11px; padding: 8px;"
        )
        self._update_log.setPlaceholderText("Update output will appear here...")
        c4.addWidget(self._update_log)

        root.addWidget(card4)
        root.addSpacing(8)

        # Save button
        save_row = QHBoxLayout()
        save_btn = QPushButton("  Save Settings")
        save_btn.setObjectName("PrimaryButton")
        save_btn.setIcon(qta.icon("fa5s.check", color="#ffffff"))
        save_btn.setIconSize(QSize(13, 13))
        save_btn.setMinimumWidth(150)
        save_btn.setMinimumHeight(42)
        save_btn.clicked.connect(self._save_and_emit)
        save_row.addWidget(save_btn)
        save_row.addStretch()
        root.addLayout(save_row)
        root.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    # ── Public ────────────────────────────────────────────────────────────

    def get_settings(self) -> dict:
        return dict(self._settings)

    def _run_update(self):
        self._update_btn.setEnabled(False)
        self._update_status.setText("Waiting for authentication...")
        self._update_status.setStyleSheet("color: #a3a3a3; font-size: 12px;")
        self._update_log.clear()
        self._db_manager.run_update()

    # ── Internal ──────────────────────────────────────────────────────────

    def _apply_to_ui(self):
        s = self._settings
        self._max_size_spin.setValue(s.get("max_file_size_mb", 100))
        self._archives_chk.setChecked(s.get("scan_archives", True))
        self._symlinks_chk.setChecked(s.get("follow_symlinks", False))
        self._recursive_chk.setChecked(s.get("recursive_scan", True))
        self._auto_quarantine_chk.setChecked(s.get("auto_quarantine", True))
        self._notify_chk.setChecked(s.get("notify_on_threat", True))
        self._autostart_chk.setChecked(s.get("autostart", False))
        self._rt_enabled_chk.setChecked(s.get("realtime_enabled", False))
        self._rt_paths_edit.setPlainText("\n".join(s.get("realtime_paths", [])))
        self._on_rt_enabled_toggled(s.get("realtime_enabled", False))

        enabled = s.get("scheduled_scan_enabled", False)
        self._sched_enabled_chk.setChecked(enabled)
        self._sched_type_combo.setCurrentIndex(
            0 if s.get("scheduled_scan_type", "quick") == "quick" else 1
        )
        trigger = s.get("scheduled_scan_trigger", "startup")
        self._sched_trigger_combo.setCurrentIndex(0 if trigger == "startup" else 1)
        t = s.get("scheduled_scan_time", "02:00")
        h, m = (int(x) for x in t.split(":"))
        self._sched_time_edit.setTime(QTime(h, m))
        self._on_sched_toggled(enabled)
        self._on_trigger_changed(self._sched_trigger_combo.currentIndex())

    def _collect_from_ui(self) -> dict:
        paths = [
            p.strip()
            for p in self._rt_paths_edit.toPlainText().splitlines()
            if p.strip()
        ]
        trigger = "startup" if self._sched_trigger_combo.currentIndex() == 0 else "time"
        t = self._sched_time_edit.time()
        return {
            "max_file_size_mb": self._max_size_spin.value(),
            "scan_archives": self._archives_chk.isChecked(),
            "follow_symlinks": self._symlinks_chk.isChecked(),
            "recursive_scan": self._recursive_chk.isChecked(),
            "auto_quarantine": self._auto_quarantine_chk.isChecked(),
            "realtime_enabled": self._rt_enabled_chk.isChecked(),
            "realtime_paths": paths,
            "notify_on_threat": self._notify_chk.isChecked(),
            "autostart": self._autostart_chk.isChecked(),
            "scheduled_scan_enabled": self._sched_enabled_chk.isChecked(),
            "scheduled_scan_type": "quick" if self._sched_type_combo.currentIndex() == 0 else "full",
            "scheduled_scan_trigger": trigger,
            "scheduled_scan_time": f"{t.hour():02d}:{t.minute():02d}",
        }

    def _save_and_emit(self):
        self._settings = self._collect_from_ui()
        self._persist()
        self._apply_autostart(self._settings.get("autostart", False))
        self.settings_changed.emit(dict(self._settings))
        QMessageBox.information(self, "Qlam", "Settings saved.")

    def _on_sched_toggled(self, enabled: bool):
        for w in (self._sched_type_combo, self._sched_trigger_combo, self._time_row_widget):
            w.setEnabled(enabled)
        if enabled:
            self._on_trigger_changed(self._sched_trigger_combo.currentIndex())

    def _on_trigger_changed(self, index: int):
        show_time = (index == 1) and self._sched_enabled_chk.isChecked()
        self._time_row_widget.setVisible(show_time)

    def _on_rt_enabled_toggled(self, enabled: bool):
        self._rt_paths_edit.setEnabled(enabled)

    @staticmethod
    def _apply_autostart(enable: bool):
        AUTOSTART_FILE.parent.mkdir(parents=True, exist_ok=True)
        launcher = Path.home() / ".local" / "bin" / "qlam"
        # Fall back to running main.py directly if launcher not installed
        if not launcher.exists():
            import sys
            from pathlib import Path as P
            launcher = P(sys.argv[0]).resolve()
        if enable:
            AUTOSTART_FILE.write_text(
                "[Desktop Entry]\n"
                "Name=Qlam\n"
                f"Exec={launcher} --tray\n"
                "Type=Application\n"
                "Categories=System;Security;\n"
                "Comment=Qlam antivirus — background protection\n"
                "X-GNOME-Autostart-enabled=true\n"
                "Hidden=false\n"
            )
        else:
            AUTOSTART_FILE.unlink(missing_ok=True)

    def _on_update_output(self, line: str):
        self._update_log.append(f'<span style="color:#525252;">{line}</span>')

    def _on_update_finished(self, success: bool, message: str):
        self._update_btn.setEnabled(True)
        color = "#22c55e" if success else "#ef4444"
        self._update_status.setText(message)
        self._update_status.setStyleSheet(f"color: {color}; font-size: 12px;")
        self._update_log.append(
            f'<span style="color:{color}; font-weight:600;">{message}</span>'
        )

    @staticmethod
    def _load() -> dict:
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE) as f:
                    return {**DEFAULTS, **json.load(f)}
            except Exception:
                pass
        return dict(DEFAULTS)

    def _persist(self):
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self._settings, f, indent=2)

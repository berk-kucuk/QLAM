from pathlib import Path

import qtawesome as qta
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QSize
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTextEdit, QFrame, QFileDialog,
)


class _ScanOptionCard(QFrame):
    clicked = pyqtSignal()

    def __init__(self, icon_name: str, icon_color: str, title: str, desc: str, parent=None):
        super().__init__(parent)
        self._icon_name = icon_name
        self._icon_color = icon_color
        self._hovered = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(180, 120)
        self._refresh_style()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 20, 0, 16)
        lay.setSpacing(6)
        lay.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)

        self._icon_lbl = QLabel()
        self._icon_lbl.setPixmap(
            qta.icon(icon_name, color=icon_color).pixmap(QSize(26, 26))
        )
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._icon_lbl.setStyleSheet("background: transparent; border: none;")
        lay.addWidget(self._icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        title_lbl.setStyleSheet(
            "background: transparent; border: none;"
            "color: #e5e5e5; font-weight: 600; font-size: 13px;"
        )
        lay.addWidget(title_lbl)

        desc_lbl = QLabel(desc)
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        desc_lbl.setStyleSheet(
            "background: transparent; border: none;"
            "color: #404040; font-size: 11px;"
        )
        lay.addWidget(desc_lbl)

    def _refresh_style(self):
        if self._hovered:
            self.setStyleSheet(
                "QFrame { background-color: #0d1929; border: 1px solid #1d4ed8;"
                " border-radius: 14px; }"
            )
        else:
            self.setStyleSheet(
                "QFrame { background-color: #0a0a0a; border: 1px solid #1e1e1e;"
                " border-radius: 14px; }"
            )

    def mousePressEvent(self, event):
        self.clicked.emit()

    def enterEvent(self, event):
        self._hovered = True
        self._refresh_style()
        self._icon_lbl.setPixmap(
            qta.icon(self._icon_name, color="#60a5fa").pixmap(QSize(26, 26))
        )

    def leaveEvent(self, event):
        self._hovered = False
        self._refresh_style()
        self._icon_lbl.setPixmap(
            qta.icon(self._icon_name, color=self._icon_color).pixmap(QSize(26, 26))
        )


class ScanPage(QWidget):
    scan_requested = pyqtSignal(str, list, bool)
    abort_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._is_scanning = False
        self._threats = 0
        self._elapsed_secs = 0
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 0, 32, 32)
        root.setSpacing(0)

        # Header
        title = QLabel("Scan")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("Select a scan type to begin")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)

        # Scan type cards
        card_row = QHBoxLayout()
        card_row.setSpacing(12)
        card_row.setContentsMargins(0, 0, 0, 0)

        self._quick_card = _ScanOptionCard(
            "fa5s.bolt", "#f59e0b", "Quick Scan", "Downloads, Desktop, /tmp"
        )
        self._full_card = _ScanOptionCard(
            "fa5s.shield-alt", "#3b82f6", "Full Scan", "Entire filesystem"
        )
        self._custom_card = _ScanOptionCard(
            "fa5s.folder-open", "#a3a3a3", "Custom Scan", "Choose a folder to scan"
        )

        self._quick_card.clicked.connect(lambda: self._trigger("quick"))
        self._full_card.clicked.connect(lambda: self._trigger("full"))
        self._custom_card.clicked.connect(self._trigger_custom)

        card_row.addWidget(self._quick_card)
        card_row.addWidget(self._full_card)
        card_row.addWidget(self._custom_card)
        card_row.addStretch()
        root.addLayout(card_row)
        root.addSpacing(24)

        # Progress section
        self._progress_frame = QFrame()
        self._progress_frame.setObjectName("Card")
        self._progress_frame.setVisible(False)
        prog_lay = QVBoxLayout(self._progress_frame)
        prog_lay.setContentsMargins(18, 16, 18, 16)
        prog_lay.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(10)

        self._scan_icon = QLabel()
        self._scan_icon.setPixmap(qta.icon("fa5s.shield-alt", color="#3b82f6").pixmap(QSize(16, 16)))
        top.addWidget(self._scan_icon)

        self._status_lbl = QLabel("Scanning...")
        self._status_lbl.setStyleSheet("font-weight: 600; font-size: 14px; color: #fafafa;")
        top.addWidget(self._status_lbl)
        top.addStretch()

        self._abort_btn = QPushButton("  Stop")
        self._abort_btn.setObjectName("DangerButton")
        self._abort_btn.setFixedWidth(84)
        self._abort_btn.setIcon(qta.icon("fa5s.stop-circle", color="#fca5a5"))
        self._abort_btn.setIconSize(QSize(13, 13))
        self._abort_btn.clicked.connect(self._do_abort)
        top.addWidget(self._abort_btn)
        prog_lay.addLayout(top)

        self._progress_bar = QProgressBar()
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(5)
        prog_lay.addWidget(self._progress_bar)

        meta_row = QHBoxLayout()
        self._files_lbl = QLabel("Preparing...")
        self._files_lbl.setObjectName("CardSub")
        meta_row.addWidget(self._files_lbl)

        self._threats_lbl = QLabel("Threats: 0")
        self._threats_lbl.setStyleSheet("color: #ef4444; font-size: 12px;")
        meta_row.addWidget(self._threats_lbl)

        meta_row.addStretch()
        self._elapsed_lbl = QLabel("00:00")
        self._elapsed_lbl.setObjectName("CardSub")
        meta_row.addWidget(self._elapsed_lbl)
        prog_lay.addLayout(meta_row)

        self._file_lbl = QLabel("")
        self._file_lbl.setObjectName("CardSub")
        self._file_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #404040;")
        self._file_lbl.setWordWrap(True)
        prog_lay.addWidget(self._file_lbl)

        root.addWidget(self._progress_frame)
        root.addSpacing(16)

        # Log
        log_header = QHBoxLayout()
        log_title = QLabel("Log")
        log_title.setObjectName("CardTitle")
        log_header.addWidget(log_title)
        log_header.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("GhostButton")
        clear_btn.setFixedWidth(72)
        clear_btn.setFixedHeight(28)
        log_header.addWidget(clear_btn)
        root.addLayout(log_header)
        root.addSpacing(8)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(180)
        self._log.setPlaceholderText("Scan output will appear here...")
        root.addWidget(self._log)

        clear_btn.clicked.connect(self._log.clear)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    # ── Public API ────────────────────────────────────────────────────────

    def start_scan_ui(self, scan_type: str, targets: list[str]):
        self._is_scanning = True
        self._threats = 0
        self._elapsed_secs = 0

        self._progress_frame.setVisible(True)
        self._progress_bar.setRange(0, 0)
        self._status_lbl.setText(f"{scan_type.title()} scan in progress")
        self._status_lbl.setStyleSheet("font-weight: 600; font-size: 14px; color: #fafafa;")
        self._files_lbl.setText("Counting files...")
        self._threats_lbl.setText("Threats: 0")
        self._elapsed_lbl.setText("00:00")
        self._file_lbl.setText("")
        self._abort_btn.setEnabled(True)

        self._log.append(
            f'<span style="color:#404040">{"─" * 50}</span>'
        )
        self._log.append(
            f'<span style="color:#3b82f6; font-weight:600;">[{_now()}]</span>'
            f'<span style="color:#a3a3a3;"> {scan_type.upper()} SCAN STARTED</span>'
        )
        self._log.append(
            f'<span style="color:#404040">Targets: {", ".join(targets)}</span>'
        )
        self._timer.start(1000)

    def update_progress(self, current: int, total: int, filepath: str):
        if total > 0:
            self._progress_bar.setRange(0, total)
        self._progress_bar.setValue(current)
        self._files_lbl.setText(f"{current:,} / {total:,} files")
        trunc = filepath[-80:] if len(filepath) > 80 else filepath
        self._file_lbl.setText(trunc)

    def on_file_scanned(self, path: str, infected: bool, threat: str):
        if infected:
            self._threats += 1
            self._threats_lbl.setText(f"Threats: {self._threats}")
            self._log.append(
                f'<span style="color:#ef4444; font-weight:600;">THREAT</span>'
                f'<span style="color:#fca5a5;"> {path}</span>'
                f'<span style="color:#ef4444;"> [{threat}]</span>'
            )

    def finish_scan_ui(self, stats):
        self._is_scanning = False
        self._timer.stop()
        self._abort_btn.setEnabled(False)
        self._progress_bar.setRange(0, max(1, stats.scanned_files))
        self._progress_bar.setValue(stats.scanned_files)

        if stats.infected_files > 0:
            self._status_lbl.setText(f"{stats.infected_files} threat(s) found")
            self._status_lbl.setStyleSheet("font-weight: 600; font-size: 14px; color: #ef4444;")
            self._scan_icon.setPixmap(
                qta.icon("fa5s.exclamation-triangle", color="#ef4444").pixmap(QSize(16, 16))
            )
        else:
            self._status_lbl.setText("Scan complete — no threats found")
            self._status_lbl.setStyleSheet("font-weight: 600; font-size: 14px; color: #22c55e;")
            self._scan_icon.setPixmap(
                qta.icon("fa5s.check-circle", color="#22c55e").pixmap(QSize(16, 16))
            )

        self._file_lbl.setText("")
        self._log.append(
            f'<span style="color:#3b82f6; font-weight:600;">[{_now()}]</span>'
            f'<span style="color:#a3a3a3;"> FINISHED  '
            f'{stats.scanned_files:,} files · '
            f'{stats.infected_files} threats · '
            f'{stats.duration_seconds():.1f}s</span>'
        )

    def start_with(self, scan_type: str, targets: list[str]):
        self._trigger_type(scan_type, targets)

    # ── Internal ──────────────────────────────────────────────────────────

    def _trigger(self, scan_type: str):
        if self._is_scanning:
            return
        from core.scan_engine import ScanEngine
        targets = (
            ScanEngine.quick_scan_paths() if scan_type == "quick"
            else ScanEngine.full_scan_paths()
        )
        self._trigger_type(scan_type, targets)

    def _trigger_custom(self):
        if self._is_scanning:
            return
        path = QFileDialog.getExistingDirectory(
            self, "Select folder to scan", str(Path.home())
        )
        if path:
            self._trigger_type("custom", [path])

    def _trigger_type(self, scan_type: str, targets: list[str]):
        self.start_scan_ui(scan_type, targets)
        self.scan_requested.emit(scan_type, targets, True)

    def _do_abort(self):
        self._abort_btn.setEnabled(False)
        self._status_lbl.setText("Stopping...")
        self.abort_requested.emit()

    def _tick(self):
        self._elapsed_secs += 1
        m, s = divmod(self._elapsed_secs, 60)
        self._elapsed_lbl.setText(f"{m:02d}:{s:02d}")


def _now() -> str:
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")

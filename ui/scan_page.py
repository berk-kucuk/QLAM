"""On-demand scans, run by the daemon so they continue if the window closes."""
from __future__ import annotations

import os

import qtawesome as qta
from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QProgressBar, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ui.theme import theme
from ui.widgets import Card, Chip, label, page_header, short_path, when

_KINDS = {
    "quick": ("fa5s.bolt", "Quick scan",
              "Downloads, desktop, startup entries and temporary folders — where new "
              "malware lands first. About a minute."),
    "home": ("fa5s.home", "Home folder",
             "Every file in your home folder, hidden ones included. Can take a while."),
    "custom": ("fa5s.folder-open", "Choose a folder",
               "Scan a folder of your choice, such as a USB stick."),
}


class _Option(Card):
    clicked = pyqtSignal(str)

    def __init__(self, kind: str, parent=None):
        super().__init__(parent)
        self.kind = kind
        icon, title, text = _KINDS[kind]
        self._icon = icon
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        top = QHBoxLayout()
        self.ic = QLabel()
        top.addWidget(self.ic)
        top.addWidget(label(title, "Strong"), 1)
        if kind == "quick":
            top.addWidget(Chip("Recommended", "good"))
        self.body.addLayout(top)
        self.body.addWidget(label(text, "Muted", wrap=True))
        self.body.addStretch(1)
        self.setMinimumHeight(118)
        self.retint()

    def retint(self):
        self.ic.setPixmap(qta.icon(self._icon, color=theme.p["text"]).pixmap(QSize(16, 16)))

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.clicked.emit(self.kind)
        super().mousePressEvent(e)


class ScanPage(QWidget):
    show_findings = pyqtSignal()

    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self.current: str | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(18)
        root.addWidget(page_header("Scan", "Real-time protection checks new files as they arrive. "
                                           "Scans check what was already there."))

        opts = QHBoxLayout()
        opts.setSpacing(14)
        self.options = [_Option(k) for k in ("quick", "home", "custom")]
        for o in self.options:
            o.clicked.connect(self.start)
            opts.addWidget(o, 1)
        root.addLayout(opts)

        # Running / result panel.
        self.panel = Card()
        p = self.panel.body
        p.setContentsMargins(22, 18, 22, 18)
        top = QHBoxLayout()
        self.p_title = label("", "Strong")
        self.p_chip = Chip()
        top.addWidget(self.p_title, 1)
        top.addWidget(self.p_chip)
        p.addLayout(top)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(6)
        p.addWidget(self.progress)
        self.p_text = label("", "Muted", wrap=True)
        p.addWidget(self.p_text)
        btns = QHBoxLayout()
        self.b_cancel = QPushButton("Stop scan")
        self.b_cancel.setObjectName("GhostButton")
        self.b_cancel.clicked.connect(self._cancel)
        self.b_review = QPushButton("Review findings")
        self.b_review.setObjectName("PrimaryButton")
        self.b_review.clicked.connect(self.show_findings)
        btns.addWidget(self.b_cancel)
        btns.addWidget(self.b_review)
        btns.addStretch(1)
        p.addLayout(btns)
        self.panel.hide()
        root.addWidget(self.panel)

        root.addWidget(label("SCAN HISTORY", "SectionLabel"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Date", "Type", "Files", "Findings", "Result"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(self.table, 1)

        client.scan_progress.connect(self._progress)
        client.scan_finished.connect(self._finished)
        theme.changed.connect(lambda _p: [o.retint() for o in self.options])

    # ── Actions ───────────────────────────────────────────────────────────

    def start(self, kind: str):
        if self.current:
            QMessageBox.information(self, "Qlam", "A scan is already running.")
            return
        paths: list[str] = []
        if kind == "custom":
            folder = QFileDialog.getExistingDirectory(self, "Choose a folder to scan", os.path.expanduser("~"))
            if not folder:
                return
            paths = [folder]
        self._show_running(kind, paths)
        self.client.start_scan(kind, paths, done=self._started, fail=self._start_failed)

    def _started(self, scan_id):
        self.current = str(scan_id)

    def _start_failed(self, msg: str):
        self.current = None
        self.panel.hide()
        self._set_options_enabled(True)
        QMessageBox.warning(self, "Qlam", f"The scan could not start.\n\n{msg}")

    def _cancel(self):
        if self.current:
            self.client.cancel_scan(self.current)
            self.b_cancel.setEnabled(False)
            self.p_text.setText("Stopping…")

    def _set_options_enabled(self, on: bool):
        for o in self.options:
            o.setEnabled(on)

    def _show_running(self, kind: str, paths: list[str]):
        self._set_options_enabled(False)
        self.panel.show()
        title = _KINDS.get(kind, _KINDS["custom"])[1]
        if paths:
            title += f": {short_path(paths[0], 50)}"
        self.p_title.setText(title)
        self.p_chip.setText("Scanning")
        self.p_chip.set_level("info")
        self.progress.show()
        self.p_text.setText("Starting…")
        self.b_cancel.show()
        self.b_cancel.setEnabled(True)
        self.b_review.hide()

    def _progress(self, scan_id: str, files: int, detections: int):
        if scan_id != self.current:
            return
        self.p_text.setText(f"{files:,} files checked" + (f" · {detections} found" if detections else ""))

    def _finished(self, rec: dict):
        if rec.get("id") != self.current:
            self.refresh()
            return
        self.current = None
        self._set_options_enabled(True)
        self.progress.hide()
        self.b_cancel.hide()
        found = int(rec.get("detections", 0))
        noted = int(rec.get("suspicious", 0))
        files = int(rec.get("files", 0))
        secs = max(0, int(rec.get("finished", 0)) - int(rec.get("started", 0)))
        dur = f"{secs // 60} min {secs % 60} s" if secs >= 60 else f"{secs} s"
        if rec.get("status") == "cancelled":
            self.p_chip.setText("Stopped")
            self.p_chip.set_level("info")
            self.p_text.setText(f"Stopped after {files:,} files.")
        elif found:
            self.p_chip.setText(f"{found} threat{'s' if found > 1 else ''}")
            self.p_chip.set_level("danger")
            self.p_text.setText(f"{files:,} files checked in {dur}. Nothing was changed — "
                                "review the findings and decide what to do.")
        elif noted:
            self.p_chip.setText(f"{noted} notice{'s' if noted > 1 else ''}")
            self.p_chip.set_level("notice")
            self.p_text.setText(f"{files:,} files checked in {dur}. No malware found; "
                                f"{noted} item{'s' if noted > 1 else ''} worth a look.")
        else:
            self.p_chip.setText("Clean")
            self.p_chip.set_level("good")
            self.p_text.setText(f"{files:,} files checked in {dur}. No threats found.")
        self.b_review.setVisible(bool(found or noted) and rec.get("status") != "cancelled")
        self.refresh()

    # ── History ───────────────────────────────────────────────────────────

    def refresh(self):
        scans = self.client.scans(50)
        running = [s for s in scans if s.get("status") == "running"]
        if running and not self.current:
            # A scan started earlier (or from the tray) is still going.
            self.current = running[0]["id"]
            self.client.my_scans.add(self.current)
            self._show_running(running[0].get("kind", "custom"), [])
        rows = [s for s in scans if s.get("status") != "running"]
        self.table.setRowCount(len(rows))
        for r, s in enumerate(rows):
            found = int(s.get("detections", 0))
            noted = int(s.get("suspicious", 0))
            result = {"cancelled": "Stopped", "failed": "Interrupted"}.get(
                s.get("status"), "Threats found" if found else ("Notices" if noted else "Clean"))
            vals = [when(s.get("started")), s.get("kind", "").capitalize(),
                    f"{int(s.get('files', 0)):,}", str(found + noted), result]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 4 and found:
                    it.setForeground(QColor(theme.p["bad"]))
                self.table.setItem(r, c, it)

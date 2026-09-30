"""Findings: every warning with a plain explanation and the user's choices.

Nothing here is automatic. Each finding offers exactly two decisions —
quarantine it, or trust it — and says clearly that nothing has been changed
until the user picks one.
"""
from __future__ import annotations

import os
import subprocess

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from ui.widgets import (
    Card, Chip, ago, chip_for, explanation, headline, label, level, page_header, short_path, when,
)

_ACTIONABLE = {"blocked", "warning", "suspicious", "persistence"}
_CHIP_TEXT = {"danger": "Malware", "warn": "Warning", "notice": "Notice", "info": "Info"}


def is_open(ev: dict) -> bool:
    return ev.get("kind") in _ACTIONABLE and not ev.get("resolution")


class AlertsPage(QWidget):
    changed = pyqtSignal()   # a decision was made; refresh everything

    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self._events: list[dict] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(18)
        head = QHBoxLayout()
        head.addWidget(page_header("Findings", "Everything Qlam noticed. Nothing is changed until you decide."), 1)
        self.filter = QComboBox()
        self.filter.addItems(["Needs your decision", "All findings"])
        self.filter.currentIndexChanged.connect(lambda _i: self._fill())
        head.addWidget(self.filter, 0, Qt.AlignmentFlag.AlignBottom)
        root.addLayout(head)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(14)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.list.currentItemChanged.connect(lambda cur, _prev: self._show(cur))
        ll.addWidget(self.list)
        self.empty = label("No findings. When Qlam notices something, it shows up here.", "EmptyState", wrap=True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.addWidget(self.empty)
        split.addWidget(left)

        # Detail panel.
        self.detail = Card()
        d = self.detail.body
        d.setContentsMargins(24, 22, 24, 22)
        d.setSpacing(12)
        top = QHBoxLayout()
        self.d_title = label("", "DetailTitle", wrap=True)
        self.d_chip = Chip()
        top.addWidget(self.d_title, 1)
        top.addWidget(self.d_chip, 0, Qt.AlignmentFlag.AlignTop)
        d.addLayout(top)
        self.d_text = label("", wrap=True)
        self.d_text.setObjectName("HeroText")
        d.addWidget(self.d_text)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        d.addWidget(sep)
        self.fields = QGridLayout()
        self.fields.setHorizontalSpacing(16)
        self.fields.setVerticalSpacing(6)
        self._field_labels: dict[str, object] = {}
        for i, name in enumerate(("File", "Detection", "Found by", "Seen", "Process", "SHA-256", "Status")):
            self.fields.addWidget(label(name.upper(), "StatLabel"), i, 0, Qt.AlignmentFlag.AlignTop)
            v = label("", "Mono", wrap=True, selectable=True)
            self._field_labels[name] = v
            self.fields.addWidget(v, i, 1)
        self.fields.setColumnStretch(1, 1)
        d.addLayout(self.fields)
        d.addStretch(1)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.b_quarantine = QPushButton("Move to quarantine")
        self.b_quarantine.setObjectName("DangerButton")
        self.b_quarantine.clicked.connect(self._quarantine)
        self.b_trust = QPushButton("I trust this file")
        self.b_trust.setObjectName("GhostButton")
        self.b_trust.clicked.connect(self._trust)
        self.b_folder = QPushButton("Show in folder")
        self.b_folder.setObjectName("GhostButton")
        self.b_folder.clicked.connect(self._open_folder)
        btns.addWidget(self.b_quarantine)
        btns.addWidget(self.b_trust)
        btns.addStretch(1)
        btns.addWidget(self.b_folder)
        d.addLayout(btns)
        split.addWidget(self.detail)
        split.setSizes([420, 560])
        root.addWidget(split, 1)
        self._show(None)

    # ── Data ──────────────────────────────────────────────────────────────

    def set_events(self, events: list[dict]):
        self._events = events
        self._fill()

    def open_count(self) -> int:
        seen = set()
        for ev in self._events:
            if is_open(ev):
                seen.add((ev.get("path"), ev.get("detection")))
        return len(seen)

    def select_event(self, event_id: int):
        self.filter.setCurrentIndex(1)
        for i in range(self.list.count()):
            if self.list.item(i).data(Qt.ItemDataRole.UserRole).get("id") == event_id:
                self.list.setCurrentRow(i)
                return

    def _fill(self):
        current = self.list.currentItem()
        keep = current.data(Qt.ItemDataRole.UserRole).get("id") if current else None
        self.list.clear()
        only_open = self.filter.currentIndex() == 0
        seen = set()
        for ev in self._events:
            if only_open:
                # One row per file and detection: a file run five times is one finding.
                key = (ev.get("path"), ev.get("detection"))
                if not is_open(ev) or key in seen:
                    continue
                seen.add(key)
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, ev)
            w = _Row(ev)
            item.setSizeHint(QSize(0, w.sizeHint().height()))
            self.list.addItem(item)
            self.list.setItemWidget(item, w)
        self.empty.setVisible(self.list.count() == 0)
        self.list.setVisible(self.list.count() > 0)
        if self.list.count():
            row = 0
            for i in range(self.list.count()):
                if self.list.item(i).data(Qt.ItemDataRole.UserRole).get("id") == keep:
                    row = i
            self.list.setCurrentRow(row)
        else:
            self._show(None)

    def _selected(self) -> dict | None:
        item = self.list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _show(self, item):
        ev = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.detail.setVisible(ev is not None)
        if not ev:
            return
        lvl = level(ev)
        self.d_title.setText(headline(ev))
        self.d_chip.setText(_CHIP_TEXT[lvl])
        self.d_chip.set_level(lvl)
        self.d_text.setText(explanation(ev))
        exists = bool(ev.get("path")) and os.path.lexists(ev["path"])
        status = {
            "quarantined": "Moved to quarantine",
            "trusted": "Trusted by you",
            "gone": "The file no longer exists; nothing to do",
            "cleared": "No longer flagged by the current signatures (it was a false alarm)",
        }.get(ev.get("resolution", ""), "Waiting for your decision" if is_open(ev) else ev.get("action", ""))
        if is_open(ev) and not exists and ev.get("kind") != "persistence":
            status = "The file no longer exists"
        vals = {
            "File": ev.get("path", ""),
            "Detection": ev.get("detection", ""),
            "Found by": {"hash": "Known-sample list", "yara": "Pattern rules", "clamav": "ClamAV",
                         "persistence": "Startup check"}.get(ev.get("engine", ""), ev.get("engine", "")),
            "Seen": f"{when(ev.get('ts'))} ({ago(ev.get('ts'))})",
            "Process": ev.get("process", "") or "—",
            # Zero-width spaces let the 64-character hash wrap.
            "SHA-256": "\u200b".join(ev.get("sha256", "")[i:i + 16] for i in range(0, 64, 16)) or "—",
            "Status": status,
        }
        for k, v in vals.items():
            self._field_labels[k].setText(v)
        can_act = is_open(ev)
        self.b_quarantine.setVisible(can_act and bool(ev.get("sha256")) and exists)
        self.b_trust.setVisible(can_act)
        self.b_folder.setEnabled(exists)

    # ── Decisions ─────────────────────────────────────────────────────────

    def _busy(self, on: bool):
        for b in (self.b_quarantine, self.b_trust):
            b.setEnabled(not on)

    def _quarantine(self):
        ev = self._selected()
        if not ev:
            return
        self._busy(True)
        self.client.quarantine_event(ev["id"], done=lambda _r: self._done("Moved to quarantine."),
                                     fail=self._failed)

    def _trust(self):
        ev = self._selected()
        if not ev:
            return
        what = "this startup entry" if ev.get("kind") == "persistence" else "this file"
        ans = QMessageBox.question(
            self, "Trust this file?",
            f"Qlam will never report {what} again, even if it changes its mind later.\n\n"
            f"{short_path(ev.get('path', ''), 90)}\n\nOnly do this if you know where it came from.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        self.client.trust_event(ev["id"], done=lambda _r: self._done(None), fail=self._failed)

    def _done(self, _msg):
        self._busy(False)
        self.changed.emit()

    def _failed(self, msg: str):
        self._busy(False)
        QMessageBox.warning(self, "Qlam", msg)
        self.changed.emit()

    def _open_folder(self):
        ev = self._selected()
        if ev and ev.get("path"):
            folder = os.path.dirname(ev["path"])
            subprocess.Popen(["xdg-open", folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class _Row(QWidget):
    def __init__(self, ev: dict, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(12)
        chip = Chip(*chip_for(ev))
        chip.setFixedWidth(84)
        chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(label(headline(ev), "Strong"))
        name = label(os.path.basename(ev.get("path", "")) or ev.get("detection", ""), "Muted")
        name.setMinimumWidth(10)
        text.addWidget(name)
        lay.addLayout(text, 1)
        lay.addWidget(label(ago(ev.get("ts")), "Dim"), 0, Qt.AlignmentFlag.AlignTop)

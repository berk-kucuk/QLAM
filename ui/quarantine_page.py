"""Quarantine: files Qlam moved aside. Stored encoded, so they can't run."""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ui.widgets import label, page_header, short_path, size, when


class QuarantinePage(QWidget):
    changed = pyqtSignal()

    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self._items: list[dict] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(18)
        root.addWidget(page_header(
            "Quarantine",
            "Files moved here are stored encoded and cannot run. Restore one if it was a false alarm."))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["File", "Detection", "Quarantined", "Size"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        hh = self.table.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for c in (1, 2, 3):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._sel_changed)
        root.addWidget(self.table, 1)
        self.empty = label("Quarantine is empty.", "EmptyState")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self.empty, 1)

        btns = QHBoxLayout()
        self.b_restore = QPushButton("Restore…")
        self.b_restore.setObjectName("GhostButton")
        self.b_restore.clicked.connect(self._restore)
        self.b_delete = QPushButton("Delete permanently")
        self.b_delete.setObjectName("DangerButton")
        self.b_delete.clicked.connect(self._delete)
        btns.addWidget(self.b_restore)
        btns.addStretch(1)
        btns.addWidget(self.b_delete)
        root.addLayout(btns)
        self._sel_changed()

    def refresh(self):
        self._items = self.client.quarantine()
        self.table.setRowCount(len(self._items))
        for r, q in enumerate(self._items):
            vals = [short_path(q.get("original_path", ""), 90), q.get("detection", ""),
                    when(q.get("ts")), size(int(q.get("size", 0)))]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setToolTip(q.get("original_path", ""))
                self.table.setItem(r, c, it)
        has = bool(self._items)
        self.table.setVisible(has)
        self.empty.setVisible(not has)
        self.b_restore.setVisible(has)
        self.b_delete.setVisible(has)
        self._sel_changed()

    def _selected(self) -> dict | None:
        rows = self.table.selectionModel().selectedRows()
        return self._items[rows[0].row()] if rows else None

    def _sel_changed(self):
        on = self._selected() is not None
        self.b_restore.setEnabled(on)
        self.b_delete.setEnabled(on)

    def _restore(self):
        q = self._selected()
        if not q:
            return
        ans = QMessageBox.warning(
            self, "Restore this file?",
            f"{q.get('detection')}\n\nRestoring puts this file back where it can run. Only restore it "
            "if you are sure it was a false alarm — Qlam will then trust it and not report it again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        if ans != QMessageBox.StandardButton.Yes:
            return
        dest = q.get("original_path", "")
        if not dest or os.path.lexists(dest) or not os.access(os.path.dirname(dest) or "/", os.W_OK):
            start = dest if dest and os.path.isdir(os.path.dirname(dest)) else os.path.expanduser("~")
            dest, _ = QFileDialog.getSaveFileName(self, "Restore to", start)
            if not dest:
                return
        self.b_restore.setEnabled(False)
        self.client.restore_quarantine(
            q["id"], dest,
            done=lambda _r: self._done(f"Restored to {short_path(dest, 80)}."),
            fail=self._failed)

    def _delete(self):
        q = self._selected()
        if not q:
            return
        ans = QMessageBox.question(
            self, "Delete permanently?",
            f"{short_path(q.get('original_path', ''), 90)}\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.client.delete_quarantine(q["id"], done=lambda _r: self._done(None), fail=self._failed)

    def _done(self, msg):
        self.refresh()
        self.changed.emit()
        if msg:
            QMessageBox.information(self, "Qlam", msg)

    def _failed(self, msg: str):
        self.refresh()
        QMessageBox.warning(self, "Qlam", msg)

import qtawesome as qta
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QAbstractItemView,
)

from core.quarantine_manager import QuarantineManager, QuarantinedFile


class QuarantinePage(QWidget):
    def __init__(self, quarantine_manager: QuarantineManager, parent=None):
        super().__init__(parent)
        self._qm = quarantine_manager
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 0, 32, 32)
        root.setSpacing(0)

        title = QLabel("Quarantine")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("Files that have been isolated due to detected threats")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._restore_btn = QPushButton("  Restore Selected")
        self._restore_btn.setObjectName("WarnButton")
        self._restore_btn.setIcon(qta.icon("fa5s.undo-alt", color="#fbbf24"))
        self._restore_btn.setIconSize(QSize(13, 13))
        self._restore_btn.clicked.connect(self._restore_selected)
        toolbar.addWidget(self._restore_btn)

        self._delete_btn = QPushButton("  Delete Selected")
        self._delete_btn.setObjectName("DangerButton")
        self._delete_btn.setIcon(qta.icon("fa5s.trash", color="#fca5a5"))
        self._delete_btn.setIconSize(QSize(13, 13))
        self._delete_btn.clicked.connect(self._delete_selected)
        toolbar.addWidget(self._delete_btn)

        self._delete_all_btn = QPushButton("  Delete All")
        self._delete_all_btn.setObjectName("DangerButton")
        self._delete_all_btn.setIcon(qta.icon("fa5s.trash-alt", color="#fca5a5"))
        self._delete_all_btn.setIconSize(QSize(13, 13))
        self._delete_all_btn.clicked.connect(self._delete_all)
        toolbar.addWidget(self._delete_all_btn)

        toolbar.addStretch()

        self._count_label = QLabel("0 files in quarantine")
        self._count_label.setObjectName("CardSub")
        toolbar.addWidget(self._count_label)

        root.addLayout(toolbar)
        root.addSpacing(12)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Filename", "Original Path", "Threat", "Date Quarantined", "Size"]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        root.addWidget(self._table)

        self.refresh()

    def refresh(self):
        files = self._qm.list_files()
        self._table.setRowCount(len(files))
        for row, qf in enumerate(files):
            self._table.setItem(row, 0, _item(qf.filename))
            self._table.setItem(row, 1, _item(qf.original_path))
            self._table.setItem(row, 2, _item(qf.threat, "#f85149"))
            self._table.setItem(row, 3, _item(qf.timestamp[:19].replace("T", " ")))
            self._table.setItem(row, 4, _item(self._file_size(qf.quarantine_path)))
            # Store ID in hidden data
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, qf.id)

        n = len(files)
        self._count_label.setText(f"{n} file{'s' if n != 1 else ''} in quarantine")
        self._restore_btn.setEnabled(n > 0)
        self._delete_btn.setEnabled(n > 0)
        self._delete_all_btn.setEnabled(n > 0)

    # ── Actions ───────────────────────────────────────────────────────────

    def _selected_ids(self) -> list[str]:
        rows = set(idx.row() for idx in self._table.selectedIndexes())
        ids = []
        for row in rows:
            item = self._table.item(row, 0)
            if item:
                ids.append(item.data(Qt.ItemDataRole.UserRole))
        return ids

    def _restore_selected(self):
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(self, "No selection", "Select files to restore.")
            return
        reply = QMessageBox.question(
            self, "Restore",
            f"Restore {len(ids)} file(s)? They will return to their original location.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        for qid in ids:
            self._qm.restore_file(qid)
        self.refresh()

    def _delete_selected(self):
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(self, "No selection", "Select files to delete.")
            return
        reply = QMessageBox.question(
            self, "Delete",
            f"Permanently delete {len(ids)} file(s)? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        for qid in ids:
            self._qm.delete_file(qid)
        self.refresh()

    def _delete_all(self):
        n = self._qm.count()
        if n == 0:
            return
        reply = QMessageBox.question(
            self, "Delete All",
            f"Permanently delete all {n} quarantined file(s)? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._qm.delete_all()
        self.refresh()

    @staticmethod
    def _file_size(path: str) -> str:
        try:
            import os
            size = os.path.getsize(path)
            if size < 1024:
                return f"{size} B"
            elif size < 1024 ** 2:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / 1024 ** 2:.1f} MB"
        except Exception:
            return "—"


def _item(text: str, color: str = "") -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if color:
        from PyQt6.QtGui import QColor
        item.setForeground(QColor(color))
    return item

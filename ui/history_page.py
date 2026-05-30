from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QAbstractItemView, QDialog, QTextEdit, QDialogButtonBox,
)
from PyQt6.QtGui import QColor

from core.history_manager import HistoryManager, ScanRecord


class ThreatDetailDialog(QDialog):
    def __init__(self, record: ScanRecord, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Scan Details — {record.scan_type.title()} Scan")
        self.resize(600, 400)

        lay = QVBoxLayout(self)

        info = (
            f"Date: {record.timestamp[:19].replace('T', ' ')}\n"
            f"Type: {record.scan_type.title()} Scan\n"
            f"Targets: {', '.join(record.targets)}\n"
            f"Files scanned: {record.total_files}\n"
            f"Threats found: {record.infected_files}\n"
            f"Duration: {record.duration:.1f}s\n"
        )
        info_label = QLabel(info)
        lay.addWidget(info_label)

        if record.threats:
            t_label = QLabel("Threats:")
            t_label.setStyleSheet("font-weight: bold; color: #f85149;")
            lay.addWidget(t_label)
            text = QTextEdit()
            text.setReadOnly(True)
            for t in record.threats:
                text.append(f"{t.get('path', '')}  →  {t.get('threat', '')}")
            lay.addWidget(text)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.accept)
        lay.addWidget(bb)


class HistoryPage(QWidget):
    def __init__(self, history_manager: HistoryManager, parent=None):
        super().__init__(parent)
        self._hm = history_manager
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 0, 32, 32)
        root.setSpacing(0)

        title = QLabel("Scan History")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        sub = QLabel("Record of all previous scans")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        details_btn = QPushButton("View Details")
        details_btn.setObjectName("GhostButton")
        details_btn.clicked.connect(self._view_details)
        toolbar.addWidget(details_btn)

        toolbar.addStretch()

        clear_btn = QPushButton("Clear History")
        clear_btn.setObjectName("DangerButton")
        clear_btn.clicked.connect(self._clear)
        toolbar.addWidget(clear_btn)

        root.addLayout(toolbar)
        root.addSpacing(12)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            ["Date", "Type", "Files Scanned", "Threats", "Duration", "Status"]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.doubleClicked.connect(self._view_details)
        root.addWidget(self._table)

        self.refresh()

    def refresh(self):
        records = self._hm.get_records()
        self._table.setRowCount(len(records))
        for row, rec in enumerate(records):
            self._table.setItem(row, 0, _item(rec.timestamp[:19].replace("T", " ")))
            self._table.setItem(row, 1, _item(rec.scan_type.title()))
            self._table.setItem(row, 2, _item(str(rec.total_files)))
            self._table.setItem(row, 3, _item(str(rec.infected_files),
                                               "#f85149" if rec.infected_files > 0 else ""))
            self._table.setItem(row, 4, _item(f"{rec.duration:.1f}s"))

            status_item = _item(rec.status)
            if rec.infected_files > 0:
                status_item.setForeground(QColor("#f85149"))
            else:
                status_item.setForeground(QColor("#3fb950"))
            self._table.setItem(row, 5, status_item)

            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, row)

        self._records = records

    def _selected_record(self) -> ScanRecord | None:
        rows = set(idx.row() for idx in self._table.selectedIndexes())
        if not rows:
            return None
        row = next(iter(rows))
        if row < len(self._records):
            return self._records[row]
        return None

    def _view_details(self):
        rec = self._selected_record()
        if rec is None:
            QMessageBox.information(self, "No selection", "Select a scan record to view details.")
            return
        dlg = ThreatDetailDialog(rec, self)
        dlg.exec()

    def _clear(self):
        reply = QMessageBox.question(
            self, "Clear History",
            "Delete all scan history records? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._hm.clear()
            self.refresh()


def _item(text: str, color: str = "") -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if color:
        item.setForeground(QColor(color))
    return item

import qtawesome as qta
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QDialogButtonBox, QFrame,
)

from ui.theme import theme


class SudoDialog(QDialog):
    def __init__(self, reason: str = "This operation requires administrator privileges.",
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Required")
        self.setFixedWidth(400)
        self.setModal(True)
        self._build_ui(reason)

    def _build_ui(self, reason: str):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 20)
        lay.setSpacing(16)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(14)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            qta.icon("fa5s.lock", color=theme.p["text_mid"]).pixmap(QSize(28, 28))
        )
        header.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(3)
        t = QLabel("Authentication Required")
        t.setObjectName("Strong")
        t.setStyleSheet("font-size: 15px; font-weight: 700;")
        title_col.addWidget(t)
        s = QLabel(reason)
        s.setObjectName("Muted")
        s.setWordWrap(True)
        title_col.addWidget(s)
        header.addLayout(title_col)
        lay.addLayout(header)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        lay.addWidget(sep)

        # Password field
        pwd_lbl = QLabel("Password:")
        pwd_lbl.setObjectName("Muted")
        lay.addWidget(pwd_lbl)

        self._pwd_field = QLineEdit()
        self._pwd_field.setEchoMode(QLineEdit.EchoMode.Password)
        self._pwd_field.setPlaceholderText("Enter your password")
        self._pwd_field.returnPressed.connect(self._on_accept)
        lay.addWidget(self._pwd_field)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel = QPushButton("Cancel")
        cancel.setMinimumWidth(96)
        cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        btn_row.addWidget(cancel)

        ok = QPushButton("Authenticate")
        ok.setObjectName("PrimaryButton")
        ok.setMinimumWidth(140)
        ok.setCursor(Qt.CursorShape.PointingHandCursor)
        ok.clicked.connect(self._on_accept)
        btn_row.addWidget(ok)
        lay.addLayout(btn_row)

    def _on_accept(self):
        if self._pwd_field.text():
            self.accept()

    def password(self) -> str:
        return self._pwd_field.text()

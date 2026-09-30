"""Settings: protection (system-wide, needs admin) and this user's preferences."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QMessageBox, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from ui.theme import load_prefs, save_pref, save_theme, theme
from ui.widgets import Card, ago, label, page_header

_AUTOSTART_OVERRIDE = Path.home() / ".config" / "autostart" / "qlam-tray.desktop"


class _Toggle(QWidget):
    """Checkbox with a title and an explanation underneath."""

    def __init__(self, title: str, text: str, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(3)
        self.box = QCheckBox(title)
        self.box.setStyleSheet("font-weight: 600;")
        lay.addWidget(self.box)
        t = label(text, "Muted", wrap=True)
        t.setContentsMargins(27, 0, 0, 0)
        lay.addWidget(t)


class SettingsPage(QWidget):
    prefs_changed = pyqtSignal()

    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self._loading = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        inner = QWidget()
        scroll.setWidget(inner)
        root = QVBoxLayout(inner)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(18)
        root.addWidget(page_header("Settings", "Protection settings apply to everyone on this computer "
                                               "and ask for an administrator password."))

        # ── Protection ────────────────────────────────────────────────────
        prot = Card()
        prot.body.addWidget(label("PROTECTION", "SectionLabel"))
        self.t_rt = _Toggle("Real-time protection",
                            "Check files as they are downloaded or created, and before they run.")
        self.t_block = _Toggle("Also stop known malware from running",
                               "Off by default. Qlam warns about files you run either way; with this on, "
                               "files identical to a known malware sample are also stopped. Every program "
                               "start then briefly waits for Qlam's check.")
        self.t_autoq = _Toggle("Move known malware to quarantine automatically",
                               "Off by default: Qlam tells you and you decide. When on, this applies only "
                               "to exact matches with known malware, never to pattern-based warnings.")
        for t, key in ((self.t_rt, "realtime"), (self.t_block, "block_exec"), (self.t_autoq, "auto_quarantine")):
            t.box.toggled.connect(lambda on, k=key, box=t.box: self._set_option(k, on, box))
            prot.body.addWidget(t)
        root.addWidget(prot)

        # ── Signatures ────────────────────────────────────────────────────
        sig = Card()
        sig.body.addWidget(label("SIGNATURES", "SectionLabel"))
        self.sig_text = label("", "Muted", wrap=True)
        sig.body.addWidget(self.sig_text)
        r = QHBoxLayout()
        self.b_update = QPushButton("Update now")
        self.b_update.setObjectName("GhostButton")
        self.b_update.clicked.connect(self._update)
        r.addWidget(self.b_update)
        r.addStretch(1)
        sig.body.addLayout(r)
        root.addWidget(sig)

        # ── This user ─────────────────────────────────────────────────────
        me = Card()
        me.body.addWidget(label("YOUR PREFERENCES", "SectionLabel"))
        self.t_tray = _Toggle("Start Qlam in the tray when I log in",
                              "Needed to see warnings as pop-ups. Protection itself runs either way.")
        self.t_tray.box.toggled.connect(self._set_autostart)
        me.body.addWidget(self.t_tray)
        self.t_notice = _Toggle("Pop up for minor notices too",
                                "By default only real warnings pop up; minor notices wait in Findings.")
        self.t_notice.box.toggled.connect(lambda on: self._pref("notify_notices", on))
        me.body.addWidget(self.t_notice)
        tr = QHBoxLayout()
        tr.addWidget(label("Appearance", "Strong"))
        tr.addStretch(1)
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Dark", "Light"])
        self.theme_box.currentIndexChanged.connect(self._set_theme)
        tr.addWidget(self.theme_box)
        me.body.addLayout(tr)
        root.addWidget(me)

        # ── About ─────────────────────────────────────────────────────────
        about = Card()
        about.body.addWidget(label("ABOUT", "SectionLabel"))
        self.about = label("", "Muted", wrap=True, selectable=True)
        self.about.setTextFormat(Qt.TextFormat.RichText)
        self.about.setOpenExternalLinks(True)
        about.body.addWidget(self.about)
        root.addWidget(about)
        root.addStretch(1)

        self._load_prefs()

    # ── Status → widgets ──────────────────────────────────────────────────

    def set_status(self, st: dict):
        self._loading = True
        rt = st.get("realtime", {})
        self.t_rt.box.setChecked(bool(rt.get("enabled")))
        self.t_block.box.setChecked(bool(rt.get("block_exec")))
        self.t_autoq.box.setChecked(bool(rt.get("auto_quarantine")))
        self._loading = False
        on = bool(st)
        for t in (self.t_rt, self.t_block, self.t_autoq):
            t.setEnabled(on)
        self.t_block.setEnabled(on and bool(rt.get("enabled")))
        self.b_update.setEnabled(on)

        eng, feeds = st.get("engines", {}), st.get("feeds", {})
        lines = [
            f"{int(eng.get('hashes', 0)):,} known malware samples (MalwareBazaar, family-attributed only)",
            f"{int(eng.get('yara_rules', 0)):,} pattern rules (Qlam + YARA Forge core)",
            "ClamAV engine: " + ("in use" if eng.get("clamav") else
                                  "not running (optional — enable clamav-daemon for extra coverage, ~1 GB RAM)"),
            f"Last update: {ago(feeds.get('updated_at'))}",
        ]
        if feeds.get("errors"):
            lines.append("Last update had problems: " + "; ".join(feeds["errors"]))
        self.sig_text.setText("\n".join(lines))
        self.about.setText(
            f"Qlam {st.get('version', '?')} · open source, MIT licensed<br>"
            "Detection data: MalwareBazaar (abuse.ch), YARA Forge, optionally ClamAV.<br>"
            '<a href="https://github.com/berk-kucuk/QLAM">github.com/berk-kucuk/QLAM</a>')

    # ── Actions ───────────────────────────────────────────────────────────

    def _set_option(self, key: str, on: bool, box: QCheckBox):
        if self._loading:
            return
        box.setEnabled(False)

        def failed(msg):
            box.setEnabled(True)
            self._loading = True
            box.setChecked(not on)
            self._loading = False
            QMessageBox.warning(self, "Qlam", msg)

        self.client.set_option(key, on, done=lambda _r: (box.setEnabled(True), self.client.refresh_status()),
                               fail=failed)

    def _update(self):
        self.b_update.setEnabled(False)
        self.b_update.setText("Updating…")

        def finish(msg=None):
            self.b_update.setEnabled(True)
            self.b_update.setText("Update now")
            if msg:
                QMessageBox.warning(self, "Qlam", msg)

        # The update runs in the background as its own service; the status
        # refreshes by itself when new signatures are loaded.
        self.client.update_signatures(done=lambda _r: finish(), fail=finish)

    def _load_prefs(self):
        prefs = load_prefs()
        self._loading = True
        self.t_notice.box.setChecked(bool(prefs.get("notify_notices", False)))
        self.t_tray.box.setChecked(not _AUTOSTART_OVERRIDE.exists())
        self.theme_box.setCurrentIndex(0 if theme.name == "dark" else 1)
        self._loading = False

    def sync_theme(self):
        """Follow a theme change made elsewhere (the title bar)."""
        self._loading = True
        self.theme_box.setCurrentIndex(0 if theme.name == "dark" else 1)
        self._loading = False

    def _pref(self, key, value):
        if not self._loading:
            save_pref(key, value)
            self.prefs_changed.emit()

    def _set_theme(self, idx: int):
        if self._loading:
            return
        name = "dark" if idx == 0 else "light"
        theme.set(name)
        save_theme(name)

    def _set_autostart(self, on: bool):
        """The package starts the tray for everyone via /etc/xdg/autostart;
        a user opts out with a Hidden=true override in their own autostart."""
        if self._loading:
            return
        try:
            if on:
                _AUTOSTART_OVERRIDE.unlink(missing_ok=True)
            else:
                _AUTOSTART_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
                _AUTOSTART_OVERRIDE.write_text("[Desktop Entry]\nType=Application\nName=Qlam\nHidden=true\n")
        except OSError as e:
            QMessageBox.warning(self, "Qlam", f"Could not change autostart: {e.strerror}")

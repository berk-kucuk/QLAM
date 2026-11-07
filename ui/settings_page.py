"""Settings: protection (system-wide, needs admin) and this user's preferences."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLineEdit,
    QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from ui.theme import load_prefs, save_pref, save_theme, theme
from ui.widgets import Card, ago, label, page_header, update_text, when

_AUTOSTART_OVERRIDE = Path.home() / ".config" / "autostart" / "qlam-tray.desktop"

# (frequency, kind, label) for the scheduled scan selector.
_SCHEDULES = [
    ("off", "quick", "Off"),
    ("weekly", "quick", "Weekly quick scan"),
    ("daily", "quick", "Daily quick scan"),
    ("weekly", "home", "Weekly home folder scan"),
    ("daily", "home", "Daily home folder scan"),
]


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


class _KeyDialog(QDialog):
    """Ask for the abuse.ch Auth-Key. accept() with key() == "" means remove."""

    def __init__(self, has_key: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("abuse.ch Auth-Key")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(12)
        lay.addWidget(label("abuse.ch Auth-Key", "Strong"))
        info = label(
            "Qlam's lists of known malware and malware download sites come from abuse.ch "
            "(MalwareBazaar, ThreatFox, URLhaus), which asks for a free Auth-Key. Sign in at "
            '<a href="https://auth.abuse.ch/">auth.abuse.ch</a> (GitHub, Google or X account), '
            "copy your Auth-Key from the profile page and paste it here.<br><br>"
            "The key is stored on this computer, readable only by Qlam, and used for nothing "
            "but downloading the lists.", "Muted", wrap=True)
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setOpenExternalLinks(True)
        lay.addWidget(info)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText("Paste your Auth-Key" if not has_key else "Paste a new Auth-Key")
        lay.addWidget(self.edit)
        self._remove = False
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.b_save = buttons.button(QDialogButtonBox.StandardButton.Save)
        self.b_save.setEnabled(False)
        self.edit.textChanged.connect(lambda t: self.b_save.setEnabled(bool(t.strip())))
        if has_key:
            rm = buttons.addButton("Remove key", QDialogButtonBox.ButtonRole.DestructiveRole)
            rm.clicked.connect(self._remove_key)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _remove_key(self):
        self._remove = True
        self.accept()

    def key(self) -> str:
        return "" if self._remove else self.edit.text().strip()


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
        self.t_behav = _Toggle("Watch running programs",
                               "Notices programs that act like malware: running from memory or from a deleted "
                               "file, posing as a system process, remote shells, cryptominers. Only reports; "
                               "never stops anything.")
        for t, key in ((self.t_rt, "realtime"), (self.t_block, "block_exec"), (self.t_autoq, "auto_quarantine"),
                       (self.t_behav, "behavior_monitor")):
            t.box.toggled.connect(lambda on, k=key, box=t.box: self._set_option(k, on, box))
            prot.body.addWidget(t)

        sched = QVBoxLayout()
        sched.setContentsMargins(0, 8, 0, 4)
        sched.setSpacing(3)
        sr = QHBoxLayout()
        sr.addWidget(label("Scheduled scan", "Strong"))
        sr.addStretch(1)
        self.sched_box = QComboBox()
        self.sched_box.addItems([s[2] for s in _SCHEDULES])
        self.sched_box.currentIndexChanged.connect(self._set_schedule)
        sr.addWidget(self.sched_box)
        sched.addLayout(sr)
        self.sched_text = label("Also catches what arrived while protection was off, and what new signatures "
                                "recognise. Runs for every user, on mains power, after the computer has been "
                                "on for a while.", "Muted", wrap=True)
        sched.addWidget(self.sched_text)
        prot.body.addLayout(sched)
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
        self.b_key = QPushButton("Set abuse.ch Auth-Key…")
        self.b_key.setObjectName("GhostButton")
        self.b_key.clicked.connect(self._set_key)
        r.addWidget(self.b_key)
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
        self.t_behav.box.setChecked(bool(rt.get("behavior_monitor")))
        self._loading = False
        on = bool(st)
        for t in (self.t_rt, self.t_block, self.t_autoq, self.t_behav):
            t.setEnabled(on)
        self.t_block.setEnabled(on and bool(rt.get("enabled")))
        upd = st.get("update")
        self.b_update.setEnabled(on and not upd)
        self.b_update.setText("Updating…" if upd else "Update now")

        sch = st.get("schedule") or {}
        idx = next((i for i, (f, k, _) in enumerate(_SCHEDULES)
                    if f == sch.get("frequency") and (f == "off" or k == sch.get("depth"))), 0)
        self._loading = True
        self.sched_box.setCurrentIndex(idx)
        self._loading = False
        self.sched_box.setEnabled(on and not st.get("session"))
        self._sched_idx = idx
        base = ("Also catches what arrived while protection was off, and what new signatures recognise. "
                "Runs for every user, on mains power, after the computer has been on for a while.")
        if sch.get("frequency", "off") != "off" and sch.get("next"):
            base += f"\nNext: {when(sch['next'])}"
            if sch.get("last"):
                base += f" · last: {ago(sch['last'])}"
        self.sched_text.setText(base)
        self.b_key.setEnabled(on)
        self._has_key = bool(st.get("abusech_key_set"))
        self.b_key.setText("Change abuse.ch Auth-Key…" if self._has_key else "Set abuse.ch Auth-Key…")

        eng, feeds = st.get("engines", {}), st.get("feeds", {})
        lines = [
            f"{int(eng.get('hashes', 0)):,} known malware samples (MalwareBazaar and ThreatFox, Linux families)",
            f"{int(eng.get('urls', 0)):,} malware download addresses (URLhaus)",
            f"{int(eng.get('yara_rules', 0)):,} pattern rules (Qlam + YARA Forge core)",
            "Archives and packages are checked inside: zip, jar, tar, deb, rpm, gz, xz, bz2, zst",
            "ClamAV engine: " + ("in use" if eng.get("clamav") else
                                  "not running (optional — enable clamav-daemon for extra coverage, ~1 GB RAM)"),
        ]
        if upd:
            lines.append(f"Updating now — {update_text(upd)}…")
        else:
            lists = [(n, feeds.get(k) or {}) for n, k in
                     (("MalwareBazaar", "malwarebazaar"), ("ThreatFox", "threatfox"), ("URLhaus", "urlhaus"))]
            got = [f"{n} {int(l.get('entries', 0)):,}" for n, l in lists if l.get("updated_at")]
            lines.append(f"Last update: {ago(feeds.get('updated_at'))}"
                         + (f" ({' · '.join(got)})" if got else ""))
        if not self._has_key:
            lines.append("The known-malware lists are not being updated: abuse.ch needs a free "
                         "Auth-Key. Set one below.")
        elif feeds.get("abusech_key") == "rejected":
            lines.append("abuse.ch did not accept the Auth-Key. Check it on auth.abuse.ch and set it again.")
        errors = [e for e in feeds.get("errors", []) if "Auth-Key" not in e]
        if errors and not upd:
            lines.append("Last update had problems: " + "; ".join(errors))
        self.sig_text.setText("\n".join(lines))
        self.about.setText(
            f"Qlam {st.get('version', '?')} · open source, MIT licensed<br>"
            "Detection data: MalwareBazaar, ThreatFox and URLhaus (abuse.ch), YARA Forge, "
            "optionally ClamAV.<br>"
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

        def failed(msg):
            self.b_update.setEnabled(True)
            self.b_update.setText("Update now")
            QMessageBox.warning(self, "Qlam", msg)

        # The update runs in the background as its own service. The daemon
        # reports its progress, which keeps this button on "Updating…" and
        # shows what it's doing until it's done.
        self.client.update_signatures(done=lambda _r: self.client.refresh_status(), fail=failed)

    def _set_schedule(self, idx: int):
        if self._loading or idx < 0:
            return
        freq, kind, _ = _SCHEDULES[idx]
        self.sched_box.setEnabled(False)

        def failed(msg):
            self._loading = True
            self.sched_box.setCurrentIndex(getattr(self, "_sched_idx", 0))
            self._loading = False
            self.sched_box.setEnabled(True)
            QMessageBox.warning(self, "Qlam", msg)

        def done(_r):
            self._sched_idx = idx
            self.sched_box.setEnabled(True)
            self.client.refresh_status()

        self.client.set_schedule(freq, kind, done=done, fail=failed)

    def _set_key(self):
        dlg = _KeyDialog(getattr(self, "_has_key", False), self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self.b_key.setEnabled(False)

        def finish(msg=None):
            self.b_key.setEnabled(True)
            self.client.refresh_status()
            if msg:
                QMessageBox.warning(self, "Qlam", msg)

        self.client.set_abusech_key(dlg.key(), done=lambda _r: finish(), fail=finish)

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

"""Overview: one clear answer to "am I OK?", then the parts that make it up."""
from __future__ import annotations

import time

import qtawesome as qta
from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
    QVBoxLayout, QWidget,
)

from ui.theme import theme
from ui.widgets import Card, Chip, ago, chip_for, headline, label, page_header, short_path


class _Component(Card):
    """A card describing one part of the protection."""

    def __init__(self, icon: str, title: str, parent=None):
        super().__init__(parent)
        self._icon_name = icon
        top = QHBoxLayout()
        top.setSpacing(10)
        self.icon = QLabel()
        self.title = label(title.upper(), "StatLabel")
        self.chip = Chip("…")
        top.addWidget(self.icon)
        top.addWidget(self.title)
        top.addStretch(1)
        top.addWidget(self.chip)
        self.body.addLayout(top)
        self.value = label("—", "StatValue")
        self.detail = label("", "Muted", wrap=True)
        self.body.addWidget(self.value)
        self.body.addWidget(self.detail)
        self.body.addStretch(1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(8)
        self.body.addLayout(self.actions)
        self.retint()

    def retint(self):
        self.icon.setPixmap(qta.icon(self._icon_name, color=theme.p["text_mid"]).pixmap(QSize(16, 16)))


class OverviewPage(QWidget):
    go_alerts = pyqtSignal()
    go_scan = pyqtSignal()
    go_settings = pyqtSignal()
    quick_scan = pyqtSignal()
    update_signatures = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(20)
        root.addWidget(page_header("Overview", "Protection status for your files"))

        # Hero: the single most important sentence.
        self.hero = Card()
        self.hero.setObjectName("Hero")
        hl = QHBoxLayout()
        hl.setSpacing(18)
        self.hero_icon = QLabel()
        self.hero_icon.setFixedSize(52, 52)
        txt = QVBoxLayout()
        txt.setSpacing(4)
        self.hero_title = label("Connecting to Qlam…", "HeroTitle")
        self.hero_text = label("", "HeroText", wrap=True)
        txt.addWidget(self.hero_title)
        txt.addWidget(self.hero_text)
        self.hero_btn = QPushButton()
        self.hero_btn.setObjectName("PrimaryButton")
        self.hero_btn.clicked.connect(self._hero_action)
        hl.addWidget(self.hero_icon)
        hl.addLayout(txt, 1)
        hl.addWidget(self.hero_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        self.hero.body.addLayout(hl)
        self.hero.body.setContentsMargins(24, 22, 24, 22)
        root.addWidget(self.hero)
        self._hero_target = None

        # Components.
        grid = QGridLayout()
        grid.setSpacing(14)
        self.rt = _Component("fa5s.shield-alt", "Real-time protection")
        self.sigs = _Component("fa5s.database", "Signatures")
        self.last = _Component("fa5s.search", "Last scan")
        b = QPushButton("Settings")
        b.setObjectName("GhostButton")
        b.clicked.connect(self.go_settings)
        self.rt.actions.addWidget(b)
        self.rt.actions.addStretch(1)
        self.update_btn = QPushButton("Update now")
        self.update_btn.setObjectName("GhostButton")
        self.update_btn.clicked.connect(self.update_signatures)
        self.sigs.actions.addWidget(self.update_btn)
        self.sigs.actions.addStretch(1)
        qs = QPushButton("Quick scan")
        qs.setObjectName("GhostButton")
        qs.clicked.connect(self.quick_scan)
        more = QPushButton("More scans")
        more.setObjectName("GhostButton")
        more.clicked.connect(self.go_scan)
        self.last.actions.addWidget(qs)
        self.last.actions.addWidget(more)
        self.last.actions.addStretch(1)
        for i, c in enumerate((self.rt, self.sigs, self.last)):
            c.setMinimumHeight(170)
            grid.addWidget(c, 0, i)
        root.addLayout(grid)

        # Recent activity.
        head = QHBoxLayout()
        head.addWidget(label("RECENT ACTIVITY", "SectionLabel"))
        head.addStretch(1)
        all_btn = QPushButton("All findings")
        all_btn.setObjectName("GhostButton")
        all_btn.clicked.connect(self.go_alerts)
        head.addWidget(all_btn)
        root.addLayout(head)
        self.activity = QListWidget()
        self.activity.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.activity.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.activity.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.activity.itemClicked.connect(lambda _i: self.go_alerts.emit())
        root.addWidget(self.activity, 1)
        self.empty = label("Nothing to report. Qlam will let you know if something needs you.", "EmptyState")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self.empty, 1)

        self._status: dict = {}
        self._connected = True
        theme.changed.connect(lambda _p: self._retint())

    # ── Updates ───────────────────────────────────────────────────────────

    def _retint(self):
        for c in (self.rt, self.sigs, self.last):
            c.retint()
        self.set_status(self._status, self._connected)

    def _set_hero(self, state: str, icon: str, color: str, title: str, text: str, button: str | None, target):
        self.hero.setProperty("state", state)
        self.hero.style().unpolish(self.hero)
        self.hero.style().polish(self.hero)
        self.hero_icon.setPixmap(qta.icon(icon, color=color).pixmap(QSize(48, 48)))
        self.hero_title.setText(title)
        self.hero_text.setText(text)
        self.hero_btn.setVisible(button is not None)
        if button:
            self.hero_btn.setText(button)
        self._hero_target = target

    def _hero_action(self):
        if self._hero_target:
            self._hero_target()

    def set_status(self, st: dict, connected: bool = True):
        self._status, self._connected = st, connected
        p = theme.p
        if not connected or not st:
            self._set_hero("notice", "fa5s.plug", p["text_mid"], "Qlam service is not running",
                           "The protection service (qlamd) could not be reached. "
                           "Enable it with: sudo systemctl enable --now qlamd", None, None)
            for c in (self.rt, self.sigs, self.last):
                c.chip.setText("unknown")
                c.chip.set_level("info")
            return

        rt = st.get("realtime", {})
        user = st.get("user", {})
        eng = st.get("engines", {})
        feeds = st.get("feeds", {})
        open_n = int(user.get("open_findings", 0))

        # Hero, in order of what matters most.
        if open_n:
            self._set_hero("attention", "fa5s.exclamation-triangle", p["bad"],
                           f"{open_n} finding{'s' if open_n > 1 else ''} to review",
                           "Qlam found something and is waiting for your decision. "
                           "Nothing has been deleted or moved.", "Review", self.go_alerts.emit)
        elif not rt.get("active"):
            why = rt.get("error") or ("turned off in settings" if not rt.get("enabled") else "not running")
            if st.get("session"):
                why = "development instance"
            self._set_hero("notice", "fa5s.shield-alt", p["warn"], "Real-time protection is off",
                           f"Files are only checked when you run a scan ({why}).",
                           "Settings", self.go_settings.emit)
        elif rt.get("actions_paused"):
            self._set_hero("notice", "fa5s.pause-circle", p["warn"], "Automatic blocking is paused",
                           "Qlam saw an unusual number of detections and paused automatic blocking "
                           "for an hour as a precaution. Findings are still reported.",
                           "Review", self.go_alerts.emit)
        else:
            stopped = " Known malware is also stopped before it can run." if rt.get("block_exec") else ""
            self._set_hero("ok", "fa5s.shield-alt", p["good"], "You're protected",
                           "New files and programs you run are checked, and you are warned "
                           "if something looks wrong." + stopped, None, None)

        # Real-time.
        if rt.get("active"):
            self.rt.chip.setText("On")
            self.rt.chip.set_level("good")
            stats = rt.get("stats") or {}
            self.rt.value.setText(f"{int(stats.get('writes_scanned', 0)) + int(stats.get('exec_checked', 0)):,}")
            blocked = int(stats.get("exec_blocked", 0))
            self.rt.detail.setText(
                "files checked since start"
                + (f" · {blocked} blocked" if blocked else "")
                + (" · known malware is stopped" if rt.get("block_exec") else " · warn only"))
        else:
            self.rt.chip.setText("Off")
            self.rt.chip.set_level("warn")
            self.rt.value.setText("Off")
            self.rt.detail.setText(rt.get("error") or "Only on-demand scans are active.")

        # Signatures.
        hashes, rules = int(eng.get("hashes", 0)), int(eng.get("yara_rules", 0))
        updated = feeds.get("updated_at")
        stale = not updated or (time.time() - updated) > 3 * 86400
        self.sigs.value.setText(f"{hashes:,}")
        extra = " · ClamAV on" if eng.get("clamav") else ""
        self.sigs.detail.setText(f"known malware samples · {rules:,} rules{extra}\nupdated {ago(updated)}")
        if hashes == 0:
            self.sigs.chip.setText("Missing")
            self.sigs.chip.set_level("warn")
        elif stale:
            self.sigs.chip.setText("Out of date")
            self.sigs.chip.set_level("warn")
        else:
            self.sigs.chip.setText("Up to date")
            self.sigs.chip.set_level("good")
        if feeds.get("errors"):
            self.sigs.detail.setToolTip("\n".join(feeds["errors"]))

        # Last scan.
        last = user.get("last_scan")
        if user.get("running_scans"):
            self.last.chip.setText("Running")
            self.last.chip.set_level("info")
        elif last:
            found = int(last.get("detections", 0)) + int(last.get("suspicious", 0))
            self.last.chip.setText("Clean" if not found else f"{found} found")
            self.last.chip.set_level("good" if not found else "warn")
        else:
            self.last.chip.setText("Never")
            self.last.chip.set_level("info")
        if last:
            self.last.value.setText(ago(last.get("finished") or last.get("started")))
            self.last.detail.setText(f"{last.get('kind', '').capitalize()} scan · {int(last.get('files', 0)):,} files")
        else:
            self.last.value.setText("No scans yet")
            self.last.detail.setText("A quick scan takes about a minute.")

    def set_events(self, events: list[dict]):
        self.activity.clear()
        recent = events[:6]
        self.activity.setVisible(bool(recent))
        self.empty.setVisible(not recent)
        for ev in recent:
            item = QListWidgetItem()
            w = _ActivityRow(ev)
            item.setSizeHint(QSize(0, w.sizeHint().height()))
            self.activity.addItem(item)
            self.activity.setItemWidget(item, w)


class _ActivityRow(QWidget):
    def __init__(self, ev: dict, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(12)
        chip = Chip(*chip_for(ev))
        chip.setFixedWidth(84)
        chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(chip)
        text = QVBoxLayout()
        text.setSpacing(1)
        text.addWidget(label(headline(ev), "Strong"))
        where = label(short_path(ev.get("path", ""), 80) or ev.get("detection", ""), "Muted")
        where.setMinimumWidth(10)
        text.addWidget(where)
        lay.addLayout(text, 1)
        lay.addWidget(label(ago(ev.get("ts")), "Dim"))

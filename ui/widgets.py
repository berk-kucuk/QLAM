"""Shared widgets and the wording used to explain findings to the user."""
from __future__ import annotations

import os
import time
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget


# ── Formatting ─────────────────────────────────────────────────────────────

def ago(ts: int | float | None) -> str:
    if not ts:
        return "never"
    d = time.time() - float(ts)
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    if d < 7 * 86400:
        n = int(d // 86400)
        return f"{n} day{'s' if n > 1 else ''} ago"
    return datetime.fromtimestamp(ts).strftime("%d %b %Y")


def when(ts: int | float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "—"


def short_path(path: str, keep: int = 60) -> str:
    home = os.path.expanduser("~")
    if path.startswith(home + "/"):
        path = "~" + path[len(home):]
    if len(path) <= keep:
        return path
    return "…" + path[-(keep - 1):]


def size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


# ── What a finding means, in plain words ───────────────────────────────────

def level(ev: dict) -> str:
    """'danger' | 'warn' | 'notice' | 'info' — drives colour and wording."""
    kind = ev.get("kind", "")
    if kind == "safety-pause":
        return "info"
    if ev.get("severity") == "malicious":
        return "danger" if ev.get("confirmed") else "warn"
    return "notice"


def chip_for(ev: dict) -> tuple[str, str]:
    """(text, level) for the small status chip of a finding."""
    settled = ev.get("resolution") or ("quarantined" if ev.get("kind") == "quarantined" else "")
    if settled == "gone":
        return "Gone", "info"
    if settled:
        return settled.capitalize(), "good"
    lvl = level(ev)
    return {"danger": "Malware", "warn": "Warning", "notice": "Notice", "info": "Info"}[lvl], lvl


# Must match qlamd's engine::IN_ARCHIVE.
_IN_ARCHIVE = " in archive member "


def archive_member(ev: dict) -> tuple[str, str] | None:
    """(detection, member path) for a finding about a file inside an archive."""
    if not ev.get("engine", "").startswith("archive:"):
        return None
    name, sep, member = ev.get("detection", "").rpartition(_IN_ARCHIVE)
    return (name, member) if sep else None


def headline(ev: dict) -> str:
    kind = ev.get("kind", "")
    if kind == "safety-pause":
        return "Automatic blocking paused"
    if kind == "blocked":
        return "Known malware was stopped"
    if kind == "quarantined":
        return "File moved to quarantine"
    if kind == "persistence":
        return "Unusual startup entry"
    if kind == "rootkit":
        return "Signs of a rootkit" if ev.get("severity") == "malicious" else "Unusual system setting"
    if kind == "behavior":
        return "A program is behaving like malware" if ev.get("severity") == "malicious" else "Unusual program behaviour"
    if ev.get("engine") == "urlhaus":
        return "Downloaded from a malware site"
    inside = archive_member(ev)
    if inside and ev.get("severity") == "malicious":
        return "Malware inside an archive" if inside[0].endswith("(known sample)") else "Possible malware inside an archive"
    if ev.get("severity") == "malicious":
        return "Known malware found" if ev.get("confirmed") else "Possible malware"
    return "Worth a look"


def explanation(ev: dict) -> str:
    name = ev.get("detection", "")
    kind = ev.get("kind", "")
    if kind == "safety-pause":
        return ev.get("action", "")
    if kind in ("behavior", "rootkit"):
        detail = ev.get("action", "").removeprefix("no changes made: ")
        proc = ev.get("process") or "A program"
        if kind == "rootkit":
            text = ("Qlam found a sign that something is hiding on this computer:\n\n"
                    f"    {detail}\n\n")
            text += ("Rootkits hide processes, files and kernel modules from the tools you'd use to "
                     "find them. If this is confirmed, the safest way out is to back up your files "
                     "and reinstall the system." if ev.get("severity") == "malicious" else
                     "Some tools set this up on purpose. If you didn't, it's worth finding out what did.")
            return text
        text = f"{proc} {detail}.\n\n"
        text += ("This is what malware does once it runs. Qlam hasn't stopped or changed anything. "
                 "If you don't know this program, end it (for example with your system monitor) and run "
                 "a scan of your home folder." if ev.get("severity") == "malicious" else
                 "Some legitimate programs do this too, such as installers and developer tools. "
                 "If you recognise it, mark it as trusted and Qlam won't mention it again.")
        return text
    if kind == "persistence":
        detail = ev.get("action", "").removeprefix("no changes made: ")
        return (
            "A setting that runs automatically when you log in contains a command "
            "in a form malware often uses to keep itself running:\n\n"
            f"    {detail}\n\n"
            "If you added this yourself, mark it as trusted and Qlam won't mention it again."
        )
    if ev.get("engine") == "urlhaus":
        family = name.removeprefix("URLhaus.MalwareDownload").lstrip(".")
        what = f" ({family})" if family else ""
        return (
            "This file was downloaded from an address that URLhaus, a public list of "
            f"malware distribution sites, lists as spreading malware{what}. Whatever the "
            "file looks like, where it came from is reason enough not to open it.\n\n"
            "Moving it to quarantine is recommended. Nothing has been changed yet."
        )
    inside = archive_member(ev)
    if inside:
        found, member = inside
        if found.endswith("(known sample)"):
            family = found.removesuffix(" (known sample)")
            text = (f"This archive contains a file, {member}, that is byte-for-byte identical to "
                    f"a known sample of {family}.")
        elif ev.get("severity") == "malicious":
            text = (f"This archive contains a file, {member}, that matches a pattern ({found}) "
                    "characteristic of malware. Pattern matches can occasionally be wrong.")
        else:
            text = (f"This archive contains a file, {member}, with traits ({found}) that malware "
                    "and hacking tools sometimes share. It is often harmless.")
        return text + ("\n\nNothing inside has been unpacked or run. If you don't need this archive, "
                       "moving it to quarantine is the safe choice; if you trust where it came from, "
                       "mark it as trusted.")
    if name.startswith("Qlam.Heur.ELF (") and name.endswith(")"):
        traits = name[len("Qlam.Heur.ELF ("):-1].split("; ")
        listed = "\n".join(f"    • {t}" for t in traits)
        return ("This program shows several traits that malware tends to have together:\n\n"
                f"{listed}\n\n"
                "Each is common enough on its own, and Qlam doesn't know this program as malware, "
                "so this is only a notice. If you don't know where it came from, don't run it.")
    if ev.get("severity") == "malicious" and ev.get("confirmed"):
        family = name.removesuffix(" (known sample)")
        text = (f"This file is byte-for-byte identical to a known sample of {family}. "
                "That is not a guess: it is the same file.")
        if kind == "blocked":
            text += " Qlam stopped it from running."
        return text + "\n\nMoving it to quarantine is recommended. Nothing on disk has been changed yet."
    if ev.get("severity") == "malicious":
        return (
            f"This file matches a pattern ({name}) that is characteristic of malware. "
            "Pattern matches can occasionally be wrong.\n\n"
            "If you know where this file came from and trust it, mark it as trusted. "
            "Otherwise, moving it to quarantine is the safe choice. Nothing has been changed yet."
        )
    return (
        f"This file has traits ({name}) that malware and hacking tools sometimes share. "
        "It is often harmless — for example a security tool or a script you wrote.\n\n"
        "No action is needed unless you don't recognise it."
    )


# ── Small building blocks ──────────────────────────────────────────────────

class Card(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 18, 20, 18)
        self.body.setSpacing(8)


class Chip(QLabel):
    """Small rounded status label; colour comes from the `level` property."""

    def __init__(self, text: str = "", lvl: str = "info", parent=None):
        super().__init__(text, parent)
        self.setObjectName("Chip")
        self.set_level(lvl)

    def set_level(self, lvl: str):
        self.setProperty("level", lvl)
        self.style().unpolish(self)
        self.style().polish(self)


def page_header(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    s.setWordWrap(True)
    lay.addWidget(t)
    lay.addWidget(s)
    return w


def row(*widgets, spacing: int = 10, stretch_at: int | None = None) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    for i, w in enumerate(widgets):
        if w is None:
            lay.addStretch(1)
        else:
            lay.addWidget(w)
            if stretch_at == i:
                lay.setStretchFactor(w, 1)
    return lay


def label(text: str, obj: str = "", wrap: bool = False, selectable: bool = False) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    if selectable:
        lb.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lb

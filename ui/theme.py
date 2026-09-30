"""Qlam theme system — monochrome Maze aesthetic with dark & light palettes.

The whole UI chrome is driven by the stylesheet built from a palette, so a
theme switch is a single ``app.setStyleSheet`` swap. Widgets that paint
dynamic neutral colours in Python read :data:`theme` (the live palette) and
re-apply on :attr:`ThemeManager.changed`. Security-semantic colours (safe /
warn / danger) are deliberately theme-independent so they carry the same
meaning on both backgrounds.
"""
from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

_CFG_FILE = Path.home() / ".local" / "share" / "Qlam" / "ui.json"


# ── Palettes ───────────────────────────────────────────────────────────────

_DARK = {
    "bg":            "#0a0a0a",
    "surface":       "#111111",
    "surface_alt":   "#0c0c0c",
    "elevated":      "#1a1a1a",
    "border":        "#1e1e1e",
    "border2":       "#2e2e2e",
    "text":          "#f0f0f0",
    "text_mid":      "#8a8a8a",
    "text_dim":      "#4a4a4a",
    "scrollbar":     "#2a2a2a",
    "scrollbar_hi":  "#3f3f3f",
    "accent":        "#f0f0f0",
    "accent_text":   "#0a0a0a",
    "accent_hover":  "#ffffff",
    "sidebar":       "#0a0a0a",
    "nav_active":    "#1a1a1a",
    "nav_active_tx": "#ffffff",
    "input":         "#141414",
    "selection":     "#2a2a2a",
    "tooltip":       "#1a1a1a",
    # checkmark image whose stroke contrasts with the (light) accent fill
    "check":         "check_light.svg",
    # security-semantic (shared meaning across themes, tuned for dark)
    "good":          "#22c55e",
    "good_soft":     "#0f2417",
    "good_border":   "#1c3b28",
    "bad":           "#ef4444",
    "bad_soft":      "#241010",
    "bad_border":    "#3d1c1c",
    "warn":          "#f59e0b",
}

_LIGHT = {
    "bg":            "#f4f4f5",
    "surface":       "#ffffff",
    "surface_alt":   "#fafafa",
    "elevated":      "#ececed",
    "border":        "#e3e3e5",
    "border2":       "#cfcfd2",
    "text":          "#0a0a0a",
    "text_mid":      "#5c5c63",
    "text_dim":      "#9a9aa2",
    "scrollbar":     "#c9c9cd",
    "scrollbar_hi":  "#a8a8ae",
    "accent":        "#0a0a0a",
    "accent_text":   "#ffffff",
    "accent_hover":  "#282828",
    "sidebar":       "#ffffff",
    "nav_active":    "#ececed",
    "nav_active_tx": "#0a0a0a",
    "input":         "#ffffff",
    "selection":     "#dcdce0",
    "tooltip":       "#1a1a1a",
    "check":         "check_dark.svg",
    "good":          "#16a34a",
    "good_soft":     "#e8f6ee",
    "good_border":   "#bfe6cd",
    "bad":           "#dc2626",
    "bad_soft":      "#fbeaea",
    "bad_border":    "#f0c8c8",
    "warn":          "#d97706",
}

_PALETTES = {"dark": _DARK, "light": _LIGHT}


# ── Stylesheet template ────────────────────────────────────────────────────

_QSS = """
* {{ outline: none; }}

QMainWindow, QDialog {{ background-color: {bg}; }}

QWidget {{
    background-color: transparent;
    color: {text};
    font-family: "Inter", "SF Pro Display", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 13px;
    selection-background-color: {selection};
    selection-color: {text};
}}

/* ── Title bar ─────────────────────────────────────────── */
#TitleBar {{
    background-color: {bg};
    border-bottom: 1px solid {border};
}}
#BrandName {{
    color: {text};
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 3px;
}}
#StatusPill {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 11px;
    padding: 2px 11px;
    font-size: 11px;
    font-weight: 600;
    color: {text_mid};
}}
QPushButton#WinBtn {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {text_mid};
    font-size: 14px;
    padding: 0;
    min-width: 44px;
    min-height: 40px;
}}
QPushButton#WinBtn:hover {{ background-color: {elevated}; color: {text}; }}
QPushButton#WinClose {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {text_mid};
    font-size: 14px;
    padding: 0;
    min-width: 44px;
    min-height: 40px;
}}
QPushButton#WinClose:hover {{ background-color: #c42b1c; color: #ffffff; }}
QPushButton#IconToggle {{
    background: transparent;
    border: 1px solid {border};
    border-radius: 8px;
    min-width: 34px;
    max-width: 34px;
    min-height: 30px;
    padding: 0;
}}
QPushButton#IconToggle:hover {{ background-color: {elevated}; border-color: {border2}; }}

/* ── Sidebar ───────────────────────────────────────────── */
#Sidebar {{
    background-color: {sidebar};
    border-right: 1px solid {border};
    min-width: 210px;
    max-width: 210px;
}}
#AppVersion {{ color: {text_dim}; font-size: 11px; }}
#SidebarSep {{ background-color: {border}; max-height: 1px; min-height: 1px; border: none; }}
#NavHeading {{
    color: {text_dim};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 2px;
}}
QPushButton#NavButton {{
    background-color: transparent;
    border: none;
    border-radius: 8px;
    color: {text_mid};
    font-size: 13px;
    font-weight: 500;
    padding: 10px 14px;
    text-align: left;
    min-height: 38px;
}}
QPushButton#NavButton:hover {{ background-color: {elevated}; color: {text}; }}
QPushButton#NavButton[active="true"] {{
    background-color: {nav_active};
    color: {nav_active_tx};
    font-weight: 600;
}}

/* ── Scroll areas (settings page) ──────────────────────── */
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ── Content / page headers ────────────────────────────── */
#ContentArea {{ background-color: {bg}; }}
#PageTitle {{
    font-size: 21px;
    font-weight: 700;
    color: {text};
    letter-spacing: -0.3px;
}}
#PageSubtitle {{ color: {text_mid}; font-size: 13px; }}

/* ── Generic text roles ────────────────────────────────── */
QLabel#Muted {{ color: {text_mid}; font-size: 12px; }}
QLabel#Dim   {{ color: {text_dim}; font-size: 12px; }}
QLabel#Strong {{ color: {text}; font-weight: 600; font-size: 13px; }}
QLabel#SectionLabel {{
    color: {text_dim};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
}}

/* ── Cards ─────────────────────────────────────────────── */
#Card {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 12px;
}}
#CardTitle {{
    color: {text_dim};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
}}
#CardValue {{ color: {text}; font-size: 26px; font-weight: 700; letter-spacing: -0.3px; }}
#CardSub   {{ color: {text_mid}; font-size: 12px; }}

/* ── Buttons ───────────────────────────────────────────── */
QPushButton {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 8px;
    color: {text};
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{ background-color: {elevated}; border-color: {border2}; }}
QPushButton:pressed {{ background-color: {bg}; }}
QPushButton:disabled {{ background-color: {surface_alt}; color: {text_dim}; border-color: {border}; }}

QPushButton#PrimaryButton {{
    background-color: {accent};
    border: 1px solid {accent};
    color: {accent_text};
    font-weight: 600;
    padding: 10px 20px;
}}
QPushButton#PrimaryButton:hover {{ background-color: {accent_hover}; border-color: {accent_hover}; }}
QPushButton#PrimaryButton:disabled {{ background-color: {elevated}; color: {text_dim}; border-color: {border}; }}

QPushButton#DangerButton {{
    background-color: {bad_soft};
    border: 1px solid {bad_border};
    color: {bad};
    font-weight: 600;
}}
QPushButton#DangerButton:hover {{ background-color: {bad}; border-color: {bad}; color: #ffffff; }}

QPushButton#SuccessButton {{
    background-color: {good_soft};
    border: 1px solid {good_border};
    color: {good};
    font-weight: 600;
}}
QPushButton#SuccessButton:hover {{ background-color: {good}; border-color: {good}; color: #ffffff; }}

QPushButton#WarnButton {{
    background-color: {surface};
    border: 1px solid {border2};
    color: {warn};
    font-weight: 600;
}}
QPushButton#WarnButton:hover {{ background-color: {elevated}; border-color: {warn}; }}

QPushButton#GhostButton {{
    background-color: transparent;
    border: 1px solid {border};
    color: {text_mid};
}}
QPushButton#GhostButton:hover {{ background-color: {elevated}; border-color: {border2}; color: {text}; }}

/* ── Progress bar ──────────────────────────────────────── */
QProgressBar {{
    background-color: {elevated};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{ background-color: {accent}; border-radius: 3px; }}
QProgressBar#DangerProgress::chunk {{ background-color: {bad}; }}
QProgressBar#SuccessProgress::chunk {{ background-color: {good}; }}

/* ── Tables ────────────────────────────────────────────── */
QTableWidget {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 12px;
    gridline-color: {border};
    color: {text_mid};
    alternate-background-color: {surface_alt};
    selection-background-color: {elevated};
    selection-color: {text};
}}
QTableWidget::item {{ padding: 8px 12px; border: none; }}
QTableWidget::item:selected {{ background-color: {elevated}; color: {text}; }}
QHeaderView {{ background-color: transparent; }}
QHeaderView::section {{
    background-color: {surface};
    color: {text_dim};
    border: none;
    border-bottom: 1px solid {border};
    padding: 10px 12px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.6px;
}}
QTableWidget QTableCornerButton::section {{ background-color: {surface}; border: none; }}

/* ── Scroll bars ───────────────────────────────────────── */
QScrollBar:vertical {{ background-color: transparent; width: 6px; border: none; margin: 0; }}
QScrollBar::handle:vertical {{ background-color: {scrollbar}; border-radius: 3px; min-height: 40px; }}
QScrollBar::handle:vertical:hover {{ background-color: {scrollbar_hi}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
QScrollBar:horizontal {{ background-color: transparent; height: 6px; border: none; }}
QScrollBar::handle:horizontal {{ background-color: {scrollbar}; border-radius: 3px; }}
QScrollBar::handle:horizontal:hover {{ background-color: {scrollbar_hi}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Text / log areas ──────────────────────────────────── */
QTextEdit, QPlainTextEdit {{
    background-color: {surface_alt};
    border: 1px solid {border};
    border-radius: 8px;
    color: {text_mid};
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    padding: 10px;
    selection-background-color: {selection};
}}

/* ── Inputs ────────────────────────────────────────────── */
QLineEdit {{
    background-color: {input};
    border: 1px solid {border2};
    border-radius: 8px;
    color: {text};
    padding: 9px 12px;
}}
QLineEdit:focus {{ border-color: {accent}; }}
QLineEdit:hover {{ border-color: {border2}; }}

QCheckBox {{ color: {text_mid}; spacing: 10px; font-size: 13px; background: transparent; }}
QCheckBox:hover {{ color: {text}; }}
QCheckBox::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {border2};
    border-radius: 5px;
    background-color: {input};
}}
QCheckBox::indicator:hover {{ border-color: {accent}; }}
QCheckBox::indicator:checked {{
    background-color: {accent};
    border-color: {accent};
    image: url({check});
}}

QSpinBox {{
    background-color: {input};
    border: 1px solid {border2};
    border-radius: 8px;
    color: {text};
    padding: 6px 32px 6px 10px;
    min-height: 32px;
}}
QSpinBox:focus {{ border-color: {accent}; }}
QSpinBox::up-button {{ subcontrol-origin: border; subcontrol-position: top right; width: 24px; height: 50%; background-color: {elevated}; border: none; border-left: 1px solid {border}; border-top-right-radius: 7px; }}
QSpinBox::down-button {{ subcontrol-origin: border; subcontrol-position: bottom right; width: 24px; height: 50%; background-color: {elevated}; border: none; border-left: 1px solid {border}; border-top: 1px solid {border}; border-bottom-right-radius: 7px; }}
QSpinBox::up-arrow {{ width: 9px; height: 9px; image: url(arrow_up.png); }}
QSpinBox::down-arrow {{ width: 9px; height: 9px; image: url(arrow_down.png); }}

QComboBox, QTimeEdit {{
    background-color: {input};
    border: 1px solid {border2};
    border-radius: 8px;
    color: {text};
    padding: 7px 12px;
    min-height: 20px;
}}
QComboBox:focus, QTimeEdit:focus {{ border-color: {accent}; }}
QComboBox:hover, QTimeEdit:hover {{ border-color: {border2}; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    background-color: {surface};
    border: 1px solid {border2};
    border-radius: 8px;
    color: {text};
    selection-background-color: {elevated};
    selection-color: {text};
    padding: 4px;
}}
QTimeEdit::up-button, QTimeEdit::down-button {{ width: 0; border: none; }}

/* ── Group box ─────────────────────────────────────────── */
QGroupBox {{
    border: 1px solid {border};
    border-radius: 12px;
    margin-top: 14px;
    padding-top: 14px;
    color: {text_dim};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.6px;
    background-color: {surface};
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; background-color: {surface}; }}

/* ── Status hero (overview) ────────────────────────────── */
#Hero {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 14px;
}}
#Hero[state="ok"]        {{ background-color: {good_soft}; border-color: {good_border}; }}
#Hero[state="attention"] {{ background-color: {bad_soft};  border-color: {bad_border}; }}
#Hero[state="notice"]    {{ background-color: {surface};   border-color: {border2}; }}
#HeroTitle {{ font-size: 20px; font-weight: 700; color: {text}; letter-spacing: -0.2px; }}
#HeroText  {{ font-size: 13px; color: {text_mid}; }}

/* ── Chips / badges ────────────────────────────────────── */
#Chip {{
    border-radius: 9px;
    padding: 2px 9px;
    font-size: 11px;
    font-weight: 600;
    background-color: {elevated};
    color: {text_mid};
}}
#Chip[level="danger"] {{ background-color: {bad_soft};  color: {bad};  border: 1px solid {bad_border}; }}
#Chip[level="warn"]   {{ background-color: {bad_soft};  color: {warn}; border: 1px solid {bad_border}; }}
#Chip[level="notice"] {{ background-color: {elevated};  color: {text_mid}; border: 1px solid {border2}; }}
#Chip[level="good"]   {{ background-color: {good_soft}; color: {good}; border: 1px solid {good_border}; }}
#Chip[level="info"]   {{ background-color: {elevated};  color: {text_mid}; border: 1px solid {border}; }}
#NavBadge {{
    background-color: {bad};
    color: #ffffff;
    border-radius: 9px;
    padding: 0 6px;
    font-size: 10px;
    font-weight: 700;
}}
#StatValue {{ color: {text}; font-size: 22px; font-weight: 700; }}
#StatLabel {{ color: {text_dim}; font-size: 10px; font-weight: 700; letter-spacing: 1.2px; }}
#DetailTitle {{ color: {text}; font-size: 17px; font-weight: 700; }}
#Mono {{
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 12px;
    color: {text_mid};
}}

/* ── Finding / activity lists ──────────────────────────── */
QListWidget {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 12px;
    padding: 4px;
}}
QListWidget::item {{ border-radius: 8px; margin: 1px 2px; }}
QListWidget::item:hover {{ background-color: {surface_alt}; }}
QListWidget::item:selected {{ background-color: {elevated}; }}
#EmptyState {{ color: {text_dim}; font-size: 13px; }}

/* ── Tooltip / dialogs / separators ────────────────────── */
QToolTip {{
    background-color: {tooltip};
    border: 1px solid {border2};
    color: #f0f0f0;
    padding: 6px 10px;
    border-radius: 6px;
}}
QMessageBox {{ background-color: {surface}; }}
QMessageBox QLabel {{ color: {text}; }}
QDialog {{ background-color: {surface}; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{ color: {border}; background: {border}; max-height: 1px; }}
"""


def get_stylesheet(name: str, resources_dir: Path | None = None) -> str:
    palette = _PALETTES.get(name, _DARK)
    qss = _QSS.format(**palette)
    if resources_dir is not None:
        qss = qss.replace("url(", f"url({resources_dir}/")
    return qss


# ── Live theme manager ─────────────────────────────────────────────────────

class ThemeManager(QObject):
    """Holds the active theme name and its palette; emits :attr:`changed`
    (with the new palette dict) so Python-painted widgets can re-style."""

    changed = pyqtSignal(dict)

    def __init__(self, name: str = "dark"):
        super().__init__()
        self.name = name if name in _PALETTES else "dark"
        self.p = _PALETTES[self.name]

    def set(self, name: str) -> None:
        if name not in _PALETTES or name == self.name:
            return
        self.name = name
        self.p = _PALETTES[name]
        self.changed.emit(self.p)

    def toggle(self) -> None:
        self.set("light" if self.name == "dark" else "dark")


def load_prefs() -> dict:
    try:
        with open(_CFG_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_pref(key: str, value) -> None:
    """Merge one UI preference into ui.json."""
    data = load_prefs()
    data[key] = value
    try:
        _CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CFG_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=1)
        tmp.replace(_CFG_FILE)
    except Exception:
        pass


def load_theme() -> str:
    return load_prefs().get("theme", "dark")


def save_theme(name: str) -> None:
    save_pref("theme", name)


# Global singleton used across the UI.
theme = ThemeManager(load_theme())

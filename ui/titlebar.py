"""Qlam's own window chrome: a title bar and resize edges for a frameless
window, so the app looks the same under every desktop instead of wearing
the window manager's decorations.

Moving and resizing are handed to the window manager (startSystemMove /
startSystemResize), which keeps snapping, tiling and multi-monitor
behaviour native and works on both Wayland and X11.
"""
from __future__ import annotations

import qtawesome as qta
from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from ui.brand import mark_pixmap
from ui.theme import theme

class TitleBar(QWidget):
    theme_toggled = pyqtSignal()

    HEIGHT = 44

    def __init__(self, window: QWidget):
        super().__init__(window)
        self._window = window
        self.setObjectName("TitleBar")
        self.setFixedHeight(self.HEIGHT)
        # Paint the QSS background on this plain QWidget.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 0, 0, 0)
        lay.setSpacing(10)
        self.logo = QLabel()
        self.logo.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        name = QLabel("QLAM")
        name.setObjectName("BrandName")
        name.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        lay.addWidget(self.logo)
        lay.addWidget(name)
        lay.addWidget(maze_linux_tag("for Maze Linux"))
        lay.addStretch(1)

        self.pill = QLabel()
        self.pill.setObjectName("StatusPill")
        self.pill.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.pill.setFixedHeight(24)
        lay.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addStretch(1)

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("IconToggle")
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.setToolTip("Switch between dark and light")
        self.theme_btn.clicked.connect(self.theme_toggled)
        lay.addWidget(self.theme_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addSpacing(8)

        self.min_btn = self._win_button("WinBtn", "Minimize", window.showMinimized)
        self.max_btn = self._win_button("WinBtn", "Maximize", self.toggle_maximize)
        self.close_btn = self._win_button("WinClose", "Close", window.close)
        for b in (self.min_btn, self.max_btn, self.close_btn):
            b.setFixedHeight(self.HEIGHT)
            lay.addWidget(b)

        self._pill_state = ("", "")
        theme.changed.connect(lambda _p: self.retint())
        self.retint()

    def _win_button(self, obj: str, tip: str, slot) -> QPushButton:
        b = QPushButton()
        b.setObjectName(obj)
        b.setToolTip(tip)
        b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        b.clicked.connect(slot)
        return b

    # ── Appearance ────────────────────────────────────────────────────────

    def retint(self):
        p = theme.p
        self.logo.setPixmap(mark_pixmap(22, ring=p["text"], small=False))
        icon = "fa5s.sun" if theme.name == "dark" else "fa5s.moon"
        self.theme_btn.setIcon(qta.icon(icon, color=p["text_mid"]))
        self.theme_btn.setIconSize(QSize(14, 14))
        maximized = self._window.isMaximized()
        for b, name in ((self.min_btn, "fa5s.minus"),
                        (self.max_btn, "fa5s.window-restore" if maximized else "fa5s.square"),
                        (self.close_btn, "fa5s.times")):
            b.setIcon(qta.icon(name, color=p["text_mid"], color_active=p["text"]))
            b.setIconSize(QSize(12, 12))
        self.max_btn.setToolTip("Restore" if maximized else "Maximize")
        self.set_status(*self._pill_state)

    def set_status(self, text: str, level: str):
        """Short protection summary in the middle of the bar."""
        self._pill_state = (text, level)
        self.pill.setText(text)
        self.pill.setVisible(bool(text))
        color = {"good": "good", "bad": "bad", "warn": "warn"}.get(level)
        self.pill.setStyleSheet(f"color: {theme.p[color]};" if color else "")

    def toggle_maximize(self):
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()

    # ── Moving ────────────────────────────────────────────────────────────

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self._window.windowHandle()
            if handle is not None:
                handle.startSystemMove()
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.toggle_maximize()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)


# ── Resizing ──────────────────────────────────────────────────────────────

_E = Qt.Edge
_GRIPS = [
    (_E.LeftEdge, Qt.CursorShape.SizeHorCursor),
    (_E.RightEdge, Qt.CursorShape.SizeHorCursor),
    (_E.TopEdge, Qt.CursorShape.SizeVerCursor),
    (_E.BottomEdge, Qt.CursorShape.SizeVerCursor),
    (_E.TopEdge | _E.LeftEdge, Qt.CursorShape.SizeFDiagCursor),
    (_E.BottomEdge | _E.RightEdge, Qt.CursorShape.SizeFDiagCursor),
    (_E.TopEdge | _E.RightEdge, Qt.CursorShape.SizeBDiagCursor),
    (_E.BottomEdge | _E.LeftEdge, Qt.CursorShape.SizeBDiagCursor),
]


class _Grip(QWidget):
    def __init__(self, window: QWidget, edges: Qt.Edge, cursor: Qt.CursorShape):
        super().__init__(window)
        self._window = window
        self.edges = edges
        self.setCursor(cursor)

    def mousePressEvent(self, event):
        handle = self._window.windowHandle()
        if event.button() == Qt.MouseButton.LeftButton and handle is not None:
            handle.startSystemResize(self.edges)
            event.accept()
            return
        super().mousePressEvent(event)


class ResizeGrips:
    """Invisible strips along the edges of a frameless window that let the
    user resize it. Call `place()` from the window's resizeEvent."""

    WIDTH = 6

    def __init__(self, window: QWidget):
        self._window = window
        self._grips = [_Grip(window, e, c) for e, c in _GRIPS]

    def place(self):
        w, h, g = self._window.width(), self._window.height(), self.WIDTH
        c = 2 * g  # corners are a bit larger than the edges
        E = _E
        rects = {
            E.LeftEdge: (0, c, g, h - 2 * c),
            E.RightEdge: (w - g, c, g, h - 2 * c),
            E.TopEdge: (c, 0, w - 2 * c, g),
            E.BottomEdge: (c, h - g, w - 2 * c, g),
            E.TopEdge | E.LeftEdge: (0, 0, c, c),
            E.BottomEdge | E.RightEdge: (w - c, h - c, c, c),
            E.TopEdge | E.RightEdge: (w - c, 0, c, c),
            E.BottomEdge | E.LeftEdge: (0, h - c, c, c),
        }
        # No resizing a maximized window.
        visible = not (self._window.isMaximized() or self._window.isFullScreen())
        for grip in self._grips:
            grip.setGeometry(*rects[grip.edges])
            grip.setVisible(visible)
            grip.raise_()


def maze_linux_tag(text: str, size_px: int = 10):
    """The small "for Maze Linux" line beside the app name. It takes the
    surrounding text colour and fades it, so it reads right in every theme."""
    from PyQt6.QtWidgets import QGraphicsOpacityEffect, QLabel
    from PyQt6.QtCore import Qt
    tag = QLabel(text)
    tag.setObjectName("mazeLinuxTag")
    tag.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    tag.setStyleSheet(f"font-size: {size_px}px; background: transparent;")
    fade = QGraphicsOpacityEffect(tag)
    fade.setOpacity(0.55)
    tag.setGraphicsEffect(fade)
    return tag

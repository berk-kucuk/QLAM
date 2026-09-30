"""The Qlam mark, drawn from the SVGs in Logos/ (made by tools/make_logo.py).

The mark is recoloured on the fly: the ring follows the theme (or the panel,
in the tray) and the tail carries the protection state in the tray.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QByteArray, QPointF, QRectF, Qt
from PyQt6.QtGui import QGuiApplication, QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

LOGOS = Path(__file__).resolve().parent.parent / "Logos"

# Colours as written by tools/make_logo.py; replaced when recolouring.
_RING = "#F2F2F2"
_TAIL = ("#9BFFDC", "#14D48B")

# Tail gradient per protection state (light end, dark end).
STATE_TAIL = {
    "protected": _TAIL,
    "alert": ("#FF9AA4", "#FF3B4E"),
    "off": ("#FFD58F", "#FFA328"),
    "offline": ("#C4C4C4", "#7E7E7E"),
}

_cache: dict[tuple, QPixmap] = {}


def _svg(small: bool) -> str:
    name = "qlam-mark-small.svg" if small else "qlam-mark.svg"
    return (LOGOS / name).read_text()


def mark_pixmap(size: int, ring: str = _RING, tail: tuple[str, str] = _TAIL, small: bool | None = None) -> QPixmap:
    """The mark at `size` logical pixels, sharp on HiDPI screens. The heavier
    small variant is used up to 32 px unless `small` says otherwise."""
    if small is None:
        small = size <= 32
    app = QGuiApplication.instance()
    dpr = app.devicePixelRatio() if app else 1.0
    key = (size, ring, tail, small, dpr)
    if key in _cache:
        return _cache[key]
    text = _svg(small).replace(_RING, ring).replace(_TAIL[0], tail[0]).replace(_TAIL[1], tail[1])
    renderer = QSvgRenderer(QByteArray(text.encode()))
    px = round(size * dpr)
    pm = QPixmap(px, px)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, px, px))
    painter.end()
    pm.setDevicePixelRatio(dpr)
    _cache[key] = pm
    return pm


def app_icon() -> QIcon:
    """The full app icon (black tile with the glowing mark)."""
    icon = QIcon()
    for size in (16, 22, 24, 32, 48, 64, 128, 256, 512):
        p = LOGOS / f"qlam-{size}.png"
        if p.exists():
            icon.addFile(str(p))
    return icon


def tray_icon(state: str) -> QIcon:
    """The bare mark for the system tray; the tail shows the state. The ring
    is light on a dark panel and dark on a light one."""
    app = QGuiApplication.instance()
    dark_panel = True
    if app is not None:
        dark_panel = app.palette().window().color().lightness() < 128
    ring = _RING if dark_panel else "#141414"
    halo = "#000000" if dark_panel else "#FFFFFF"
    tail = STATE_TAIL.get(state, _TAIL)
    icon = QIcon()
    for size in (16, 22, 24, 32, 48, 64):
        icon.addPixmap(_with_halo(mark_pixmap(size, ring, tail), mark_pixmap(size, halo, (halo, halo))))
    return icon


def _with_halo(mark: QPixmap, shadow: QPixmap) -> QPixmap:
    """The mark with a one-pixel contrasting outline, so it stays readable
    whatever colour the panel turns out to be (the app's palette is only a
    guess at it)."""
    dpr = mark.devicePixelRatio()
    out = QPixmap(mark.size())
    out.fill(Qt.GlobalColor.transparent)
    out.setDevicePixelRatio(dpr)
    p = QPainter(out)
    p.setOpacity(0.55)
    for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1), (-1, -1), (1, 1), (-1, 1), (1, -1)):
        p.drawPixmap(QPointF(dx / dpr, dy / dpr), shadow)
    p.setOpacity(1.0)
    p.drawPixmap(0, 0, mark)
    p.end()
    return out

"""The Qlam mark, drawn from the SVGs in Logos/ (made by tools/make_logo.py).

The mark is recoloured on the fly: the ring follows the theme (or the panel,
in the tray) and the tail carries the protection state in the tray.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QByteArray, QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QGuiApplication, QIcon, QPainter, QPixmap
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
    """The tray icon: like the app icon, the mark on a black rounded tile,
    with the tail showing the protection state. The tile gives the mark its
    own background, so it reads the same on light and dark panels."""
    tail = STATE_TAIL.get(state, _TAIL)
    icon = QIcon()
    for size in (16, 22, 24, 32, 48, 64):
        icon.addPixmap(_tile(size, tail))
    return icon


# Share of the tile the mark's square takes (its SVG carries 4% padding per
# side, so the mark itself spans ~63%, as in the app icon); the rest is black.
_TILE_MARK = 0.68
# Corner radius as a share of the tile: 224 on the 1024 Maze family grid.
_TILE_RADIUS = 224 / 1024


def _tile(size: int, tail: tuple[str, str]) -> QPixmap:
    app = QGuiApplication.instance()
    dpr = app.devicePixelRatio() if app else 1.0
    px = round(size * dpr)
    out = QPixmap(px, px)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    # The full-size black tile of the app icon, edge to edge like Maze AI's
    # and Maze Connect's, so the three tray icons come out the same size.
    r = px * _TILE_RADIUS
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#000000"))
    p.drawRoundedRect(QRectF(0, 0, px, px), r, r)
    inner = round(px * _TILE_MARK)
    mark = mark_pixmap(inner, _RING, tail, small=size <= 32)
    mark.setDevicePixelRatio(1.0)  # drawn in device pixels here
    off = (px - mark.width()) / 2
    p.drawPixmap(QPointF(off, off), mark)
    p.end()
    out.setDevicePixelRatio(dpr)
    return out

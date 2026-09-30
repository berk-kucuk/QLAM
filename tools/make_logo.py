#!/usr/bin/env python3
"""Generate the Qlam logo set from geometry.

The mark: a squircle "Q" in near-white with a luminous mint tail cutting
through its lower-right corner. OLED look: pure black, crisp white, one
glowing accent. Every file is derived from the numbers below, so the set
stays consistent; edit them and run:

    python3 tools/make_logo.py

Outputs in Logos/:
  qlam.svg, qlam-<size>.png   app icon: the mark on a black squircle, glow
  qlam-mark.svg               the mark alone, transparent, no filters (Qt's
                              SVG renderer supports neither masks nor blur);
                              the app recolours it (ui/brand.py)
  qlam-mark-small.svg         heavier strokes for 16–32 px (tray)
  qlam-wordmark.svg / .png    mark + QLAM, on black (README, about)

PNG rendering needs rsvg-convert (librsvg).
"""
from __future__ import annotations

import math
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "Logos"

# Colours. ui/brand.py swaps RING and the TAIL stops to recolour the mark,
# so keep them unique strings in the SVGs.
RING = "#F2F2F2"
TAIL_LIGHT, TAIL_DARK = "#9BFFDC", "#14D48B"
GLOW = "#2BF5A4"
BLACK = "#000000"


def f(x: float) -> str:
    return f"{x:.1f}".rstrip("0").rstrip(".")


CX, CY, A, N = 470.0, 470.0, 300.0, 4.2      # ring: centre, radius, squareness
TAIL_FROM, TAIL_TO = 0.40, 1.06               # tail span along the diagonal, in A


def _superellipse(steps: int = 720) -> list[tuple[float, float]]:
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        ct, st = math.cos(t), math.sin(t)
        pts.append((CX + A * math.copysign(abs(ct) ** (2 / N), ct),
                    CY + A * math.copysign(abs(st) ** (2 / N), st)))
    return pts


def _offset(pts, d):
    """The curve moved `d` along its outward normal (a true offset, so the
    stroke keeps its width round the corners)."""
    out = []
    n = len(pts)
    for i in range(n):
        (x0, y0), (x1, y1) = pts[i - 1], pts[(i + 1) % n]
        tx, ty = x1 - x0, y1 - y0
        ln = math.hypot(tx, ty)
        nx, ny = ty / ln, -tx / ln
        px, py = pts[i]
        if (px - CX) * nx + (py - CY) * ny < 0:   # make it point outwards
            nx, ny = -nx, -ny
        out.append((px + nx * d, py + ny * d))
    return out


def _cut(curve, clear):
    """Keep the part of a closed curve outside the tail's band (|distance to
    the diagonal| < clear, on the tail's side), with its two ends placed
    exactly on the band's edges. Returns the kept points, in order."""
    s2 = math.sqrt(0.5)

    def perp(p):   # signed distance to the diagonal through the centre
        return ((p[0] - CX) - (p[1] - CY)) * s2

    def along(p):
        return ((p[0] - CX) + (p[1] - CY)) * s2

    def inside(p):
        return along(p) > 0 and abs(perp(p)) < clear

    n = len(curve)
    start = next(i for i in range(n) if not inside(curve[i]) and inside(curve[i - 1]))
    kept = []
    for k in range(n):
        i = (start + k) % n
        if inside(curve[i]):
            break
        kept.append(curve[i])

    def edge_point(a, b):
        # where segment a-b crosses the band edge |perp| = clear
        pa, pb = perp(a), perp(b)
        target = math.copysign(clear, pa if abs(pa) >= clear else pb)
        t = (target - pa) / (pb - pa)
        return (a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1]))

    first_in = curve[(start - 1) % n]
    last_i = (start + len(kept) - 1) % n
    after = curve[(last_i + 1) % n]
    return [edge_point(first_in, kept[0])] + kept + [edge_point(kept[-1], after)]


def mark_shapes(ring_w: float, tail_w: float, gap: float):
    """Ring outline (as a filled path) and the tail's end points, in a
    1000-unit box. The opening is real geometry — no masks — so the mark
    works on any background and in Qt's SVG renderer."""
    base = _superellipse()
    clear = tail_w / 2 + gap
    outer = _cut(_offset(base, ring_w / 2), clear)
    inner = _cut(_offset(base, -ring_w / 2), clear)
    poly = outer + inner[::-1]
    d = "M " + " L ".join(f"{f(x)} {f(y)}" for x, y in poly) + " Z"
    t0 = (CX + TAIL_FROM * A, CY + TAIL_FROM * A)
    t1 = (CX + TAIL_TO * A, CY + TAIL_TO * A)
    return d, t0, t1, poly


def mark_bbox(ring_w: float, tail_w: float) -> tuple[float, float, float, float]:
    _, t0, t1, poly = mark_shapes(ring_w, tail_w, 30)
    xs = [p[0] for p in poly] + [t1[0] + tail_w / 2]
    ys = [p[1] for p in poly] + [t1[1] + tail_w / 2]
    return min(xs), min(ys), max(xs), max(ys)


def mark_body(small: bool = False, glow: bool = False) -> str:
    ring_w, tail_w, gap = (92, 104, 30) if small else (64, 72, 30)
    ring, t0, t1, _ = mark_shapes(ring_w, tail_w, gap)
    line = (f'x1="{f(t0[0])}" y1="{f(t0[1])}" x2="{f(t1[0])}" y2="{f(t1[1])}" '
            f'stroke-width="{tail_w}" stroke-linecap="round"')
    halo = (f'<line {line} stroke="{GLOW}" opacity="0.55" filter="url(#glow)"/>' if glow else "")
    return f'<path d="{ring}" fill="{RING}"/>\n  {halo}<line {line} stroke="url(#tail)"/>'


def square_around(bbox, pad: float) -> tuple[float, float, float]:
    """A square (x, y, side) centred on bbox with `pad` (fraction) around."""
    x0, y0, x1, y1 = bbox
    side = max(x1 - x0, y1 - y0) * (1 + 2 * pad)
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    return cx - side / 2, cy - side / 2, side


def defs(glow: bool = False) -> str:
    blur = ('<filter id="glow" x="-50%" y="-50%" width="200%" height="200%">'
            '<feGaussianBlur stdDeviation="26"/></filter>') if glow else ""
    return (f'<defs><linearGradient id="tail" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{TAIL_LIGHT}"/><stop offset="1" stop-color="{TAIL_DARK}"/>'
            f'</linearGradient>{blur}</defs>')


def svg(body: str, w: float, h: float, vb: str | None = None) -> str:
    vb = vb or f"0 0 {f(w)} {f(h)}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" width="{f(w)}" height="{f(h)}">\n'
            f'  <title>Qlam</title>\n  {body}\n</svg>\n')


def mark_view(small: bool = False) -> str:
    x, y, side = square_around(mark_bbox(*((92, 104) if small else (64, 72))), 0.04)
    return f"{f(x)} {f(y)} {f(side)} {f(side)}"


def placed(size: float, box: tuple[float, float, float], small: bool = False, glow: bool = False) -> str:
    """The mark scaled so its bounding square fills `box` (x, y, side)."""
    x, y, side = square_around(mark_bbox(*((92, 104) if small else (64, 72))), 0)
    bx, by, bside = box
    k = bside / side
    return (f'<g transform="translate({f(bx)} {f(by)}) scale({k:.5f}) translate({f(-x)} {f(-y)})">\n'
            f'  {mark_body(small=small, glow=glow)}\n  </g>')


def app_icon() -> str:
    # The mark takes ~60% of the tile, centred.
    inner = 1024 * 0.60
    body = (f'{defs(glow=True)}\n'
            f'  <rect x="32" y="32" width="960" height="960" rx="224" fill="{BLACK}"/>\n'
            f'  <rect x="34" y="34" width="956" height="956" rx="222" fill="none" stroke="#1E1E1E" stroke-width="4"/>\n'
            f'  {placed(1024, ((1024 - inner) / 2, (1024 - inner) / 2, inner), glow=True)}')
    return svg(body, 1024, 1024)


def mark(small: bool = False) -> str:
    return svg(f"{defs()}\n  {mark_body(small=small)}", 512, 512, mark_view(small))


def wordmark() -> str:
    body = (f'{defs(glow=True)}\n'
            f'  <rect width="1400" height="440" fill="{BLACK}"/>\n'
            f'  {placed(300, (80, 70, 300), glow=True)}\n'
            f'  <text x="450" y="284" font-family="Inter Display, Inter, sans-serif" font-weight="600" '
            f'font-size="176" letter-spacing="30" fill="{RING}">QLAM</text>')
    return svg(body, 1400, 440)


def render(src: Path, dst: Path, w: int, h: int | None = None):
    args = ["rsvg-convert", "-w", str(w)]
    if h:
        args += ["-h", str(h)]
    subprocess.run(args + [str(src), "-o", str(dst)], check=True)


def main():
    OUT.mkdir(exist_ok=True)
    files = {
        "qlam.svg": app_icon(),
        "qlam-mark.svg": mark(),
        "qlam-mark-small.svg": mark(small=True),
        "qlam-wordmark.svg": wordmark(),
    }
    for name, text in files.items():
        (OUT / name).write_text(text)
    if not shutil.which("rsvg-convert"):
        print("rsvg-convert not found: SVGs written, PNGs skipped")
        return
    for size in (16, 22, 24, 32, 48, 64, 128, 256, 512, 1024):
        render(OUT / "qlam.svg", OUT / f"qlam-{size}.png", size, size)
    render(OUT / "qlam-wordmark.svg", OUT / "qlam-wordmark.png", 1400)
    print(f"logo set written to {OUT}")


if __name__ == "__main__":
    main()

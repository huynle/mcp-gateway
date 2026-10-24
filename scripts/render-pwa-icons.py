#!/usr/bin/env python3
"""Render the portal's installable-app (PWA) icons from the brand mark.

The brand mark is internal/portal/static/favicon.svg: a teal (#0e7268)
rounded square with a white arch. This script draws it with headless
Chromium (Playwright) and writes the PNGs the web app manifest and the
iOS home screen use into internal/portal/static/icons/:

  icon-192.png           192x192, transparent corners (manifest, purpose "any")
  icon-512.png           512x512, transparent corners (manifest, purpose "any")
  icon-maskable-512.png  512x512, full-bleed teal, the arch inside the 80%
                         safe zone (manifest, purpose "maskable")
  apple-touch-icon.png   180x180, opaque RGB (iOS adds its own rounding and
                         shows transparency as black)

Usage (from the repository root; needs `pip install playwright pillow` and
`playwright install chromium`):

  python3 scripts/render-pwa-icons.py

The output is deterministic for a given Chromium: Pillow re-encodes each
screenshot without metadata, so re-running it without changing the SVGs
leaves the files byte-identical. Commit the PNGs; the gateway embeds them
(package internal/portal/static) and never runs this script.
"""

import io
import pathlib

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC = ROOT / "internal" / "portal" / "static"
OUT = STATIC / "icons"

TEAL = "#0e7268"
# The arch of favicon.svg (24x24 view box, centred on 12,12).
ARCH = (
    '<path d="M7 18v-7a5 5 0 0 1 10 0v7M12 12.5V18" fill="none" stroke="#fff" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
)


def full_bleed(scale: float) -> str:
    """A teal square edge to edge with the arch scaled about the centre.

    At scale 1 the arch's farthest point is ~9.4 units from the centre; the
    maskable safe zone is a circle of radius 9.6 (40% of 24), so any scale
    <= 1 keeps the mark inside it.
    """
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        f'<rect width="24" height="24" fill="{TEAL}"/>'
        f'<g transform="translate(12 12) scale({scale}) translate(-12 -12)">{ARCH}</g>'
        "</svg>"
    )


ICONS = [
    # (file, size, svg source, keep alpha)
    ("icon-192.png", 192, (STATIC / "favicon.svg").read_text(), True),
    ("icon-512.png", 512, (STATIC / "favicon.svg").read_text(), True),
    ("icon-maskable-512.png", 512, full_bleed(0.8), False),
    ("apple-touch-icon.png", 180, full_bleed(0.9), False),
]

PAGE = """<!doctype html><html><head><style>
html, body {{ margin: 0; padding: 0; background: transparent; }}
svg {{ display: block; width: {size}px; height: {size}px; }}
</style></head><body>{svg}</body></html>"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            for name, size, svg, alpha in ICONS:
                page = browser.new_page(viewport={"width": size, "height": size}, device_scale_factor=1)
                page.set_content(PAGE.format(size=size, svg=svg))
                shot = page.screenshot(omit_background=alpha, clip={"x": 0, "y": 0, "width": size, "height": size})
                page.close()
                img = Image.open(io.BytesIO(shot))
                img = img.convert("RGBA" if alpha else "RGB")
                if img.size != (size, size):
                    raise SystemExit(f"{name}: rendered {img.size}, want {size}x{size}")
                img.save(OUT / name, format="PNG", optimize=True)
                print(f"wrote {(OUT / name).relative_to(ROOT)} ({size}x{size}, {img.mode})")
        finally:
            browser.close()


if __name__ == "__main__":
    main()

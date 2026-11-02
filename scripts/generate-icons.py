#!/usr/bin/env python3
"""Regenerate icons/icon{16,48,128}.png: a red shield with a white '!'.

Run: python3 scripts/generate-icons.py
Requires Pillow (only used at build time, not by the extension).
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "icons"
OUT.mkdir(exist_ok=True)


def make(size: int) -> None:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Shield: red rounded shape.
    pad = max(1, size // 16)
    d.rounded_rectangle([pad, pad, size - pad, size - pad], radius=size // 5, fill=(179, 38, 30, 255))
    # White exclamation mark.
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", size=int(size * 0.62))
    except OSError:
        font = ImageFont.load_default()
    d.text((size / 2, size / 2), "!", fill=(255, 255, 255, 255), font=font, anchor="mm")
    img.save(OUT / f"icon{size}.png")


for s in (16, 48, 128):
    make(s)
print("Wrote icons/icon16.png, icon48.png, icon128.png")

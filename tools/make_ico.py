#!/usr/bin/env python3
"""
Generate an .ico file from the repository PNG app icon.

Usage:
  python tools/make_ico.py [input_png] [output_ico]

Defaults:
  input_png  = icon-safe.png (repo root)
  output_ico = icon-safe.ico (repo root)

Requires Pillow:
  pip install pillow
"""
import sys
from pathlib import Path

try:
    from PIL import Image
except Exception as e:
    print("Pillow is required: pip install pillow")
    raise

def main():
    root = Path(__file__).resolve().parents[1]
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "icon-safe.png"
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "icon-safe.ico"
    if not src.exists():
        raise SystemExit(f"Input PNG not found: {src}")
    img = Image.open(src).convert("RGBA")
    # Create multiple sizes for crisp scaling in Windows shell
    sizes = [(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)]
    img.save(dst, sizes=sizes)
    print(f"Wrote {dst}")

if __name__ == "__main__":
    main()


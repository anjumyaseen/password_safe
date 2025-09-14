#!/usr/bin/env python3
"""
make_ico.py — Create a multi-size Windows .ico from a PNG.

Defaults assume this file lives in repo_root/tools/ and the input PNG
is at repo_root/icon-safe.png with output to repo_root/assets/app.ico.

Usage (from repo root):
  python .\tools\make_ico.py
  python .\tools\make_ico.py .\icon-safe.png .\assets\app.ico
  python .\tools\make_ico.py --sizes 16,24,32,48,64,128,256

Requires: Pillow
  pip install pillow
"""

from __future__ import annotations
import argparse
from pathlib import Path
from typing import List, Tuple

from PIL import Image, ImageOps


def parse_sizes(s: str) -> List[Tuple[int, int]]:
    if not s:
        return [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    out = []
    for token in s.split(","):
        token = token.strip()
        if not token:
            continue
        n = int(token)
        if n <= 0:
            raise ValueError("Icon sizes must be positive integers")
        out.append((n, n))
    return out


def repo_root_from_tools(script_path: Path) -> Path:
    # If this file is repo_root/tools/make_ico.py, repo root is parent of tools
    tools_dir = script_path.resolve().parent
    return tools_dir.parent


def prepare_square_canvas(img: Image.Image, base_size: int = 256) -> Image.Image:
    """
    Return an RGBA square image of base_size x base_size with the input
    centered and scaled to fit while preserving aspect ratio & transparency.
    """
    img = img.convert("RGBA")
    contained = ImageOps.contain(img, (base_size, base_size))
    base = Image.new("RGBA", (base_size, base_size), (0, 0, 0, 0))
    base.paste(contained, ((base_size - contained.width) // 2,
                           (base_size - contained.height) // 2), contained)
    return base


def make_ico(src: Path, dst: Path, sizes: List[Tuple[int, int]]) -> None:
    if not src.exists():
        raise FileNotFoundError(f"Source image not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    with Image.open(src) as im:
        # Build a clean square base (256x256 by default); Pillow will downscale for sizes list.
        max_edge = max(s for s, _ in sizes)
        square_base = prepare_square_canvas(im, base_size=max_edge)
        # Save ICO with all requested sizes explicitly
        square_base.save(dst, format="ICO", sizes=sizes)

    print(f"Wrote {dst} with sizes: {', '.join(str(s[0]) for s in sizes)}")


def main() -> None:
    script_path = Path(__file__).resolve()
    root = repo_root_from_tools(script_path)

    default_src = root / "icon-safe.png"
    default_dst = root / "assets" / "app.ico"

    parser = argparse.ArgumentParser(description="Create multi-size .ico from PNG.")
    parser.add_argument("src", nargs="?", type=Path, default=default_src,
                        help=f"Input PNG (default: {default_src})")
    parser.add_argument("dst", nargs="?", type=Path, default=default_dst,
                        help=f"Output ICO (default: {default_dst})")
    parser.add_argument("--sizes", default="16,24,32,48,64,128,256",
                        help="Comma-separated square sizes (e.g., 16,24,32,48,64,128,256)")
    args = parser.parse_args()

    sizes = parse_sizes(args.sizes)
    make_ico(args.src, args.dst, sizes)


if __name__ == "__main__":
    main()

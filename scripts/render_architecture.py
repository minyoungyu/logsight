"""docs/img/architecture.html → docs/img/architecture.png (Playwright 필요).

    python scripts/render_architecture.py  (Chromium 경로가 다르면 CHROMIUM_PATH 지정)
"""
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
src = ROOT / "docs" / "img" / "architecture.html"
out = ROOT / "docs" / "img" / "architecture.png"

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
    pg = b.new_page(viewport={"width": 1360, "height": 900}, device_scale_factor=2)
    pg.goto(src.as_uri())
    pg.locator(".wrap").screenshot(path=str(out))
    b.close()
print(out.relative_to(ROOT))

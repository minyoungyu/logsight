"""보고서 첫 화면 확인(사양서 NFR-22): 두 화면 크기에서 결론 문장과 먼저 할 일 1번이 스크롤 없이 보이나.

    python scripts/first_screen_check.py reports/x/report.html [다른 보고서 ...]
    python scripts/first_screen_check.py --json 결과.json reports/x/report.html ...   # 결과를 파일로도 남김

헤드리스 브라우저(Playwright)가 필요하다. 없으면 건너뛴다고 알리고 종료 코드 2를 돌려준다.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

SIZES = {"데스크톱 1366×768": (1366, 768), "휴대폰 390×844": (390, 844)}
TARGETS = {"결론 문장": "#conclusion .lead", "먼저 할 일 1번": "#conclusion ol.now li"}


def check(paths: list[str]) -> list[dict]:
    from playwright.sync_api import sync_playwright
    rows = []
    with sync_playwright() as p:
        exe = os.environ.get("LOGSIGHT_CHROMIUM")  # 브라우저를 따로 깔아 둔 경우 그 경로
        b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        for path in paths:
            for name, (w, h) in SIZES.items():
                pg = b.new_page(viewport={"width": w, "height": h})
                pg.goto(Path(path).resolve().as_uri())
                for label, sel in TARGETS.items():
                    el = pg.query_selector(sel)
                    box = el.bounding_box() if el else None
                    ok = bool(box) and box["y"] + box["height"] <= h
                    rows.append({"file": path, "size": name, "target": label, "ok": ok,
                                 "bottom": round(box["y"] + box["height"]) if box else None, "height": h})
                pg.close()
        b.close()
    return rows


def main(argv: list[str]) -> int:
    out = None
    if argv[:1] == ["--json"]:
        out, argv = argv[1], argv[2:]
    if not argv:
        print(__doc__)
        return 2
    try:
        rows = check(argv)
    except ImportError:
        print("Playwright가 없어 확인하지 못했습니다(pip install playwright && playwright install chromium).")
        return 2
    for r in rows:
        where = f"아래쪽 {r['bottom']}px / 화면 {r['height']}px" if r["bottom"] is not None else "요소 없음"
        print(f"{'통과' if r['ok'] else '실패'}  {r['size']}  {r['target']}  ({where})  {r['file']}")
    bad = [r for r in rows if not r["ok"]]
    if out:
        import json
        Path(out).write_text(json.dumps({"n_checks": len(rows), "n_ok": len(rows) - len(bad), "rows": rows},
                                        ensure_ascii=False, indent=1), encoding="utf-8")
    print("첫 화면 확인 통과" if not bad else f"실패 {len(bad)}건")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""저장소 샘플(실제 형식의 로그 파일)로 돌린 결과를 고정 파일과 비교한다.

규칙·묶기·판정 코드를 바꾸면 샘플에서 걸리는 규칙, 사건 수, 사건 판정이 달라질 수 있다.
달라진 것이 의도한 변화면 --update로 고정 파일을 다시 쓰고, 그 차이를 PR에 적는다.

    python scripts/regress_samples.py           # 비교(다르면 종료 코드 1)
    python scripts/regress_samples.py --update  # 고정 파일 다시 쓰기
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.pipeline import run_paths  # noqa: E402

FIXED = ROOT / "tests" / "regression" / "samples.json"
SETS = ["demo", "free", "combined", "guardduty"]


def snapshot() -> dict:
    os.environ.pop("ANTHROPIC_API_KEY", None)  # 규칙 판정만 고정한다
    out = {}
    for name in SETS:
        d = ROOT / "samples" / name
        r = run_paths([str(d)], str(d / "environment.json"), use_ai=False, top=50)
        out[name] = {
            "n_events": r["n_events"],
            "rules": {k: v["findings"] for k, v in sorted(r["rule_counts"].items())},
            "incidents": [{"id": i["id"], "verdict": i.get("verdict"), "rules": i["rules"],
                           "stages": i["stages"], "severity": i["severity"]}
                          for i in r["incident_index"]],
        }
    return out


def diff(old: dict, new: dict) -> list[str]:
    lines = []
    for name in sorted(set(old) | set(new)):
        a, b = old.get(name, {}), new.get(name, {})
        for k in ("n_events", "rules", "incidents"):
            if a.get(k) != b.get(k):
                lines.append(f"{name}.{k}: {json.dumps(a.get(k), ensure_ascii=False)} -> "
                             f"{json.dumps(b.get(k), ensure_ascii=False)}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true")
    a = ap.parse_args()
    new = snapshot()
    if a.update:
        FIXED.write_text(json.dumps(new, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"고정 파일을 다시 썼다: {FIXED.relative_to(ROOT)}")
        return 0
    d = diff(json.loads(FIXED.read_text(encoding="utf-8")), new)
    print("\n".join(d) or "샘플 결과가 고정 파일과 같다")
    return 1 if d else 0


if __name__ == "__main__":
    sys.exit(main())

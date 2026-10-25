#!/usr/bin/env python3
"""CTF 로그로 탐지 성능 재기.

  python scripts/ctf_evaluate.py --profile data/ctf-2026-10/profile.json \
      --truth data/ctf-2026-10/ground_truth.json --out data/ctf-2026-10/eval.json

프로필로 웹 점검을 돌리고(규칙만, AI 호출 없음), 정답 파일과 대조해 표를 출력한다.
결과 JSON(--out)에는 같은 숫자와 놓친 항목·오탐 목록이 들어간다.
정답 파일 형식은 docs/CTF_로그_수집_가이드.md 3절을 본다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.web.measure import TruthError, format_report, load_truth, score  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="정답 파일과 LogSight 판정을 대조해 재현율·오탐률을 낸다")
    ap.add_argument("--profile", required=True, help="사이트 프로필 profile.json")
    ap.add_argument("--truth", required=True, help="정답 파일(ground_truth.json)")
    ap.add_argument("--out", help="결과를 저장할 JSON 경로")
    args = ap.parse_args(argv)
    try:
        truth = load_truth(args.truth)
    except TruthError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2
    profile = SiteProfile.load(args.profile)
    result = assess(profile, use_ai=False, top=500)
    s = score(truth, result)
    print(format_report(s))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(s, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

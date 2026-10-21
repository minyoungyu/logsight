"""
명령줄 실행.

  python -m logsight analyze samples/demo --out reports/demo
  python -m logsight analyze flaws_cloudtrail_logs/ --top 5 --no-ai
  python -m logsight rules
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .correlate import summarize_rules
from .pipeline import run_paths
from .report import render


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔에서 한글 깨짐 방지
    ap = argparse.ArgumentParser(prog="logsight", description="AWS 로그 공격 흐름 분석")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="로그 파일/폴더 분석")
    a.add_argument("paths", nargs="+", help="로그 파일 또는 폴더(.json/.log/.gz)")
    a.add_argument("--env", help="설정 스냅샷 environment.json 경로")
    a.add_argument("--out", default="reports/latest", help="결과 폴더")
    a.add_argument("--top", type=int, default=5, help="상세 분석할 사건 수")
    a.add_argument("--window", type=int, default=30, help="사건 묶기 시간창(분)")
    a.add_argument("--no-ai", action="store_true", help="Claude를 호출하지 않고 규칙 기반으로만")
    a.add_argument("--model", help="Claude 모델 ID (기본: claude-haiku-5-5)")
    sub.add_parser("rules", help="탐지 규칙 목록 출력")
    args = ap.parse_args(argv)

    if args.cmd == "rules":
        for k, v in summarize_rules().items():
            print(f"{k:28s} {v['technique']:10s} {v['stage']:18s} {v['title']}")
        return 0

    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        print(f"경로를 찾을 수 없음: {', '.join(missing)}", file=sys.stderr)
        return 2
    result = run_paths(args.paths, args.env, top=args.top, use_ai=not args.no_ai,
                       model=args.model, window_min=args.window)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "report.html").write_text(render(result), encoding="utf-8")
    print(f"이벤트 {result['n_events']:,}건 → 의심 {result['n_flagged']:,}건 → "
          f"탐지 {result['n_findings']:,}건 → 사건 {result['n_incidents']:,}건 "
          f"({result['timing']['total_s']}초)")
    for r in result["results"]:
        inc, m = r["incident"], r["meta"]
        print(f"  {inc['id']} [{inc['severity']}] {inc['start'][:19]} "
              f"{', '.join(inc['src_ips'][:3]) or '-'} 단계={'→'.join(inc['stages'])} "
              f"수정안 {len(r['checks'])}개 분석={m['mode']} 근거검증={'통과' if m['validation']['passed'] else '실패'}")
    for f in result["files"]:
        if f.get("error"):
            print(f"  [건너뜀] {f['file']}: {f['error']}", file=sys.stderr)
    print(f"보고서: {out / 'report.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

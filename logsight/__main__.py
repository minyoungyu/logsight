"""
명령줄 실행.

  python -m logsight analyze samples/demo --out reports/demo
  python -m logsight analyze flaws_cloudtrail_logs/ --top 5 --no-ai
  python -m logsight rules
  python -m logsight check                    # 로그 켜짐 사전 점검(읽기 전용)
  python -m logsight check --apply CT_TRAIL   # 확인 후 지정 항목만 켜기
  python -m logsight collect environment --out environment.json
  python -m logsight collect cloudtrail-history --days 30 --out logs/cloudtrail_history.json
  python -m logsight cost --web-requests 3000000
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
    a.add_argument("--year", type=int, help="연도가 없는 syslog 줄(auth.log, kern.log)의 연도(기본: 올해, 미래면 작년)")
    a.add_argument("--syslog-tz", help="syslog 줄의 시간대(예: +09:00). 기본 UTC. 한국 서버 기본 설정이면 +09:00")
    a.add_argument("--dry-run", action="store_true",
                   help="Claude를 부르지 않고 보낼 내용(마스킹 후)을 ai_payload.json으로 저장")
    a.add_argument("--since", help="이 시각 이후만 분석(예: 2017-02-12 또는 2017-02-12T10:00:00Z)")
    a.add_argument("--until", help="이 시각 이전만 분석(날짜만 주면 그날 끝까지)")
    sub.add_parser("rules", help="탐지 규칙 목록 출력")
    c = sub.add_parser("check", help="AWS 로그가 켜져 있는지 점검(읽기 전용)")
    c.add_argument("--region")
    c.add_argument("--profile", help="~/.aws 프로필 이름")
    c.add_argument("--json", help="결과를 JSON 파일로도 저장")
    c.add_argument("--apply", nargs="+", metavar="ID",
                   help="지정한 항목만 켠다(CT_TRAIL VPC_FLOW GUARDDUTY). 실행 전 확인을 묻는다")
    c.add_argument("--yes", action="store_true", help="--apply 확인 질문 생략")
    co = sub.add_parser("collect", help="읽기 전용 수집(설정 스냅샷, 무료 CloudTrail 이벤트 기록)")
    co.add_argument("what", choices=["environment", "cloudtrail-history"])
    co.add_argument("--region")
    co.add_argument("--profile")
    co.add_argument("--days", type=int, default=7, help="cloudtrail-history: 최근 며칠(최대 90)")
    co.add_argument("--max", type=int, help="cloudtrail-history: 최대 이벤트 수")
    co.add_argument("--out", required=True)
    cs = sub.add_parser("cost", help="로그를 켰을 때 월 비용 어림셈")
    cs.add_argument("--mgmt-events", type=int, default=300_000, help="월 관리 이벤트 수")
    cs.add_argument("--s3-data-events", type=int, default=0)
    cs.add_argument("--flow-lines", type=int, default=5_000_000, help="월 Flow Logs 줄 수")
    cs.add_argument("--web-requests", type=int, default=1_000_000, help="월 웹 요청 수")
    cs.add_argument("--waf-rules", type=int, default=3)
    cs.add_argument("--retention", type=int, default=3, help="보관 개월")
    cs.add_argument("--region", default="ap-northeast-2", choices=["ap-northeast-2", "us-east-1"])
    args = ap.parse_args(argv)

    if args.cmd == "cost":
        from .costs import estimate, format_text
        print(format_text(estimate(mgmt_events_month=args.mgmt_events,
                                   s3_data_events_month=args.s3_data_events,
                                   flow_lines_month=args.flow_lines,
                                   web_requests_month=args.web_requests,
                                   waf_rules=args.waf_rules, retention_months=args.retention,
                                   region=args.region)))
        return 0
    if args.cmd in ("check", "collect"):
        return _aws_cmd(args)

    if args.cmd == "rules":
        for k, v in summarize_rules().items():
            print(f"{k:28s} {v['technique']:10s} {v['stage']:18s} {v['title']}")
        return 0

    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        print(f"경로를 찾을 수 없음: {', '.join(missing)}", file=sys.stderr)
        return 2
    from .normalize import SYSLOG, parse_tz, parse_when
    if args.year:
        SYSLOG["year"] = args.year
    if args.syslog_tz:
        try:
            SYSLOG["tz"] = parse_tz(args.syslog_tz)
        except ValueError:
            print("--syslog-tz 형식: +09:00", file=sys.stderr)
            return 2
    try:
        since, until = parse_when(args.since), parse_when(args.until, end=True)
    except ValueError:
        print("--since/--until 형식: 2017-02-12 또는 2017-02-12T10:00:00Z", file=sys.stderr)
        return 2
    result = run_paths(args.paths, args.env, since=since, until=until, top=args.top, use_ai=not args.no_ai, preview=args.dry_run,
                       model=args.model, window_min=args.window)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "report.html").write_text(render(result), encoding="utf-8")
    if args.dry_run:
        from .analyze import SYSTEM
        payload = {"model": args.model or "claude-haiku-5-5", "system": SYSTEM,
                   "incidents": [r.pop("ai_payload") for r in result["results"]]}
        (out / "ai_payload.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                                             encoding="utf-8")
        n = len(json.dumps(payload, ensure_ascii=False))
        print(f"AI에 보낼 내용: {out / 'ai_payload.json'} (약 {n:,}자, 사건 {len(payload['incidents'])}건). "
              "Claude는 호출하지 않았습니다.")
    print(f"이벤트 {result['n_events']:,}건 → 의심 {result['n_flagged']:,}건 → "
          f"탐지 {result['n_findings']:,}건 → 사건 {result['n_incidents']:,}건 "
          f"(반복을 묶으면 {result['n_groups']:,}건, {result['timing']['total_s']}초)")
    for r in result["results"]:
        inc, m = r["incident"], r["meta"]
        rep = f" 반복 {inc['repeats']}회" if inc.get("repeats", 1) > 1 else ""
        print(f"  {inc['id']} [{inc['severity']}]{rep} {inc['start'][:19]} "
              f"{', '.join(inc['src_ips'][:3]) or '-'} 단계={'→'.join(inc['stages'])} "
              f"수정안 {len(r['checks'])}개 분석={m['mode']} 근거검증={'통과' if m['validation']['passed'] else '실패'}")
    for f in result["files"]:
        if f.get("error"):
            print(f"  [건너뜀] {f['file']}: {f['error']}", file=sys.stderr)
    print(f"보고서: {out / 'report.html'}")
    return 0


def _aws_cmd(args) -> int:
    try:
        import boto3
    except ImportError:
        print("boto3가 필요합니다: pip install boto3", file=sys.stderr)
        return 2
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.cmd == "collect":
        from . import aws_collect
        if args.what == "environment":
            env = aws_collect.export_environment(session, args.region)
            Path(args.out).write_text(json.dumps(env, ensure_ascii=False, indent=1, default=str),
                                      encoding="utf-8")
            print(f"저장: {args.out} (인스턴스 {len(env['instances'])}, 보안그룹 {len(env['security_groups'])}, "
                  f"WAF {len(env['waf_web_acls'])}, IAM 역할 {len(env['iam_roles'])})")
            if env["_errors"]:
                print("확인 못 한 항목(권한 부족 등): " + ", ".join(env["_errors"]))
        else:
            n = aws_collect.collect_event_history(args.out, session=session, region=args.region,
                                                  days=args.days, max_events=args.max)
            print(f"저장: {args.out} (CloudTrail 이벤트 기록 {n:,}건, 최근 {min(args.days, 90)}일, 무료)")
        return 0
    from . import aws_check
    if args.apply:
        ids = [i.upper() for i in args.apply]
        print("다음 항목을 켭니다(요금이 생길 수 있음): " + ", ".join(ids))
        for i in ids:
            if i in aws_check.ITEMS:
                print(f"  {i}: {aws_check.ITEMS[i]['cost']}")
        if not args.yes and input("계속하려면 yes 입력: ").strip().lower() != "yes":
            print("취소했습니다.")
            return 1
        ok = True
        for r in aws_check.apply(ids, session, args.region):
            ok &= r["ok"]
            print(f"  [{'완료' if r['ok'] else '실패'}] {r['id']}: {r['detail']}")
        return 0 if ok else 1
    res = aws_check.run_checks(session, args.region)
    print(aws_check.format_text(res))
    if args.json:
        Path(args.json).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

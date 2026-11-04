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
  python -m logsight watch --queue-url <SQS URL> --logs /var/logsight/logs   # AWS 경보 → 자동 분석
  python -m logsight on-alert event.json --logs samples/demo --no-ai          # 경보 이벤트 하나로 시험
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
    a.add_argument("--team", help="확인된 우리 팀 목록 team.json(logsight team --confirm으로 만듦)")
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

    s = sub.add_parser("scan", help="웹서버 로그·파일로 침해 여부 판단")
    s.add_argument("--profile", help="사이트 프로필 profile.json 경로")
    s.add_argument("--access", action="append", default=[], help="접속 로그 경로(여러 번 가능, 글롭 가능)")
    s.add_argument("--error", action="append", default=[], help="오류 로그 경로")
    s.add_argument("--auth", action="append", default=[], help="인증 로그 경로(auth.log/secure)")
    s.add_argument("--webroot", help="웹 루트 경로(웹셸 파일 점검)")
    s.add_argument("--name", default="웹서버", help="사이트 이름(보고서 표시)")
    s.add_argument("--out", default="reports/web", help="결과 폴더")
    s.add_argument("--top", type=int, default=10, help="상세 분석할 사건 수")
    s.add_argument("--window", type=int, default=30, help="사건 묶기 시간창(분)")
    s.add_argument("--no-ai", action="store_true", help="Claude 호출 없이 규칙 기반으로만")
    s.add_argument("--model", help="Claude 모델 ID")

    def alert_opts(p):
        p.add_argument("--logs", action="append", default=[], help="로컬 로그 폴더/파일(여러 번 가능)")
        p.add_argument("--s3", action="append", default=[],
                       help="s3://버킷/접두어. {date}를 넣으면 날짜 폴더(YYYY/MM/DD)만 읽음")
        p.add_argument("--env", help="environment.json")
        p.add_argument("--collect-env", action="store_true", help="경보 때 설정 스냅샷을 새로 읽기(읽기 전용)")
        p.add_argument("--out", default="reports/alerts")
        p.add_argument("--min-severity", default="medium", choices=["low", "medium", "high"])
        p.add_argument("--lookback-hours", type=float, default=24.0, help="활동이 처음 보인 시각보다 몇 시간 앞부터")
        p.add_argument("--cooldown", type=int, default=60, help="같은 경보를 다시 분석하지 않는 시간(분)")
        p.add_argument("--top", type=int, default=5)
        p.add_argument("--no-ai", action="store_true")
        p.add_argument("--model")
        p.add_argument("--team", help="확인된 우리 팀 목록 team.json")
        p.add_argument("--notify", help="통지 설정 notify.json(이메일·디스코드·슬랙·웹훅 중 골라 쓰기)")
        p.add_argument("--notify-cmd", help="보고서가 나오면 실행할 명령(환경변수 LOGSIGHT_SUMMARY 등 전달)")
        p.add_argument("--region")
        p.add_argument("--profile")
        p.add_argument("--heartbeat", help="s3://보관 버킷/heartbeat/ : 서버 로그 전송이 끊기면 경보")
        p.add_argument("--heartbeat-max", type=float, default=5.0, help="생존 신호가 몇 분 없으면 끊김으로 볼지")
        p.add_argument("--respond", help="자동 격리 설정 respond.json(없으면 격리 안 함)")
        p.add_argument("--respond-profile", help="격리 실행용 ~/.aws 프로필(쓰기 권한이 있는 별도 역할)")
    oa = sub.add_parser("on-alert", help="EventBridge 경보 이벤트(JSON 파일)로 분석 한 번 실행")
    oa.add_argument("events", nargs="+", help="이벤트 JSON 파일")
    alert_opts(oa)
    w = sub.add_parser("watch", help="SQS 대기열의 AWS 경보를 받아 자동으로 분석")
    w.add_argument("--queue-url", required=True)
    w.add_argument("--once", action="store_true", help="한 번만 받고 끝내기")
    alert_opts(w)
    nt = sub.add_parser("notify-test", help="통지 설정 확인: 시험 메시지를 모든 채널로 보냄")
    nt.add_argument("config", help="notify.json")
    hb = sub.add_parser("heartbeat", help="서버 로그 전송 생존 신호 확인(끊긴 서버가 있으면 종료 코드 1)")
    hb.add_argument("uri", help="s3://보관 버킷/heartbeat/")
    hb.add_argument("--max-age", type=float, default=5.0)
    hb.add_argument("--region")
    hb.add_argument("--profile")
    tm = sub.add_parser("team", help="로그에서 우리 팀으로 보이는 계정을 찾아 확인받기(확인된 계정의 작업은 공격 판정에서 뺌)")
    tm.add_argument("paths", nargs="+", help="로그 파일 또는 폴더")
    tm.add_argument("--env", help="설정 스냅샷(기존 IAM 사용자 목록을 함께 봄)")
    tm.add_argument("--confirm", nargs="+", metavar="이름", help="우리 팀이 맞다고 확인한 계정 이름(후보 목록의 이름)")
    tm.add_argument("--out", default="team.json", help="확인 목록을 저장할 파일")
    ob = sub.add_parser("onboard-link", help="고객이 버튼 하나로 설치하는 AWS 콘솔 링크 만들기")
    ob.add_argument("--template-url", required=True, help="S3에 올린 logsight-onboard.yaml 주소(https)")
    ob.add_argument("--bus-arn", required=True, help="허브 스택 출력 IntakeBusArn")
    ob.add_argument("--archive-bucket", required=True, help="보관 버킷 이름")
    ob.add_argument("--principal-arn", required=True, help="LogSight 분석 서버 역할 ARN")
    ob.add_argument("--region", default="ap-northeast-2", help="고객의 주 리전")
    ob.add_argument("--vpc-id", default="", help="VPC Flow Logs를 켤 VPC(선택)")
    ob.add_argument("--isolation", action="store_true", help="격리 전용 역할도 만들기(LogSight는 시험 모드로 시작)")
    ob.add_argument("--min-severity", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    ob.add_argument("--no-trail", action="store_true", help="보관용 CloudTrail을 만들지 않음(기존 추적이 있어 비용이 걱정될 때)")
    rp = sub.add_parser("respond", help="자동 격리: 기준선·확인·마감 처리·되돌리기")
    rp.add_argument("action", choices=["baseline", "ack", "tick", "undo", "plan", "allow"])
    rp.add_argument("target", nargs="*", help="ack/undo: 경보 결과 폴더, plan: 로그 경로, allow: 종류 ID")
    rp.add_argument("--config", default="respond.json")
    rp.add_argument("--out", default="reports/alerts", help="tick: 경보 결과 상위 폴더, baseline: 저장 파일")
    rp.add_argument("--region")
    rp.add_argument("--profile")

    args = ap.parse_args(argv)

    if args.cmd in ("on-alert", "watch"):
        return _alert_cmd(args)
    if args.cmd == "respond":
        return _respond_cmd(args)
    if args.cmd == "team":
        return _team_cmd(args)
    if args.cmd == "onboard-link":
        from .onboard import make
        r = make(args.template_url, args.bus_arn, args.archive_bucket, args.principal_arn, region=args.region,
                 vpc_id=args.vpc_id, isolation=args.isolation, min_severity=args.min_severity,
                 create_trail=not args.no_trail)
        for i, ln in enumerate(r["links"], 1):
            what = "전체 설정" if ln["part"] == "full" else "IAM 경보 받기(키·사용자 생성은 이 리전으로만 옴)"
            print(f"{i}. {ln['region']} — {what}\n   {ln['url']}")
        print(f"\nExternalId(고객 기록에 저장): {r['external_id']}")
        print("고객 계정 ID를 허브 스택 CustomerAccountIds와 보관 스택 SourceAccountIds에 더해야 경보·로그가 들어온다.")
        return 0
    if args.cmd == "notify-test":
        from .notify import load_config, send_all, test_message
        res = send_all(load_config(args.config), test_message())
        for r in res:
            print(f"{r['channel']}: {'성공' if r.get('ok') else '실패 ' + str(r.get('error') or r.get('status'))}")
        return 0 if res and all(r.get("ok") for r in res) else 1
    if args.cmd == "heartbeat":
        import boto3
        from .heartbeat import check
        rows = check(args.uri, boto3.Session(profile_name=args.profile, region_name=args.region).client("s3"),
                     max_age_min=args.max_age)
        for r in rows:
            print(f"{'정상' if r['ok'] else '끊김'}  {r['host']}  마지막 {r['last'] or '없음'}"
                  + (f" ({r['age_min']}분 전)" if r['age_min'] is not None else ""))
        if not rows:
            print("생존 신호를 보내는 서버가 없습니다.")
        return 0 if rows and all(r["ok"] for r in rows) else 1

    if args.cmd == "scan":
        return _scan(args)

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
    result = run_paths(args.paths, args.env, since=since, until=until, team_path=args.team, top=args.top, use_ai=not args.no_ai, preview=args.dry_run,
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


def _team_cmd(args) -> int:
    from .detect import run_detections
    from .normalize import load_paths
    from .pipeline import load_env
    from . import team
    events, _ = load_paths([Path(p) for p in args.paths])
    env = load_env(args.env)
    run_detections(events, env)
    props = team.propose(events, env)
    if not args.confirm:
        if not props:
            print("우리 팀으로 보이는 계정을 찾지 못했습니다(콘솔로 오래 작업한 사람 계정이 없음).")
        for p in props:
            print(f"- {p['name']}: {', '.join(p['reasons'])} (이벤트 {p['n_events']:,}건, IP {p['n_ips']}개)")
        for x in team.excluded(events):
            print(f"  (제외) {x['name']}: 키 유출에서 흔한 모습({', '.join(x['rules'])})이 있어 후보에서 뺐습니다")
        if props:
            names = " ".join(p["name"] for p in props)
            print(f"\n맞으면 확인하세요: python -m logsight team {' '.join(args.paths)} --confirm {names}")
            print("확인한 계정의 작업은 공격 판정에서 뺍니다. 모르는 계정은 넣지 마세요(비밀번호를 훔친 공격자도 콘솔로 들어옵니다).")
        return 0
    allowed = {p["name"] for p in props}
    unknown = [n for n in args.confirm if n not in allowed]
    if unknown:
        print(f"후보에 없는 이름: {', '.join(unknown)}. 후보 목록의 이름만 확인할 수 있습니다.", file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(team.to_env(args.confirm), ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"저장: {args.out} (analyze·watch에 --team {args.out})")
    return 0


def _alert_cmd(args) -> int:
    from . import alert as al
    opt = al.Options(logs=args.logs, s3=args.s3, env=args.env, collect_env=args.collect_env, out=args.out,
                     min_severity=args.min_severity, lookback_h=args.lookback_hours, cooldown_min=args.cooldown,
                     top=args.top, use_ai=not args.no_ai, model=args.model, notify_cmd=args.notify_cmd,
                     region=args.region, respond=args.respond, notify=args.notify, heartbeat=args.heartbeat,
                     heartbeat_max_min=args.heartbeat_max, team=args.team)
    if args.notify:
        from .notify import load_config
        try:
            load_config(args.notify)
        except (OSError, ValueError) as exc:
            print(f"notify 설정 오류: {exc}", file=sys.stderr)
            return 2
    if args.respond:
        from .respond import Config
        try:
            Config.load(args.respond)
        except (TypeError, ValueError) as exc:
            print(f"respond 설정 오류: {exc}", file=sys.stderr)
            return 2
    missing = [p for p in args.logs if not Path(p).exists()]
    if missing:
        print(f"경로를 찾을 수 없음: {', '.join(missing)}", file=sys.stderr)
        return 2
    session = None
    if args.s3 or args.heartbeat or args.collect_env or args.cmd == "watch":
        try:
            import boto3
        except ImportError:
            print("boto3가 필요합니다: pip install boto3", file=sys.stderr)
            return 2
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3") if session and (args.s3 or args.heartbeat) else None
    if args.cmd == "on-alert":
        ok = True
        for ev in al.load_events(args.events):
            r = al.process_message(json.dumps(ev), opt, s3=s3, session=session)
            ok &= r is not None
        return 0 if ok else 1
    print(f"대기열 감시 시작: {args.queue_url} (기준 등급 {args.min_severity} 이상, Ctrl+C로 끝)")
    try:
        rsess = boto3.Session(profile_name=args.respond_profile, region_name=args.region) if args.respond_profile else None
        al.watch(args.queue_url, opt, sqs=session.client("sqs"), s3=s3, session=session, once=args.once,
                 respond_session=rsess)
    except KeyboardInterrupt:
        print("감시를 끝냈습니다.")
    return 0


def _respond_cmd(args) -> int:
    from . import respond as rs
    if args.action == "ack":
        ok = all(rs.ack(t) for t in args.target)
        print("확인했습니다. 자동 격리를 하지 않습니다." if ok and args.target else "response.json을 찾지 못함")
        return 0 if ok and args.target else 1
    if args.action == "baseline":
        import boto3
        b = rs.take_baseline(boto3.Session(profile_name=args.profile, region_name=args.region), args.region)
        out = args.out if args.out.endswith(".json") else "baseline.json"
        rs._save(out, b)
        print(f"기준선 저장: {out} (사용자 {len(b['users'])}, 역할 {len(b['roles'])}, 키 {len(b['access_keys'])}, "
              f"보안그룹 규칙 {len(b['sg_rules'])})")
        return 0
    cfg = rs.Config.load(args.config)
    if args.action == "allow":
        if len(args.target) != 2:
            print("사용: respond allow <access_key|user|role|sg_rule> <ID>", file=sys.stderr)
            return 2
        rs.Responder(cfg).allow_manual(*args.target)
        print("허용 목록에 추가했습니다.")
        return 0
    if args.action == "plan":
        p = rs.Responder(cfg).plan(rs.iter_records(args.target))
        print(json.dumps(p, ensure_ascii=False, indent=1))
        return 0
    session = None
    if cfg.mode == "enforce" or args.action == "undo":
        import boto3
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.action == "tick":
        for r in rs.tick(cfg, args.out, session=session):
            print(f"{r['alert']['id']}: {r['status']}")
        return 0
    for t in args.target:
        for a in rs.undo(t, session=session):
            print(f"되돌림 {a['op']} {a['id']}: {a['undo']['result']}")
    return 0


def _scan(args) -> int:
    from .web.webprofile import SiteProfile
    from .web.webpipeline import assess
    from .web.webreport import render as render_web

    if args.profile:
        profile = SiteProfile.load(args.profile)
    else:
        log_paths: dict[str, list[str]] = {}
        if args.access:
            log_paths["access"] = args.access
        if args.error:
            log_paths["weberror"] = args.error
        if args.auth:
            log_paths["auth"] = args.auth
        if not log_paths and not args.webroot:
            print("분석할 로그나 웹 루트를 지정하세요 (--profile 또는 --access/--auth/--webroot)",
                  file=sys.stderr)
            return 2
        profile = SiteProfile(name=args.name, webroot=args.webroot, log_paths=log_paths)

    result = assess(profile, top=args.top, use_ai=not args.no_ai, model=args.model,
                    window_min=args.window)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "report.html").write_text(render_web(result), encoding="utf-8")
    print(f"판정: {result['overall_verdict_ko']}  "
          f"(이벤트 {result['n_events']:,} → 의심 {result['n_flagged']:,} → "
          f"탐지 {result['n_findings']:,} → 사건 {result['n_incidents']:,}, "
          f"{result['timing']['total_s']}초)")
    for r in result["results"]:
        inc, rep, m = r["incident"], r["report"], r["meta"]
        print(f"  {inc['id']} [{rep.get('verdict')}] {inc['start'][:19]} "
              f"{', '.join(inc['src_ips'][:3]) or '-'} 단계={'→'.join(inc['stages'])} "
              f"분석={m['mode']} 근거검증={'통과' if m['validation']['passed'] else '확인필요'}")
    for f in result["files"]:
        if f.get("error"):
            print(f"  [건너뜀] {f['file']}: {f['error']}", file=sys.stderr)
    print(f"보고서: {out / 'report.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

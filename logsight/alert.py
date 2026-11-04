"""
경보 연동: AWS 경보가 오면 LogSight 분석을 자동으로 돌린다.

    AWS 계정                                    분석 서버(팀원 PC 또는 별도 서버)
    GuardDuty 결과 ─┐
    CloudWatch 경보 ─┼→ EventBridge 규칙 → SQS 대기열 ←── logsight watch (긴 폴링, 들어오는 포트 없음)
    위험 API 호출  ─┘                                     → 경보 시각 앞뒤 로그 모으기(로컬 폴더·S3)
                                                          → 분석(run) → reports/alerts/<시각>_<종류>_<id>/

왜 SQS인가: 분석 서버가 인터넷에 포트를 열 필요가 없다(밖으로 나가는 HTTPS만). 서버가 꺼져 있던
동안의 경보도 대기열에 남아 있다가 켜지면 처리된다(보관 기간 안). 처리에 실패한 메시지는 지우지
않아 다시 시도되고, 여러 번 실패하면 템플릿의 DLQ로 빠진다.

이 모듈은 AWS 설정을 바꾸지 않는다. 읽기(SQS 받기·지우기, S3 읽기)만 한다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

# EventBridge로 받는 CloudTrail API 호출 중 바로 분석을 돌릴 것(로그 훼손·지속성 확보·권한 상승)
API_HIGH = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector",
            "DeleteFlowLogs", "DeleteLogGroup", "DeleteBucketPolicy", "PutBucketPolicy",
            "DeactivateMFADevice", "DisableKey", "ScheduleKeyDeletion"}
API_MEDIUM = {"CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile",
              "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
              "CreatePolicyVersion", "UpdateAssumeRolePolicy", "AuthorizeSecurityGroupIngress",
              "ConsoleLogin"}


@dataclass
class Alert:
    id: str
    source: str          # guardduty | cloudwatch | cloudtrail | securityhub | unknown
    title: str
    severity: str        # high | medium | low
    time: datetime       # 경보 시각(UTC)
    first_seen: datetime  # 관련 활동이 처음 보인 시각(모르면 time과 같다)
    account: str = ""
    region: str = ""
    detail: dict = field(default_factory=dict)  # 원본 detail(분석 입력으로도 쓴다)

    def summary(self) -> dict:
        d = asdict(self)
        d["time"], d["first_seen"] = _iso(self.time), _iso(self.first_seen)
        d.pop("detail")
        return d


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(s: Any) -> datetime | None:
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def gd_severity(n: float) -> str:
    """GuardDuty 점수: 7 이상 높음(9 이상 치명 포함), 4 이상 중간, 나머지 낮음."""
    return "high" if n >= 7 else "medium" if n >= 4 else "low"


def unwrap(body: str | dict) -> dict | None:
    """SQS 메시지 본문 → EventBridge 이벤트. SNS를 거쳐 온 경우({"Type":"Notification","Message":...})도 푼다."""
    try:
        obj = json.loads(body) if isinstance(body, str) else body
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict) and obj.get("Type") == "Notification" and isinstance(obj.get("Message"), str):
        return unwrap(obj["Message"])
    return obj if isinstance(obj, dict) else None


def parse_event(ev: dict) -> Alert | None:
    """EventBridge 이벤트 하나를 Alert로. 경보가 아닌 이벤트(경보 해제 등)는 None."""
    src, dt, d = ev.get("source", ""), ev.get("detail-type", ""), ev.get("detail") or {}
    when = _ts(ev.get("time")) or datetime.now(timezone.utc)
    base = dict(account=str(ev.get("account", "")), region=str(ev.get("region", "")))
    if src == "aws.guardduty" or dt == "GuardDuty Finding":
        svc = d.get("service") or {}
        t = _ts(d.get("updatedAt")) or when
        first = _ts(svc.get("eventFirstSeen")) or _ts(d.get("createdAt")) or t
        return Alert(id=f"gd-{d.get('id', ev.get('id', ''))}", source="guardduty",
                     title=f"{d.get('type', '')}: {d.get('title', '')}".strip(": "),
                     severity=gd_severity(float(d.get("severity") or 0)), time=t,
                     first_seen=min(first, t), detail=d, **base)
    if src == "aws.cloudwatch" or dt == "CloudWatch Alarm State Change":
        if (d.get("state") or {}).get("value") != "ALARM":
            return None  # OK·INSUFFICIENT_DATA로 바뀐 것은 경보가 아니다
        name = d.get("alarmName", "")
        prev = _ts((d.get("previousState") or {}).get("timestamp"))
        return Alert(id=f"cw-{name}-{(d.get('state') or {}).get('timestamp', ev.get('time', ''))}",
                     source="cloudwatch", title=f"CloudWatch 경보: {name}",
                     severity=_cw_severity(d), time=when, first_seen=min(prev or when, when),
                     detail=d, **base)
    if dt == "AWS API Call via CloudTrail" or dt == "AWS Console Sign In via CloudTrail":
        name = d.get("eventName", "")
        sev = "high" if name in API_HIGH else "medium" if name in API_MEDIUM else "low"
        t = _ts(d.get("eventTime")) or when
        return Alert(id=f"ct-{d.get('eventID', ev.get('id', ''))}", source="cloudtrail",
                     title=f"위험 API 호출: {name} ({d.get('sourceIPAddress', '-')})",
                     severity=sev, time=t, first_seen=t, detail=d, **base)
    if src == "logsight.heartbeat":
        last = _ts(d.get("last")) or when - timedelta(days=1)
        age = d.get("age_min")
        return Alert(id=f"hb-{d.get('host', '')}", source="heartbeat",
                     title=f"서버 로그 전송 끊김: {d.get('host', '')} (마지막 신호 "
                           + (f"{age}분 전)" if age is not None else "하루 넘게 없음)"),
                     severity="high", time=when, first_seen=last, detail=d)
    if dt.startswith("Security Hub Findings"):
        fs = d.get("findings") or [{}]
        f = fs[0]
        label = ((f.get("Severity") or {}).get("Label") or "LOW").lower()
        sev = "high" if label in ("high", "critical") else "medium" if label == "medium" else "low"
        t = _ts(f.get("UpdatedAt")) or when
        return Alert(id=f"sh-{f.get('Id', ev.get('id', ''))}", source="securityhub",
                     title=f.get("Title", "Security Hub 결과"), severity=sev, time=t,
                     first_seen=_ts(f.get("FirstObservedAt")) or t, detail=d, **base)
    if not src:
        return None
    return Alert(id=f"ev-{ev.get('id', '')}", source="unknown", title=f"{src} {dt}".strip(),
                 severity="low", time=when, first_seen=when, detail=d, **base)


def _cw_severity(d: dict) -> str:
    """CloudWatch 경보에는 등급이 없다. 경보 이름에 high/critical/medium이 있으면 따르고, 없으면 중간."""
    n = (d.get("alarmName") or "").lower()
    if any(k in n for k in ("critical", "high", "sev1")):
        return "high"
    if "low" in n:
        return "low"
    return "medium"


def alert_input(alert: Alert) -> tuple[str, str] | None:
    """경보 자체를 분석 입력 파일로(파일 이름, 내용). GuardDuty 결과와 CloudTrail 이벤트만 해당."""
    if alert.source == "guardduty":
        return "alert_guardduty.json", json.dumps({"detail-type": "GuardDuty Finding", "detail": alert.detail},
                                                  ensure_ascii=False)
    if alert.source == "cloudtrail":
        return "alert_cloudtrail.json", json.dumps({"Records": [alert.detail]}, ensure_ascii=False)
    return None


# ------------------------------------------------------------------ 중복 처리 막기
class SeenStore:
    """같은 경보(GuardDuty는 같은 결과가 갱신될 때마다 이벤트가 다시 온다)를 cooldown 안에 다시 돌리지 않는다."""

    def __init__(self, path: str | Path, cooldown_min: int = 60):
        self.path, self.cooldown = Path(path), timedelta(minutes=cooldown_min)
        try:
            self.data: dict[str, str] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def recent(self, key: str, now: datetime | None = None) -> bool:
        t = _ts(self.data.get(key))
        return bool(t and (now or datetime.now(timezone.utc)) - t < self.cooldown)

    def mark(self, key: str, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        self.data[key] = _iso(now)
        cutoff = now - timedelta(days=7)
        self.data = {k: v for k, v in self.data.items() if (_ts(v) or now) >= cutoff}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=0), encoding="utf-8")
        os.replace(tmp, self.path)


# ------------------------------------------------------------------ S3에서 기간 로그 받기
def _days(since: datetime, until: datetime) -> list[datetime]:
    d, out = since.replace(hour=0, minute=0, second=0, microsecond=0), []
    while d <= until:
        out.append(d)
        d += timedelta(days=1)
    return out


def fetch_s3(uri: str, since: datetime, until: datetime, dest: Path, s3=None, *,
             max_objects: int = 2000, max_bytes: int = 500 * 1024 * 1024) -> dict:
    """s3://버킷/접두어 아래에서 기간 안에 쓰인 객체를 dest로 받는다.

    접두어에 {date}를 넣으면 기간의 날짜마다 YYYY/MM/DD로 바꿔 그 날짜 폴더만 본다(CloudTrail·Flow Logs의
    S3 구조: AWSLogs/<계정>/CloudTrail/<리전>/2026/11/04/). 없으면 접두어 전체를 보고 수정 시각으로 거른다.
    전달 지연(CloudTrail 약 5분, Flow Logs 약 10분)이 있어 until 뒤 1시간까지 받는다."""
    if not uri.startswith("s3://"):
        raise ValueError(f"s3:// 로 시작해야 함: {uri}")
    bucket, _, prefix = uri[5:].partition("/")
    if s3 is None:
        import boto3
        s3 = boto3.client("s3")
    prefixes = ([prefix.replace("{date}", d.strftime("%Y/%m/%d")) for d in _days(since - timedelta(hours=1), until)]
                if "{date}" in prefix else [prefix])
    lo, hi = since - timedelta(hours=1), until + timedelta(hours=1)
    n = size = 0
    truncated = False
    for pf in prefixes:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=pf):
            for o in page.get("Contents", []):
                lm = o["LastModified"]
                lm = lm if lm.tzinfo else lm.replace(tzinfo=timezone.utc)
                if not (lo <= lm <= hi):
                    continue
                if n >= max_objects or size + o.get("Size", 0) > max_bytes:
                    truncated = True
                    break
                target = dest / bucket / o["Key"]
                target.parent.mkdir(parents=True, exist_ok=True)
                s3.download_file(bucket, o["Key"], str(target))
                n += 1
                size += o.get("Size", 0)
    return {"uri": uri, "objects": n, "bytes": size, "truncated": truncated}


# ------------------------------------------------------------------ 경보 하나 처리
@dataclass
class Options:
    logs: list[str] = field(default_factory=list)     # 로컬 로그 폴더/파일(배송 에이전트나 s3 sync가 채우는 곳)
    s3: list[str] = field(default_factory=list)       # s3://버킷/접두어({date} 가능)
    env: str | None = None                            # environment.json
    collect_env: bool = False                         # 경보 때 설정 스냅샷을 새로 읽기(읽기 전용 권한 필요)
    out: str = "reports/alerts"
    min_severity: str = "medium"
    lookback_h: float = 24.0                          # 처음 보인 시각보다 이만큼 앞부터
    cooldown_min: int = 60
    top: int = 5
    use_ai: bool = True
    model: str | None = None
    notify_cmd: str | None = None                     # 보고서가 나오면 실행할 명령(통지 연결 지점)
    region: str | None = None
    respond: str | None = None                        # 자동 격리 설정 respond.json(없으면 끔)
    heartbeat: str | None = None                      # s3://보관 버킷/heartbeat/ (서버 로그 전송 끊김 감시)
    heartbeat_max_min: float = 5.0


def handle(alert: Alert, opt: Options, *, s3=None, session=None,
           now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> dict:
    """경보 하나를 처리한다. 반환: {"status": "done"|"skipped", ...}. 실패하면 예외(메시지를 지우지 않게)."""
    received = now()
    rcfg = None
    if opt.respond:
        from . import respond as rs
        rcfg = rs.Config.load(opt.respond)
        if alert.source == "cloudtrail":  # 키·사용자 생성 이벤트로 허용 목록을 계속 갱신(등급과 무관)
            rs.Responder(rcfg).observe([alert.detail])
    if SEV_ORDER[alert.severity] < SEV_ORDER[opt.min_severity]:
        return {"status": "skipped", "reason": f"등급 {alert.severity} < 기준 {opt.min_severity}", "alert": alert.summary()}
    seen = SeenStore(Path(opt.out) / ".seen.json", opt.cooldown_min)
    if seen.recent(alert.id, received):
        return {"status": "skipped", "reason": f"{opt.cooldown_min}분 안에 이미 분석함", "alert": alert.summary()}

    from .normalize import load_paths
    from .pipeline import load_env, run
    from .report import render

    since = alert.first_seen - timedelta(hours=opt.lookback_h)
    until = max(received, alert.time) + timedelta(minutes=5)
    short = hashlib.sha1(alert.id.encode()).hexdigest()[:8]
    out = Path(opt.out) / f"{received.strftime('%Y%m%d_%H%M%S')}_{alert.source}_{short}"
    inputs = out / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    (out / "alert.json").write_text(json.dumps({**alert.summary(), "detail": alert.detail}, ensure_ascii=False,
                                               indent=1, default=str), encoding="utf-8")
    paths = list(opt.logs)
    ai = alert_input(alert)
    if ai:
        (inputs / ai[0]).write_text(ai[1], encoding="utf-8")
    fetched = []
    for uri in opt.s3:
        fetched.append(fetch_s3(uri, since, until, inputs / "s3", s3=s3))
    paths.append(str(inputs))

    env_path = opt.env
    env_note = None
    if opt.collect_env:
        try:
            from .aws_collect import export_environment
            env = export_environment(session=session, region=opt.region or alert.region or None)
            env_path = str(out / "environment.json")
            Path(env_path).write_text(json.dumps(env, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 — 설정을 못 읽어도 로그만으로 분석은 한다
            env_note = f"설정 스냅샷 실패: {type(exc).__name__}"
    if env_path is None:
        for p in opt.logs:
            cand = Path(p) / "environment.json"
            if cand.is_file():
                env_path = str(cand)
                break

    t0 = time.time()
    events, stats = load_paths([Path(p) for p in paths], since=since, until=until)
    result = run(events, load_env(env_path), file_stats=stats, top=opt.top, use_ai=opt.use_ai, model=opt.model)
    result["alert"] = alert.summary()
    (out / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "report.html").write_text(render(result), encoding="utf-8")
    resp = None
    if rcfg and SEV_ORDER[alert.severity] >= SEV_ORDER[rcfg.min_severity]:
        from . import respond as rs
        resp = rs.prepare(rs.Responder(rcfg), alert.summary(), rs.iter_records(paths, since, until), out,
                          now=now())
    done = now()
    text = summary_text(alert, result, out)
    if resp:
        from .respond import summary_lines
        extra = summary_lines(resp, out)
        if extra:
            text = text.rstrip("\n").rsplit("\n", 1)
            text = "\n".join([text[0], *extra, text[1]]) + "\n"
    (out / "summary.txt").write_text(text, encoding="utf-8")
    run_info = {"alert": alert.summary(), "received": _iso(received), "report_at": _iso(done),
                "alert_to_report_s": round((done - alert.time).total_seconds(), 1),
                "received_to_report_s": round((done - received).total_seconds(), 1),
                "analyze_s": round(time.time() - t0, 2), "window": [_iso(since), _iso(until)],
                "inputs": paths, "s3": fetched, "env": env_path, "env_note": env_note,
                "n_events": result["n_events"], "n_incidents": result["n_incidents"],
                "response": resp and {k: resp[k] for k in ("status", "mode", "deadline")}}
    if opt.notify_cmd:
        run_info["notify"] = notify(opt.notify_cmd, out, alert)
    (out / "run.json").write_text(json.dumps(run_info, ensure_ascii=False, indent=1), encoding="utf-8")
    seen.mark(alert.id, received)
    return {"status": "done", "out": str(out), **run_info}


def summary_text(alert: Alert, result: dict, out: Path) -> str:
    """통지용 짧은 요약(문자 한 통·이메일 제목+본문에 들어갈 길이). 원본 로그·키는 넣지 않는다."""
    sev = {"high": "높음", "medium": "중간", "low": "낮음"}
    lines = [f"[LogSight] {sev[alert.severity]} 경보: {alert.title[:80]}",
             f"시각 {alert.time.strftime('%m-%d %H:%M')} UTC, 계정 {alert.account or '-'} {alert.region}",
             f"이벤트 {result['n_events']:,}건 → 사건 {result['n_groups']:,}건"]
    for r in result.get("results", [])[:3]:
        inc = r["incident"]
        first = next((c.get("title") for c in r.get("checks", []) if c.get("title")), None)
        lines.append(f"- {inc['id']} [{sev.get(inc['severity'], inc['severity'])}] "
                     f"{'→'.join(inc['stages'][:4])}" + (f" / 먼저: {first[:40]}" if first else ""))
    lines.append("참고: CloudTrail(약 5분)·Flow Logs(약 10분)는 S3 전달이 늦어 경보 직전 몇 분은 빠졌을 수 있음")
    lines.append(f"보고서: {out / 'report.html'}")
    return "\n".join(lines) + "\n"


def notify(cmd: str, out: Path, alert: Alert) -> dict:
    """보고서가 나오면 사용자가 정한 명령을 실행한다(셸을 거치지 않음). 통지 수단(이메일·문자·메신저)은
    이 명령이 맡는다. 실패해도 분석 결과는 남는다."""
    envv = {**os.environ, "LOGSIGHT_REPORT_DIR": str(out), "LOGSIGHT_SUMMARY": str(out / "summary.txt"),
            "LOGSIGHT_SEVERITY": alert.severity, "LOGSIGHT_ALERT_ID": alert.id}
    try:
        p = subprocess.run(shlex.split(cmd), env=envv, capture_output=True, text=True, timeout=60)
        return {"cmd": cmd, "returncode": p.returncode, "stderr": p.stderr[-500:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"cmd": cmd, "error": type(exc).__name__}


# ------------------------------------------------------------------ SQS 대기열 감시
def watch(queue_url: str, opt: Options, *, sqs=None, s3=None, session=None, once: bool = False,
          wait_s: int = 20, log: Callable[[str], None] = print, stop: Callable[[], bool] = lambda: False,
          respond_session=None) -> list[dict]:
    """SQS를 긴 폴링으로 읽어 경보마다 handle()을 돌린다. 처리했거나 건너뛴 메시지만 지운다.
    once=True면 한 번 받고 끝(시험·cron용)."""
    if sqs is None:
        import boto3
        sqs = (session or boto3.Session(region_name=opt.region)).client("sqs")
    done: list[dict] = []
    last_hb = 0.0
    while not stop():
        if opt.heartbeat and time.time() - last_hb >= 60:  # 1분마다 생존 신호 확인
            last_hb = time.time()
            from .heartbeat import check, to_event
            try:
                rows = check(opt.heartbeat, s3=s3, max_age_min=opt.heartbeat_max_min)
            except Exception as exc:  # noqa: BLE001
                log(f"[생존 신호 확인 실패] {type(exc).__name__}")
                rows = []
            for row in rows:
                if not row["ok"]:
                    r = process_message(json.dumps(to_event(row, opt.heartbeat)), opt, s3=s3, session=session, log=log)
                    if r is not None:
                        done.append(r)
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for m in resp.get("Messages", []):
            r = process_message(m.get("Body", ""), opt, s3=s3, session=session, log=log)
            if r is not None:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                done.append(r)
        if opt.respond:  # 마감이 지난 자동 격리 처리(최대 wait_s초 늦음)
            from . import respond as rs
            for resp in rs.tick(rs.Config.load(opt.respond), opt.out, session=respond_session):
                n = sum(1 for a in resp["actions"] if (a.get("outcome") or {}).get("result") in ("done", "would-do"))
                log(f"[격리 {resp['status']}] {resp['alert']['id']}: {n}개")
        if once:
            break
    return done


def process_message(body: str, opt: Options, *, s3=None, session=None,
                    log: Callable[[str], None] = print) -> dict | None:
    """메시지 하나. None이면 실패(지우지 말 것 → 가시성 시간 뒤 재시도, 여러 번 실패하면 DLQ)."""
    ev = unwrap(body)
    alert = parse_event(ev) if ev else None
    if alert is None:
        log("[건너뜀] 경보가 아닌 메시지")
        return {"status": "skipped", "reason": "경보 아님"}
    try:
        r = handle(alert, opt, s3=s3, session=session)
    except Exception as exc:  # noqa: BLE001
        log(f"[실패] {alert.id}: {type(exc).__name__}: {exc}")
        return None
    if r["status"] == "done":
        log(f"[분석] {alert.title[:60]} → {r['out']} (경보→보고서 {r['alert_to_report_s']}초, "
            f"수신→보고서 {r['received_to_report_s']}초)")
    else:
        log(f"[건너뜀] {alert.id}: {r['reason']}")
    return r


def load_events(paths: Iterable[str]) -> list[dict]:
    """on-alert 명령용: 파일에 담긴 EventBridge 이벤트(하나, 목록, 또는 줄마다 하나)."""
    out: list[dict] = []
    for p in paths:
        t = Path(p).read_text(encoding="utf-8-sig").strip()
        try:
            o = json.loads(t)
            out.extend(o if isinstance(o, list) else [o])
        except json.JSONDecodeError:
            out.extend(json.loads(x) for x in t.splitlines() if x.strip())
    return [e for e in (unwrap(x) for x in out) if e]

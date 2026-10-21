"""
LogSight 공통 이벤트 스키마와 파서.
서로 다른 AWS 로그(CloudTrail, VPC Flow Logs, AWS WAF, ALB 접속 로그, EC2 인증 로그)를
하나의 공통 형식(Event)으로 바꾼다. OCSF를 참고한 최소 스키마.
"""
from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(slots=True)
class Event:
    ts: datetime                 # 발생 시각(UTC)
    source: str                  # cloudtrail | vpcflow | waf | alb | sshauth
    src_ip: str | None = None    # 출발지 IP
    dst_ip: str | None = None    # 대상 IP
    dst_port: int | None = None  # 대상 포트
    actor: str | None = None     # 주체(IAM 사용자/역할 ARN, 리눅스 계정)
    instance_id: str | None = None
    access_key: str | None = None  # 마스킹된 액세스 키 ID(연결고리용)
    action: str | None = None    # 행위 또는 API 이름
    outcome: str | None = None   # success | failure | accept | reject | block | allow | count
    raw_ref: str = ""            # 근거 위치(파일:줄 또는 파일:레코드 번호)
    extra: dict = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)  # 이 이벤트에 붙은 탐지 규칙 ID

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d


def _epoch(sec: str | int) -> datetime:
    return datetime.fromtimestamp(int(sec), tz=timezone.utc)


def _iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ 마스킹
_SECRET = re.compile(r"(?i)(password|passwd|secret|token|authorization|cookie)(\"?\s*[=:]\s*\"?)[^\s\"&,}]+")
_AKID = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{4})[0-9A-Z]{8}([0-9A-Z]{4})\b")


def mask_text(s: str) -> str:
    """자격증명/키로 보이는 문자열을 가린다. 액세스 키 ID는 앞 8자·뒤 4자만 남겨
    서로 다른 키를 구분(연결고리)할 수 있게 한다."""
    s = _AKID.sub(r"\1********\2", s)
    return _SECRET.sub(r"\1\2[REDACTED]", s)


def mask_obj(o):
    if isinstance(o, str):
        return mask_text(o)
    if isinstance(o, list):
        return [mask_obj(x) for x in o]
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if isinstance(k, str) and re.search(r"(?i)password|secret|sessiontoken|privatekey", k):
                out[k] = "[REDACTED]"
            else:
                out[k] = mask_obj(v)
        return out
    return o


def mask(events: list[Event]) -> None:
    """AI에 보내기 전 민감정보 마스킹(제자리)."""
    for e in events:
        e.extra = mask_obj(e.extra)
        if e.action:
            e.action = mask_text(e.action)
        if e.access_key:
            e.access_key = mask_text(e.access_key)


# ------------------------------------------------------------------ VPC Flow Logs
# 기본 형식 version 2, 공백 구분 14필드
# version account-id interface-id srcaddr dstaddr srcport dstport
# protocol packets bytes start end action log-status
_PROTO = {"1": "icmp", "6": "tcp", "17": "udp"}


def parse_vpcflow(text: str, name: str = "vpcflow") -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line or line.startswith("version"):
            continue
        f = line.split()
        if len(f) < 14 or f[13] in ("NODATA", "SKIPDATA") or f[3] == "-":
            continue
        try:
            events.append(Event(
                ts=_epoch(f[10]),
                source="vpcflow",
                src_ip=f[3], dst_ip=f[4],
                dst_port=int(f[6]) if f[6].isdigit() else None,
                action=f"{_PROTO.get(f[7], f[7])}/{f[6]} {f[12]}",
                outcome="accept" if f[12] == "ACCEPT" else "reject",
                raw_ref=f"{name}:{i+1}",
                extra={"interface": f[2], "protocol": _PROTO.get(f[7], f[7]),
                       "packets": f[8], "bytes": f[9], "raw": line[:300]},
            ))
        except (ValueError, IndexError, OSError):
            continue
    return events


# ------------------------------------------------------------------ AWS WAF (JSON Lines)
def parse_waf(text: str, name: str = "waf") -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            req = r.get("httpRequest", {})
            ts = datetime.fromtimestamp(int(r["timestamp"]) / 1000, tz=timezone.utc)
        except (ValueError, KeyError, TypeError):
            continue
        counted = [m.get("ruleId") for g in r.get("ruleGroupList") or []
                   for m in (g.get("nonTerminatingMatchingRules") or [])]
        counted += [m.get("ruleId") for m in r.get("nonTerminatingMatchingRules") or []]
        groups = [g.get("ruleGroupId") for g in r.get("ruleGroupList") or []
                  if g.get("nonTerminatingMatchingRules") or g.get("terminatingRule")]
        uri = req.get("uri", "")
        args = req.get("args", "")
        ua = next((h.get("value", "") for h in req.get("headers") or []
                   if str(h.get("name", "")).lower() == "user-agent"), "")
        events.append(Event(
            ts=ts, source="waf",
            src_ip=req.get("clientIp"),
            action=f'{req.get("httpMethod", "")} {uri}{"?" + args if args else ""}'[:300],
            outcome=str(r.get("action", "")).lower(),
            raw_ref=f"{name}:{i+1}",
            extra={
                "terminating_rule": r.get("terminatingRuleId"),
                "counted_rules": [c for c in counted if c],
                "matched_groups": [g for g in groups if g],
                "labels": [lb.get("name") for lb in r.get("labels") or []],
                "country": req.get("country"),
                "ua": ua[:200],
                "web_acl": str(r.get("webaclId", "")).split("/")[-2:-1][0]
                if r.get("webaclId") else None,
            },
        ))
    return events


# ------------------------------------------------------------------ ALB 접속 로그
_ALB = re.compile(r'"[^"]*"|\S+')


def parse_alb(text: str, name: str = "alb") -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        f = _ALB.findall(line)
        if len(f) < 13:
            continue
        try:
            ts = _iso(f[1])
            client = f[3].rsplit(":", 1)[0]
            req = f[12].strip('"').split(" ")
            url = req[1] if len(req) > 1 else ""
            events.append(Event(
                ts=ts, source="alb", src_ip=client,
                action=f"{req[0]} {url}" if req else None,
                outcome="success" if f[8].startswith(("2", "3")) else "failure",
                raw_ref=f"{name}:{i+1}",
                extra={"elb_status": f[8], "ua": f[13].strip('"') if len(f) > 13 else ""},
            ))
        except (ValueError, IndexError):
            continue
    return events


# ------------------------------------------------------------------ EC2 리눅스 인증 로그
_SSH = re.compile(
    r'^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<result>Failed|Accepted)\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?'
    r'(?P<user>\S+)\s+from\s+(?P<ip>[\d.a-fA-F:]+)\s+port\s+(?P<port>\d+)'
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_sshauth(text: str, name: str = "sshauth", year: int = 2026) -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        m = _SSH.search(line)
        if not m or m["mon"] not in _MONTHS:
            continue
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=timezone.utc)
        events.append(Event(
            ts=ts, source="sshauth", src_ip=m["ip"], actor=m["user"], dst_port=22,
            action="ssh_login",
            outcome="success" if m["result"] == "Accepted" else "failure",
            raw_ref=f"{name}:{i+1}",
            extra={"raw": line.strip()[:300]},
        ))
    return events


# ------------------------------------------------------------------ CloudTrail
_INST = re.compile(r"assumed-role/[^/]+/(i-[0-9a-f]+)")


def cloudtrail_record_to_event(r: dict, ref: str) -> Event | None:
    try:
        ts = _iso(r["eventTime"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    ident = r.get("userIdentity") or {}
    arn = ident.get("arn") or ""
    if not arn and ident.get("type") == "Root":
        arn = f"arn:aws:iam::{ident.get('accountId', '')}:root"
    m = _INST.search(arn) if "assumed-role" in arn else None
    params = r.get("requestParameters")
    extra = {k: r[k] for k in ("errorCode", "errorMessage", "awsRegion", "userAgent",
                               "eventType", "recipientAccountId") if r.get(k)}
    extra["identity_type"] = ident.get("type")
    aed = r.get("additionalEventData")
    if isinstance(aed, dict) and aed.get("MFAUsed"):
        extra["mfa"] = aed["MFAUsed"]
    if isinstance(params, dict) and params:
        # 근거 확인에 필요한 대표 파라미터만 남긴다(전체는 원본에 있음)
        extra["params"] = {k: params[k] for k in list(params)[:8]}
    src = r.get("sourceIPAddress")
    return Event(
        ts=ts, source="cloudtrail",
        src_ip=src,
        actor=arn or ident.get("type") or ident.get("invokedBy"),
        instance_id=m.group(1) if m else None,
        access_key=ident.get("accessKeyId"),
        action=f'{str(r.get("eventSource", "")).split(".")[0]}:{r.get("eventName", "")}',
        outcome="failure" if r.get("errorCode") else "success",
        raw_ref=ref,
        extra=extra,
    )


def iter_cloudtrail(text: str, name: str = "cloudtrail") -> Iterator[Event]:
    """{"Records":[...]} 한 파일, 레코드 배열, 또는 JSON Lines 모두 받는다."""
    text = text.strip()
    if not text:
        return
    records: list = []
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            records = data.get("Records") or ([data] if "eventTime" in data else [])
        elif isinstance(data, list):
            records = data
    except json.JSONDecodeError:
        for line in text.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.extend(obj.get("Records", [obj]) if isinstance(obj, dict) else [])
    for i, r in enumerate(records):
        if isinstance(r, dict):
            ev = cloudtrail_record_to_event(r, f"{name}:{i+1}")
            if ev:
                yield ev


def parse_cloudtrail(text: str, name: str = "cloudtrail") -> list[Event]:
    return list(iter_cloudtrail(text, name))


PARSERS = {
    "cloudtrail": parse_cloudtrail,
    "vpcflow": parse_vpcflow,
    "waf": parse_waf,
    "alb": parse_alb,
    "sshauth": parse_sshauth,
}


# ------------------------------------------------------------------ 파일 읽기/형식 판별
def read_text(path: Path) -> str:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8-sig", "replace")  # Windows 메모장의 BOM 제거


def detect_kind(name: str, text: str) -> str | None:
    """파일 이름과 내용 앞부분으로 로그 종류를 추정한다."""
    n = name.lower()
    for kind, keys in (("cloudtrail", ("cloudtrail",)), ("vpcflow", ("vpcflow", "flow")),
                       ("waf", ("waf",)), ("alb", ("alb", "elb")),
                       ("sshauth", ("auth", "secure", "ssh"))):
        if any(k in n for k in keys):
            return kind
    head = text.lstrip()[:2000]
    if '"eventTime"' in head or '"Records"' in head:
        return "cloudtrail"
    if '"httpRequest"' in head and '"terminatingRuleId"' in head:
        return "waf"
    if "sshd[" in head:
        return "sshauth"
    first = head.splitlines()[0] if head else ""
    parts = first.split()
    if first.startswith("version account-id") or (len(parts) >= 14 and parts[0] == "2"):
        return "vpcflow"
    if parts and parts[0] in ("http", "https", "h2", "ws", "wss"):
        return "alb"
    return None


def _walk(paths: Iterable[Path]) -> Iterator[Path]:
    for p in paths:
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*") if x.is_file()
                              and not x.name.startswith(".")
                              and x.suffix.lower() in (".json", ".log", ".gz", ".txt", ".jsonl", ""))
        elif p.is_file():
            yield p


def load_paths(paths: Iterable[Path], kind: str | None = None) -> tuple[list[Event], list[dict]]:
    """파일/폴더 목록을 읽어 이벤트로 바꾼다. 반환: (이벤트, 파일별 처리 결과)."""
    events: list[Event] = []
    stats: list[dict] = []
    for p in _walk([Path(x) for x in paths]):
        if p.name in ("environment.json",):
            continue
        try:
            text = read_text(p)
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            stats.append({"file": str(p), "kind": None, "events": 0, "error": str(exc)})
            continue
        k = kind or detect_kind(p.name, text)
        if not k:
            stats.append({"file": str(p), "kind": None, "events": 0, "error": "형식 판별 실패"})
            continue
        evs = PARSERS[k](text, name=p.name)
        events.extend(evs)
        stats.append({"file": str(p), "kind": k, "events": len(evs)})
    return events, stats


def load_uploads(files: dict[str, tuple[str, bytes]]) -> tuple[list[Event], list[dict]]:
    """웹 업로드용: {필드명: (파일명, 내용)}."""
    events: list[Event] = []
    stats: list[dict] = []
    for field_name, (fname, data) in files.items():
        if data[:2] == b"\x1f\x8b":
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        text = data.decode("utf-8-sig", "replace")
        k = field_name if field_name in PARSERS else detect_kind(fname, text)
        if not k:
            stats.append({"file": fname, "kind": None, "events": 0, "error": "형식 판별 실패"})
            continue
        evs = PARSERS[k](text, name=fname or k)
        events.extend(evs)
        stats.append({"file": fname, "kind": k, "events": len(evs)})
    return events, stats

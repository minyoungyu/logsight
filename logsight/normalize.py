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
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit


@dataclass(slots=True)
class Event:
    ts: datetime                 # 발생 시각(UTC)
    source: str                  # cloudtrail | vpcflow | waf | alb | sshauth | hostfw | weblog | guardduty
    src_ip: str | None = None    # 출발지 IP
    dst_ip: str | None = None    # 대상 IP
    dst_port: int | None = None  # 대상 포트
    actor: str | None = None     # 주체(IAM 사용자/역할 ARN, 리눅스 계정)
    instance_id: str | None = None
    access_key: str | None = None  # 마스킹된 액세스 키 ID(연결고리용)
    action: str | None = None    # 행위 또는 API 이름
    outcome: str | None = None   # 원본 표현: success | failure | accept | reject | block | allow | count | detected
    raw_ref: str = ""            # 근거 위치(파일:줄 또는 파일:레코드 번호)
    extra: dict = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)  # 이 이벤트에 붙은 탐지 규칙 ID

    @property
    def status(self) -> str:
        """로그 종류와 무관한 공통 결과: success(요청이 처리됨) | failure(거부·실패) | unknown."""
        return _STATUS.get((self.outcome or "").lower(), "unknown")

    @property
    def disposition(self) -> str:
        """보안 장치의 판단: allowed | blocked | detected | none(장치 판단이 없는 로그)."""
        o = (self.outcome or "").lower()
        return _DISPOSITION.get(o, "none")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        d["status"], d["disposition"] = self.status, self.disposition
        return d


# 원본마다 다른 결과 표현을 공통 값으로(OCSF의 status/disposition 개념을 단순화)
_STATUS = {"success": "success", "accept": "success", "allow": "success", "count": "success",
           "failure": "failure", "reject": "failure", "block": "failure", "detected": "unknown"}
_DISPOSITION = {"accept": "allowed", "allow": "allowed", "count": "allowed", "reject": "blocked",
                "block": "blocked", "detected": "detected"}

# syslog 형식(연도·시간대가 없는 줄) 해석 설정. CLI의 --year/--syslog-tz로 바꾼다.
SYSLOG = {"year": None, "tz": timezone.utc}


def _syslog_dt(mon: int, day: int, hh: int, mm: int, ss: int, year: int | None = None) -> datetime:
    """연도가 없으면 올해로 보되, 미래 시각이 되면 작년으로 본다(연말에 쌓인 로그를 연초에 분석하는 경우)."""
    tz = SYSLOG["tz"]
    y = year or SYSLOG["year"]
    if y:
        return datetime(y, mon, day, hh, mm, ss, tzinfo=tz).astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    dt = datetime(now.year, mon, day, hh, mm, ss, tzinfo=tz)
    if dt - now > timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt.astimezone(timezone.utc)


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
            target = f[4].rsplit(":", 1)[0] if f[4] != "-" else None
            req = f[12].strip('"').split(" ")
            method, url = (req[0], req[1]) if len(req) > 1 else (req[0], "")
            # 다른 웹 로그(nginx, WAF)와 같은 형식으로: 행위는 "메서드 경로?쿼리", 호스트·포트는 따로
            u = urlsplit(url)
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            port = u.port or {"http": 80, "https": 443}.get(u.scheme)
            events.append(Event(
                ts=ts, source="alb", src_ip=client, dst_ip=target, dst_port=port,
                action=f"{method} {path}"[:300],
                outcome="success" if f[8].startswith(("2", "3")) else "failure",
                raw_ref=f"{name}:{i+1}",
                extra={"http_status": int(f[8]) if f[8].isdigit() else None, "host": u.hostname, "ua": f[13].strip('"') if len(f) > 13 else ""},
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


def parse_sshauth(text: str, name: str = "sshauth", year: int | None = None) -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        m = _SSH.search(line)
        if not m or m["mon"] not in _MONTHS:
            continue
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        ts = _syslog_dt(_MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, year)
        events.append(Event(
            ts=ts, source="sshauth", src_ip=m["ip"], actor=m["user"], dst_port=22,
            action="ssh_login",
            outcome="success" if m["result"] == "Accepted" else "failure",
            raw_ref=f"{name}:{i+1}",
            extra={"raw": line.strip()[:300]},
        ))
    return events


# ------------------------------------------------------------------ 서버 방화벽 로그(iptables/nftables/ufw)
# VPC Flow Logs 대신 쓰는 무료 대안. 커널 LOG 줄 예:
#   Nov  1 10:00:01 web1 kernel: [123.4] LOGSIGHT-NEW IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.1.10 ... PROTO=TCP SPT=40000 DPT=22 ... SYN
# 보안그룹을 통과해 서버까지 들어온 패킷만 보인다(보안그룹이 막은 것은 안 보임).
_FW_KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|IN)=(\S*)")
_FW_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?)")
_FW_SYSLOG = re.compile(r"^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)")
_FW_PREFIX = re.compile(r"kernel:\s*(?:\[\s*[\d.]+\]\s*)?(.*?)\s*IN=")


def _line_ts(line: str, year: int | None) -> datetime | None:
    m = _FW_ISO.match(line)
    if m:
        s = m.group(1)
        if re.search(r"[+-]\d{4}$", s):
            s = s[:-2] + ":" + s[-2:]
        try:
            return _iso(s)
        except ValueError:
            return None
    m = _FW_SYSLOG.match(line)
    if m and m.group(1) in _MONTHS:
        return _syslog_dt(_MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), year)
    return None


def parse_hostfw(text: str, name: str = "hostfw", year: int | None = None) -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        if "SRC=" not in line or "DPT=" not in line and "PROTO=ICMP" not in line:
            continue
        kv = dict(_FW_KV.findall(line))
        ts = _line_ts(line.strip(), year)
        if not ts or not kv.get("SRC"):
            continue
        pm = _FW_PREFIX.search(line)
        prefix = (pm.group(1) if pm else "").upper()
        # 차단 규칙 접두어면 reject, 그 외(허용·신규 연결 기록)는 서버까지 도달 = accept
        outcome = "reject" if any(w in prefix for w in ("BLOCK", "DROP", "REJECT", "DENY")) else "accept"
        proto = kv.get("PROTO", "").lower()
        port = kv.get("DPT")
        events.append(Event(
            ts=ts, source="hostfw", src_ip=kv["SRC"], dst_ip=kv.get("DST"),
            dst_port=int(port) if port and port.isdigit() else None,
            action=f"{proto}/{port or '-'} {'REJECT' if outcome == 'reject' else 'ACCEPT'}",
            outcome=outcome, raw_ref=f"{name}:{i+1}",
            extra={"interface": kv.get("IN"), "protocol": proto, "prefix": prefix.strip()[:40],
                   "raw": line.strip()[:300]},
        ))
    return events


# ------------------------------------------------------------------ 웹 서버 접속 로그(nginx/apache combined)
# WAF 로그 대신 쓰는 무료 대안. 예:
#   203.0.113.5 - - [01/Nov/2026:10:00:00 +0000] "GET /item?id=1 HTTP/1.1" 200 512 "-" "curl/8.0"
_WEB = re.compile(r'^(?P<ip>[\da-fA-F.:]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
                  r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
                  r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')


def parse_weblog(text: str, name: str = "weblog") -> list[Event]:
    events = []
    for i, line in enumerate(text.splitlines()):
        m = _WEB.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except ValueError:
            continue
        req = m["req"].split(" ")
        st = m["status"]
        events.append(Event(
            ts=ts, source="weblog", src_ip=m["ip"],
            action=(f"{req[0]} {req[1]}" if len(req) > 1 else m["req"])[:300],
            outcome="success" if st[0] in "23" else "failure",
            raw_ref=f"{name}:{i+1}",
            extra={"http_status": int(st), "ua": (m["ua"] or "")[:200]},
        ))
    return events


# ------------------------------------------------------------------ Amazon GuardDuty 탐지 결과
# get-findings 결과({"Findings":[...]}), S3 내보내기(JSON Lines), EventBridge 이벤트({"detail": {...}}) 모두 받는다.
# GuardDuty가 탐지한 것을 LogSight가 쉬운 한국어 설명·수정안으로 바꾸는 용도("탐지는 AWS, 설명과 수정은 LogSight").
GD_ALIAS = [  # 탐지 유형(부분 문자열) → 같은 의미의 LogSight 규칙(수정안 생성에 사용)
    ("InstanceCredentialExfiltration", "CT_INSTANCE_CRED_OUTSIDE"),
    ("SSHBruteForce", "SSH_BRUTE_FORCE"), ("RDPBruteForce", "SSH_BRUTE_FORCE"),
    ("PortProbeUnprotectedPort", "VPC_REMOTE_ADMIN_EXPOSED"), ("Recon:EC2/Portscan", "VPC_PORT_SCAN"),
    ("CloudTrailLoggingDisabled", "CT_LOGGING_TAMPER"), ("RootCredentialUsage", "CT_ROOT_USAGE"),
    ("Persistence:IAMUser", "CT_IAM_PERSISTENCE"), ("PrivilegeEscalation:IAMUser", "CT_IAM_PERSISTENCE"),
    ("Discovery:IAMUser", "CT_DISCOVERY_BURST"), ("Exfiltration:S3", "CT_S3_BULK_READ"),
    ("UnauthorizedAccess:IAMUser/MaliciousIPCaller", "CT_UNTRUSTED_IP"),
    ("UnauthorizedAccess:IAMUser/TorIPCaller", "CT_UNTRUSTED_IP"),
    ("Policy:S3/BucketBlockPublicAccessDisabled", "CT_LOGGING_TAMPER"),
]


def _gd_ip(action: dict) -> str | None:
    for k in ("AwsApiCallAction", "NetworkConnectionAction", "KubernetesApiCallAction", "RdsLoginAttemptAction"):
        ip = ((action.get(k) or {}).get("RemoteIpDetails") or {}).get("IpAddressV4")
        if ip:
            return ip
    for d in (action.get("PortProbeAction") or {}).get("PortProbeDetails") or []:
        ip = (d.get("RemoteIpDetails") or {}).get("IpAddressV4")
        if ip:
            return ip
    return None


def _gd_port(action: dict) -> int | None:
    p = ((action.get("NetworkConnectionAction") or {}).get("LocalPortDetails") or {}).get("Port")
    if p is None:
        for d in (action.get("PortProbeAction") or {}).get("PortProbeDetails") or []:
            p = (d.get("LocalPortDetails") or {}).get("Port")
            if p is not None:
                break
    return int(p) if isinstance(p, (int, float, str)) and str(p).isdigit() else None


def _iter_gd(text: str):
    t = text.lstrip()
    try:
        data = json.loads(t)
        items = data.get("Findings") or data.get("findings") or [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        items = []
        for line in t.splitlines():
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for it in items or []:
        if isinstance(it, dict) and isinstance(it.get("detail"), dict):
            it = it["detail"]  # EventBridge 형식
        if isinstance(it, dict) and it.get("Type"):
            yield it


def parse_guardduty(text: str, name: str = "guardduty") -> list[Event]:
    events = []
    for i, f in enumerate(_iter_gd(text)):
        svc = f.get("Service") or {}
        action = svc.get("Action") or {}
        res = f.get("Resource") or {}
        try:
            ts = _iso(svc.get("EventFirstSeen") or f.get("CreatedAt") or svc.get("EventLastSeen")
                      or f.get("UpdatedAt"))
        except (TypeError, ValueError):
            continue
        akd = res.get("AccessKeyDetails") or {}
        typ = str(f.get("Type"))
        api = (action.get("AwsApiCallAction") or {}).get("Api")
        events.append(Event(
            ts=ts, source="guardduty", src_ip=_gd_ip(action),
            dst_port=_gd_port(action),
            actor=akd.get("UserName") or akd.get("PrincipalId"),
            instance_id=(res.get("InstanceDetails") or {}).get("InstanceId"),
            access_key=akd.get("AccessKeyId"),
            action=typ, outcome="detected", raw_ref=f"{name}:{i+1}",
            extra={"gd_id": f.get("Id"), "gd_type": typ, "gd_title": str(f.get("Title", ""))[:200],
                   "gd_severity": float(f.get("Severity") or 0), "gd_count": svc.get("Count"),
                   "gd_api": api, "gd_resource": res.get("ResourceType"),
                   "gd_last_seen": svc.get("EventLastSeen") or f.get("UpdatedAt"),
                   "gd_alias": sorted({r for k, r in GD_ALIAS if k in typ})},
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
    # 수백만 건을 메모리에 올리므로 판단에 필요한 필드만, 반복 문자열은 intern으로 공유
    extra = {k: sys.intern(str(r[k])[:120]) for k in ("errorCode", "awsRegion", "userAgent",
                                                       "eventType") if r.get(k)}
    extra["identity_type"] = ident.get("type")
    aed = r.get("additionalEventData")
    if isinstance(aed, dict) and aed.get("MFAUsed"):
        extra["mfa"] = aed["MFAUsed"]
    if isinstance(params, dict) and params:
        # 근거 확인에 필요한 대표 파라미터만 남긴다(전체는 원본에 있음)
        extra["params"] = json.dumps({k: params[k] for k in list(params)[:8]},
                                     ensure_ascii=False, default=str)[:400]
    src = r.get("sourceIPAddress")
    actor = arn or ident.get("type") or ident.get("invokedBy")
    key = ident.get("accessKeyId")
    return Event(
        ts=ts, source="cloudtrail",
        src_ip=sys.intern(src) if isinstance(src, str) else None,
        actor=sys.intern(actor) if isinstance(actor, str) else None,
        instance_id=m.group(1) if m else None,
        access_key=sys.intern(key) if isinstance(key, str) else None,
        action=sys.intern(f'{str(r.get("eventSource", "")).split(".")[0]}:{r.get("eventName", "")}'),
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
    "hostfw": parse_hostfw,
    "weblog": parse_weblog,
    "guardduty": parse_guardduty,
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
    for kind, keys in (("guardduty", ("guardduty",)), ("cloudtrail", ("cloudtrail",)), ("vpcflow", ("vpcflow", "flow")),
                       ("waf", ("waf",)), ("alb", ("alb", "elb")),
                       ("hostfw", ("hostfw", "iptables", "nftables", "ufw", "kern", "firewall")),
                       ("weblog", ("nginx", "apache", "httpd", "access", "weblog")),
                       ("sshauth", ("auth", "secure", "ssh"))):
        if any(k in n for k in keys):
            return kind
    head = text.lstrip()[:2000]
    if '"Severity"' in head and '"Type"' in head and ('"Service"' in head or '"SchemaVersion"' in head):
        return "guardduty"
    if '"eventTime"' in head or '"Records"' in head:
        return "cloudtrail"
    if '"httpRequest"' in head and '"terminatingRuleId"' in head:
        return "waf"
    if "kernel:" in head and "SRC=" in head and "PROTO=" in head:
        return "hostfw"
    if "sshd[" in head:
        return "sshauth"
    if _WEB.match(head.splitlines()[0] if head else ""):
        return "weblog"
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


_PATH_DATE = re.compile(r"(?:^|[/\\_])(20\d\d)[/\\-]?(\d\d)[/\\-]?(\d\d)(?:[/\\T_]|$)")


def parse_when(s: str | None, end: bool = False) -> datetime | None:
    """'2017-02-12' 또는 ISO 시각을 UTC datetime으로. end=True면 날짜만 준 경우 그날 끝까지."""
    if not s:
        return None
    if len(s) == 10:
        d = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return d + timedelta(days=1) - timedelta(microseconds=1) if end else d
    return _iso(s)


def _path_day(p: Path) -> datetime | None:
    """CloudTrail S3 경로(.../2017/02/12/...)나 파일명(..._20170212T...)에서 날짜를 읽는다."""
    m = _PATH_DATE.search(p.as_posix())
    if not m:
        return None
    try:
        return datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc)
    except ValueError:
        return None


def load_paths(paths: Iterable[Path], kind: str | None = None, since: datetime | None = None,
               until: datetime | None = None) -> tuple[list[Event], list[dict]]:
    """파일/폴더 목록을 읽어 이벤트로 바꾼다. 반환: (이벤트, 파일별 처리 결과).
    since/until을 주면 그 기간 이벤트만 남긴다. 경로에 날짜가 있는 파일(CloudTrail S3 구조)은
    기간 밖이면 아예 읽지 않아 시간과 메모리를 아낀다."""
    events: list[Event] = []
    stats: list[dict] = []
    day, hour = timedelta(days=1), timedelta(hours=1)
    for p in _walk([Path(x) for x in paths]):
        if p.name in ("environment.json",):
            continue
        if since or until:
            d = _path_day(p)
            # 경로 날짜는 전달된 날이라 그날 0시 직전~다음 날 0시의 이벤트가 들어 있다(1시간 여유)
            if d and ((since and d + day + hour < since) or (until and d - hour > until)):
                stats.append({"file": str(p), "kind": None, "events": 0, "skipped": "기간 밖"})
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
        if since or until:
            evs = [e for e in evs if (not since or e.ts >= since) and (not until or e.ts <= until)]
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

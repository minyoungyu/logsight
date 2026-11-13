"""
웹서버·리눅스 서버 로그 파서.

지원 형식:
  - access : nginx/Apache 접속 로그(Common Log Format, Combined Log Format 자동 판별)
  - weberror : nginx/Apache 오류 로그
  - auth   : 리눅스 인증 로그(/var/log/auth.log, secure) — SSH, sudo, su, 계정 생성

모두 normalize.Event 공통 스키마로 바꾼다. 웹 요청은 action에 "METHOD /경로?쿼리"를,
상태 코드·User-Agent·Referer는 extra에 담는다. 원본 줄은 근거(raw_ref=파일:줄)로 추적한다.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from ..normalize import Event

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_clf_time(s: str) -> datetime:
    """10/Oct/2026:13:55:36 +0000 형태의 접속 로그 시각을 UTC로."""
    m = re.match(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?", s)
    if not m:
        raise ValueError(s)
    day, mon, year, hh, mm, ss, tz = m.groups()
    dt = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                  tzinfo=timezone.utc)
    if tz:
        sign = 1 if tz[0] == "+" else -1
        off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        dt = datetime.fromtimestamp(dt.timestamp() - off, tz=timezone.utc)
    return dt


# ------------------------------------------------------------------ 접속 로그
# Common/Combined Log Format:
#   host ident authuser [time] "request" status bytes "referer" "user-agent"
_ACCESS = re.compile(
    # Apache vhost_combined: 줄 앞의 '가상호스트:포트'는 건너뛴다(normalize._WEB과 같은 기준).
    r'^(?:(?P<vhost>(?:[^\s:\[\]"]*[^\s\d:.\[\]"][^\s:\[\]"]*|\[[\da-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5})\s+'
    r'(?=[0-9a-fA-F.:]+\s))?'
    r'(?P<host>\S+(?:,\s*[0-9a-fA-F.:]+)*)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
# 프록시/로드밸런서 뒤의 실제 클라이언트가 X-Forwarded-For로 들어오는 변형(nginx 커스텀)도
# 흔하므로, host 자리에 쉼표로 여러 IP가 올 수 있다. 맨 앞(원 클라이언트)을 쓴다.


def _status_outcome(status: str) -> str:
    if not status.isdigit():
        return "unknown"
    code = int(status)
    if code < 400:
        return "success"
    if code < 500:
        return "client-error"
    return "server-error"


def parse_access(text: str, name: str = "access") -> list[Event]:
    events: list[Event] = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        m = _ACCESS.match(line)
        if not m:
            continue
        try:
            ts = _parse_clf_time(m["time"])
        except (ValueError, KeyError):
            continue
        host = m["host"].split(",")[0].strip()
        # 요청 줄은 "METHOD URI PROTO". URI 안에 (비정상) 공백이 있어도 잃지 않도록
        # 첫 토큰(메서드)과 마지막 HTTP/x 토큰(프로토콜)만 떼고 가운데 전체를 URI로 본다.
        req = (m["request"] or "").split(" ")
        method = req[0] if req and req[0] else "-"
        proto = ""
        if len(req) >= 3 and req[-1].startswith(("HTTP/", "http/")):
            proto = req[-1]
            path = " ".join(req[1:-1])
        else:
            path = " ".join(req[1:]) if len(req) > 1 else ""
        q = path.split("?", 1)
        events.append(Event(
            ts=ts, source="access", src_ip=host,
            actor=m["user"] if m["user"] not in ("-", "") else None,
            action=f"{method} {path}"[:400],
            outcome=_status_outcome(m["status"]),
            raw_ref=f"{name}:{i+1}",
            extra={
                "status": m["status"],
                "method": method,
                "path": q[0],
                "query": q[1] if len(q) > 1 else "",
                "bytes": m["bytes"] if m["bytes"] != "-" else "0",
                "referer": (m["referer"] or "")[:300],
                "ua": (m["ua"] or "")[:300],
                "proto": proto,
                "raw": line[:500],
                **({"vhost": m["vhost"]} if m["vhost"] else {}),
            },
        ))
    return events


# ------------------------------------------------------------------ 오류 로그
# nginx:  2026/10/10 13:55:36 [error] 1234#0: *5 open() "..." failed ... client: 1.2.3.4
# apache: [Sat Oct 10 13:55:36.123456 2026] [php:error] [pid 1234] [client 1.2.3.4:5678] msg
_NGINX_ERR = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?P<msg>.*)")
_NGINX_CLIENT = re.compile(r"client:\s*(?P<ip>[\d.a-fA-F:]+)")
_APACHE_ERR = re.compile(
    r"^\[(?P<time>[^\]]+)\]\s+\[(?P<mod>[^\]]+)\]\s+(?:\[pid [^\]]+\]\s+)?"
    r"(?:\[client (?P<ip>[0-9a-fA-F.:]+?)(?::\d+)?\]\s+)?(?P<msg>.*)")


def parse_weberror(text: str, name: str = "weberror") -> list[Event]:
    events: list[Event] = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        ip = None
        level = "error"
        msg = line
        ts = None
        mn = _NGINX_ERR.match(line)
        if mn:
            try:
                ts = datetime.strptime(mn["time"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
            level = mn["level"]
            msg = mn["msg"]
            cm = _NGINX_CLIENT.search(line)
            ip = cm["ip"] if cm else None
        else:
            ma = _APACHE_ERR.match(line)
            if ma:
                level = ma["mod"].split(":")[-1] if ":" in ma["mod"] else ma["mod"]
                msg = ma["msg"]
                ip = ma["ip"]
                for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
                    try:
                        ts = datetime.strptime(ma["time"], fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue
        if ts is None:
            continue
        events.append(Event(
            ts=ts, source="weberror", src_ip=ip,
            action=msg[:300], outcome=level,
            raw_ref=f"{name}:{i+1}",
            extra={"level": level, "message": msg[:500], "raw": line[:500]},
        ))
    return events


# ------------------------------------------------------------------ 리눅스 인증 로그
# SSH 성공/실패는 기존 normalize.parse_sshauth 가 담당. 여기서는 그 외 권한 상승·계정 변화
# (sudo, su, useradd, passwd)를 추가로 뽑아 하나의 "auth" 소스로 합친다.
_SYSLOG_HEAD = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)")
_SSH_LINE = re.compile(
    r"(?P<result>Failed|Accepted)\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d.a-fA-F:]+)")
_SUDO = re.compile(r"(?P<who>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$")
_USERADD = re.compile(r"new user: name=(?P<user>[^,]+)")


def parse_auth(text: str, name: str = "auth", year: int = 2026) -> list[Event]:
    events: list[Event] = []
    for i, line in enumerate(text.splitlines()):
        m = _SYSLOG_HEAD.match(line.strip())
        if not m or m["mon"] not in _MONTHS:
            continue
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=timezone.utc)
        proc, msg = m["proc"], m["msg"]
        ev = None
        if "sshd" in proc:
            sm = _SSH_LINE.search(msg)
            if sm:
                ev = Event(ts=ts, source="auth", src_ip=sm["ip"], actor=sm["user"], dst_port=22,
                           action="ssh_login",
                           outcome="success" if sm["result"] == "Accepted" else "failure",
                           raw_ref=f"{name}:{i+1}", extra={"proc": "sshd", "raw": line.strip()[:300]})
        elif "sudo" in proc:
            su = _SUDO.search(msg)
            if su:
                ev = Event(ts=ts, source="auth", actor=su["who"], action="sudo",
                           outcome="success", raw_ref=f"{name}:{i+1}",
                           extra={"proc": "sudo", "command": su["cmd"][:200], "raw": line.strip()[:300]})
        elif "useradd" in proc or "usermod" in proc:
            ua = _USERADD.search(msg)
            if ua:
                ev = Event(ts=ts, source="auth", actor=ua["user"], action="useradd",
                           outcome="success", raw_ref=f"{name}:{i+1}",
                           extra={"proc": proc, "raw": line.strip()[:300]})
        if ev is not None:
            events.append(ev)
    return events


def decode_query(action_or_query: str) -> str:
    """URL 인코딩된 쿼리/경로를 사람이 읽을 수 있게 풀어 준다(탐지 규칙·보고서용)."""
    try:
        return unquote_plus(action_or_query)
    except Exception:  # noqa: BLE001
        return action_or_query

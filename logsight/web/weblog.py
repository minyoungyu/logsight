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

from urllib.parse import unquote_plus

from ..normalize import Event, parse_sshauth, parse_weberror, parse_web_line, web_extra  # noqa: F401


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
        w = parse_web_line(line)
        if not w:
            continue
        extra = web_extra(w)
        # 웹서버 점검 규칙이 쓰는 옛 이름(문자열 상태 코드·바이트 수)도 함께 둔다
        extra.update({"status": w["status"], "bytes": str(w["resp_bytes"]), "raw": line[:500]})
        events.append(Event(
            ts=w["ts"], source="access", src_ip=w["src_ip"], actor=w["user"],
            action=f"{w['method']} {w['uri']}"[:400],
            outcome=_status_outcome(w["status"]),
            raw_ref=f"{name}:{i+1}",
            extra=extra,
        ))
    return events




def parse_auth(text: str, name: str = "auth", year: int | None = None) -> list[Event]:
    """웹서버 점검의 auth 로그. 사후 분석과 같은 파서(normalize.parse_sshauth)를 쓰고 이름표만 auth로 둔다."""
    events = parse_sshauth(text, name=name, year=year)
    for e in events:
        e.source = "auth"
    return events


def decode_query(action_or_query: str) -> str:
    """URL 인코딩된 쿼리/경로를 사람이 읽을 수 있게 풀어 준다(탐지 규칙·보고서용)."""
    try:
        return unquote_plus(action_or_query)
    except Exception:  # noqa: BLE001
        return action_or_query

"""
통지: 경보 분석이 끝나면 이메일·디스코드·슬랙·일반 웹훅으로 알린다(notify.json에서 골라 쓴다).

    {"channels": [
      {"type": "email",   "smtp_host": "email-smtp.ap-northeast-2.amazonaws.com", "smtp_port": 587,
                          "user_env": "LOGSIGHT_SMTP_USER", "password_env": "LOGSIGHT_SMTP_PASSWORD",
                          "from": "alerts@example.com", "to": ["security@example.com"]},
      {"type": "slack",   "url_env": "LOGSIGHT_SLACK_WEBHOOK"},
      {"type": "discord", "url_env": "LOGSIGHT_DISCORD_WEBHOOK", "min_severity": "high"},
      {"type": "webhook", "url_env": "LOGSIGHT_WEBHOOK_URL", "secret_env": "LOGSIGHT_WEBHOOK_SECRET"}
    ]}

웹훅 주소·비밀번호는 설정 파일에 직접 쓰지 않고 환경변수 이름(*_env)으로 받는다(주소 자체가 비밀이다).
통지에는 원본 로그·키를 넣지 않는다. 요약, 먼저 할 일, 보고서(마스킹된 HTML)만 보낸다.
이메일은 정보성 통지임을 제목과 본문 끝에 밝히고 광고 문구를 넣지 않는다(정보통신망법 제50조 광고성 정보와 구별).
카카오 알림톡은 사업자 등록 뒤 붙인다(type "kakao_alimtalk"은 지금은 '미지원'으로 기록만 한다).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from .analyze import STAGE_KO

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
TYPES = ("email", "slack", "discord", "webhook", "kakao_alimtalk")


def load_config(path: str | Path) -> list[dict]:
    d = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    chans = d.get("channels") if isinstance(d, dict) else None
    if not isinstance(chans, list):
        raise ValueError("notify.json에 channels 목록이 필요")
    for c in chans:
        if c.get("type") not in TYPES:
            raise ValueError(f"모르는 통지 종류: {c.get('type')} (가능: {', '.join(TYPES)})")
    return [c for c in chans if c.get("enabled", True)]


def _secret(c: dict, key: str) -> str | None:
    """설정의 key_env(환경변수 이름)를 우선, 없으면 key 값을 그대로."""
    env = c.get(f"{key}_env")
    return os.environ.get(env) if env else c.get(key)


# ------------------------------------------------------------------ 보낼 내용
def build(alert: dict, result: dict, out: Path, response: dict | None = None) -> dict:
    """채널 공통 내용. alert는 Alert.summary(), result는 분석 결과."""
    first: list[str] = []
    incidents = []
    for r in result.get("results", [])[:3]:
        inc = r["incident"]
        incidents.append({"id": inc["id"], "severity": inc["severity"], "stages": inc["stages"][:5],
                          "src_ips": inc.get("src_ips", [])[:3]})
        for c in r.get("checks", []):
            t = c.get("title")
            if t and t not in first:
                first.append(t)
    msg = {
        "title": f"{SEV_KO.get(alert['severity'], alert['severity'])} 경보: {alert['title'][:120]}",
        "severity": alert["severity"], "alert": alert,
        "counts": {"events": result.get("n_events", 0), "incidents": result.get("n_groups", 0)},
        "incidents": incidents, "first_actions": first[:5],
        "report_dir": str(out), "report_html": str(out / "report.html"),
    }
    if response and response.get("actions"):
        test = response.get("mode") == "dry-run"
        msg["auto_isolation"] = {"deadline": response["deadline"], "count": len(response["actions"]),
                                 "dry_run": test, "ack": f"python -m logsight respond ack {out}"}
    return msg


def text(msg: dict) -> str:
    a = msg["alert"]
    lines = [f"[LogFinder] {msg['title']}",
             f"시각 {a['time'][:16].replace('T', ' ')} UTC · 계정 {a.get('account') or '-'} {a.get('region') or ''}".rstrip(),
             f"이벤트 {msg['counts']['events']:,}건 → 사건 {msg['counts']['incidents']:,}건"]
    for i in msg["incidents"]:
        lines.append(f"- {i['id']} [{SEV_KO.get(i['severity'], i['severity'])}] {' → '.join(STAGE_KO.get(x, x) for x in i['stages'])}"
                     + (f" (출발지 {', '.join(i['src_ips'])})" if i["src_ips"] else ""))
    if msg["first_actions"]:
        lines.append("먼저 할 일:")
        lines += [f"  {n}. {t}" for n, t in enumerate(msg["first_actions"][:3], 1)]
    iso = msg.get("auto_isolation")
    if iso:
        lines.append(f"{iso['deadline'][11:16]} UTC까지 확인하지 않으면 외부에서 만든 {iso['count']}개를 격리"
                     + (" (시험 모드: 기록만)" if iso["dry_run"] else "") + f". 확인: {iso['ack']}")
    lines.append(f"보고서: {msg['report_html']}")
    return "\n".join(lines)


def _slack_escape(s: str) -> str:
    # <!channel> 같은 전체 호출이나 링크 위장이 로그 문자열로 들어오지 못하게
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ------------------------------------------------------------------ 채널별 전송
def _post(url: str, body: bytes, headers: dict[str, str], tries: int = 3) -> dict:
    last = None
    for n in range(tries):
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "LogSight", **headers})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - 사용자가 정한 주소
                return {"ok": True, "status": r.status}
        except urllib.error.HTTPError as e:
            last = {"ok": False, "status": e.code}
            if e.code != 429 and e.code < 500:
                return last  # 주소·형식 오류는 다시 해도 같다
        except (urllib.error.URLError, OSError) as e:
            last = {"ok": False, "error": type(e).__name__}
        time.sleep(min(2 ** n, 5) if n < tries - 1 else 0)
    return last or {"ok": False}


def send_slack(c: dict, msg: dict) -> dict:
    url = _secret(c, "url")
    if not url:
        return {"ok": False, "error": "웹훅 주소 없음(url_env)"}
    body = {"text": _slack_escape(text(msg))}
    return _post(url, json.dumps(body, ensure_ascii=False).encode(), {})


def send_discord(c: dict, msg: dict) -> dict:
    url = _secret(c, "url")
    if not url:
        return {"ok": False, "error": "웹훅 주소 없음(url_env)"}
    color = {"high": 0xD93025, "medium": 0xF29900, "low": 0x5F6368}.get(msg["severity"], 0x5F6368)
    body = {"username": "LogFinder", "allowed_mentions": {"parse": []},  # @everyone 등 호출 막기
            "embeds": [{"title": msg["title"][:250], "description": text(msg)[:3900], "color": color}]}
    return _post(url, json.dumps(body, ensure_ascii=False).encode(), {})


def send_webhook(c: dict, msg: dict) -> dict:
    """일반 웹훅: JSON 그대로. secret이 있으면 X-LogSight-Signature: sha256=HMAC(secret, 시각.본문)."""
    url = _secret(c, "url")
    if not url:
        return {"ok": False, "error": "웹훅 주소 없음(url_env)"}
    payload = {"source": "logsight", "version": 1, "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "text": text(msg), **msg}
    body = json.dumps(payload, ensure_ascii=False).encode()
    headers = {}
    secret = _secret(c, "secret")
    if secret:
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers = {"X-LogSight-Timestamp": ts, "X-LogSight-Signature": f"sha256={sig}"}
    return _post(url, body, headers)


EMAIL_FOOTER = (
    "\n\n─────────────\n"
    "이 메일은 귀사가 이용 중인 LogFinder 보안 분석이 AWS 보안 경보를 받아 자동으로 보낸 정보성 알림입니다. "
    "광고가 아니며, 수신 담당자 변경은 LogFinder 설정(notify.json)에서 합니다.\n"
    "첨부한 보고서는 IP·키를 일부 가린(마스킹) 분석 결과이며, 원본 로그는 들어 있지 않습니다."
)


def email_message(c: dict, msg: dict) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = f"[LogFinder 보안 경보·정보성] {msg['title'][:150]}"
    m["From"] = c["from"]
    m["To"] = ", ".join(c["to"])
    body = [text(msg), "", "무슨 일이 있었나: 보고서의 '공격 흐름'과 '판정 이유'를 보세요.",
            "고칠 곳: 보고서의 '수정안'에 AWS CLI 명령과 되돌리기 명령이 있습니다(자동 적용하지 않음)."]
    m.set_content("\n".join(body) + EMAIL_FOOTER)
    rep = Path(msg["report_html"])
    if c.get("attach_report", True) and rep.is_file() and rep.stat().st_size <= 5 * 1024 * 1024:
        m.add_attachment(rep.read_bytes(), maintype="text", subtype="html", filename="logsight_report.html")
    return m


def send_email(c: dict, msg: dict) -> dict:
    for k in ("smtp_host", "from", "to"):
        if not c.get(k):
            return {"ok": False, "error": f"{k} 없음"}
    m = email_message(c, msg)
    port = int(c.get("smtp_port", 587))
    try:
        if c.get("ssl") or port == 465:
            s = smtplib.SMTP_SSL(c["smtp_host"], port, timeout=15, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(c["smtp_host"], port, timeout=15)
            if c.get("starttls", True):
                s.starttls(context=ssl.create_default_context())
        with s:
            user, pw = _secret(c, "user"), _secret(c, "password")
            if user and pw:
                s.login(user, pw)
            s.send_message(m)
        return {"ok": True}
    except (smtplib.SMTPException, OSError) as e:
        return {"ok": False, "error": type(e).__name__}


SENDERS = {"email": send_email, "slack": send_slack, "discord": send_discord, "webhook": send_webhook}


def send_all(channels: list[dict], msg: dict) -> list[dict]:
    """채널마다 보내고 결과를 돌려준다. 하나가 실패해도 나머지는 보낸다. 예외를 밖으로 내지 않는다."""
    out = []
    for c in channels:
        t = c.get("type")
        name = c.get("name") or t
        if SEV_ORDER.get(msg["severity"], 0) < SEV_ORDER.get(c.get("min_severity", "low"), 0):
            out.append({"channel": name, "ok": None, "skipped": "등급 미만"})
            continue
        if t == "kakao_alimtalk":
            out.append({"channel": name, "ok": False, "error": "카카오 알림톡은 사업자 등록 뒤 지원 예정"})
            continue
        try:
            r = SENDERS[t](c, msg)
        except Exception as e:  # noqa: BLE001 - 통지 실패가 분석을 멈추면 안 된다
            r = {"ok": False, "error": type(e).__name__}
        out.append({"channel": name, **r})
    return out


def test_message() -> dict:
    """설정 확인용 시험 메시지(`logsight notify-test`)."""
    alert: dict[str, Any] = {"id": "test", "source": "test", "title": "LogFinder 통지 시험입니다. 실제 경보가 아닙니다.",
                             "severity": "low", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "account": "", "region": ""}
    return {"title": "시험: LogFinder 통지 연결 확인", "severity": "high", "alert": alert,
            "counts": {"events": 0, "incidents": 0}, "incidents": [], "first_actions": [],
            "report_dir": "-", "report_html": "-"}

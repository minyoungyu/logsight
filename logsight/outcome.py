"""결과 낱말과 구체 대상(사양서 FR-24·25·26).

한 사건 안에서 '성공'이 세 가지 뜻(방화벽이 연결을 받아들임, WAF·서버가 요청을 막지 않음, 공격이 목적을 이룸)으로
섞여 쓰이지 않도록 이벤트 하나의 결과를 네 가지로 나눈다.

- success(성공): 공격이 목적을 이룬 근거. 거부 없이 처리된 API·로그인·명령, 웹셸 실행, 큰 응답 유출 등
- pass(통과): WAF가 기록만 하고 넘김(COUNT·ALLOW) 또는 웹서버가 공격 요청에 정상 응답(2xx)했지만 성공 근거는 없음
- allowed(허용): 방화벽·VPC Flow가 연결을 받아들임(ACCEPT). 연결이 됐다는 뜻일 뿐 침투가 아니다
- blocked(실패·차단): 거부, 차단, 오류 응답

그리고 사건 이벤트에서 조치에 쓸 이름(계정, 파일 경로, 파라미터, 버킷·객체, IP)을 뽑는다.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, unquote, urlsplit

# 조치의 단계: 번지는 것 막기(0) → 들어온 길 닫기(1) → 원인 고치기(2)
PHASE = {
    "IAM_ROLE_SESSION_REVOKE": 0, "IAM_KEY_COMPROMISED": 0, "WEB_FIX_WEBSHELL": 0, "WEB_FIX_ACCOUNT": 0,
    "WEB_FIX_PRIVESC": 0,
    "SG_ADMIN_PORT_OPEN": 1, "SG_DB_PORT_OPEN": 1, "NACL_BLOCK_ATTACKER": 1, "WAF_SQLI_COUNT": 1,
    "WAF_SQLI_MISSING": 1, "WEB_NO_WAF": 1, "IMDSV1_ENABLED": 1, "WEB_FIX_RATE_LIMIT": 1,
    "IAM_OVERBROAD": 2, "WEB_FIX_SQLI": 2, "WEB_FIX_INPUT": 2, "TRAIL_UNPROTECTED": 2, "WEB_FIX_LOG_RETENTION": 3,
}

KO = {"success": "성공", "pass": "통과", "allowed": "허용", "blocked": "실패·차단"}

NETWORK = {"vpcflow", "hostfw"}
WAF = {"waf"}
WEB = {"weblog", "alb", "access"}
NO_RESULT = {"guardduty", "weberror"}

# 웹 요청이 2xx여도 '성공'으로 볼 수 있는 규칙(규칙 자체가 성공 신호를 본다)
WEB_SUCCESS = {"WEBLOG_UPLOAD_EXEC", "WEBLOG_WEBSHELL_ACCESS", "WEBLOG_LARGE_EXFIL", "WEBLOG_IDOR_ENUM",
               "WEBLOG_ADMIN_ACCESS", "WEBLOG_ADMIN_FORGED", "WEBLOG_BACKUP_LEAK",
               "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"}


def kind(e: dict) -> str | None:
    """이벤트 하나의 결과: success | pass | allowed | blocked | None(결과가 없는 로그, 예: GuardDuty 결과)."""
    src = e.get("source")
    if src in NO_RESULT:
        return None
    if e.get("disposition") == "blocked" or e.get("status") == "failure":
        return "blocked"
    if e.get("status") != "success":
        return None
    if src in NETWORK:
        return "allowed"
    if src in WAF:
        return "pass"
    if src in WEB:
        return "success" if set(e.get("rules", [])) & WEB_SUCCESS else "pass"
    return "success"


def counts(events: list[dict], *, skip_known: bool = True) -> dict[str, int]:
    out = {k: 0 for k in KO}
    for e in events:
        if skip_known and e.get("known"):
            continue
        k = kind(e)
        if k:
            out[k] += 1
    return out


def phrase(c: dict[str, int]) -> str:
    """'성공 2건, 허용 1건, 실패·차단 4건'처럼 0이 아닌 것만."""
    return ", ".join(f"{KO[k]} {c[k]}건" for k in ("success", "pass", "allowed", "blocked") if c.get(k))


# ── 구체 대상 ─────────────────────────────────────────────

def request_path(action: str | None) -> tuple[str, list[str]]:
    """'GET /search.php?q=..' → ('/search.php', ['q'])."""
    parts = str(action or "").split()
    url = parts[1] if len(parts) > 1 and parts[0].isupper() else (parts[0] if parts else "")
    if not url.startswith("/") and "://" not in url:
        return "", []
    sp = urlsplit(url)
    names = [k for k, _ in parse_qsl(sp.query, keep_blank_values=True)]
    return unquote(sp.path) or "/", list(dict.fromkeys(names))


UNUSUAL_EXT = (".phtml", ".php3", ".php4", ".php5", ".phar", ".jspx")  # 정상 앱에 드문 실행 파일 확장자


def webshell_files(events: list[dict]) -> tuple[list[str], list[str]]:
    """(웹셸로 보이는 파일, 웹셸처럼 악용된 앱 경로). 업로드 폴더의 스크립트·웹 루트 점검이 찾은 파일은 앞,
    로그 포이즈닝처럼 정상 앱 파일이 악용된 경로는 뒤(지우면 안 되고 코드를 고쳐야 한다)."""
    files, abused = [], []
    for e in events:
        rules = set(e.get("rules", []))
        if "FILE_WEBSHELL" in rules or e.get("source") == "file":
            p = e.get("webshell_path") or e.get("path") or request_path(e.get("action"))[0] or str(e.get("action") or "")
            if p:
                files.append(p)
            continue
        if not rules & {"WEBLOG_WEBSHELL_ACCESS", "WEBLOG_UPLOAD_EXEC"}:
            continue
        p, _ = request_path(e.get("action"))
        if not p:
            continue
        if "WEBLOG_UPLOAD_EXEC" in rules or "/upload" in p.lower() or p.lower().endswith(UNUSUAL_EXT):
            files.append(p)
        else:
            abused.append(p)
    return list(dict.fromkeys(files)), [p for p in dict.fromkeys(abused) if p not in files]


def logged_in_accounts(events: list[dict]) -> list[str]:
    """비밀번호 대입 뒤 로그인에 성공한 계정(서버 SSH·웹 로그인)."""
    out = []
    for e in events:
        rules = set(e.get("rules", []))
        if kind(e) == "success" and (e.get("action") in ("ssh_login", "login") or
                                     rules & {"SSH_SUCCESS_AFTER_FAIL", "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"}):
            a = str(e.get("actor") or "").strip()
            if a and e.get("source") in ("sshauth", "auth"):
                out.append(a)
    return list(dict.fromkeys(out))


def vulnerable_params(events: list[dict], rules: set[str]) -> list[str]:
    """공격 문자열이 들어간 경로와 파라미터: '/search.php(q)'."""
    by: dict[str, list[str]] = {}
    for e in events:
        if not set(e.get("rules", [])) & rules:
            continue
        p, names = request_path(e.get("action"))
        if p:
            by.setdefault(p, [])
            by[p] += [n for n in names if n not in by[p]]
    return [f"{p}({', '.join(n)})" if n else p for p, n in by.items()]


def attacker_ips(events: list[dict]) -> list[str]:
    return list(dict.fromkeys(e["src_ip"] for e in events if e.get("src_ip") and not e.get("known")))


_PARAM_KEYS = (("bucketName", "버킷"), ("key", "객체"), ("userName", "사용자"), ("roleName", "역할"),
               ("functionName", "함수"), ("instanceId", "인스턴스"), ("instancesSet", "인스턴스"),
               ("groupId", "보안그룹"), ("secretId", "비밀값"), ("name", "이름"), ("tableName", "테이블"),
               ("policyArn", "정책"), ("accessKeyId", "키"))


def api_target(e: dict) -> str | None:
    """CloudTrail 요청 파라미터에서 대상 이름. 없으면 None(로그에 없음)."""
    raw = e.get("params")
    if not raw:
        return None
    try:
        p = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (ValueError, TypeError):
        return None
    parts = []
    for k, ko in _PARAM_KEYS:
        v = p.get(k)
        if v and not isinstance(v, (dict, list)):
            parts.append(f"{ko} {v}")
    return ", ".join(parts[:3]) or None


OBJECT_LEVEL = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:CopyObject", "s3:DeleteObjects",
                "s3:GetObjectAcl", "s3:PutObjectAcl", "s3:RestoreObject"}

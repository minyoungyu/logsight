"""
웹서버 로그 공격 탐지 규칙.

각 규칙은 접속/오류/인증 로그에서 "공격으로 보이는 요청"을 골라 Finding으로 만든다.
규칙 ID·기법·단계·심각도는 detect.RULES에 등록돼 있고, 여기서는 매칭만 한다.
탐지 신호는 OWASP·공개 WAF 규칙(ModSecurity CRS 류)에서 흔히 쓰는 패턴을 최소로 옮긴 것이며,
근거(raw_ref)가 항상 원본 로그 줄을 가리킨다. 오탐을 줄이기 위해 "공격 패턴 + 결과(응답
코드·응답 크기·연쇄)"를 함께 본다.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import unquote_plus, urlparse

from ..normalize import Event
from ..detect import Finding, _bursts, _ok_fail
from .webprofile import SiteProfile

# ------------------------------------------------------------------ 공격 패턴
# 한 번 디코드한 "경로+쿼리" 문자열에 대해 검사한다.
# SQL 인젝션은 셋 중 하나일 때만 본다: (1) UNION SELECT, (2) 따옴표 뒤의 항상-참 조건,
# (3) 따옴표·주석과 함께 나온 SELECT…FROM. "select color from menu"처럼 따옴표 없는
# 일반 문장은 잡지 않는다(정상 검색어 오탐 방지).
SQLI_UNION = re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b")
SQLI_TAUTOLOGY = re.compile(r"(?i)'\s*(?:or|and)\s+['\d(]|\b(?:or|and)\s+\d+\s*=\s*\d+\b")
SQLI_TAIL = re.compile(r"(?i)'|--|/\*")
SQLI_MISC = re.compile(
    r"(?i)\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|information_schema|"
    r"@@version|\bextractvalue\s*\(|\bupdatexml\s*\(")
SQLI_SELECT = re.compile(r"(?i)\bselect\b.+\bfrom\b")


def is_sqli(text: str) -> bool:
    if SQLI_UNION.search(text) or SQLI_TAUTOLOGY.search(text) or SQLI_MISC.search(text):
        return True
    return bool(SQLI_SELECT.search(text) and SQLI_TAIL.search(text))


TRAVERSAL = re.compile(
    r"(?i)(?:\.\./|\.\.%2f|%2e%2e/|\.\.\\|/etc/passwd|/proc/self/|c:\\windows|"
    r"php://(?:filter|input)|data://|expect://|/\.ssh/|boot\.ini|"
    r"access\.log|error\.log|/var/log/)")
# 헤더(User-Agent·Referer)에 실행 가능한 코드가 들어 있으면 로그 포이즈닝 준비일 가능성이 크다.
CODE_IN_HEADER = re.compile(r"(?i)<\?php|<\?=|\beval\s*\(|base64_decode\s*\(|system\s*\(\s*\$_")
# 알려진 취약점 공격 문자열(헤더): Log4Shell(JNDI 조회), Shellshock(빈 함수 정의)
EXPLOIT_PROBE = re.compile(r"(?i)\$\{jndi:|\$\{(?:lower|upper|env|sys):|\(\)\s*\{\s*:\s*;\s*\}")
# 서버가 대신 내부 주소를 요청하게 만드는 주소 인자(SSRF)
SSRF_TARGET = re.compile(
    r"(?i)[?&](?:url|src|dest|uri|callback|file|path)=https?://(?:127\.|localhost|0\.0\.0\.0|"
    r"169\.254\.169\.254|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")
# 외부 사이트로 보내는 리다이렉트 인자(열린 리다이렉트)
REDIRECT_TARGET = re.compile(r"(?i)[?&](?:next|return|redirect|continue|to)=https?://")
# 백업·덤프 파일 이름
BACKUP_NAME = re.compile(r"(?i)(?:backup|dump|\.sql|\.bak|\.old|\.zip|\.tar\.gz|/\.git/)")
RFI = re.compile(r"(?i)=\s*(?:https?|ftp)://")
CMDI = re.compile(
    r"(?i)(?:;\s*(?:id|ls|cat|whoami|uname|wget|curl|nc|bash|sh)\b|\|\s*(?:id|ls|cat|nc|sh|bash)\b|"
    r"`[^`]+`|\$\([^)]+\)|&&\s*(?:cat|id|whoami|wget|curl)\b|%0a|\bwget\s+http|\bcurl\s+http)")
XSS = re.compile(r"(?i)(?:<script\b|%3cscript|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=)")
SCANNER_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|nuclei|wpscan|dirbuster|gobuster|"
    r"feroxbuster|hydra|zgrab|whatweb|wfuzz|ffuf|arachni|openvas|netsparker|xray)\b")
# 알려진 웹셸 파일 이름(구별력이 큰 것만). cmd/shell/up/upload 처럼 흔한 이름은 정상 페이지와
# 겹쳐서 넣지 않는다 — 그런 경우는 업로드 폴더 실행(UPLOAD_EXEC)이나 cmd 파라미터로 잡는다.
WEBSHELL_NAME = re.compile(
    r"(?i)(?:^|/)(?:c99|r57|b374k|wso|webshell|backdoor|adminer|"
    r"alfa|indoxploit|p0wny|antichat|phpspy|tryag|0byt3m1n1)\.(?:php|phtml|jsp|asp|aspx)\b")
SHELL_PARAM = re.compile(r"(?i)[?&](?:cmd|exec|command|c|run|shell|system|passthru)\s*=")


def _dec(s: str | None) -> str:
    if not s:
        return ""
    out = s
    for _ in range(2):  # 이중 인코딩(%252e..)까지 한 번 더 푼다
        new = unquote_plus(out)
        if new == out:
            break
        out = new
    return out


def _trusted(ip: str | None, cidrs: list[str]) -> bool:
    if not ip or not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_admin_path(path: str, prefixes: tuple[str, ...]) -> bool:
    p = path.lower()
    return any(p == x or p.startswith(x + "/") for x in prefixes)


def _foreign_host(referer: str, own_hosts: list[str]) -> bool:
    host = (urlparse(referer).hostname or "").lower()
    return bool(host) and host not in own_hosts


def _mk(rule: str, by_ip: dict[str, list[Event]], detail_fn) -> list[Finding]:
    out = []
    for ip, evs in by_ip.items():
        if evs:
            out.append(Finding(rule, sorted(evs, key=lambda e: e.ts), detail_fn(evs), ip))
    return out


def run_web_detections(events: list[Event], profile: SiteProfile | None = None) -> list[Finding]:
    profile = profile or SiteProfile()
    trusted = [t["cidr"] if isinstance(t, dict) else t for t in profile.trusted_ips]
    upload_dirs = tuple(profile.upload_dirs)
    sensitive = [s.lower() for s in profile.sensitive_files]
    admin_prefixes = tuple(a.lower().rstrip("/") for a in profile.admin_paths if a.lower().startswith("/admin"))
    own_hosts = [h.lower() for h in profile.own_hosts]
    findings: list[Finding] = []

    access = [e for e in events if e.source == "access"]
    errors = [e for e in events if e.source == "weberror"]
    auth = [e for e in events if e.source in ("auth", "sshauth")]

    # 규칙별로 공격자 IP → 이벤트 목록을 모은다
    buckets: dict[str, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))
    admin_pages: dict[str, list[Event]] = defaultdict(list)

    for e in access:
        ip = e.src_ip or "?"
        target = _dec((e.extra.get("path", "") + "?" + e.extra.get("query", "")).rstrip("?"))
        ua = e.extra.get("ua", "")
        path = e.extra.get("path", "")
        status = e.extra.get("status", "")
        trusted_ip = _trusted(e.src_ip, trusted)

        matched = False
        if is_sqli(target):
            buckets["WEBLOG_SQLI"][ip].append(e); matched = True
        if TRAVERSAL.search(target):
            buckets["WEBLOG_TRAVERSAL"][ip].append(e); matched = True
        if RFI.search(target):
            buckets["WEBLOG_RFI"][ip].append(e); matched = True
        if CMDI.search(target):
            buckets["WEBLOG_CMD_INJECTION"][ip].append(e); matched = True
        if XSS.search(target):
            buckets["WEBLOG_XSS"][ip].append(e); matched = True
        # 웹셸 접근은 "존재하는 자원"에 닿았을 때만(404 스캔 제외). cmd 류 파라미터 또는
        # 구별력 있는 웹셸 파일 이름이 있고 응답이 404가 아니면 센다.
        if (SHELL_PARAM.search("?" + e.extra.get("query", "")) or WEBSHELL_NAME.search(path)) \
                and e.outcome != "client-error":
            buckets["WEBLOG_WEBSHELL_ACCESS"][ip].append(e); matched = True
        if any(s in target.lower() for s in sensitive) or "/.git/" in path.lower():
            buckets["WEBLOG_SENSITIVE_FILE"][ip].append(e)
        method = e.extra.get("method", "")
        if SSRF_TARGET.search(target):
            buckets["WEBLOG_SSRF"][ip].append(e); matched = True
        if REDIRECT_TARGET.search(target):
            buckets["WEBLOG_OPEN_REDIRECT"][ip].append(e)
        if EXPLOIT_PROBE.search(ua) or EXPLOIT_PROBE.search(e.extra.get("referer", "")):
            buckets["WEBLOG_EXPLOIT_PROBE"][ip].append(e)
        if e.outcome == "success" and BACKUP_NAME.search(path) and not path.endswith("/"):
            buckets["WEBLOG_BACKUP_LEAK"][ip].append(e); matched = True
        if method == "GET" and e.outcome == "success" and path.endswith("/") \
                and path.lower().startswith(upload_dirs):
            buckets["WEBLOG_DIR_LISTING"][ip].append(e)
        if method == "POST" and _is_admin_path(path, admin_prefixes) and e.extra.get("referer") \
                and _foreign_host(e.extra["referer"], own_hosts):
            buckets["WEBLOG_CSRF_SUSPECT"][ip].append(e); matched = True
        # 헤더에 실행 코드를 심는 로그 포이즈닝 준비(User-Agent·Referer)
        if CODE_IN_HEADER.search(ua) or CODE_IN_HEADER.search(e.extra.get("referer", "")):
            buckets["WEBLOG_CODE_IN_HEADER"][ip].append(e)
        # 관리자 영역에 성공적으로 들어간 흔적: 2xx 응답, 또는 관리자 로그인 뒤 302(로그인 성공).
        # 인증 없이 302로 로그인 화면에 튕긴 것은 성공으로 치지 않는다.
        login_ok = e.extra.get("status") == "302" and path.lower().endswith("login.php")
        if not trusted_ip and _is_admin_path(path, admin_prefixes) and (
                (e.outcome == "success" and e.extra.get("status") != "302") or login_ok):
            buckets["WEBLOG_ADMIN_ACCESS"][ip].append(e)
            if not login_ok:
                admin_pages[ip].append(e)
        if SCANNER_UA.search(ua) and not trusted_ip:
            buckets["WEBLOG_SCANNER"][ip].append(e)
        # 업로드 폴더 안의 스크립트가 실행(=요청)되면 매우 의심스럽다
        if path.lower().startswith(upload_dirs) and re.search(r"\.(php\d?|phtml|phar|jsp|asp|aspx|cgi|pl)\b", path, re.I):
            buckets["WEBLOG_UPLOAD_EXEC"][ip].append(e); matched = True
        # 공격 패턴 요청에 서버가 500으로 반응하면 취약점이 실제로 건드려졌을 가능성
        if matched and e.outcome == "server-error":
            buckets["WEBLOG_EXPLOIT_5XX"][ip].append(e)
        # 공격 패턴 요청이 성공(2xx)하면서 응답이 유난히 크면 데이터 유출 의심
        if (matched or _is_admin_path(path, admin_prefixes)) and e.outcome == "success":
            try:
                if int(e.extra.get("bytes", "0")) >= 50_000:
                    buckets["WEBLOG_LARGE_EXFIL"][ip].append(e)
            except ValueError:
                pass

    for rule, by_ip in buckets.items():
        findings += _mk(rule, by_ip, lambda evs: _ok_fail(evs))

    # --- 주문 번호 연속 열람(IDOR): 같은 IP가 서로 다른 주문 번호를 10개 이상 연속으로 열람
    idor: dict[str, list[Event]] = defaultdict(list)
    for e in access:
        if e.extra.get("path") == "/order.php" and e.outcome == "success":
            idor[e.src_ip or "?"].append(e)
    for ip, evs in idor.items():
        for seg in _bursts(evs, timedelta(minutes=5), 10, key=lambda e: e.extra.get("query", "")):
            findings.append(Finding("WEBLOG_IDOR_ENUM", seg,
                                    f"5분 안에 주문 {len({e.extra.get('query') for e in seg})}건 열람", ip))

    # --- 로그인 기록 없이 관리자 페이지에 바로 들어감: 쿠키 위조 의심
    login_ips = {e.src_ip for e in access if e.extra.get("method") == "POST"
                 and e.extra.get("status") == "302" and e.extra.get("path", "").lower().endswith("login.php")}
    for ip, evs in admin_pages.items():
        if ip not in login_ips:
            findings.append(Finding("WEBLOG_ADMIN_FORGED", evs,
                                    f"이 IP의 로그인 기록 없이 관리자 페이지 {len(evs)}건 열람", ip))

    # --- 404 열거(없는 경로 연속 탐색) — 자동 스캐너의 전형
    enum: dict[str, list[Event]] = defaultdict(list)
    for e in access:
        if e.extra.get("status") == "404" and not _trusted(e.src_ip, trusted):
            enum[e.src_ip or "?"].append(e)
    for ip, evs in enum.items():
        for seg in _bursts(evs, timedelta(minutes=5), 15, key=lambda e: e.extra.get("path", e.raw_ref)):
            findings.append(Finding("WEBLOG_ENUM_404", seg,
                                    f"5분 안에 404 {len(seg)}건, 경로 {len({e.extra.get('path') for e in seg})}종", ip))

    # --- 웹 로그인 무차별 대입: 로그인/관리자 경로로의 POST가 한 IP에서 몰릴 때
    login_paths = [p.rstrip("/") for p in (profile.login_paths or profile.admin_paths)]
    login_hits: dict[str, list[Event]] = defaultdict(list)
    for e in access:
        p = e.extra.get("path", "").rstrip("/")
        if e.extra.get("method") == "POST" and any(p == lp or p.startswith(lp) for lp in login_paths):
            login_hits[e.src_ip or "?"].append(e)
    REDIRECT = {"301", "302", "303"}
    for ip, evs in login_hits.items():
        evs.sort(key=lambda e: e.ts)
        for seg in _bursts(evs, timedelta(minutes=10), 10, key=lambda e: e.raw_ref):
            findings.append(Finding("WEBLOG_AUTH_BRUTE", seg,
                                    f"10분 안에 로그인 POST {len(seg)}건", ip))
        # 반복 시도(실패) 뒤 리다이렉트(302 등)로 바뀌면 로그인 성공 신호. 리다이렉트 직전의
        # 같은-상태 시도가 충분히 많을 때만(정상 사용자의 1회 로그인 성공은 제외).
        redirects = [e for e in evs if e.extra.get("status") in REDIRECT]
        fails = [e for e in evs if e.extra.get("status") not in REDIRECT]
        if redirects and len(fails) >= 5:
            first_ok = redirects[0]
            prior = [e for e in fails if e.ts <= first_ok.ts]
            if len(prior) >= 5:
                findings.append(Finding("WEBLOG_AUTH_SUCCESS_AFTER_FAIL", prior + [first_ok],
                                        f"로그인 실패 {len(prior)}건 뒤 성공 추정(응답 "
                                        f"{first_ok.extra.get('status')})", ip))

    # --- SSH 무차별 대입/성공(auth 로그) — 웹 사고가 서버 계정 탈취로 이어졌는지 본다
    by_ssh: dict[str, list[Event]] = defaultdict(list)
    for e in auth:
        if e.action in ("ssh_login",):
            by_ssh[e.src_ip or "?"].append(e)
    for ip, evs in by_ssh.items():
        evs.sort(key=lambda e: e.ts)
        fails = [e for e in evs if e.outcome == "failure"]
        for seg in _bursts(fails, timedelta(minutes=10), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("SSH_BRUTE_FORCE", seg, f"10분 안에 SSH 실패 {len(seg)}건", ip))
        for e in evs:
            if e.outcome == "success":
                prior = [f for f in fails if timedelta(0) <= e.ts - f.ts <= timedelta(minutes=30)]
                if len(prior) >= 2:
                    findings.append(Finding("SSH_SUCCESS_AFTER_FAIL", prior + [e],
                                            f"직전 30분 SSH 실패 {len(prior)}건 뒤 '{e.actor}' 성공", ip))

    # 이벤트에 규칙 ID 표시(상관분석·보고서 근거용)
    for f in findings:
        for e in f.events:
            if f.rule not in e.findings:
                e.findings.append(f.rule)
    return findings

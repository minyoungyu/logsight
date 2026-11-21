"""
웹서버 로그 공격 탐지 규칙.

각 규칙은 접속/오류/인증 로그에서 "공격으로 보이는 요청"을 골라 Finding으로 만든다.
규칙 ID·기법·단계·심각도는 detect.RULES에 등록돼 있고, 여기서는 매칭만 한다.
탐지 신호는 OWASP·공개 WAF 규칙(ModSecurity CRS 류)에서 흔히 쓰는 패턴을 최소로 옮긴 것이며,
근거(raw_ref)가 항상 원본 로그 줄을 가리킨다. 오탐을 줄이기 위해 "공격 패턴 + 결과(응답
코드·응답 크기·연쇄)"를 함께 본다.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import timedelta
from urllib.parse import parse_qsl, unquote_plus, urlparse

from ..normalize import Event, _private
from ..detect import Finding, _bursts, _ok_fail, _route, host_auth_findings, sqli_success_signal
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
# 사후 분석에서 쓰던 판단을 합친 것: 따옴표 바로 뒤의 SQL 키워드·주석·문장 끝(';'), 값 끝의 따옴표 하나
# (sqlmap 등이 오류를 일으켜 보려고 처음 보내는 요청), 쌓은 질의(;select …), PostgreSQL의 pg_sleep
SQLI_QUOTE = re.compile(r"(?i)'\s*(?:union\b|select\b|;|--|#)|'\s*(?:&|$)")
SQLI_STACKED = re.compile(r"(?i);\s*(?:select|insert|update|delete|drop|exec|declare)\b|\bpg_sleep\s*\(")


def is_sqli(text: str) -> bool:
    """SQL 인젝션 패턴. 사후 분석(WEBLOG_SQLI, 예전 WEB_SQLI_PATTERN)과 웹서버 점검이 같은 판단을 쓴다."""
    if SQLI_UNION.search(text) or SQLI_TAUTOLOGY.search(text) or SQLI_MISC.search(text) \
            or SQLI_QUOTE.search(text) or SQLI_STACKED.search(text):
        return True
    return bool(SQLI_SELECT.search(text) and SQLI_TAIL.search(text))


TRAVERSAL = re.compile(
    r"(?i)(?:\.\./|\.\.%2f|%2e%2e/|\.\.\\|/etc/passwd|/proc/self/|c:\\windows|"
    # ../ 없이 절대 경로로 바로 읽는 경우(file=/etc/shadow). 경로가 아니라 인자 값으로 들어온 것만 본다
    r"[=:]\s*(?:file:/+)?/(?:etc/(?:shadow|gshadow|sudoers|group|hosts|crontab|ssh/)|root/\.|proc/\d+/|var/www/.*\.env\b)|"
    r"/etc/shadow|win\.ini|"
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
# 웹 요청 중 응답 본문으로 파일을 내려받는 방식(백업 파일 유출 판단에 쓴다)
_READ_METHODS = frozenset({"GET", "POST", "-", ""})
# 내부망 IP의 관리자 접근을 같은 IP의 다른 공격 신호와 묶어 볼 시간 폭
ADMIN_SIGNAL_SPAN = timedelta(hours=1)
# 백업·덤프 파일 이름
BACKUP_NAME = re.compile(r"(?i)(?:backup|dump|\.sql|\.bak|\.old|\.zip|\.tar\.gz|/\.git/)")
RFI = re.compile(r"(?i)=\s*(?:https?|ftp)://([^/?#&\s:]*)")
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
SHELL_PARAM = re.compile(r"(?i)[?&](?:cmd|exec|command|c|run|shell|system|passthru)\s*=([^&]*)")
# 스크립트로 실행되는 파일 확장자(경로 끝). /remote.php/dav/a.jpg 처럼 스크립트 뒤에 경로가
# 붙은 요청은 그 파일을 내려받는 것이라 실행으로 보지 않는다.
SCRIPT_EXT = re.compile(r"(?i)\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl)$")
# 해시·토큰처럼 보이는 값(16자 이상 영숫자만). 명령이 아니다.
HASH_LIKE = re.compile(r"^[A-Za-z0-9]{16,}$")
# base64로 감춘 명령을 풀었을 때 나오는 셸 명령어
SHELL_WORDS = re.compile(
    r"(?i)(?:^|[\s\"'\[,;|&(])(?:whoami|uname|id|ls|cat|wget|curl|bash|sh|nc|ncat|python3?|perl|"
    r"chmod|chown|ps|netstat|ifconfig|ip|mysql|tar|echo|rm|cp|mv|find|sudo|su|passwd|crontab)"
    r"(?:$|[\s\"',\]])")
BASE64_VALUE = re.compile(r"^[A-Za-z0-9+/_-]{12,}={0,2}$")


# 필터를 피하려고 쓰는 변형 인코딩: UTF-8 과잉 길이(%c0%ae = "."), IIS 유니코드(%u002e), 전각 문자.
# 표준 디코더는 이것을 깨진 글자(�)로 바꿔 ../ 를 놓치므로 먼저 원래 글자로 바꾼다
_EVASION = [(re.compile(p, re.I), c) for p, c in (
    (r"%c0%ae|%e0%80%ae|%f0%80%80%ae|%c0%2e|%u002e|%uff0e", "."),
    (r"%c0%af|%e0%80%af|%f0%80%80%af|%c0%2f|%u2215|%u002f|%uff0f", "/"),
    (r"%c1%9c|%u2216|%u005c|%uff3c", "\\"))]
_FULLWIDTH = str.maketrans({"\uff0e": ".", "\uff0f": "/", "\uff3c": "\\"})


def _undo_evasion(s: str) -> str:
    for rx, ch in _EVASION:
        s = rx.sub(lambda _m, c=ch: c, s)
    return s.translate(_FULLWIDTH)


def _dec(s: str | None) -> str:
    if not s:
        return ""
    out = _undo_evasion(s)
    for _ in range(2):  # 이중 인코딩(%252e..)까지 한 번 더 푼다
        new = _undo_evasion(unquote_plus(out))
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


# 관리자 영역 안에 있지만 관리 작업이 아닌 곳: WordPress의 AJAX·폼 처리 창구(방문자 브라우저가 늘 부름),
# 관리자 화면이 부르는 CSS·JS 묶음(load-scripts·load-styles), 정적 파일.
ADMIN_PUBLIC = re.compile(r"(?i)/(?:admin-ajax|admin-post|load-scripts|load-styles)\.php$"
                          r"|\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$")


def _is_admin_path(path: str, prefixes: tuple[str, ...]) -> bool:
    p = path.lower()
    if ADMIN_PUBLIC.search(p):
        return False
    return any(p == x or p.startswith(x + "/") for x in prefixes)


def _shell_param_hit(path: str, query: str) -> bool:
    """명령 인자(cmd=, c= 등)로 스크립트를 부른 요청인가. 해시 같은 값은 뺀다."""
    if not SCRIPT_EXT.search(path):
        return False
    for m in SHELL_PARAM.finditer("?" + query):
        value = unquote_plus(m.group(1)).strip()
        # 숫자만 있는 값(c=0, run=1)은 켜고 끄는 옵션이지 명령이 아니다(WordPress load-scripts.php?c=0 등)
        if value and not value.isdigit() and not HASH_LIKE.match(value):
            return True
    return False


def _decoded_command(query: str) -> str | None:
    """쿼리 값 중 base64로 감춘 셸 명령이 있으면 풀어서 돌려준다."""
    for _, value in parse_qsl(query, keep_blank_values=False):
        v = value.strip()
        if not BASE64_VALUE.match(v):
            continue
        try:
            raw = base64.b64decode(v + "=" * (-len(v) % 4), altchars=b"-_" if ("-" in v or "_" in v) else None,
                                   validate=False)
            text = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if text.isprintable() and SHELL_WORDS.search(text):
            return text
    return None


def _in_upload_dir(path: str, upload_dirs: tuple[str, ...]) -> bool:
    """업로드 폴더 안인가. 프로필 폴더는 앞부분으로, uploads/upload 폴더는 경로 어디에 있든 본다
    (/wp-content/uploads/ 같은 CMS 기본 위치)."""
    p = path.lower()
    if p.startswith(upload_dirs):
        return True
    return "/uploads/" in p or "/upload/" in p


def _remote_url(target: str, own_hosts: list[str]) -> bool:
    """인자 값으로 바깥 주소(http://, ftp://)를 넘겼는가. 우리 사이트 이름으로 돌아오는 값
    (/wp-login.php?redirect_to=https://우리사이트/wp-admin/)은 정상 이동이라 뺀다.
    localhost·루프백·내부망 IP는 우리 것이어도 빼지 않는다(서버가 자기 내부를 부르게 하는 SSRF 표적이다)."""
    site = {h for h in own_hosts if h != "localhost" and not _private(h)}
    return any(m.group(1).lower() not in site for m in RFI.finditer(target))


def _foreign_host(referer: str, own_hosts: list[str]) -> bool:
    host = (urlparse(referer).hostname or "").lower()
    return bool(host) and host not in own_hosts


# 웹 요청을 담는 로그 종류. access는 웹서버 점검(scan), weblog·alb는 AWS 분석(analyze·watch)에서 읽은 것이다.
# 모두 normalize.parse_web_line과 같은 필드(method, path, query, http_status, resp_bytes, referer, ua)를 갖는다.
WEB_REQUEST_SOURCES = ("access", "weblog", "alb", "waf")


def _status(e: Event) -> str:
    """응답 코드 문자열("404"). 웹서버 점검은 status, AWS 분석은 http_status(정수)를 둔다."""
    st = e.extra.get("status")
    if st:
        return str(st)
    st = e.extra.get("http_status")
    return str(st) if st is not None else ""


def _resp_bytes(e: Event) -> int:
    v = e.extra.get("resp_bytes")
    if v is None:
        v = e.extra.get("bytes", 0)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _oc(e: Event) -> str:
    """success | client-error | server-error | unknown. 웹서버 점검 접속 로그의 결과 표현으로 맞춘다."""
    if e.source == "access":
        return e.outcome or "unknown"
    st = _status(e)
    if not st.isdigit():
        return "unknown"
    code = int(st)
    return "success" if code < 400 else "client-error" if code < 500 else "server-error"


def _private_object(path: str, query: str, patterns: list[str]) -> tuple[str, str] | None:
    """(맞은 패턴, 객체 식별값) 또는 None. 패턴에 {id}가 있으면 그 자리 경로 조각이 식별값,
    없으면 경로가 같을 때 쿼리 문자열이 식별값(/order.php?id=3)."""
    p = path.rstrip("/") or "/"
    for pat in patterns:
        if "{id}" in pat:
            segs, psegs = p.split("/"), pat.rstrip("/").split("/")
            if len(segs) == len(psegs) and all(a == b or b == "{id}" for a, b in zip(segs, psegs)):
                return pat, "/".join(a for a, b in zip(segs, psegs) if b == "{id}")
        elif p == pat.rstrip("/") and query:
            return pat, query
    return None


def _is_login_path(path: str, login_paths: list[str]) -> bool:
    """로그인 처리 경로인가. 프로필에 적은 경로이거나, 마지막 조각에 login이 든 경로
    (/login, /login.php, /admin/login.php, /wp-login.php, /user/login). 예전의 'login.php로 끝남'을 넓힌 것이다."""
    p = path.lower().rstrip("/")
    if any(p == lp or p.startswith(lp + "/") for lp in (x.lower().rstrip("/") for x in login_paths)):
        return True
    return "login" in p.rsplit("/", 1)[-1]


def _mk(rule: str, by_ip: dict[str, list[Event]], detail_fn) -> list[Finding]:
    out = []
    for ip, evs in by_ip.items():
        if evs:
            out.append(Finding(rule, sorted(evs, key=lambda e: e.ts), detail_fn(evs), ip))
    return out


def run_web_detections(events: list[Event], profile: SiteProfile | None = None, *,
                       sources: tuple[str, ...] = ("access",), skip: frozenset[str] = frozenset(),
                       covered: dict[str, set[str]] | None = None,
                       include_auth: bool = True) -> list[Finding]:
    """sources: 볼 웹 요청 로그 종류. 웹서버 점검은 access, AWS 분석은 weblog·alb(detect.run_detections가 부름).
    skip: 만들지 않을 규칙(같은 행동을 AWS 분석의 다른 규칙이 이미 잡을 때).
    covered: {규칙: IP 집합}. 그 IP에 대해서만 그 규칙을 만들지 않는다(다른 규칙이 이미 같은 IP를 잡았을 때).
    include_auth: auth.log의 SSH 규칙도 볼지(AWS 분석은 detect.py의 SSH 규칙이 따로 본다)."""
    profile = profile or SiteProfile()
    trusted = [t["cidr"] if isinstance(t, dict) else t for t in profile.trusted_ips]
    upload_dirs = tuple(profile.upload_dirs)
    sensitive = [s.lower() for s in profile.sensitive_files]
    # 관리자 영역: 프로필의 관리자 경로 중 로그인 화면이 아닌 것(/admin, /wp-admin, /manager/html …).
    # 로그인 화면(/wp-login.php, /user/login)은 누구나 여는 곳이라 '관리자 영역 접근'으로 세지 않는다
    admin_prefixes = tuple(a.lower().rstrip("/") for a in profile.admin_paths
                           if "login" not in a.lower().rsplit("/", 1)[-1])
    own_hosts = [h.lower() for h in profile.own_hosts]
    findings: list[Finding] = []

    access = [e for e in events if e.source in sources]
    for e in access:  # 파서가 method·path·query를 따로 두지 않은 이벤트는 action("GET /p?q")에서 채운다
        if "path" not in e.extra and e.action:
            method, _, url = e.action.partition(" ")
            path, _, query = url.partition("?")
            e.extra.update(method=method, path=path or "/", query=query)
    # 오류 로그(weberror)는 사건 묶기에는 들어가지만 아직 이것만 보는 규칙은 없다
    auth = [e for e in events if e.source in ("auth", "sshauth")] if include_auth else []

    # 규칙별로 공격자 IP → 이벤트 목록을 모은다
    buckets: dict[str, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))
    admin_pages: dict[str, list[Event]] = defaultdict(list)
    admin_large: dict[str, list[Event]] = defaultdict(list)  # 공격 패턴 없이 관리자 화면에서 큰 응답

    for e in access:
        if e.disposition == "blocked":
            continue  # WAF가 이미 막은 요청은 WAF_BLOCKED가 센다
        ip = e.src_ip or "?"
        target = _dec((e.extra.get("path", "") + "?" + e.extra.get("query", "")).rstrip("?"))
        ua = e.extra.get("ua", "")
        path = e.extra.get("path", "")
        trusted_ip = _trusted(e.src_ip, trusted)

        matched = False
        method = e.extra.get("method", "")
        if is_sqli(target):
            buckets["WEBLOG_SQLI"][ip].append(e); matched = True
        if TRAVERSAL.search(target):
            buckets["WEBLOG_TRAVERSAL"][ip].append(e); matched = True
        if _remote_url(target, own_hosts):
            buckets["WEBLOG_RFI"][ip].append(e); matched = True
        if CMDI.search(target) or _decoded_command(e.extra.get("query", "")):
            buckets["WEBLOG_CMD_INJECTION"][ip].append(e); matched = True
        if XSS.search(target):
            buckets["WEBLOG_XSS"][ip].append(e); matched = True
        # 웹셸 접근은 "존재하는 자원"에 닿았을 때만(404 스캔 제외). cmd 류 파라미터 또는
        # 구별력 있는 웹셸 파일 이름이 있고 응답이 404가 아니면 센다.
        if (_shell_param_hit(path, e.extra.get("query", "")) or WEBSHELL_NAME.search(path)) \
                and _oc(e) != "client-error":
            buckets["WEBLOG_WEBSHELL_ACCESS"][ip].append(e); matched = True
        if any(s in target.lower() for s in sensitive) or "/.git/" in path.lower():
            buckets["WEBLOG_SENSITIVE_FILE"][ip].append(e)
        if SSRF_TARGET.search(target):
            buckets["WEBLOG_SSRF"][ip].append(e); matched = True
        if REDIRECT_TARGET.search(target):
            buckets["WEBLOG_OPEN_REDIRECT"][ip].append(e)
        if EXPLOIT_PROBE.search(ua) or EXPLOIT_PROBE.search(e.extra.get("referer", "")):
            buckets["WEBLOG_EXPLOIT_PROBE"][ip].append(e)
        # 내려받기(GET·POST)만 유출로 본다. WebDAV로 자기 파일을 올리고(PUT) 살피고(PROPFIND) 지우는(DELETE)
        # 것은 백업 파일 노출이 아니다(Nextcloud 사용자의 unit.zip 업로드가 걸린 것을 AIT fox에서 확인).
        if _oc(e) == "success" and method in _READ_METHODS and BACKUP_NAME.search(path) \
                and not path.endswith("/"):
            buckets["WEBLOG_BACKUP_LEAK"][ip].append(e); matched = True
        if method == "GET" and _oc(e) == "success" and path.endswith("/") \
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
        login_ok = _status(e) == "302" and _is_login_path(path, profile.login_paths)
        if not trusted_ip and _is_admin_path(path, admin_prefixes) and (
                (_oc(e) == "success" and _status(e) != "302") or login_ok):
            buckets["WEBLOG_ADMIN_ACCESS"][ip].append(e)
            if not login_ok:
                admin_pages[ip].append(e)
        if SCANNER_UA.search(ua) and not trusted_ip:
            buckets["WEBLOG_SCANNER"][ip].append(e)
        # 업로드 폴더 안의 스크립트가 실행(=요청)되면 매우 의심스럽다
        if _in_upload_dir(path, upload_dirs) and re.search(r"\.(php\d?|phtml|phar|jsp|asp|aspx|cgi|pl)\b", path, re.I):
            buckets["WEBLOG_UPLOAD_EXEC"][ip].append(e); matched = True
        # 공격 패턴 요청에 서버가 500으로 반응하면 취약점이 실제로 건드려졌을 가능성
        if matched and _oc(e) == "server-error":
            buckets["WEBLOG_EXPLOIT_5XX"][ip].append(e)
        # 공격 패턴 요청이 성공(2xx)하면서 응답이 유난히 크면 데이터 유출 의심
        if _oc(e) == "success" and _resp_bytes(e) >= profile.large_response_bytes:
            if matched:
                buckets["WEBLOG_LARGE_EXFIL"][ip].append(e)
            elif _is_admin_path(path, admin_prefixes):
                admin_large[ip].append(e)

    # 관리자 영역 접근은 뒤에서 다른 공격 신호와 함께 본다(아래 '관리자 영역 접근' 참고)
    admin_access = buckets.pop("WEBLOG_ADMIN_ACCESS", {})
    for rule, by_ip in buckets.items():
        if rule == "WEBLOG_SQLI":  # 응답 크기로 본 성공 신호(코드 판단)를 함께 적는다
            findings += _mk(rule, by_ip, lambda evs: f"{_ok_fail(evs)} · {sqli_success_signal(evs, access)}")
        else:
            findings += _mk(rule, by_ip, lambda evs: _ok_fail(evs))

    # --- 남의 객체 연속 열람(IDOR): 프로필의 private_object_paths(예: /order.php, /api/orders/{id})에서
    # 같은 IP가 5분 안에 서로 다른 객체 10개 이상을 성공적으로 열람. 경로를 적지 않으면 끈다
    # (상품 목록처럼 누구나 넘겨 보는 페이지와 구별할 수 없어서다)
    idor: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in access:
        hit = _private_object(e.extra.get("path", ""), e.extra.get("query", ""), profile.private_object_paths)
        if hit and _oc(e) == "success":
            idor[(e.src_ip or "?", hit[0])].append(e)
    for (ip, where), evs in idor.items():
        for seg in _bursts(evs, timedelta(minutes=5), 10,
                           key=lambda e: _private_object(e.extra.get("path", ""), e.extra.get("query", ""),
                                                         profile.private_object_paths)[1]):
            n = len({e.raw_ref for e in seg})
            findings.append(Finding("WEBLOG_IDOR_ENUM", seg, f"5분 안에 {where}의 서로 다른 객체 {n}건 열람", ip))

    # --- 같은 API에서 객체 번호만 바꿔 가며 403/404를 연달아 받음: 남의 객체를 열어 보려는 IDOR 탐색
    # (예전 사후 분석의 WEB_OBJECT_ENUM). 경로 이름에 기대지 않는다. 막힌 시도라 심각도는 중간으로 둔다
    probes: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in access:
        if _status(e) in ("403", "404") and not _trusted(e.src_ip, trusted):
            r = _route(e.action or "")
            if r:
                probes[(e.src_ip or "?", r)].append(e)
    for (ip, r), evs in probes.items():
        for seg in _bursts(evs, timedelta(minutes=10), 5, key=lambda e: (e.action or "").split("?", 1)[0]):
            findings.append(Finding("WEBLOG_IDOR_ENUM", seg,
                                    f"10분 안에 {r} 객체 {len({(e.action or '').split('?', 1)[0] for e in seg})}개에 "
                                    f"403/404 {len(seg)}건", ip,
                                    override={"severity": "medium", "title": "남의 객체 번호를 바꿔 가며 접근 시도(IDOR 탐색)"}))

    # --- 로그인 기록 없이 관리자 페이지에 바로 들어감: 쿠키 위조 의심
    login_ips = {e.src_ip for e in access if e.extra.get("method") == "POST"
                 and _status(e) == "302" and _is_login_path(e.extra.get("path", ""), profile.login_paths)}
    for ip, evs in admin_pages.items():
        if ip not in login_ips:
            findings.append(Finding("WEBLOG_ADMIN_FORGED", evs,
                                    f"이 IP의 로그인 기록 없이 관리자 페이지 {len(evs)}건 열람", ip))

    # --- 없는 경로 연속 탐색(열거) — 자동 스캐너의 전형. 5분 안에 서로 다른 경로 15개 이상에서 404/403
    # (예전 사후 분석의 WEB_PATH_PROBE는 20개, 웹서버 점검은 404만 봤다. 하나로 맞춤)
    enum: dict[str, list[Event]] = defaultdict(list)
    for e in access:
        if _status(e) in ("403", "404") and not _trusted(e.src_ip, trusted):
            enum[e.src_ip or "?"].append(e)
    for ip, evs in enum.items():
        for seg in _bursts(evs, timedelta(minutes=5), 15, key=lambda e: e.extra.get("path", e.raw_ref)):
            findings.append(Finding("WEBLOG_ENUM_404", seg,
                                    f"5분 안에 404/403 {len(seg)}건, 경로 {len({e.extra.get('path') for e in seg})}종", ip))

    # --- 웹 로그인 무차별 대입: 로그인/관리자 경로로의 POST가 한 IP에서 몰릴 때
    # 로그인 경로를 따로 적지 않았으면 관리자 경로 중 "login"이 든 것만 앞부분으로 보고, 나머지는
    # 정확히 같을 때만 센다. /wp-admin/admin-ajax.php 같은 관리 영역 안의 일반 요청(댓글 갱신 등)을
    # 로그인 시도로 세지 않기 위해서다.
    if profile.login_paths:
        prefix_paths = [p.rstrip("/") for p in profile.login_paths]
        exact_paths: list[str] = []
    else:
        prefix_paths = [p.rstrip("/") for p in profile.admin_paths if "login" in p.lower()]
        exact_paths = [p.rstrip("/") for p in profile.admin_paths if "login" not in p.lower()]
    login_hits: dict[str, list[Event]] = defaultdict(list)
    for e in access:
        p = e.extra.get("path", "").rstrip("/")
        if e.extra.get("method") == "POST" and (any(p == lp or p.startswith(lp) for lp in prefix_paths)
                                                or p in exact_paths):
            login_hits[e.src_ip or "?"].append(e)
    REDIRECT = {"301", "302", "303"}
    for ip, evs in login_hits.items():
        evs.sort(key=lambda e: e.ts)
        for seg in _bursts(evs, timedelta(minutes=10), 10, key=lambda e: e.raw_ref):
            findings.append(Finding("WEBLOG_AUTH_BRUTE", seg,
                                    f"10분 안에 로그인 POST {len(seg)}건", ip))
        # 반복 시도(실패) 뒤 리다이렉트(302 등)로 바뀌면 로그인 성공 신호. 리다이렉트 직전의
        # 같은-상태 시도가 충분히 많을 때만(정상 사용자의 1회 로그인 성공은 제외).
        redirects = [e for e in evs if _status(e) in REDIRECT]
        fails = [e for e in evs if _status(e) not in REDIRECT]
        if redirects and len(fails) >= 5:
            first_ok = redirects[0]
            prior = [e for e in fails if e.ts <= first_ok.ts]
            if len(prior) >= 5:
                findings.append(Finding("WEBLOG_AUTH_SUCCESS_AFTER_FAIL", prior + [first_ok],
                                        f"로그인 실패 {len(prior)}건 뒤 성공 추정(응답 "
                                        f"{_status(first_ok)})", ip))

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

    # --- 서버 권한 상승·계정 생성(sudo·su·useradd): 웹셸에서 root로 올라갔는지 본다(사후 분석과 같은 코드)
    if auth:
        findings += host_auth_findings(auth)

    # --- 관리자 영역 접근: 관리자는 원래 관리자 화면을 쓰므로 그것만으로는 공격 근거가 아니다.
    # 프로필에 믿을 IP(trusted_ips)를 적었으면 그 밖에서 들어온 것을 모두 알린다(주인이 관리자 IP를 밝힌 경우).
    # 적지 않았으면 인터넷(공인 IP)에서 들어온 것, 또는 내부망 IP라도 같은 IP에 다른 공격 신호
    # (스캐너·탐색·인젝션·무차별 대입·쿠키 위조 등)가 있는 것만 알린다. 사무실·VPN의 관리자가 내부망에서
    # 관리 화면을 쓰는 것은 평소 모습이라서다.
    # 공격 패턴 없이 관리자 화면에서 받은 큰 응답(대용량 유출 의심)도 같은 조건을 따른다.
    # 내부망 IP는 다른 공격 신호 앞뒤 ADMIN_SIGNAL_SPAN 안의 관리자 접근만 본다. NAT·VPN 주소 하나를
    # 공격자와 직원이 같이 쓰면, 며칠 전후 직원의 평소 관리 작업까지 공격처럼 걸리기 때문이다.
    # 관리자 접근 요청 자체에서 나온 신호(로그인 기록 없는 관리자 페이지 등)는 '다른' 신호로 치지 않는다
    admin_ids = {id(e) for evs in admin_access.values() for e in evs}
    signal_ts: dict[str, list] = defaultdict(list)
    for f in findings:
        signal_ts[f.key] += [e.ts for e in f.events if id(e) not in admin_ids]

    for ts in signal_ts.values():
        ts.sort()

    def _near_signal(ip: str, evs: list[Event]) -> list[Event]:
        if trusted or not _private(ip):
            return evs
        ts = signal_ts.get(ip)
        if not ts:
            return []
        out = []
        for e in evs:
            i = bisect_left(ts, e.ts)  # 가장 가까운 신호 시각은 i-1 또는 i
            near = [ts[j] for j in (i - 1, i) if 0 <= j < len(ts)]
            if any(abs(e.ts - t) <= ADMIN_SIGNAL_SPAN for t in near):
                out.append(e)
        return out

    for rule, by_ip in (("WEBLOG_ADMIN_ACCESS", admin_access), ("WEBLOG_LARGE_EXFIL", admin_large)):
        keep = {ip: kept for ip, evs in by_ip.items() if (kept := _near_signal(ip, evs))}
        for ip, evs in by_ip.items():  # 알리지 않은 것은 숨기지 않고 표시해 보고서에 따로 적는다(quiet_admin_summary)
            kept_ids = {id(e) for e in keep.get(ip, [])}
            for e in evs:
                if id(e) not in kept_ids:
                    e.extra["admin_quiet"] = rule
        for f in findings:  # 같은 IP의 대용량 응답 결과가 이미 있으면 그 결과에 합친다
            if f.rule == rule and f.key in keep:
                f.events = sorted({id(e): e for e in f.events + keep.pop(f.key)}.values(), key=lambda e: e.ts)
                f.detail = _ok_fail(f.events)
        findings += _mk(rule, keep, lambda evs: _ok_fail(evs))

    if skip or covered:
        covered = covered or {}
        findings = [f for f in findings if f.rule not in skip and f.key not in covered.get(f.rule, ())]
    # 이벤트에 규칙 ID 표시(상관분석·보고서 근거용)
    for f in findings:
        for e in f.events:
            if f.rule not in e.findings:
                e.findings.append(f.rule)
    return findings


def quiet_admin_summary(events: list, max_ips: int = 10) -> list[dict]:
    """내부망 IP의 관리자 접근 중 공격 신호가 없어 알리지 않은 것(IP별). 퇴사자·도난 계정의 사내망·VPN 접근이
    이렇게 보이므로 경보 대신 보고서에 목록으로 남긴다."""
    by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        if e.extra.get("admin_quiet") and not e.extra.get("known"):
            by_ip[e.src_ip or "?"].append(e)
    out = []
    for ip, evs in sorted(by_ip.items(), key=lambda x: -len(x[1]))[:max_ips]:
        paths = Counter(str(e.extra.get("path") or e.action or "").split("?")[0] for e in evs)
        out.append({"ip": ip, "n": len(evs), "first": min(e.ts for e in evs).isoformat(),
                    "last": max(e.ts for e in evs).isoformat(),
                    "paths": [p for p, _ in paths.most_common(3)],
                    "users": sorted({str(e.actor) for e in evs if e.actor and e.actor != "-"})[:3]})
    return out

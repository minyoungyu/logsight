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
from urllib.parse import unquote_plus

from ..normalize import Event
from ..detect import Finding, _bursts, _ok_fail
from .webprofile import SiteProfile

# ------------------------------------------------------------------ 공격 패턴
# 한 번 디코드한 "경로+쿼리" 문자열에 대해 검사한다.
SQLI = re.compile(
    r"(?i)(?:'\s*(?:or|and)\s+['\d]|\bunion\s+(?:all\s+)?select\b|\bselect\b.+\bfrom\b|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|information_schema|\bconcat\s*\(|"
    r"@@version|\bextractvalue\s*\(|\bupdatexml\s*\(|'\s*(?:--|#)|\b(?:or|and)\s+\d+\s*=\s*\d+)")
TRAVERSAL = re.compile(
    r"(?i)(?:\.\./|\.\.%2f|%2e%2e/|\.\.\\|/etc/passwd|/proc/self/|c:\\windows|"
    r"php://(?:filter|input)|data://|expect://|/\.ssh/|boot\.ini)")
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
    findings: list[Finding] = []

    access = [e for e in events if e.source == "access"]
    errors = [e for e in events if e.source == "weberror"]
    auth = [e for e in events if e.source in ("auth", "sshauth")]

    # 규칙별로 공격자 IP → 이벤트 목록을 모은다
    buckets: dict[str, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))

    for e in access:
        ip = e.src_ip or "?"
        target = _dec((e.extra.get("path", "") + "?" + e.extra.get("query", "")).rstrip("?"))
        ua = e.extra.get("ua", "")
        path = e.extra.get("path", "")
        status = e.extra.get("status", "")
        trusted_ip = _trusted(e.src_ip, trusted)

        matched = False
        if SQLI.search(target):
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
        if SCANNER_UA.search(ua) and not trusted_ip:
            buckets["WEBLOG_SCANNER"][ip].append(e)
        # 업로드 폴더 안의 스크립트가 실행(=요청)되면 매우 의심스럽다
        if path.lower().startswith(upload_dirs) and re.search(r"\.(php|phtml|jsp|asp|aspx|cgi|pl)\b", path, re.I):
            buckets["WEBLOG_UPLOAD_EXEC"][ip].append(e); matched = True
        # 공격 패턴 요청에 서버가 500으로 반응하면 취약점이 실제로 건드려졌을 가능성
        if matched and e.outcome == "server-error":
            buckets["WEBLOG_EXPLOIT_5XX"][ip].append(e)
        # 공격 패턴 요청이 성공(2xx)하면서 응답이 유난히 크면 데이터 유출 의심
        if matched and e.outcome == "success":
            try:
                if int(e.extra.get("bytes", "0")) >= 50_000:
                    buckets["WEBLOG_LARGE_EXFIL"][ip].append(e)
            except ValueError:
                pass

    for rule, by_ip in buckets.items():
        findings += _mk(rule, by_ip, lambda evs: _ok_fail(evs))

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

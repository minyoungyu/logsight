"""코드 프리즈 전 보강(2026-11-20)의 경계 사례. 사양서 ID는 docs/사양서.md, 체크리스트는 docs/테스트_체크리스트.md.

- 서버 권한 상승·계정 생성(sudo·su·useradd)   → FR-03 (TC-DET-HOST-*)
- 변형 인코딩·절대 경로 파일 열람              → FR-03 (TC-DET-WEB-EVASION-*)
- 콘솔 로그인 연속 실패, 실패한 콘솔 로그인 해석 → FR-03 (TC-DET-CT-CONSOLE-*)
입력은 모두 합성이고 IP는 문서용 대역만 쓴다.
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import cloudtrail_record_to_event, parse_sshauth  # noqa: E402
from logsight.web import webdetect, weblog  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

T0 = datetime(2026, 10, 11, 5, 0, tzinfo=timezone.utc)
ATK = "198.51.100.7"


def line(i, proc, msg):
    return f"{(T0 + timedelta(seconds=i * 10)).strftime('%b %d %H:%M:%S')} web {proc}[{500 + i}]: {msg}"


def acc(i, path, st=200):
    ts = (T0 + timedelta(seconds=i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ATK} - - [{ts}] "GET {path} HTTP/1.1" {st} 100 "-" "Mozilla/5.0"'


def web_findings(paths):
    evs = weblog.parse_access("\n".join(acc(i, p) for i, p in enumerate(paths)), "access.log")
    return webdetect.run_web_detections(evs, SiteProfile())


def rules_of(findings):
    return {f.rule for f in findings}


class HostPrivEsc(unittest.TestCase):
    """TC-DET-HOST-01~06"""

    def run_auth(self, lines):
        return run_detections(parse_sshauth("\n".join(lines), year=2026), {})

    def test_webshell_sudo_find_exec(self):  # TC-DET-HOST-01: CTF F4 모양
        f = self.run_auth([line(0, "sudo", "www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; "
                                           "COMMAND=/usr/bin/find /tmp -exec /bin/sh -p ; -quit")])
        hit = [x for x in f if x.rule == "HOST_PRIV_ESC"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].severity, "high")
        self.assertIn("www-data", hit[0].detail)

    def test_service_account_su(self):  # TC-DET-HOST-02
        f = self.run_auth([line(0, "su", "(to root) www-data on pts/0"),
                           line(0, "su", "pam_unix(su:session): session opened for user root(uid=0) by www-data(uid=33)")])
        hit = [x for x in f if x.rule == "HOST_PRIV_ESC"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(len(hit[0].events), 1, "같은 su 한 번이 남긴 두 줄은 한 번으로 센다")

    def test_admin_daily_sudo_is_quiet(self):  # TC-DET-HOST-03: 오탐 방지
        f = self.run_auth([line(0, "sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update"),
                           line(1, "sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"),
                           line(2, "su", "Successful su for root by alice")])
        self.assertFalse(rules_of(f) & {"HOST_PRIV_ESC", "HOST_PRIV_ESC_FAIL", "HOST_ACCOUNT_CREATED"})

    def test_not_in_sudoers_is_failure(self):  # TC-DET-HOST-04: 예전에는 거부된 줄을 성공으로 읽었다
        evs = parse_sshauth(line(0, "sudo", "www-data : user NOT in sudoers ; TTY=unknown ; PWD=/ ; USER=root ; "
                                            "COMMAND=/bin/bash"), year=2026)
        self.assertEqual(evs[0].outcome, "failure")
        f = run_detections(evs, {})
        self.assertIn("HOST_PRIV_ESC_FAIL", rules_of(f))
        self.assertNotIn("HOST_PRIV_ESC", rules_of(f))

    def test_ssh_then_useradd_joins_one_incident(self):  # TC-DET-HOST-05: 직전 SSH 로그인 IP를 이어 붙임
        evs = parse_sshauth("\n".join([
            line(0, "sshd", f"Accepted password for root from {ATK} port 40000 ssh2"),
            line(1, "sudo", "root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m svc")]), year=2026)
        sudo_ev = [e for e in evs if e.action == "sudo"][0]
        self.assertEqual(sudo_ev.src_ip, ATK)
        self.assertIn("src_ip_from", sudo_ev.extra)
        f = [x for x in run_detections(evs, {}) if x.rule == "HOST_ACCOUNT_CREATED"]
        self.assertEqual(len(f), 1)
        # 만들어진 계정(svc)을 적는다. 명령을 실행한 root를 '생성된 계정'으로 적으면 읽는 사람이 오해한다(모의 사용자 시험에서 발견)
        self.assertEqual(f[0].key, "svc")
        self.assertIn("'svc'", f[0].detail)
        self.assertIn("실행: root", f[0].detail)

    def test_scan_engine_sees_host_rules(self):  # TC-DET-HOST-06: 웹서버 점검 엔진도 같은 규칙
        evs = parse_sshauth(line(0, "sudo", "nginx : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/python3 -c 'import os'"),
                            year=2026)
        f = webdetect.run_web_detections(evs, SiteProfile(), sources=("access",))
        self.assertIn("HOST_PRIV_ESC", rules_of(f))


class WebEvasion(unittest.TestCase):
    """TC-DET-WEB-EVASION-01~04 (11/19 변형 17가지 시험에서 놓친 것)"""

    def test_overlong_utf8(self):
        for p in ("/view.php?file=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
                  "/view.php?f=%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd",
                  "/view.php?f=%u002e%u002e%u2215etc%u2215passwd"):
            with self.subTest(p=p):
                self.assertIn("WEBLOG_TRAVERSAL", rules_of(web_findings([p])))

    def test_absolute_sensitive_path_without_dotdot(self):
        self.assertIn("WEBLOG_TRAVERSAL", rules_of(web_findings(["/download.php?file=/etc/shadow"])))
        self.assertIn("WEBLOG_TRAVERSAL", rules_of(web_findings(["/v.php?f=file:///root/.ssh/id_rsa"])))

    def test_normal_requests_stay_quiet(self):
        f = web_findings(["/view.php?page=about.txt", "/search?q=etc+hosts", "/go?next=/root/menu",
                          "/static/style.css?v=3"])
        self.assertNotIn("WEBLOG_TRAVERSAL", rules_of(f))

    def test_aws_engine_same_decision(self):  # 사후 분석 엔진(nginx 로그를 AWS 로그와 함께 넣을 때)도 같은 판단
        from logsight.normalize import parse_weblog
        evs = parse_weblog("\n".join(acc(i, p) for i, p in enumerate(
            ["/view.php?file=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/download.php?file=/etc/shadow"])))
        self.assertIn("WEBLOG_TRAVERSAL", rules_of(run_detections(evs, {})))


class ConsoleBrute(unittest.TestCase):
    """TC-DET-CT-CONSOLE-01~03"""

    def login(self, i, ok, mfa="No"):
        return cloudtrail_record_to_event({
            "eventTime": (T0 + timedelta(seconds=30 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": ATK,
            "userIdentity": {"type": "IAMUser", "userName": "dev", "arn": "arn:aws:iam::111122223333:user/dev"},
            "responseElements": {"ConsoleLogin": "Success" if ok else "Failure"},
            "additionalEventData": {"MFAUsed": mfa}}, f"ct:{i}")

    def test_failed_console_login_is_failure(self):  # 예전에는 실패한 로그인을 성공으로 읽어 'MFA 없는 로그인'으로 냈다
        e = self.login(0, False)
        self.assertEqual(e.outcome, "failure")
        self.assertNotIn("CT_CONSOLE_NO_MFA", rules_of(run_detections([e], {})))

    def test_success_after_burst_is_high(self):
        f = [x for x in run_detections([self.login(i, False) for i in range(5)] + [self.login(6, True)], {})
             if x.rule == "CT_CONSOLE_BRUTE"]
        self.assertEqual(len(f), 1, "IP 묶음과 사용자 묶음이 같은 실패를 두 번 내지 않는다")
        self.assertEqual(f[0].severity, "high")

    def test_four_failures_quiet(self):
        self.assertNotIn("CT_CONSOLE_BRUTE", rules_of(run_detections([self.login(i, False) for i in range(4)], {})))


if __name__ == "__main__":
    unittest.main()

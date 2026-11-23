"""오탐·놓침 수정(2026-10-26) 회귀 테스트. 입력은 직접 만든 로그 줄이다(공개 데이터셋 줄을 복사하지 않음).

실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.web import weblog, webdetect, webanalyze  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

T0 = datetime(2026, 10, 10, 13, 0, 0, tzinfo=timezone.utc)


def line(path, ip="198.51.100.9", method="GET", st=200, by=100, sec=0, ua="Mozilla/5.0"):
    ts = (T0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {st} {by} "-" "{ua}"'


def rules(lines, profile=None):
    evs = weblog.parse_access("\n".join(lines), "a.log")
    return {f.rule for f in webdetect.run_web_detections(evs, profile)}


class ShellParamTests(unittest.TestCase):
    def test_hash_value_on_file_download_is_not_webshell(self):
        # 앱이 스크립트 뒤에 파일 경로를 붙여 내려받는 요청, c= 값은 캐시 해시
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS",
                         rules([line("/app.php/files/u1/photo.jpg?c=9f2b6c1d0e4a7b3c8d5e&x=32")]))

    def test_hash_value_on_script_is_not_webshell(self):
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/index.php?c=a1b2c3d4e5f6a7b8c9d0")]))

    def test_real_command_param_is_webshell(self):
        self.assertIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/files/x.php?cmd=id")]))
        self.assertIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/files/x.php?c=ls%20-la")]))


class UploadDirTests(unittest.TestCase):
    def test_cms_upload_folder_script_is_exec(self):
        self.assertIn("WEBLOG_UPLOAD_EXEC", rules([line("/site/content/uploads/2026/10/a.php?x=1")]))

    def test_profile_prefix_still_works(self):
        p = SiteProfile(upload_dirs=["/data"])
        self.assertIn("WEBLOG_UPLOAD_EXEC", rules([line("/data/a.php")], p))

    def test_static_file_in_upload_folder_is_not_exec(self):
        self.assertNotIn("WEBLOG_UPLOAD_EXEC", rules([line("/site/content/uploads/2026/10/a.png")]))


class Base64CommandTests(unittest.TestCase):
    def _b64(self, s):
        return base64.b64encode(s.encode()).decode().rstrip("=")

    def test_base64_shell_command_is_cmd_injection(self):
        q = self._b64('["cat", "/etc/hosts"]')
        self.assertIn("WEBLOG_CMD_INJECTION", rules([line(f"/x.php?meta={q}")]))

    def test_base64_plain_text_is_not_cmd_injection(self):
        q = self._b64("hello world this is a caption")
        self.assertNotIn("WEBLOG_CMD_INJECTION", rules([line(f"/x.php?meta={q}")]))


class LoginBruteTests(unittest.TestCase):
    def test_ajax_posts_under_admin_are_not_login_brute(self):
        lines = [line("/wp-admin/admin-ajax.php", method="POST", sec=i * 20) for i in range(15)]
        self.assertNotIn("WEBLOG_AUTH_BRUTE", rules(lines))

    def test_login_posts_are_login_brute(self):
        lines = [line("/wp-login.php", method="POST", sec=i * 20) for i in range(15)]
        self.assertIn("WEBLOG_AUTH_BRUTE", rules(lines))

    def test_exact_admin_path_post_still_counts(self):
        lines = [line("/admin", method="POST", sec=i * 20) for i in range(15)]
        self.assertIn("WEBLOG_AUTH_BRUTE", rules(lines))


class VerdictTests(unittest.TestCase):
    def test_single_weak_success_signal_is_suspicious(self):
        for r in ("WEBLOG_WEBSHELL_ACCESS", "WEBLOG_LARGE_EXFIL", "WEBLOG_ADMIN_ACCESS"):
            self.assertEqual(webanalyze.rule_verdict([{"rule": r}])[0], "suspicious", r)

    def test_weak_signal_with_attempt_is_likely_breached(self):
        v = webanalyze.rule_verdict([{"rule": "WEBLOG_WEBSHELL_ACCESS"}, {"rule": "WEBLOG_SQLI"}])
        self.assertEqual(v[0], "likely_breached")

    def test_two_weak_signals_are_likely_breached(self):
        v = webanalyze.rule_verdict([{"rule": "WEBLOG_ADMIN_ACCESS"}, {"rule": "WEBLOG_LARGE_EXFIL"}])
        self.assertEqual(v[0], "likely_breached")


class CategoryParamNotWebshellTests(unittest.TestCase):
    """2026-11-23 CTF 리허설 회귀: 짧은 매개변수 c= 가 정상 앱 값(카테고리 등)일 때
    웹셸로 오탐하면 안 된다. 실제 웹셸(c=/경로, c=명령)은 그대로 잡혀야 한다."""

    def test_category_word_value_is_not_webshell(self):
        for v in ("mouse", "laptop", "keyboard", "headset"):
            self.assertNotIn("WEBLOG_WEBSHELL_ACCESS",
                             rules([line(f"/category.php?c={v}")]), v)

    def test_run_word_value_is_not_webshell(self):
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/report.php?run=weekly")]))

    def test_real_webshell_command_value_still_detected(self):
        # 업로드된 .phtml 에 명령형 값(경로·공백·명령어)을 준 진짜 웹셸은 유지
        for q in ("c=/usr/local/bin/proof", "c=cat /etc/passwd", "cmd=id"):
            self.assertIn("WEBLOG_WEBSHELL_ACCESS",
                          rules([line(f"/uploads/x.phtml?{q}")]), q)


class BootstrapAccountNotFlaggedTests(unittest.TestCase):
    """2026-11-23 CTF 리허설 회귀: 부팅(cloud-init)·패키지 설치가 만드는 기본·서비스 계정
    (ec2-user·nginx·apache)은 HOST_ACCOUNT_CREATED 로 잡으면 안 된다. 공격자가 sudo 로
    만들거나 목록에 없는 이름을 만들면 그대로 잡혀야 한다."""

    @staticmethod
    def _findings(text):
        from logsight.detect import host_auth_findings
        from logsight.normalize import parse_sshauth
        evs = parse_sshauth(text, "auth.log", year=2026)
        return {f.rule for f in host_auth_findings(evs)}

    def test_boot_and_service_accounts_not_flagged(self):
        text = "\n".join([
            "Nov 23 02:34:21 host useradd[1950]: new user: name=ec2-user, UID=1000, GID=1000, home=/home/ec2-user, shell=/bin/bash",
            "Nov 23 02:34:50 host useradd[2010]: new user: name=nginx, UID=990, GID=990, home=/var/lib/nginx, shell=/sbin/nologin",
            "Nov 23 02:34:51 host useradd[2011]: new user: name=apache, UID=48, GID=48, home=/usr/share/httpd, shell=/sbin/nologin",
        ])
        self.assertNotIn("HOST_ACCOUNT_CREATED", self._findings(text))

    def test_attacker_created_account_still_flagged(self):
        text = "Nov 23 03:10:00 host useradd[9100]: new user: name=backdoor, UID=1500, GID=1500, home=/home/backdoor, shell=/bin/bash"
        self.assertIn("HOST_ACCOUNT_CREATED", self._findings(text))


if __name__ == "__main__":
    unittest.main()

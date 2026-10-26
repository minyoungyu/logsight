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


if __name__ == "__main__":
    unittest.main()

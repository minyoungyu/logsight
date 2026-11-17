"""웹 공격 규칙(web/webdetect)이 웹서버 점검(scan)뿐 아니라 AWS 분석(analyze·watch)에서도 돈다.

예전에는 같은 nginx 로그를 넣어도 AWS 분석은 웹 규칙 3개(SQL 인젝션·경로 탐색·객체 번호)만 봐서
sqlmap 같은 스캐너, 경로 조작, 웹셸 접근을 놓쳤다. 같은 로그 → 같은 규칙인지 본다.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.detect import WEB_RULES_COVERED, WEB_RULES_SAME_IP, run_detections  # noqa: E402
from logsight.normalize import parse_alb, parse_weblog  # noqa: E402
from logsight.web.webdetect import run_web_detections  # noqa: E402
from logsight.web.weblog import parse_access  # noqa: E402
from logsight.web.webprofile import SiteProfile, web_profile_from_env  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SHOP_LOG = ROOT / "samples" / "web" / "logs" / "shopmall_access.log"


def _alb(sec: int, path: str, st: int, ua: str = "Mozilla/5.0") -> str:
    t = f"2026-01-13T05:00:{sec:02d}.000000Z"
    return (f'http {t} app/demo/abc 203.0.113.9:44322 10.0.1.10:80 0.000 0.001 0.000 {st} {st} 34 366 '
            f'"GET http://shop.example{path} HTTP/1.1" "{ua}" - - '
            f'arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:targetgroup/t/1 "Root=1-x" "-" "-" 0 '
            f'{t} "forward" "-" "-" "10.0.1.10:80" "{st}" "-" "-"')


class SameLogSameRulesTest(unittest.TestCase):
    """샘플 쇼핑몰의 nginx 접속 로그를 두 경로로 돌려 웹 규칙 집합을 비교한다."""

    @classmethod
    def setUpClass(cls):
        text = SHOP_LOG.read_text(encoding="utf-8")
        prof = SiteProfile(login_paths=["/login.php"], upload_dirs=["/uploads"])
        cls.scan = {f.rule for f in run_web_detections(parse_access(text, SHOP_LOG.name), prof)}
        env = {"web": {"login_paths": ["/login.php"], "upload_dirs": ["/uploads"]}}
        cls.aws = {f.rule for f in run_detections(parse_weblog(text, SHOP_LOG.name), env)}

    def test_web_rules_match_except_covered(self):
        # 뺀 것: AWS 규칙이 대신 잡는 셋, 사이트 이름을 알아야 하는 CSRF(env에 own_hosts가 없으면 끔)
        excluded = WEB_RULES_COVERED | {"WEBLOG_CSRF_SUSPECT"}
        self.assertEqual(self.scan - excluded, {r for r in self.aws if r.startswith("WEBLOG_")} - excluded)

    def test_covered_rules_come_from_aws_side(self):
        self.assertTrue(self.aws.isdisjoint(WEB_RULES_COVERED))   # 같은 요청을 두 번 세지 않는다
        self.assertIn("WEB_SQLI_PATTERN", self.aws)
        self.assertIn("WEBLOG_SQLI", self.scan)

    def test_web_rule_kept_when_aws_rule_misses(self):
        # 이 로그의 스캐너는 404 경로 19개: WEB_PATH_PROBE(20개) 문턱 아래라 WEBLOG_ENUM_404가 대신 잡는다
        self.assertNotIn("WEB_PATH_PROBE", self.aws)
        self.assertIn("WEBLOG_ENUM_404", self.aws)

    def test_scanner_caught_in_analyze(self):
        self.assertIn("WEBLOG_SCANNER", self.aws)


class SameIpDedupTest(unittest.TestCase):
    def test_enum_404_dropped_when_path_probe_fired(self):
        lines = [f'203.0.113.5 - - [13/Jan/2026:05:01:{i:02d} +0000] "GET /p{i}.php HTTP/1.1" 404 9 "-" "Mozilla/5.0"'
                 for i in range(25)]
        rules = {f.rule for f in run_detections(parse_weblog("\n".join(lines) + "\n", "access.log"), {})}
        self.assertIn(WEB_RULES_SAME_IP["WEBLOG_ENUM_404"], rules)
        self.assertNotIn("WEBLOG_ENUM_404", rules)


class AlbTest(unittest.TestCase):
    def test_alb_scanner_and_traversal(self):
        lines = [_alb(1, "/", 200, ua="sqlmap/1.8"),
                 _alb(2, "/download.php?file=../../../../etc/passwd", 200)]
        rules = {f.rule for f in run_detections(parse_alb("\n".join(lines)), {})}
        self.assertIn("WEBLOG_SCANNER", rules)
        self.assertIn("WEBLOG_TRAVERSAL", rules)

    def test_alb_fields_for_web_rules(self):
        e = parse_alb(_alb(1, "/a.php?x=1", 404))[0]
        self.assertEqual((e.extra["method"], e.extra["path"], e.extra["query"]), ("GET", "/a.php", "x=1"))


class ProfileFromEnvTest(unittest.TestCase):
    def test_env_fields(self):
        env = {"trusted_ips": ["198.51.100.0/24"],
               "instances": [{"public_ip": "3.3.3.3", "private_ip": "10.0.1.10", "private_dns": "IP-10-0-1-10.ec2"}],
               "web": {"login_paths": ["/signin"], "own_hosts": ["Shop.Example"]}}
        p = web_profile_from_env(env, {"api.shop.example"})
        self.assertEqual(p.trusted_ips, ["198.51.100.0/24"])
        self.assertEqual(p.login_paths, ["/signin"])
        for h in ("shop.example", "api.shop.example", "3.3.3.3", "10.0.1.10", "ip-10-0-1-10.ec2", "localhost"):
            self.assertIn(h, p.own_hosts)

    def test_csrf_off_without_site_name(self):
        line = ('203.0.113.9 - - [13/Jan/2026:05:01:00 +0000] "POST /admin/delete.php HTTP/1.1" 200 10 '
                '"https://shop.example/admin/" "Mozilla/5.0"')
        evs = parse_weblog(line + "\n", "access.log")
        self.assertNotIn("WEBLOG_CSRF_SUSPECT", {f.rule for f in run_detections(evs, {})})
        # 사이트 이름을 env에 적으면 켜지고, 우리 사이트에서 온 요청은 CSRF로 보지 않는다
        evs = parse_weblog(line + "\n", "access.log")
        self.assertNotIn("WEBLOG_CSRF_SUSPECT",
                         {f.rule for f in run_detections(evs, {"web": {"own_hosts": ["shop.example"]}})})
        evs = parse_weblog(line.replace("shop.example", "evil.example") + "\n", "access.log")
        self.assertIn("WEBLOG_CSRF_SUSPECT",
                      {f.rule for f in run_detections(evs, {"web": {"own_hosts": ["shop.example"]}})})


if __name__ == "__main__":
    unittest.main()

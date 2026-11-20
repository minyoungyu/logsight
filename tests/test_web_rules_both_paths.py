"""웹 공격 규칙(web/webdetect)이 웹서버 점검(scan)뿐 아니라 AWS 분석(analyze·watch)에서도 돈다.

예전에는 같은 nginx 로그를 넣어도 AWS 분석은 웹 규칙 3개(SQL 인젝션·경로 탐색·객체 번호)만 봐서
sqlmap 같은 스캐너, 경로 조작, 웹셸 접근을 놓쳤다. 같은 로그 → 같은 규칙인지 본다.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.detect import RULE_ALIASES, canonical_rule, run_detections  # noqa: E402
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

    def test_web_rules_match(self):
        # 같은 로그 → 같은 웹 규칙. CSRF만 다르다(사후 분석은 env에 사이트 이름이 없으면 끈다)
        self.assertEqual(self.scan - {"WEBLOG_CSRF_SUSPECT"},
                         {r for r in self.aws if r.startswith("WEBLOG_")} - {"WEBLOG_CSRF_SUSPECT"})

    def test_old_names_are_gone(self):
        self.assertTrue(self.aws.isdisjoint(RULE_ALIASES))
        self.assertIn("WEBLOG_SQLI", self.aws)
        self.assertIn("WEBLOG_ENUM_404", self.aws)

    def test_scanner_caught_in_analyze(self):
        self.assertIn("WEBLOG_SCANNER", self.aws)

    def test_canonical_rule(self):
        self.assertEqual(canonical_rule("WEB_SQLI_PATTERN"), "WEBLOG_SQLI")
        self.assertEqual(canonical_rule("WEBLOG_XSS"), "WEBLOG_XSS")


class SqliOneJudgementTest(unittest.TestCase):
    """예전에는 두 경로의 SQL 인젝션 판단이 달랐다. 이제 같은 요청은 두 경로에서 같은 결과."""
    CASES = {"id=1'": True, "id=1 or 1=1": True, "id=1;select pg_sleep(5)--": True,
             "id=1 union select null": True, "q=select color from menu": False, "q=O'Brien and sons": False}

    def test_same_on_both_paths(self):
        for q, want in self.CASES.items():
            line = f'203.0.113.9 - - [13/Jan/2026:05:01:00 +0000] "GET /item?{q.replace(" ", "%20")} HTTP/1.1" 200 9 "-" "x"\n'
            aws = "WEBLOG_SQLI" in {f.rule for f in run_detections(parse_weblog(line, "a.log"), {})}
            scan = "WEBLOG_SQLI" in {f.rule for f in run_web_detections(parse_access(line, "a.log"))}
            self.assertEqual((aws, scan), (want, want), q)


class OldAwsCasesTest(unittest.TestCase):
    """예전 사후 분석 규칙(WEB_PATH_PROBE·WEB_OBJECT_ENUM)이 잡던 ALB 예는 새 이름으로 계속 잡는다."""

    def _rules(self, lines):
        return {f.rule for f in run_detections(parse_alb("\n".join(lines)), {})}

    def test_path_probe(self):
        self.assertIn("WEBLOG_ENUM_404", self._rules([_alb(i, f"/p{i}x", 404) for i in range(15)]))
        self.assertNotIn("WEBLOG_ENUM_404", self._rules([_alb(i, f"/p{i}x", 404) for i in range(14)]))

    def test_object_enum(self):
        fs = [f for f in run_detections(parse_alb("\n".join(_alb(i, f"/api/jobs/job-{i}", 403) for i in range(5))), {})
              if f.rule == "WEBLOG_IDOR_ENUM"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, "medium")   # 막힌 시도는 중간
        self.assertNotIn("WEBLOG_IDOR_ENUM",
                         self._rules([_alb(i, f"/api/jobs/job-{i}", 403) for i in range(4)]))


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


class DownstreamTest(unittest.TestCase):
    """웹 규칙이 걸린 사건이 설정 점검·수정안·문장까지 이어지는지."""

    def _incident(self, lines, env):
        from logsight.pipeline import run
        return run(parse_weblog("\n".join(lines) + "\n", "access.log"), env, use_ai=False)["results"][0]

    LINES = [f'203.0.113.7 - - [13/Jan/2026:05:01:{i:02d} +0000] '
             f'"GET /view.php?page=../../../../etc/passwd&n={i} HTTP/1.1" 200 2100 "-" "Mozilla/5.0"'
             for i in range(3)] + [
        '203.0.113.7 - - [13/Jan/2026:05:02:00 +0000] "GET /uploads/x.php?cmd=id HTTP/1.1" 200 40 "-" "Mozilla/5.0"']

    def test_no_waf_and_nacl_from_web_rules(self):
        env = {"network_acls": [{"nacl_id": "acl-1", "entries": []}]}
        ids = {c["id"] for c in self._incident(self.LINES, env)["checks"]}
        self.assertIn("WEB_NO_WAF", ids)            # SQL 인젝션이 아니어도 웹 공격이면
        self.assertIn("NACL_BLOCK_ATTACKER", ids)   # 공격 IP 차단 제안
        self.assertIn("WEB_FIX_INPUT", ids)         # 웹서버 점검과 같은 코드 수정안
        self.assertIn("WEB_FIX_WEBSHELL", ids)

    def test_korean_sentence_for_web_rule(self):
        flow = self._incident(self.LINES, {})["report"]["attack_flow"]
        whats = " ".join(s["what"] for s in flow)
        self.assertIn("경로 조작(../)", whats)
        self.assertNotIn("에 해당하는 요청이", whats)  # 템플릿 없는 규칙의 기본 문장이 아님


if __name__ == "__main__":
    unittest.main()

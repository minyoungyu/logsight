"""같은 nginx 접속 로그 한 줄은 AWS 분석 경로(normalize.parse_weblog)와 웹서버 점검(web/weblog.parse_access)에서
같은 IP·같은 필드로 읽혀야 한다. 두 파서가 따로 놀던 때 생긴 문제(위조 가능한 IP를 쓰거나, AI에 응답 코드가
안 가던 것)가 다시 생기지 않게 막는다."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.correlate import _compact  # noqa: E402
from logsight.normalize import parse_weblog  # noqa: E402
from logsight.web.weblog import parse_access  # noqa: E402

LINES = [
    # 기본 combined
    '203.0.113.9 - - [13/Jan/2026:05:01:00 +0000] "GET /item.php?id=1%27%20OR%201=1 HTTP/1.1" 200 5120 "-" "sqlmap/1.7"',
    # 공격자가 X-Forwarded-For를 넣어 인터넷에서 바로 접속(첫 칸이 목록): 맨 왼쪽은 위조 값
    '1.2.3.4, 203.0.113.77 - - [13/Jan/2026:05:02:00 +0000] "GET /admin HTTP/1.1" 403 12 "-" "curl/8"',
    # ALB 뒤(사설 IP에서 옴) + nginx main 형식 마지막 칸의 XFF
    '10.0.1.5 - - [13/Jan/2026:05:03:00 +0000] "POST /login.php HTTP/1.1" 302 0 "https://shop.example/" "Mozilla/5.0" "198.51.100.23"',
    # 요청 주소에 공백이 섞인 비정상 요청, 상태 500
    '198.51.100.8 - - [13/Jan/2026:05:04:00 +0000] "GET /a b.php?x=1 HTTP/1.1" 500 77 "-" "-"',
]
TEXT = "\n".join(LINES) + "\n"


class ParserParityTest(unittest.TestCase):
    def setUp(self):
        self.aws = parse_weblog(TEXT, name="nginx_access.log")
        self.web = parse_access(TEXT, name="nginx_access.log")

    def test_same_lines_same_fields(self):
        self.assertEqual(len(self.aws), len(LINES))
        self.assertEqual(len(self.web), len(LINES))
        for a, w in zip(self.aws, self.web):
            self.assertEqual((a.ts, a.src_ip, a.action, a.raw_ref), (w.ts, w.src_ip, w.action, w.raw_ref))
            for k in ("method", "path", "query", "http_status", "resp_bytes", "referer", "ua"):
                self.assertEqual(a.extra.get(k), w.extra.get(k), k)

    def test_leftmost_forwarded_ip_is_not_trusted(self):
        # 인터넷에서 바로 온 요청의 X-Forwarded-For는 무시하고 실제로 접속한 쪽을 쓴다
        self.assertEqual(self.web[1].src_ip, "203.0.113.77")
        self.assertEqual(self.aws[1].src_ip, "203.0.113.77")

    def test_behind_proxy_uses_forwarded_ip(self):
        self.assertEqual(self.web[2].src_ip, "198.51.100.23")
        self.assertEqual(self.web[2].extra.get("proxy_ip"), "10.0.1.5")

    def test_uri_with_space_kept(self):
        self.assertEqual(self.aws[3].extra["path"], "/a b.php")
        self.assertEqual(self.aws[3].action, "GET /a b.php?x=1")

    def test_access_keeps_old_field_names_for_web_rules(self):
        w = self.web[0]
        self.assertEqual((w.extra["status"], w.extra["bytes"]), ("200", "5120"))
        self.assertEqual(w.outcome, "success")
        self.assertEqual(self.web[3].outcome, "server-error")
        self.assertEqual(self.web[3].status, "failure")   # 공통 결과로는 실패

    def test_ai_sees_status_code_on_both_paths(self):
        # 웹서버 점검 경로에서 AI가 응답 코드를 못 받던 문제
        for e in (self.aws[0], self.web[0]):
            self.assertEqual(_compact(e).get("http_status"), 200)


if __name__ == "__main__":
    unittest.main()

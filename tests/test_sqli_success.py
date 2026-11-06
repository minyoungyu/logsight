"""SQL 인젝션 성공 신호: 응답 크기로 코드가 판단한다(AI에 맡기지 않는다)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import run_detections as detect, sqli_success_signal  # noqa: E402
from logsight.normalize import parse_weblog  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402

ATK = '203.0.113.50 - - [20/Oct/2026:03:{m:02d}:00 +0000] "GET /item?id={q} HTTP/1.1" {st} {size} "-" "sqlmap/1.8"'
NORMAL = '198.51.100.{n} - - [20/Oct/2026:02:{m:02d}:00 +0000] "GET /item?id={n} HTTP/1.1" 200 {size} "-" "Mozilla/5.0"'
INJ = ["1%27", "1%27%20OR%20%271%27%3D%271", "1%20UNION%20SELECT%20NULL--", "1%27%20AND%20SLEEP(5)--"]


def _log(sizes, normal=None, statuses=None):
    lines = [NORMAL.format(n=i + 1, m=i, size=s) for i, s in enumerate(normal or [])]
    statuses = statuses or [200] * len(sizes)
    lines += [ATK.format(m=i, q=INJ[i % len(INJ)], st=st, size=s) for i, (s, st) in enumerate(zip(sizes, statuses))]
    return parse_weblog("\n".join(lines), "access.log")


def _signal(evs):
    att = [e for e in evs if e.src_ip == "203.0.113.50"]
    return sqli_success_signal(att, evs)


class SqliSuccessSignal(unittest.TestCase):
    def test_size_is_parsed(self):
        evs = _log([812])
        self.assertEqual(evs[0].extra["resp_bytes"], 812)

    def test_same_as_normal_page_is_no_success(self):
        s = _signal(_log([812, 812, 812], normal=[812, 815, 810]))
        self.assertTrue(s.startswith("성공 근거 없음"), s)

    def test_bigger_than_normal_page_is_suspected(self):
        s = _signal(_log([812, 9400, 812], normal=[812, 815, 810]))
        self.assertTrue(s.startswith("성공 의심"), s)
        self.assertIn("9400", s)

    def test_all_same_without_baseline(self):
        s = _signal(_log([812, 812, 812]))
        self.assertTrue(s.startswith("성공 근거 없음"), s)
        self.assertIn("확정은 못 함", s)

    def test_varied_without_baseline_is_suspected(self):
        s = _signal(_log([812, 5000, 812]))
        self.assertTrue(s.startswith("성공 의심"), s)

    def test_only_errors(self):
        s = _signal(_log([500, 500], statuses=[500, 403]))
        self.assertTrue(s.startswith("성공 신호 없음"), s)

    def test_no_size_in_log(self):
        evs = parse_weblog(ATK.format(m=1, q=INJ[1], st=200, size="-"), "a.log")
        self.assertTrue(_signal(evs).startswith("성공 판단 불가"))

    def test_rule_detail_carries_signal(self):
        evs = _log([812, 812, 812], normal=[812, 815, 810])
        fs = [f for f in detect(evs) if f.rule == "WEB_SQLI_PATTERN"]
        self.assertEqual(len(fs), 1)
        self.assertIn("성공 근거 없음", fs[0].detail)

    def test_combined_sample(self):
        """samples/combined의 INC-002: 응답이 모두 평소와 같은 812바이트 → 성공 근거 없음."""
        res = run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        details = [f["detail"] for r in res["results"] for f in r["incident"]["findings"]
                   if f["rule"] == "WEB_SQLI_PATTERN"]
        self.assertTrue(any("성공 근거 없음" in d for d in details), details)


if __name__ == "__main__":
    unittest.main()

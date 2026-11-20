"""웹서버 점검도 사후 분석과 같은 처리 단계(정상 작업 목록, 반복 사건 접기, 공격 축 판정)를 거친다."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.web.webpipeline import assess  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402
from logsight.web.webreport import render  # noqa: E402


def _scan_burst(ip: str, hour: int) -> str:
    # 같은 모양(스캐너 User-Agent 3건)을 시간을 띄워 되풀이
    return "".join(f'{ip} - - [13/Jan/2026:{hour:02d}:00:0{i} +0000] "GET /p{i} HTTP/1.1" 404 9 "-" "sqlmap/1.7"\n'
                   for i in range(3))


class ScanStepsTest(unittest.TestCase):
    def _run(self, text: str, **prof):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "access.log"
            p.write_text(text, encoding="utf-8")
            return assess(SiteProfile(name="t", log_paths={"access": [str(p)]}, **prof), use_ai=False)

    def test_repeats_folded(self):
        r = self._run(_scan_burst("198.51.100.7", 1) + _scan_burst("198.51.100.7", 5) + _scan_burst("198.51.100.7", 9))
        self.assertEqual(r["n_incidents"], 3)
        self.assertEqual(r["n_groups"], 1)
        self.assertEqual(r["incident_index"][0]["repeats"], 3)

    def test_two_axes(self):
        r = self._run(_scan_burst("198.51.100.7", 1))
        rep = r["results"][0]["report"]
        self.assertIn(rep["verdict"], ("suspicious", "likely_breached", "breached", "no_evidence"))
        self.assertEqual(rep["attack_verdict"], "attack")
        self.assertIn("공격 판정(사후 분석과 같은 기준)", render(json.loads(json.dumps(r))))

    def test_known_activity(self):
        r = self._run(_scan_burst("198.51.100.7", 1),
                      known_activity=[{"label": "외부 점검 업체", "ips": ["198.51.100.7/32"]}])
        self.assertEqual(r["n_known"], 3)
        self.assertEqual(r["results"][0]["report"]["attack_verdict"], "benign_activity")


if __name__ == "__main__":
    unittest.main()

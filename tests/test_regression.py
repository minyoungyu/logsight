"""AWS 파이프라인 회귀 테스트. 웹 모듈을 추가하기 전(faceda7^) 출력에서 뽑은 기준값과 같아야 한다.

기준값 파일: tests/fixtures/aws_demo_baseline.json (사건별 시각·심각도·단계·출발지·규칙·판정).
기준이 바뀌면 의도한 변경인지 확인하고, 의도라면 CHANGELOG에 호환성 항목을 남긴 뒤 파일을 갱신한다.
실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.pipeline import run_paths  # noqa: E402

BASELINE = ROOT / "tests" / "fixtures" / "aws_demo_baseline.json"


class AwsPipelineRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_paths([str(ROOT / "samples" / "demo")], use_ai=False)
        cls.expected = json.loads(BASELINE.read_text(encoding="utf-8"))

    def test_counts_match_baseline(self):
        for key in ("n_events", "n_flagged", "n_findings", "n_incidents", "rule_counts"):
            self.assertEqual(self.report[key], self.expected[key], key)

    def test_incidents_match_baseline(self):
        got = [{"start": r["incident"]["start"], "severity": r["incident"]["severity"],
                "stages": r["incident"]["stages"], "src_ips": r["incident"]["src_ips"],
                "rules": sorted({f["rule"] for f in r["incident"]["findings"]}),
                "verdict": r["report"].get("verdict")} for r in self.report["results"]]
        self.assertEqual(got, self.expected["incidents"])


if __name__ == "__main__":
    unittest.main()

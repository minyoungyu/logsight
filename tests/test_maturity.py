"""규칙 성숙도: 시험 중 규칙은 경보·사건에서 빠지고 result["experimental"]에만 보인다."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from logsight import maturity  # noqa: E402
from logsight.detect import RULES, run_detections  # noqa: E402
from logsight.pipeline import run  # noqa: E402
from logsight.rulespec import SPEC  # noqa: E402
from test_rule_validation import ct  # noqa: E402


class MaturityTest(unittest.TestCase):
    def test_status_values(self):
        for r, s in SPEC.items():
            self.assertIn(s.get("status", "stable"), {"stable", "experimental"}, r)
        self.assertTrue(maturity.experimental_rules() <= set(RULES))

    def test_initial_experimental_set(self):
        # 계획 파일(holdout_plan maturity.initial_experimental)과 같아야 한다
        self.assertEqual(maturity.experimental_rules(), {
            "WEBLOG_ROBOTS_HIDDEN", "CT_RESOURCE_PUBLIC", "CT_DEFENSE_IMPAIR", "CT_KEY_EXPOSED", "CT_DATA_EXPORT"})

    def test_experimental_excluded_from_incidents(self):
        evs = [ct(0, "CreateInstanceExportTask", "ec2", params={"instanceId": "i-1"})]
        self.assertIn("CT_DATA_EXPORT", {f.rule for f in run_detections(evs, {})})
        evs = [ct(0, "CreateInstanceExportTask", "ec2", params={"instanceId": "i-1"})]
        res = run(evs, {}, use_ai=False)
        self.assertEqual(res["n_incidents"], 0)
        self.assertEqual([x["rule"] for x in res["experimental"]], ["CT_DATA_EXPORT"])
        self.assertNotIn("CT_DATA_EXPORT", evs[0].findings)

    def test_stable_rule_still_alerts(self):
        evs = [ct(0, "StopLogging", "cloudtrail", params={"name": "main"})]
        res = run(evs, {}, use_ai=False)
        self.assertGreaterEqual(res["n_incidents"], 1)
        self.assertEqual(res["experimental"], [])


if __name__ == "__main__":
    unittest.main()

"""Stratus 채점 스크립트: 시간 창으로 사건을 기법에 붙이고 예상과 비교한다."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab" / "aws" / "stratus"))

import score as S  # noqa: E402


class StratusScore(unittest.TestCase):
    def test_expected_file_lists_every_technique_once(self):
        exp = S.expected()
        self.assertEqual(len(exp), 46)
        self.assertTrue(all(e in {"catch", "miss", "maybe"} for e, _ in exp.values()))

    def test_window_and_result(self):
        exp = S.expected()
        times = [{"technique": "aws.defense-evasion.cloudtrail-stop", "start": "2026-11-05T01:00:00Z",
                  "end": "2026-11-05T01:00:30Z", "status": "ok"},
                 {"technique": "aws.persistence.lambda-overwrite-code", "start": "2026-11-05T01:10:00Z",
                  "end": "2026-11-05T01:10:20Z", "status": "ok"},
                 {"technique": "aws.exfiltration.ec2-share-ami", "start": "-", "end": "-",
                  "status": "warmup_failed"}]
        incs = [{"start": "2026-11-05T01:00:10+00:00", "rules": ["CT_LOGGING_TAMPER"]},
                {"start": "2026-11-05T01:30:00+00:00", "rules": ["CT_ROOT_USAGE"]}]  # 어느 창에도 없음
        rows = {r["technique"]: r["result"] for r in S.score(times, incs, exp)}
        self.assertEqual(rows["aws.defense-evasion.cloudtrail-stop"], "caught")
        self.assertEqual(rows["aws.persistence.lambda-overwrite-code"], "missed")
        self.assertEqual(rows["aws.exfiltration.ec2-share-ami"], "warmup_failed")


if __name__ == "__main__":
    unittest.main()

"""사용자 평가 집계 스크립트(scripts/study_score.py) 테스트. 합성 응답만 쓴다."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from study_score import sign_flip_p, summarize  # noqa: E402


def row(pid, cond, scen, mins, qs, conf=3, fa=0):
    return {"pid": pid, "condition": cond, "scenario": scen, "minutes": str(mins),
            **{f"q{i + 1}": str(q) for i, q in enumerate(qs)}, "confidence": str(conf), "false_accusations": str(fa)}


class StudyScoreTests(unittest.TestCase):
    def test_sign_flip_exact(self):
        self.assertEqual(sign_flip_p([1, 1, 1]), 2 / 8)  # 모두 +1: 전부 같은 부호인 경우 2가지
        self.assertEqual(sign_flip_p([0, 0]), 1.0)

    def test_paired_summary_and_success_rule(self):
        rows = []
        for i in range(8):
            rows.append(row(f"P{i}", "logsight", "A" if i % 2 else "B", 12, [2, 2, 1, 2, 1]))
            rows.append(row(f"P{i}", "baseline", "B" if i % 2 else "A", 20, [1, 1, 1, 1, 1], fa=1))
        rows.append(row("P9", "logsight", "A", 10, [2, 2, 2, 2, 2]))  # 짝이 없는 사람은 뺀다
        s = summarize(rows)
        self.assertEqual(s["n"], 8)
        self.assertEqual(s["dropped"], ["P9"])
        self.assertEqual(s["d_score_median"], 3)
        self.assertEqual(s["d_minutes_median"], -8)
        self.assertEqual(s["baseline"]["false_accusations"], 8)
        self.assertTrue(s["success"])
        self.assertLess(s["p_score"], 0.01)

    def test_blank_answers_are_dropped(self):
        r = row("P1", "logsight", "A", 10, [2, 2, 2, 2, 2])
        r["q3"] = ""
        s = summarize([r, row("P1", "baseline", "B", 10, [1] * 5)])
        self.assertEqual(s["n"], 0)
        self.assertEqual(s["dropped"], ["P1"])
        self.assertFalse(s["success"])


if __name__ == "__main__":
    unittest.main()

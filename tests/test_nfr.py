"""비기능 요구사항 자동 확인(docs/사양서.md의 NFR). CI 기계가 느려도 통과하도록 기준값에 여유를 둔다.

- NFR-01: 이벤트 1만 건 규칙 분석이 10초 안에 끝난다(측정 기준값은 20만 건 14초).
- NFR-04: 1만 건 처리의 최대 메모리가 200MB 안이다(20만 건 기준 500MB 목표의 비례값보다 넉넉함).
- NFR-09: 같은 입력이면 규칙 모드 결과가 같다.
"""
from __future__ import annotations

import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from bench import make  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402


class Performance(unittest.TestCase):
    def test_10k_events_under_10s_and_200mb(self):  # TC-NFR-01, TC-NFR-04
        with tempfile.TemporaryDirectory() as d:
            make(10_000, Path(d))
            tracemalloc.start()
            t = time.time()
            res = run_paths([d], use_ai=False)
            took = time.time() - t
            peak = tracemalloc.get_traced_memory()[1] / 1e6
            tracemalloc.stop()
        self.assertEqual(res["n_events"], 10_000)
        self.assertLess(took, 10.0, f"1만 건 {took:.1f}초")
        self.assertLess(peak, 200.0, f"최대 메모리 {peak:.0f}MB")


class Deterministic(unittest.TestCase):
    def test_same_input_same_result(self):  # TC-NFR-09
        a = run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        b = run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        key = lambda r: [(x["incident"]["id"], x["incident"]["severity"], tuple(f["rule"] for f in x["incident"]["findings"]),
                         len(x["checks"])) for x in r["results"]]  # noqa: E731
        self.assertEqual(key(a), key(b))


if __name__ == "__main__":
    unittest.main()

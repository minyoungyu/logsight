"""사양서 ↔ 체크리스트 ↔ 테스트 추적이 끊기지 않았는지(scripts/spec_trace.py)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import spec_trace  # noqa: E402

SPEC = "| FR-01 | 입력 | 기준 | ✅ |\n| FR-02 | 다음 | 기준 | ⬜ |\n| NFR-01 | 시간 | 10초 | 1초 | ✅ |\n"


class SpecTrace(unittest.TestCase):
    def test_repository_docs_are_traced(self):
        errors, st = spec_trace.check(spec_trace.SPEC.read_text(encoding="utf-8"),
                                      spec_trace.CHECK.read_text(encoding="utf-8"))
        self.assertEqual(errors, [])
        self.assertGreater(st["auto"], st["tcs"] // 2, "자동 TC가 절반을 넘어야 한다")

    def test_requirement_without_tc_is_reported(self):
        errors, _ = spec_trace.check(SPEC, "| TC-A-01 | FR-01 | x | 수동 화면 | - |\n")
        self.assertEqual(errors, ["NFR-01: 테스트 케이스가 없음"])  # FR-02는 ⬜라 빼고 센다

    def test_missing_test_and_unknown_requirement(self):
        chk = ("| TC-A-01 | FR-01, NFR-01 | x | 자동 tests/test_spec_trace.py::NoSuchTest | - |\n"
               "| TC-A-02 | FR-09 | x | 수동 | - |\n")
        errors, _ = spec_trace.check(SPEC, chk)
        self.assertIn("TC-A-01: 테스트 tests/test_spec_trace.py::NoSuchTest 를 찾을 수 없음", errors)
        self.assertIn("TC-A-02: 사양서에 없는 요구사항 FR-09", errors)


if __name__ == "__main__":
    unittest.main()

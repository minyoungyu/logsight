"""샘플 로그 결과가 고정 파일(tests/regression/samples.json)과 같은지 본다.
의도한 변화면: python scripts/regress_samples.py --update 후 차이를 PR에 적는다."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import regress_samples as R  # noqa: E402


class SamplesRegression(unittest.TestCase):
    def test_samples_match_fixed_file(self):
        old = json.loads(R.FIXED.read_text(encoding="utf-8"))
        d = R.diff(old, R.snapshot())
        self.assertEqual(d, [], "샘플 결과가 바뀜. 의도한 것이면 python scripts/regress_samples.py --update\n" + "\n".join(d))


if __name__ == "__main__":
    unittest.main()

"""문서의 측정 숫자가 저장소의 결과 파일과 맞는지(scripts/evidence_check.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import evidence_check  # noqa: E402


def test_documented_numbers_match_result_files():
    errs = evidence_check.run()
    assert not errs, "\n".join(errs)

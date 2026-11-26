"""문서의 측정 숫자가 저장소의 결과 파일과 맞는지(scripts/evidence_check.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import evidence_check  # noqa: E402


def test_documented_numbers_match_result_files():
    errs = evidence_check.run()
    assert not errs, "\n".join(errs)


def test_spec_number_without_evidence_fails(monkeypatch, tmp_path):
    """사양서 '지금' 칸에 근거 항목 없는 숫자를 새로 쓰면 실패한다."""
    spec = "| S7 | 오탐 | 0.1% 이하 | 데이터셋 | fox 0.18%, 새 측정 0.07%(3/4,000) | ⬜ |\n"
    reg = {"claims": [{"id": "x", "doc": evidence_check.SPEC, "quote": "fox 0.18%"}], "spec_unbacked": []}
    (tmp_path / "docs").mkdir()
    (tmp_path / evidence_check.SPEC).write_text(spec, encoding="utf-8")
    monkeypatch.setattr(evidence_check, "ROOT", tmp_path)
    errs = evidence_check.check_spec(reg)
    assert any("0.07%" in e for e in errs) and any("3/4,000" in e for e in errs)
    assert not any("0.18%" in e for e in errs)


def test_spec_dates_and_confidence_level_are_not_numbers():
    rows = evidence_check.spec_numbers(
        "| S6 | x | y | z | 11/24 처음 재는 15개 9/15(95% 구간 36~80%), 10/26 재측정 7/7 | ⬜ |\n")
    assert [t for _, t in rows] == ["9/15", "36~80%", "7/7"]


def test_spec_unbacked_needs_reason_and_must_still_exist(monkeypatch, tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / evidence_check.SPEC).write_text("| NFR-03 | 시간 | 15분 | 차이 | 0.6초 | 🟡 |\n", encoding="utf-8")
    monkeypatch.setattr(evidence_check, "ROOT", tmp_path)
    errs = evidence_check.check_spec({"claims": [], "spec_unbacked": [
        {"row": "NFR-03", "token": "0.6초", "reason": ""}, {"row": "NFR-03", "token": "9.9초", "reason": "옛 값"}]})
    assert any("이유가 비어" in e for e in errs) and any("더는 없음" in e for e in errs)


def test_spec_number_needs_quote_in_same_row(monkeypatch, tmp_path):
    """다른 행에 같은 숫자의 근거가 있어도, 그 행에 근거가 없으면 실패한다."""
    spec = ("| S1 | a | b | c | 재현율 95%(19/20) | 🟡 |\n"
            "| NFR-20 | a | b | c | 새 세트 95% | 🟡 |\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / evidence_check.SPEC).write_text(spec, encoding="utf-8")
    monkeypatch.setattr(evidence_check, "ROOT", tmp_path)
    errs = evidence_check.check_spec({"claims": [{"id": "x", "doc": evidence_check.SPEC,
                                                  "quote": "재현율 95%(19/20)"}], "spec_unbacked": []})
    assert len(errs) == 1 and "NFR-20" in errs[0]

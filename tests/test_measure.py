"""정답 대조 측정(measure.py) 단위 테스트. 실행: python -m unittest discover -s tests -v"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.web.measure import TruthError, format_report, load_truth, score, validate_entry  # noqa: E402


def _result(*ip_rules):
    """(ip, [rule...]) 목록으로 assess() 모양의 결과를 흉내 낸다."""
    incidents = []
    for ip, rules in ip_rules:
        incidents.append({"incident": {"src_ips": [ip], "findings": [
            {"rule": r, "key": ip} for r in rules]}})
    return {"results": incidents}


def _t(ip, rules=(), malicious=True, detectable=True, label=None):
    return {"attacker_ip": ip, "malicious": malicious, "detectable": detectable,
            "expected_rules": list(rules), "label": label or ip}


class ScoreTests(unittest.TestCase):
    def test_perfect_detection(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"]), _t("198.51.100.2", ["WEBLOG_XSS"]),
                 _t("203.0.113.5", malicious=False)]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_SQLI"]), ("198.51.100.2", ["WEBLOG_XSS"])))
        self.assertEqual(s["recall"], 1.0)
        self.assertEqual(s["precision"], 1.0)
        self.assertEqual(s["false_positive_rate"], 0.0)
        self.assertEqual(s["f1"], 1.0)

    def test_missed_attack_lowers_recall_and_is_listed(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"]), _t("198.51.100.2", ["WEBLOG_XSS"])]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_SQLI"])))
        self.assertEqual(s["recall"], 0.5)
        self.assertEqual([m["ip"] for m in s["missed"]], ["198.51.100.2"])

    def test_wrong_rule_counts_as_miss(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"])]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_XSS"])))
        self.assertEqual(s["recall"], 0.0)

    def test_empty_expected_rules_means_any_rule(self):
        truth = [_t("198.51.100.1", [])]
        self.assertEqual(score(truth, _result(("198.51.100.1", ["WEBLOG_XSS"])))["recall"], 1.0)
        self.assertEqual(score(truth, _result())["recall"], 0.0)

    def test_undetectable_entries_excluded_from_recall(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"]), _t("198.51.100.9", [], detectable=False, label="blind")]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_SQLI"])))
        self.assertEqual(s["recall"], 1.0)
        self.assertEqual(s["counts"]["blind_spot_entries"], 1)
        self.assertEqual(s["blind_spots"][0]["label"], "blind")

    def test_false_positive_on_benign_ip(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"]), _t("203.0.113.5", malicious=False)]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_SQLI"]), ("203.0.113.5", ["WEBLOG_SCANNER"])))
        self.assertEqual(s["false_positive_rate"], 1.0)
        self.assertEqual(s["false_positives"], ["203.0.113.5"])
        self.assertEqual(s["precision"], 0.5)

    def test_unknown_flagged_ip_is_counted_separately(self):
        truth = [_t("198.51.100.1", ["WEBLOG_SQLI"])]
        s = score(truth, _result(("198.51.100.1", ["WEBLOG_SQLI"]), ("192.0.2.77", ["WEBLOG_XSS"])))
        self.assertEqual(s["unknown_flagged"], ["192.0.2.77"])
        self.assertEqual(s["precision"], 1.0)  # 정답에 없는 IP는 정밀도 분모에 넣지 않는다

    def test_no_attacks_gives_none_not_zero(self):
        s = score([_t("203.0.113.5", malicious=False)], _result())
        self.assertIsNone(s["recall"])
        self.assertIsNone(s["precision"])
        self.assertEqual(s["false_positive_rate"], 0.0)

    def test_report_mentions_key_numbers(self):
        s = score([_t("198.51.100.1", ["WEBLOG_SQLI"])], _result())
        text = format_report(s)
        self.assertIn("재현율", text)
        self.assertIn("0.0%", text)
        self.assertIn("놓친 공격", text)


class LoadTruthTests(unittest.TestCase):
    def _write(self, data) -> Path:
        d = tempfile.mkdtemp()
        p = Path(d) / "gt.json"
        p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return p

    def test_list_and_entries_forms_both_load(self):
        entry = {"attacker_ip": "198.51.100.1", "expected_rules": ["WEBLOG_SQLI"]}
        self.assertEqual(len(load_truth(self._write([entry]))), 1)
        self.assertEqual(len(load_truth(self._write({"entries": [entry]}))), 1)

    def test_defaults(self):
        e = validate_entry({"attacker_ip": "198.51.100.1"})
        self.assertTrue(e["malicious"])
        self.assertTrue(e["detectable"])
        self.assertEqual(e["expected_rules"], [])

    def test_missing_ip_gives_hint(self):
        with self.assertRaisesRegex(TruthError, "attacker_ip가 없음"):
            validate_entry({"expected_rules": []}, 3)

    def test_wildcard_ip_rejected_with_hint(self):
        with self.assertRaisesRegex(TruthError, "와일드카드"):
            validate_entry({"attacker_ip": "203.0.113.*"})

    def test_unknown_rule_rejected_with_hint(self):
        with self.assertRaisesRegex(TruthError, "rules"):
            validate_entry({"attacker_ip": "198.51.100.1", "expected_rules": ["NOPE"]})

    def test_bad_json_rejected(self):
        with self.assertRaisesRegex(TruthError, "JSON"):
            load_truth(self._write("[{"))

    def test_missing_file_rejected(self):
        with self.assertRaisesRegex(TruthError, "찾을 수 없음"):
            load_truth(Path(tempfile.mkdtemp()) / "none.json")


class SampleIntegrationTests(unittest.TestCase):
    def test_sample_truth_scores_as_expected(self):
        from logsight.web.webpipeline import assess
        from logsight.web.webprofile import SiteProfile
        truth = load_truth(ROOT / "samples" / "ctf" / "ground_truth.json")
        result = assess(SiteProfile.load(ROOT / "samples" / "web" / "profile.json"), use_ai=False, top=500)
        s = score(truth, result)
        self.assertEqual(s["recall"], 1.0)
        self.assertEqual(s["false_positive_rate"], 0.0)
        self.assertEqual(s["counts"]["blind_spot_entries"], 1)


if __name__ == "__main__":
    unittest.main()

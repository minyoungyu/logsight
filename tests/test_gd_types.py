"""GuardDuty 결과 해석(탐지는 AWS, 해석과 조치는 LogFinder): 유형 풀이, 먼저 할 일, 성공 여부 문장."""
from __future__ import annotations

import os
import sys
import unittest
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from logsight import briefing as bf  # noqa: E402
from logsight.gd_types import describe, parse  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402

import gd_coverage  # noqa: E402


@lru_cache(maxsize=1)
def gd_only() -> dict:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    return run_paths([str(ROOT / "samples/guardduty_only")], use_ai=False)


class TypeTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse("Backdoor:EC2/C&CActivity.B!DNS"),
                         {"purpose": "Backdoor", "resource": "EC2", "behavior": "C&CActivity", "variant": "B", "tag": "DNS"})

    def test_every_active_type_has_korean(self):  # TC-GD-01
        rows = gd_coverage.load()
        self.assertGreaterEqual(len(rows), 200)
        raw = [t for t, _, _ in rows if describe(t)["level"] == "raw"]
        self.assertEqual(raw, [])
        for t, _, _ in rows:
            d = describe(t)
            self.assertTrue(d["action"], t)
            self.assertIn(d["phase"], (0, 1, 2), t)

    def test_unknown_type_keeps_english_and_says_raw(self):
        d = describe("NewPurpose:EC2/SomethingNew")
        self.assertEqual(d["level"], "raw")
        self.assertIn("SomethingNew", d["title"])

    def test_soft_behavior_is_not_isolate_first(self):
        d = describe("Impact:EC2/SuspiciousDomainRequest.Reputation")
        self.assertNotIn("격리하고(보안그룹", d["action"])
        self.assertEqual(d["phase"], 2)


class GuardDutyOnlyReport(unittest.TestCase):
    def test_first_actions_without_environment(self):  # TC-GD-02
        first, rest = bf.actions(gd_only())
        self.assertTrue(first)
        joined = " ".join(x["text"] + " " + x["target"] for x in first + rest)
        self.assertIn("i-0shop0web0001", joined)
        self.assertIn("shop-web-role", joined)
        self.assertNotIn("ASIAZ3SAMPLEKEY00001", joined)  # 키는 가린 형식으로만(NFR-06)

    def test_detection_is_not_counted_as_failure(self):  # TC-GD-03
        r = gd_only()["results"][0]
        reason = r["report"]["verdict"]["reason"] if isinstance(r["report"].get("verdict"), dict) else ""
        text = " ".join([reason, bf.headline(gd_only())["sentence"]])
        self.assertNotIn("급하지 않을", text)
        self.assertNotIn("모두 막히거나 실패", text)
        self.assertIn("GuardDuty 결과에는 성공 여부가 없어", text)

    def test_each_step_uses_its_own_explanation(self):
        flow = gd_only()["results"][0]["report"]["attack_flow"]
        shell = [s for s in flow if "ReverseShell" in s["what"]]
        self.assertTrue(shell)
        self.assertIn("셸", shell[0]["what"])
        self.assertNotIn("포트에 접속을 시도", shell[0]["what"])

    def test_bucket_target(self):
        flow = gd_only()["results"][0]["report"]["attack_flow"]
        self.assertTrue(any("버킷 shop-customer-orders" in s["what"] for s in flow))


if __name__ == "__main__":
    unittest.main()

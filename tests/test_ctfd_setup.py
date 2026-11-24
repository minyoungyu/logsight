"""CTFd 등록 스크립트: 실제 서버 없이 API 호출 순서·내용을 확인한다."""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ctfd_setup", ROOT / "lab" / "ctf" / "ctfd" / "ctfd_setup.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SPEC = json.loads((ROOT / "lab" / "ctf" / "ctfd" / "challenges.json").read_text(encoding="utf-8"))
FLAGS = {t: {"f1": f"LS{{{t}1}}", "f1_path": "x", "f2": f"LS{{{t}2}}", "f3": f"LS{{{t}3}}",
             "f4": f"LS{{{t}4}}", "f5": f"ctf-{t}-role", "f6": f"LS{{{t}6}}"} for t in ("t01", "t02")}


class FakeAPI:
    def __init__(self, subs=None):
        self.calls, self.next, self.subs = [], 1, subs or []

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path.startswith("/challenges?"):
            return [{"id": i + 1, "name": c["name"]} for i, c in enumerate(SPEC["challenges"])] if self.subs else []
        if method == "POST":
            self.next += 1
            return {"id": self.next}
        return []

    def pages(self, path):
        return [{"id": 7, "name": "t02"}] if path == "/teams" else self.subs


class CtfdSetupTests(unittest.TestCase):
    def test_spec_has_two_paid_hints_per_challenge(self):
        self.assertEqual([c["key"] for c in SPEC["challenges"]], ["f1", "f2", "f3", "f4", "f5", "f6"])
        for c in SPEC["challenges"]:
            costs = [h["cost"] for h in c["hints"]]
            self.assertEqual(len(costs), 2)
            self.assertTrue(0 < costs[0] < costs[1] < c["value"])

    def test_setup_registers_all_team_flags_and_chained_hints(self):
        api = FakeAPI()
        mod.setup(api, SPEC, FLAGS)
        flags = [b["content"] for m, p, b in api.calls if p == "/flags"]
        self.assertEqual(len(flags), 12)
        self.assertIn("ctf-t02-role", flags)
        hints = [b for m, p, b in api.calls if p == "/hints"]
        self.assertEqual(len(hints), 12)
        self.assertNotIn("requirements", hints[0])
        self.assertIn("requirements", hints[1])

    def test_check_sharing_flags_other_teams_flag(self):
        subs = [{"challenge_id": 1, "team_id": 7, "provided": "LS{t011}", "date": "d"},
                {"challenge_id": 1, "team_id": 7, "provided": "LS{t021}", "date": "d"}]
        self.assertEqual(mod.check_sharing(FakeAPI(subs), SPEC, FLAGS, {}), 1)


if __name__ == "__main__":
    unittest.main()

"""공격 흐름 그림(graph.py): 그림의 모든 선이 근거 이벤트에서 나오는지, 추측으로 잇지 않는지."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import graph as G  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402


class CombinedGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        cls.res = r
        cls.incs = {x["incident"]["id"]: x["incident"] for x in r["results"]}

    def test_every_event_drawn_and_verified(self):
        for iid, inc in self.incs.items():
            g = G.build([inc])
            v = G.verify(g, [inc])
            self.assertTrue(v["passed"], (iid, v))
            self.assertEqual(v["events_drawn"], v["events_total"], iid)
            self.assertFalse(v["unknown_refs"], iid)

    def test_inc001_shape(self):
        inc = self.incs["INC-001"]
        g = G.build([inc])
        kinds = sorted(e["kind"] for e in g["edges"])
        self.assertEqual(kinds, ["call", "call", "net", "ssh", "use", "web"])
        # GuardDuty 결과는 선이 아니라 노드 표시
        self.assertTrue(any("GuardDuty" in m["text"] for ms in g["marks"].values() for m in ms))
        self.assertFalse(any("guardduty" in r.lower() for e in g["edges"] for r in e["refs"]))
        # 점선은 역할 세션 이름 = 서버 ID라는 기록이 있을 때만
        self.assertEqual(len(g["links"]), 1)
        self.assertTrue(g["links"][0]["src"].startswith("inst:") and g["links"][0]["dst"].startswith("cred:"))
        # 번호는 첫 이벤트 시각 순
        firsts = [e["first"] for e in g["edges"]]
        self.assertEqual(firsts, sorted(firsts))

    def test_net_grouped_not_per_port(self):
        g = G.build([self.incs["INC-002"]])
        net = [e for e in g["edges"] if e["kind"] == "net"]
        self.assertEqual(len(net), 1)
        self.assertGreater(net[0]["n"], 1)

    def test_web_without_target_not_linked_to_server(self):
        g = G.build([self.incs["INC-003"]])
        self.assertEqual([e["kind"] for e in g["edges"]], ["web"])
        self.assertFalse(g["links"])
        web = next(n for n in g["nodes"] if n["col"] == "entry")
        self.assertIn("대상 서버 정보 없음", " ".join(web["lines"]))

    def test_verify_catches_missing_and_unknown(self):
        inc = self.incs["INC-001"]
        g = G.build([inc])
        g["edges"] = g["edges"][1:]
        self.assertFalse(G.verify(g, [inc])["passed"])
        g = G.build([inc])
        g["edges"][0] = dict(g["edges"][0], refs=g["edges"][0]["refs"] + ["없는:1"])
        self.assertIn("없는:1", G.verify(g, [inc])["unknown_refs"])

    def test_figure_html(self):
        html = G.figure([self.incs["INC-001"]])
        self.assertIn("<svg", html)
        self.assertIn("table class=steps", html)
        self.assertIn("근거 이벤트와 다시 대조", html)
        self.assertIn("#INC-001-", html)

    def test_report_contains_figure(self):
        from logsight.report import render
        html = render(self.res)
        self.assertGreaterEqual(html.count("<svg"), len(self.incs))


class CampaignLinking(unittest.TestCase):
    def test_same_server_different_attackers_not_linked(self):
        r = run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        incs = [x["incident"] for x in r["results"]]
        camps = [c for c in r["rule_triage"]["campaigns"] if len(c["incident_ids"]) > 1]
        # INC-001(203.0.113.9)과 INC-002(203.0.113.50)는 같은 서버를 노렸지만 출발지가 달라 묶지 않는다
        self.assertFalse(any({"INC-001", "INC-002"} <= set(c["incident_ids"]) for c in camps), camps)
        self.assertTrue(incs)


if __name__ == "__main__":
    unittest.main()

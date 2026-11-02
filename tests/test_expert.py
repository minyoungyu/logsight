"""비숙련자 카드·숙련자 보고서(expert.py) 단위 테스트. 실행: python -m unittest discover -s tests -v"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.web.expert import _exclusions, _is_blockable, expert_report
from logsight.web.layman import layman_card  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402


def _result(verdict="likely_breached", remediation=None, incidents=None):
    return {
        "overall_verdict": verdict,
        "overall_verdict_ko": "테스트",
        "n_incidents": len(incidents or []),
        "incident_index": [{"start": "2026-01-01T10:00:00", "end": "2026-01-01T10:30:00"}],
        "results": [{"incident": inc, "report": {"remediation": remediation or []}}
                    for inc in (incidents or [])],
    }


def _incident(ips=("198.51.100.9",), shell=True):
    findings = [
        {"rule": "WEBLOG_SQLI", "technique": "T1190", "stage": "initial-access", "title": "SQL 인젝션",
         "detail": "UNION 질의", "key": ips[0], "first": "2026-01-01T10:05:00", "evidence": ["access.log:3"]},
    ]
    if shell:
        findings.append({"rule": "FILE_WEBSHELL", "technique": "T1505.003", "stage": "persistence",
                         "title": "웹셸", "detail": "명령 실행 코드", "key": "/uploads/shell.phtml",
                         "first": "2026-01-01T10:01:00", "evidence": ["shell.phtml:1"]})
    return {"id": "INC-001", "src_ips": list(ips), "findings": findings,
            "events": [{"src_ip": ips[0], "ua": "sqlmap/1.8"}]}


class LaymanCardTests(unittest.TestCase):
    def test_headline_matches_verdict(self):
        for verdict in ("breached", "likely_breached", "suspicious", "no_evidence"):
            card = layman_card(_result(verdict))
            self.assertEqual(card["verdict"], verdict)
            self.assertTrue(card["headline"])

    def test_now_actions_come_first_and_are_deduplicated(self):
        remediation = [
            {"action": "나중 조치", "priority": "later", "detail": "d"},
            {"action": "지금 조치", "priority": "now", "detail": "d"},
            {"action": "지금 조치", "priority": "now", "detail": "d"},
        ]
        card = layman_card(_result(remediation=remediation, incidents=[_incident()]))
        self.assertEqual([a["action"] for a in card["now"]], ["지금 조치", "나중 조치"])
        self.assertEqual(card["now"][0]["priority"], "지금")


class BlockableTests(unittest.TestCase):
    def test_loopback_and_excluded_are_not_blocked(self):
        self.assertFalse(_is_blockable("127.0.0.1", []))
        self.assertFalse(_is_blockable("10.0.0.5", _exclusions({"trusted_ips": ["10.0.0.0/24"]})))
        self.assertFalse(_is_blockable("not-an-ip", []))

    def test_attacker_ip_is_blockable(self):
        self.assertTrue(_is_blockable("198.51.100.9", []))


class ExpertReportTests(unittest.TestCase):
    def test_block_rules_and_iocs(self):
        report = expert_report(_result(incidents=[_incident()]))
        self.assertEqual(report["block_rules"]["nginx"], ["deny 198.51.100.9;"])
        self.assertEqual(report["block_rules"]["iptables"], ["iptables -I INPUT -s 198.51.100.9 -j DROP"])
        self.assertEqual(report["block_rules"]["nginx_path"],
                         ["location = /uploads/shell.phtml { deny all; return 404; }"])
        self.assertEqual(report["iocs"]["user_agents"], ["sqlmap/1.8"])
        self.assertEqual(report["iocs"]["paths"], ["/uploads/shell.phtml"])

    def test_timeline_is_sorted_and_keeps_evidence(self):
        report = expert_report(_result(incidents=[_incident()]))
        times = [t["time"] for t in report["timeline"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual(report["timeline"][0]["rule"], "FILE_WEBSHELL")
        self.assertEqual(report["timeline"][1]["evidence"], ["access.log:3"])

    def test_profile_exclusions_apply(self):
        inc = _incident(ips=("198.51.100.9", "198.51.100.77"))
        profile = {"own_hosts": ["198.51.100.77"], "trusted_ips": [{"cidr": "198.51.100.9/32"}]}
        report = expert_report(_result(incidents=[inc]), profile)
        self.assertEqual(report["block_rules"]["nginx"], [])

    def test_no_shell_means_no_path_rule(self):
        report = expert_report(_result(incidents=[_incident(shell=False)]))
        self.assertNotIn("nginx_path", report["block_rules"])


class AssessIntegrationTests(unittest.TestCase):
    def test_assess_returns_both_views(self):
        profile = SiteProfile.load(ROOT / "samples" / "web" / "profile.json")
        result = assess(profile, use_ai=False)
        self.assertEqual(result["simple"]["verdict"], result["overall_verdict"])
        self.assertEqual(len(result["expert"]["timeline"]), sum(len(r["incident"]["findings"])
                                                               for r in result["results"]))
        for ip in result["expert"]["iocs"]["ips"]:
            self.assertFalse(ip.startswith("127."))


if __name__ == "__main__":
    unittest.main()

"""조치 전 영향 미리보기(사양서 FR-35): 설정 스냅샷과 사건 이벤트로 센 것만 말한다."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.impact_preview import preview  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402
from logsight.report import render  # noqa: E402

ENV = {
    "trusted_ips": [{"cidr": "192.0.2.0/24"}],
    "vpcs": [{"vpc_id": "vpc-1", "cidrs": ["10.0.0.0/16"]}],
    "instances": [
        {"instance_id": "i-web1", "name": "web-1", "security_groups": ["sg-web"], "subnet_id": "subnet-a",
         "iam_role": "app-role", "imds": "optional"},
        {"instance_id": "i-web2", "name": "web-2", "security_groups": ["sg-web"], "subnet_id": "subnet-a",
         "iam_role": "app-role", "imds": "optional"},
        {"instance_id": "i-db", "security_groups": ["sg-db"], "subnet_id": "subnet-b", "iam_role": "db-role",
         "imds": "required"},
    ],
    "network_interfaces": [{"eni_id": "eni-alb", "subnet_id": "subnet-a", "type": "network_load_balancer",
                            "security_groups": ["sg-web"]}],
    "network_acls": [{"nacl_id": "acl-1", "subnet_ids": ["subnet-a"],
                      "entries": [{"rule_number": 100, "egress": False}]}],
}
INC = {"events": [], "src_ips": ["203.0.113.9"]}


class Preview(unittest.TestCase):
    def test_sg_counts_servers_and_other_interfaces(self):  # TC-FIX-IMP-01
        out = preview({"id": "SG_ADMIN_PORT_OPEN", "resource": "sg-web"}, INC, ENV)
        self.assertIn("서버 2대", out[0])
        self.assertIn("web-1(i-web1)", out[0])
        self.assertIn("네트워크 인터페이스 1개", out[0])
        self.assertIn("192.0.2.0/24", out[1])

    def test_sg_without_admin_ip_warns_lockout(self):
        env = {**ENV, "trusted_ips": []}
        out = preview({"id": "SG_ADMIN_PORT_OPEN", "resource": "sg-web"}, INC, env)
        self.assertTrue(any("모든 접속이 끊깁니다" in x for x in out))

    def test_nacl_counts_subnet_servers_and_warns_own_ip(self):
        fix = {"id": "NACL_BLOCK_ATTACKER", "resource": "acl-1", "proposed": {"deny": ["203.0.113.9/32", "192.0.2.7/32"]}}
        out = preview(fix, INC, ENV)
        self.assertIn("서버 2대", out[0])
        self.assertNotIn("i-db", out[0])
        self.assertTrue(any("192.0.2.7" in x and "관리자 IP" in x for x in out))
        self.assertFalse(any("203.0.113.9는" in x for x in out))

    def test_role_revoke_lists_servers_using_role(self):
        out = preview({"id": "IAM_ROLE_SESSION_REVOKE", "resource": "app-role"}, INC, ENV)
        self.assertIn("서버 2대", out[0])

    def test_imds_mentions_other_servers_left_unchanged(self):
        out = preview({"id": "IMDSV1_ENABLED", "resource": "i-web1"}, INC, ENV)
        self.assertTrue(any("i-web2" in x and "바꾸지 않습니다" in x for x in out))

    def test_key_counts_our_own_use(self):
        inc = {"events": [{"access_key": "AKIA1", "src_ip": "203.0.113.9"},
                          {"access_key": "AKIA1", "src_ip": "192.0.2.5"}]}
        out = preview({"id": "IAM_KEY_COMPROMISED", "resource": "dev", "current": {"keys": ["AKIA1"]}}, inc, ENV)
        self.assertIn("IP 2곳에서 2번", out[0])
        self.assertIn("우리 작업", out[0])

    def test_nothing_invented_without_snapshot_or_handler(self):  # TC-FIX-IMP-02
        self.assertEqual(preview({"id": "SG_ADMIN_PORT_OPEN", "resource": "sg-web"}, INC, {}), [])
        self.assertEqual(preview({"id": "WAF_SQLI_COUNT", "resource": "acl"}, INC, ENV), [])
        self.assertEqual(preview({"id": "IAM_ROLE_SESSION_REVOKE", "resource": "없는역할"}, INC, ENV), [])


class InReport(unittest.TestCase):
    def test_combined_report_shows_impact_before_commands(self):  # TC-FIX-IMP-03
        os.environ.pop("ANTHROPIC_API_KEY", None)
        html = render(run_paths([str(ROOT / "samples/combined")], use_ai=False))
        i = html.find("적용하면 함께 바뀌는 것")
        self.assertGreater(i, 0)
        self.assertLess(i, html.find("적용·되돌리기 명령 보기", i))
        self.assertIn("서버 1대(i-0abc123def456)", html)


if __name__ == "__main__":
    unittest.main()

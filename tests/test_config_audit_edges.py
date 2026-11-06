"""설정 점검(environment.json → 원인 설정·수정 명령)의 경계 사례.
실제 계정 스냅샷에서 흔한 모양(포트 범위, IPv6, 서브넷이 여럿, 깨진 파일)에서 틀린 명령을 내지 않는지 본다."""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.pipeline import run_paths  # noqa: E402

COMBINED = ROOT / "samples" / "combined"
BASE = json.loads((COMBINED / "environment.json").read_text(encoding="utf-8"))


def _run(env) -> dict:
    d = Path(tempfile.mkdtemp())
    try:
        for f in COMBINED.iterdir():
            if f.name != "environment.json":
                shutil.copy(f, d)
        if env is not None:
            (d / "environment.json").write_text(env if isinstance(env, str) else json.dumps(env), encoding="utf-8")
        return run_paths([str(d)], use_ai=False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _checks(res, cid=None):
    return [c for r in res["results"] for c in r["checks"] if cid is None or c["id"] == cid]


class ConfigAuditEdges(unittest.TestCase):
    def test_sample_produces_expected_checks(self):
        ids = {c["id"] for c in _checks(_run(BASE))}
        self.assertEqual(ids, {"SG_ADMIN_PORT_OPEN", "WAF_SQLI_COUNT", "IMDSV1_ENABLED",
                               "IAM_OVERBROAD", "NACL_BLOCK_ATTACKER", "IAM_ROLE_SESSION_REVOKE"})
        for c in _checks(_run(BASE)):
            if any(not x.startswith("#") for x in c["cli"]) and c["id"] != "WAF_SQLI_COUNT":
                self.assertTrue(c["rollback"], c["id"])  # 실행 명령이 있으면 되돌리기도 있다

    def test_malformed_json_does_not_crash(self):
        res = _run("{bad json")
        self.assertFalse(_checks(res))
        self.assertFalse(res["has_environment"])
        self.assertTrue(any("JSON으로 읽지 못했습니다" in a for a in res["assumptions"]))

    def test_non_object_json(self):
        res = _run("[1, 2]")
        self.assertTrue(any("최상위가 객체" in a for a in res["assumptions"]))

    def test_missing_ids_are_skipped(self):
        e = copy.deepcopy(BASE)
        del e["security_groups"][0]["group_id"]
        e["security_groups"][0]["ingress"][0]["to_port"] = None
        ids = {c["id"] for c in _checks(_run(e))}
        self.assertNotIn("SG_ADMIN_PORT_OPEN", ids)
        self.assertIn("NACL_BLOCK_ATTACKER", ids)

    def test_port_range_revokes_exact_rule_and_warns(self):
        e = copy.deepcopy(BASE)
        e["security_groups"][0]["ingress"][0].update(from_port=0, to_port=65535)
        c = _checks(_run(e), "SG_ADMIN_PORT_OPEN")[0]
        self.assertIn("FromPort=0,ToPort=65535", c["cli"][0])
        self.assertIn("함께 열고 있어", c["caution"])
        self.assertFalse(_checks(_run(e), "SG_DB_PORT_OPEN"))  # 같은 규칙을 두 번 지우라고 하지 않는다

    def test_ipv6_uses_ip_permissions(self):
        e = copy.deepcopy(BASE)
        e["security_groups"][0]["ingress"][0]["cidr"] = "::/0"
        c = _checks(_run(e), "SG_ADMIN_PORT_OPEN")[0]
        self.assertIn("Ipv6Ranges=[{CidrIpv6=::/0}]", c["cli"][0])
        self.assertNotIn("--cidr ::/0", c["cli"][0])
        self.assertTrue(c["rollback"][-1].startswith("aws ec2 authorize-security-group-ingress"))

    def test_unrelated_security_group_is_not_blamed(self):
        e = copy.deepcopy(BASE)
        e["security_groups"].append({"group_id": "sg-other", "name": "bastion", "ingress": [
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}]})
        self.assertEqual({c["resource"] for c in _checks(_run(e), "SG_ADMIN_PORT_OPEN")},
                         {"sg-0web000000000001"})

    def test_nacl_follows_instance_subnet(self):
        e = copy.deepcopy(BASE)
        e["network_acls"].insert(0, {"nacl_id": "acl-other", "subnet_ids": ["subnet-zzz"], "entries": []})
        e["instances"][0]["subnet_id"] = "subnet-0a1"
        c = _checks(_run(e), "NACL_BLOCK_ATTACKER")[0]
        self.assertEqual(c["resource"], "acl-0default00000001")
        self.assertNotIn("서브넷을 설정에서 찾지 못해", c["caution"])

    def test_nacl_without_subnet_info_warns(self):
        c = _checks(_run(BASE), "NACL_BLOCK_ATTACKER")[0]
        self.assertIn("서브넷을 설정에서 찾지 못해", c["caution"])

    def test_waf_keeps_block_default_action(self):
        e = copy.deepcopy(BASE)
        e["waf_web_acls"][0]["default_action"] = "BLOCK"
        c = _checks(_run(e), "WAF_SQLI_COUNT")[0]
        self.assertIn("--default-action Block={}", c["cli"][2])
        self.assertNotIn("Allow={}", c["cli"][2])

    def test_imds_unknown_is_not_reported_as_optional(self):
        e = copy.deepcopy(BASE)
        del e["instances"][0]["imds"]
        c = _checks(_run(e), "IMDSV1_ENABLED")[0]
        self.assertEqual(c["current"]["HttpTokens"], "확인 안 됨(설정에 없음)")


if __name__ == "__main__":
    unittest.main()

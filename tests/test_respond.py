"""자동 격리(logsight/respond.py) 테스트. AWS는 moto로 흉내 낸다(실제 계정·키 불필요)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import respond as rs  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:
    boto3 = None

REGION = "ap-northeast-2"
ACCT = "123456789012"
ALICE = f"arn:aws:iam::{ACCT}:user/alice"
ATTACKER = f"arn:aws:iam::{ACCT}:user/app"   # 탈취된 기존 키(내부 사용자처럼 보임)
DEPLOY = f"arn:aws:iam::{ACCT}:role/github-deploy"


def rec(name, who=ATTACKER, ip="198.51.100.7", mfa=False, req=None, resp=None, t="2026-11-04T02:00:00Z",
        assumed=False, error=None):
    ui = {"type": "IAMUser", "arn": who, "sessionContext": {"attributes": {"mfaAuthenticated": str(mfa).lower()}}}
    if assumed:
        ui = {"type": "AssumedRole", "arn": who.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/") + "/s",
              "sessionContext": {"sessionIssuer": {"arn": who}, "attributes": {"mfaAuthenticated": "false"}}}
    r = {"eventTime": t, "eventSource": "iam.amazonaws.com", "eventName": name, "sourceIPAddress": ip,
         "awsRegion": REGION, "userIdentity": ui, "requestParameters": req or {}, "responseElements": resp}
    if error:
        r["errorCode"] = error
    return r


def sg_rec(group, port, cidr="0.0.0.0/0", **kw):
    req = {"groupId": group, "ipPermissions": {"items": [
        {"ipProtocol": "tcp", "fromPort": port, "toPort": port, "ipRanges": {"items": [{"cidrIp": cidr}]}}]}}
    return rec("AuthorizeSecurityGroupIngress", req=req, **kw)


class Classify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "baseline.json").write_text(json.dumps({"users": ["app", "alice"], "roles": ["ec2-app-role"],
                                                      "access_keys": ["AKIABASE"], "sg_rules": []}))
        (d / "respond.json").write_text(json.dumps({"admin_principals": [ALICE], "deploy_principals": [DEPLOY],
                                                     "trusted_ips": ["192.0.2.0/24"], "max_per_incident": 3}))
        self.cfg = rs.Config.load(d / "respond.json")

    def tearDown(self):
        self.tmp.cleanup()

    def plan(self, records):
        return rs.Responder(self.cfg).plan(records)

    def test_attacker_with_stolen_internal_key_is_candidate(self):
        p = self.plan([rec("CreateUser", req={"userName": "evil"}),
                       rec("CreateAccessKey", req={"userName": "evil"},
                           resp={"accessKey": {"accessKeyId": "AKIAEVIL", "userName": "evil"}})])
        self.assertEqual([a["op"] for a in p["actions"]], ["deactivate_key", "deny_user"])

    def test_admin_needs_trusted_ip_and_mfa(self):
        ok = rec("CreateUser", who=ALICE, ip="192.0.2.10", mfa=True, req={"userName": "ci-bot"})
        no_mfa = rec("CreateUser", who=ALICE, ip="192.0.2.10", mfa=False, req={"userName": "x1"})
        far = rec("CreateUser", who=ALICE, ip="203.0.113.5", mfa=True, req={"userName": "x2"})
        p = self.plan([ok, no_mfa, far])
        self.assertEqual(sorted(a["id"] for a in p["actions"]), ["x1", "x2"])
        self.assertIn("ci-bot", [i["id"] for i in json.loads(Path(self.cfg.allowlist).read_text(encoding="utf-8"))["items"]])

    def test_deploy_role_is_allowlisted(self):
        p = self.plan([rec("CreateRole", who=DEPLOY, assumed=True, req={"roleName": "new-svc"})])
        self.assertEqual(p["actions"], [])

    def test_baseline_never_touched_and_changes_go_to_human(self):
        p = self.plan([rec("CreateAccessKey", req={"userName": "app"},
                           resp={"accessKey": {"accessKeyId": "AKIABASE", "userName": "app"}}),
                       rec("AttachUserPolicy", req={"userName": "app", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
                       rec("CreateLoginProfile", req={"userName": "app"})])
        self.assertEqual(p["actions"], [])
        self.assertEqual(len(p["human_only"]), 2)

    def test_service_roles_failed_calls_and_limit(self):
        p = self.plan([rec("CreateRole", req={"roleName": "AWSServiceRoleForX", "path": "/aws-service-role/x/"}),
                       rec("CreateUser", req={"userName": "fail"}, error="AccessDenied"),
                       *[rec("CreateUser", req={"userName": f"u{i}"}) for i in range(5)]])
        self.assertEqual(len(p["actions"]), 3)
        self.assertEqual(len(p["held"]), 2)
        self.assertNotIn("fail", [a["id"] for a in p["actions"] + p["held"]])

    def test_dry_run_ack_and_stop(self):
        root = Path(self.tmp.name) / "alerts"
        recs = [rec("CreateUser", req={"userName": "evil"})]
        t0 = datetime(2026, 11, 4, 2, 0, tzinfo=timezone.utc)
        for name in ("a", "b", "c"):
            rs.prepare(rs.Responder(self.cfg), {"id": name}, recs, root / name, now=t0)
        self.assertEqual(rs.tick(self.cfg, root, now=t0 + timedelta(minutes=4)), [])  # 아직 5분 안
        rs.ack(root / "a")
        (Path(self.tmp.name) / "STOP").touch()
        out = {r["alert"]["id"]: r for r in rs.tick(self.cfg, root, now=t0 + timedelta(minutes=6))}
        self.assertEqual(set(out), {"b", "c"})
        self.assertEqual(out["b"]["status"], "stopped")
        os.remove(Path(self.tmp.name) / "STOP")
        rs.prepare(rs.Responder(self.cfg), {"id": "d"}, recs, root / "d", now=t0)
        r = rs.tick(self.cfg, root, now=t0 + timedelta(minutes=6))[0]
        self.assertEqual((r["status"], r["actions"][0]["outcome"]["result"]), ("dry-run", "would-do"))
        self.assertEqual(json.loads((root / "a" / "response.json").read_text(encoding="utf-8"))["status"], "acknowledged")


@unittest.skipIf(boto3 is None, "moto 없음")
class Enforce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                                                "AWS_DEFAULT_REGION": REGION})
        self.env.start()
        self.mock = mock_aws()
        self.mock.start()
        self.s = boto3.Session(region_name=REGION)
        self.iam, self.ec2 = self.s.client("iam"), self.s.client("ec2")

    def tearDown(self):
        self.mock.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_isolate_then_undo(self):
        iam, ec2, d = self.iam, self.ec2, Path(self.tmp.name)
        iam.create_user(UserName="app")
        base_key = iam.create_access_key(UserName="app")["AccessKey"]["AccessKeyId"]
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        rs._save(d / "baseline.json", rs.take_baseline(self.s, REGION))
        # moto에는 AWS 관리형 AWSDenyAll이 없어 같은 내용의 고객 관리형 정책으로 대신한다
        deny = iam.create_policy(PolicyName="DenyAllTest", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"]
        rs._save(d / "respond.json", {"mode": "enforce", "deny_policy_arn": deny})
        cfg = rs.Config.load(d / "respond.json")

        # 기준선 뒤 공격자가 만든 것
        iam.create_user(UserName="evil")
        evil_key = iam.create_access_key(UserName="evil")["AccessKey"]["AccessKeyId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        recs = [rec("CreateUser", req={"userName": "evil"}),
                rec("CreateAccessKey", req={"userName": "evil"},
                    resp={"accessKey": {"accessKeyId": evil_key, "userName": "evil"}}),
                sg_rec(sg, 22), sg_rec(sg, 443)]
        root = d / "alerts"
        t0 = datetime.now(timezone.utc)
        resp = rs.prepare(rs.Responder(cfg), {"id": "x", "region": REGION}, recs, root / "x", now=t0)
        self.assertEqual([a["op"] for a in resp["actions"]], ["deactivate_key", "deny_user", "revoke_ingress"])
        r = rs.tick(cfg, root, iam=iam, ec2=ec2, now=t0 + timedelta(minutes=6))[0]
        self.assertEqual([a["outcome"]["result"] for a in r["actions"]], ["done"] * 3)

        def key_status(user, kid):
            return next(k["Status"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
                        if k["AccessKeyId"] == kid)

        def ports():
            g = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]
            return sorted(p["FromPort"] for p in g["IpPermissions"])

        self.assertEqual(key_status("evil", evil_key), "Inactive")
        self.assertEqual(key_status("app", base_key), "Active")  # 기준선 키는 그대로
        self.assertIn(deny, [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="evil")["AttachedPolicies"]])
        self.assertEqual(ports(), [443])
        self.assertIn("update-access-key", (root / "x" / "undo.sh").read_text(encoding="utf-8"))

        rs.undo(root / "x", iam=iam, ec2=ec2)
        self.assertEqual(key_status("evil", evil_key), "Active")
        self.assertEqual(iam.list_attached_user_policies(UserName="evil")["AttachedPolicies"], [])
        self.assertEqual(ports(), [22, 443])

    def test_alert_handle_prepares_response(self):
        from logsight import alert as al
        d = Path(self.tmp.name)
        rs._save(d / "baseline.json", {"users": [], "roles": [], "access_keys": [], "sg_rules": []})
        rs._save(d / "respond.json", {})
        ev = {"source": "aws.cloudtrail", "detail-type": "AWS API Call via CloudTrail", "id": "e",
              "time": "2026-11-04T02:00:00Z", "account": ACCT, "region": REGION,
              "detail": {**rec("CreateAccessKey", req={"userName": "evil"},
                               resp={"accessKey": {"accessKeyId": "AKIAEVIL", "userName": "evil"}}),
                         "eventID": "e1"}}
        ev["detail"]["eventName"] = "StopLogging"  # 높음 등급으로 만들기 위해 이름만 바꾼 경우는 생성 아님
        opt = al.Options(out=str(d / "alerts"), use_ai=False, respond=str(d / "respond.json"))
        r = al.handle(al.parse_event(ev), opt)
        self.assertEqual(r["response"]["status"], "nothing")
        ev2 = dict(ev, detail=dict(ev["detail"], eventName="CreateAccessKey", eventID="e2"))
        a = al.parse_event(ev2)
        a.severity = "high"
        r = al.handle(a, opt)
        self.assertEqual(r["response"]["status"], "pending")
        self.assertIn("격리합니다", (Path(r["out"]) / "summary.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

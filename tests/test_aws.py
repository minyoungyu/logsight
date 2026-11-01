"""로그 점검·수집(AWS)과 무료 대체 로그 테스트. AWS는 moto로 흉내 내므로 실제 계정·키가 필요 없다."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.costs import estimate  # noqa: E402
from logsight.normalize import detect_kind, parse_hostfw, parse_weblog  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:  # moto가 없으면 AWS 테스트만 건너뜀
    boto3 = None

REGION = "ap-northeast-2"


class FreeAlternativeLogs(unittest.TestCase):
    def test_hostfw_syslog_iso_and_ufw(self):
        text = (
            "Oct 20 03:00:00 web1 kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.1.10 "
            "LEN=44 PROTO=TCP SPT=4000 DPT=3306 SYN\n"
            "2026-10-20T03:00:05+0000 web1 kernel: LOGSIGHT-NEW IN=eth0 OUT= SRC=203.0.113.5 "
            "DST=10.0.1.10 PROTO=TCP SPT=4001 DPT=22 SYN\n"
            "Oct 20 03:00:06 web1 sshd[1]: unrelated line\n")
        ev = parse_hostfw(text)
        self.assertEqual(len(ev), 2)
        self.assertEqual((ev[0].outcome, ev[0].dst_port), ("reject", 3306))
        self.assertEqual((ev[1].outcome, ev[1].dst_port), ("accept", 22))
        self.assertEqual(ev[1].ts, datetime(2026, 10, 20, 3, 0, 5, tzinfo=timezone.utc))
        self.assertEqual(detect_kind("messages", text), "hostfw")

    def test_weblog_combined(self):
        text = ('203.0.113.5 - - [20/Oct/2026:12:00:00 +0900] "GET /a?id=1%27 HTTP/1.1" 500 10 "-" "curl/8"\n'
                'garbage\n')
        ev = parse_weblog(text)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].ts.hour, 3)  # +0900 → UTC
        self.assertEqual(ev[0].outcome, "failure")
        self.assertEqual(detect_kind("x.log", text), "weblog")
        self.assertEqual(detect_kind("access.log", ""), "weblog")

    def test_free_sample_pipeline(self):
        res = run_paths([str(ROOT / "samples" / "free")], use_ai=False)
        rules = {f["rule"] for r in res["results"] for f in r["incident"]["findings"]}
        self.assertTrue({"VPC_PORT_SCAN", "VPC_REMOTE_ADMIN_EXPOSED", "WEB_PATH_PROBE",
                         "WEB_SQLI_PATTERN"} <= rules, rules)
        checks = {c["id"] for r in res["results"] for c in r["checks"]}
        self.assertIn("SG_ADMIN_PORT_OPEN", checks)
        self.assertIn("WEB_NO_WAF", checks)
        # 정상 사용자(198.51.100.x)는 사건에 들어가지 않는다
        ips = {ip for r in res["results"] for ip in r["incident"]["src_ips"]}
        self.assertEqual(ips, {"203.0.113.50"})

    def test_cost_estimate(self):
        r = {x["id"]: x for x in estimate(web_requests_month=2_000_000, waf_rules=2)["rows"]}
        self.assertEqual(r["waf"]["monthly"], 5 + 2 + 1.2)
        self.assertEqual(r["cloudtrail_s3_data"]["monthly"], 0)
        self.assertTrue(all(x["free_alt"] for x in r.values()))

    def test_cost_cli(self):
        from logsight.__main__ import main
        self.assertEqual(main(["cost", "--web-requests", "100"]), 0)


@unittest.skipIf(boto3 is None, "boto3/moto 미설치")
class AwsCheckAndCollect(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": REGION})
        self.env.start()
        self.mock = mock_aws()
        self.mock.start()
        self.s = boto3.Session(region_name=REGION)

    def tearDown(self):
        self.mock.stop()
        self.env.stop()

    def _status(self, res):
        return {i["id"]: i["status"] for i in res["items"]}

    def test_empty_account_reports_missing_logs(self):
        from logsight.aws_check import format_text, run_checks
        res = run_checks(self.s, REGION)
        st = self._status(res)
        self.assertEqual(st["CT_TRAIL"], "missing")
        self.assertEqual(st["VPC_FLOW"], "missing")   # 기본 VPC에 Flow Logs 없음
        self.assertEqual(st["GUARDDUTY"], "missing")
        self.assertEqual(st["WAF_LOGGING"], "info")
        text = format_text(res)
        self.assertIn("서버 방화벽 로그", text)       # 무료 대안 안내
        self.assertIn("--apply CT_TRAIL", text)

    def test_apply_then_check_ok(self):
        from logsight.aws_check import apply, run_checks
        out = apply(["CT_TRAIL", "VPC_FLOW", "GUARDDUTY", "ALB_LOGS"], self.s, REGION)
        ok = {r["id"]: r["ok"] for r in out}
        self.assertEqual(ok, {"CT_TRAIL": True, "VPC_FLOW": True, "GUARDDUTY": True, "ALB_LOGS": False})
        st = self._status(run_checks(self.s, REGION))
        self.assertEqual((st["CT_TRAIL"], st["VPC_FLOW"], st["GUARDDUTY"]), ("ok", "ok", "ok"))
        # 버킷은 비공개로 생성
        s3 = self.s.client("s3", region_name=REGION)
        bucket = [b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith("logsight-logs-")][0]
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        self.assertTrue(all(pab.values()))
        # 두 번 실행해도 안전(멱등)
        self.assertTrue(all(r["ok"] for r in apply(["CT_TRAIL", "VPC_FLOW", "GUARDDUTY"], self.s, REGION)))

    def test_open_ssh_and_imdsv1_flagged(self):
        from logsight.aws_check import run_checks
        ec2 = self.s.client("ec2", region_name=REGION)
        sg = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SecurityGroupIds=[sg],
                          MetadataOptions={"HttpTokens": "optional"})
        st = self._status(run_checks(self.s, REGION))
        self.assertEqual(st["SG_ADMIN_OPEN"], "warn")
        self.assertEqual(st["IMDSV2"], "warn")

    def test_export_environment_feeds_audit(self):
        from logsight.aws_collect import export_environment
        iam = self.s.client("iam")
        iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                    "Principal": {"Service": "ec2.amazonaws.com"}}]}))
        iam.put_role_policy(RoleName="app-role", PolicyName="all", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
        iam.create_instance_profile(InstanceProfileName="app-profile")
        iam.add_role_to_instance_profile(InstanceProfileName="app-profile", RoleName="app-role")
        ec2 = self.s.client("ec2", region_name=REGION)
        sg = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SecurityGroupIds=[sg],
                          IamInstanceProfile={"Name": "app-profile"})
        env = export_environment(self.s, REGION)
        self.assertEqual(env["account_id"], "123456789012")
        inst = env["instances"][0]
        self.assertEqual(inst["iam_role"], "app-role")
        self.assertEqual(inst["security_groups"], [sg])
        web = next(g for g in env["security_groups"] if g["group_id"] == sg)
        self.assertIn({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0",
                       "description": ""}, web["ingress"])
        self.assertEqual(env["iam_roles"][0]["policies"][0]["document"]["Statement"][0]["Action"], "s3:*")
        self.assertTrue(env["network_acls"])
        # 자동 수집한 설정으로 수정안이 실제로 나오는지: 관리 포트 노출 사건에 적용
        from logsight.config_audit import audit
        inc = {"events": [{"ref": "x:1", "src_ip": "203.0.113.9", "rules": ["VPC_REMOTE_ADMIN_EXPOSED"],
                           "instance_id": inst["instance_id"]}],
               "findings": [{"rule": "VPC_REMOTE_ADMIN_EXPOSED", "refs": ["x:1"]}],
               "src_ips": ["203.0.113.9"], "instances": [inst["instance_id"]], "actors": []}
        try:
            checks = audit(inc, env)
        except KeyError as exc:
            self.fail(f"자동 수집 형식이 audit와 안 맞음: {exc}")
        self.assertIn("SG_ADMIN_PORT_OPEN", {c["id"] for c in checks})

    def test_event_history_records(self):
        from logsight import aws_collect
        rec = {"eventTime": "2026-10-20T03:00:00Z", "eventSource": "iam.amazonaws.com",
               "eventName": "CreateUser", "sourceIPAddress": "203.0.113.9",
               "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/dev"}}
        pages = [{"Events": [{"CloudTrailEvent": json.dumps(rec)},
                             {"EventTime": datetime(2026, 10, 20, tzinfo=timezone.utc),
                              "EventName": "ListBuckets", "EventSource": "s3.amazonaws.com",
                              "Username": "dev"}]}]
        client = mock.Mock()
        client.get_paginator.return_value.paginate.return_value = pages
        sess = mock.Mock(region_name=REGION)
        sess.client.return_value = client
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "cloudtrail_history.json"
            n = aws_collect.collect_event_history(out, session=sess, region=REGION, days=200)
            self.assertEqual(n, 2)
            kw = client.get_paginator.return_value.paginate.call_args.kwargs
            self.assertLessEqual((kw["EndTime"] - kw["StartTime"]).days, 90)  # 무료 보관 90일
            res = run_paths([str(out)], use_ai=False)
            self.assertEqual(res["n_events"], 2)
            self.assertEqual(res["events_by_source"], {"cloudtrail": 2})


if __name__ == "__main__":
    unittest.main()

"""실제 AWS 로그(BOTSv3) 측정에서 드러난 결함의 회귀 테스트. 데이터셋 내용은 쓰지 않고 합성 입력만 쓴다.

1. EventBridge로 받은 GuardDuty 결과(키가 camelCase)도 읽는다
2. auth.log의 'Invalid user' 줄도 SSH 실패로 센다(같은 시도의 Failed 줄과 중복 없이)
3. S3 버킷을 공개하는 ACL·정책 변경을 잡는다(CT_S3_PUBLIC)
4. 서버 응답 방향 흐름은 포트 스캔으로 세지 않는다
5. 정상 작업 목록 계정이라도 키 유출 징후가 있으면 '정상'으로 내리지 않는다
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import explain as X  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import (cloudtrail_record_to_event, parse_guardduty,  # noqa: E402
                                parse_sshauth, parse_vpcflow, s3_public)
from tests.test_explain import _cev, _inc  # noqa: E402


class GuardDutyCamelCaseTests(unittest.TestCase):
    def test_eventbridge_detail_is_parsed(self):
        f = {"schemaVersion": "2.0", "accountId": "111122223333", "region": "us-west-2",
             "type": "Recon:EC2/PortProbeUnprotectedPort", "severity": 2, "title": "포트 탐색",
             "createdAt": "2026-10-11T05:00:00.000Z", "updatedAt": "2026-10-11T05:10:00.000Z",
             "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-0example"}},
             "service": {"action": {"actionType": "PORT_PROBE", "portProbeAction": {"portProbeDetails": [
                 {"localPortDetails": {"port": 22},
                  "remoteIpDetails": {"ipAddressV4": "198.51.100.7"}}]}}}}
        evs = parse_guardduty(json.dumps({"detail-type": "GuardDuty Finding", "detail": f}) + "\n")
        self.assertEqual(len(evs), 1)
        self.assertIn("PortProbe", evs[0].action)


class SshInvalidUserTests(unittest.TestCase):
    def test_invalid_user_counts_once(self):
        log = "\n".join([
            "Aug 20 14:54:01 host sshd[101]: Invalid user admin from 198.51.100.9 port 40000",
            "Aug 20 14:54:01 host sshd[101]: Failed password for invalid user admin from 198.51.100.9 port 40000 ssh2",
            "Aug 20 14:54:02 host sshd[102]: Invalid user test from 198.51.100.9 port 40002",
            "Aug 20 14:54:03 host sshd[103]: Accepted publickey for ops from 192.0.2.5 port 50000 ssh2",
        ]) + "\n"
        evs = parse_sshauth(log, year=2026)
        fails = [e for e in evs if e.outcome == "failure"]
        self.assertEqual(len(fails), 2)  # pid 101은 Failed 줄 하나만, pid 102는 Invalid user 줄
        self.assertEqual([e.outcome for e in evs if e.src_ip == "192.0.2.5"], ["success"])


class S3PublicTests(unittest.TestCase):
    def _rec(self, name, params):
        return {"eventTime": "2026-10-11T05:00:00Z", "eventSource": "s3.amazonaws.com", "eventName": name,
                "sourceIPAddress": "198.51.100.20", "awsRegion": "us-west-2",
                "userIdentity": {"type": "IAMUser", "userName": "dev", "arn": "arn:aws:iam::111122223333:user/dev"},
                "requestParameters": params}

    def test_public_acl_and_policy(self):
        grant = {"AccessControlPolicy": {"AccessControlList": {"Grant": [{"Grantee": {
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}}}
        self.assertTrue(s3_public("s3:PutBucketAcl", grant))
        self.assertTrue(s3_public("s3:PutBucketAcl", {"x-amz-acl": ["public-read-write"]}))
        pol = {"bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}
        self.assertTrue(s3_public("s3:PutBucketPolicy", pol))
        self.assertFalse(s3_public("s3:PutBucketAcl", {"x-amz-acl": ["private"]}))

    def test_rule_fires_only_for_public(self):
        pub = cloudtrail_record_to_event(self._rec("PutBucketAcl", {"x-amz-acl": ["public-read"]}), "ct:1")
        priv = cloudtrail_record_to_event(self._rec("PutBucketAcl", {"x-amz-acl": ["private"]}), "ct:2")
        rules = [f.rule for f in run_detections([pub, priv], {})]
        self.assertEqual(rules.count("CT_S3_PUBLIC"), 1)


class VpcReplyTests(unittest.TestCase):
    def _line(self, i, sp, dp, src="198.51.100.30", dst="10.0.0.5"):
        t = 1791700000 + i
        return f"2 111122223333 eni-0example {src} {dst} {sp} {dp} 6 5 400 {t} {t + 60} ACCEPT OK"

    def test_server_replies_are_not_scan(self):
        # 외부 서버(443)가 우리 쪽 임시 포트 20개로 응답한 기록
        reply = "\n".join(self._line(i, 443, 40000 + i) for i in range(20))
        self.assertNotIn("VPC_PORT_SCAN", [f.rule for f in run_detections(parse_vpcflow(reply), {})])
        # 같은 IP가 포트 20개를 두드리면 스캔
        scan = "\n".join(self._line(i, 51000, 20 + i) for i in range(20))
        self.assertIn("VPC_PORT_SCAN", [f.rule for f in run_detections(parse_vpcflow(scan), {})])


class KnownButKeyMisuseTests(unittest.TestCase):
    def test_known_actor_with_denied_burst_is_unclear(self):
        evs = [_cev(i, "CT_ACCESS_DENIED_BURST", status="failure", known="직원") for i in range(3)]
        v = X.verdict_for(_inc(["CT_ACCESS_DENIED_BURST", "CT_IAM_PERSISTENCE"], evs,
                               n_known=3, known_labels=["직원"]))
        self.assertEqual(v["verdict"], "unclear")
        self.assertIn("198.18.0.1", v["reason"])

    def test_known_actor_risky_change_and_scanner_exposure(self):
        evs = [_cev(0, "CT_S3_PUBLIC", known="직원")]
        v = X.verdict_for(_inc(["CT_S3_PUBLIC"], evs, n_known=1, known_labels=["직원"]))
        self.assertEqual(v["verdict"], "risky_not_attack")
        evs = [_cev(0, "VPC_REMOTE_ADMIN_EXPOSED", source="vpcflow", dst_port=22)]
        self.assertEqual(X.verdict_for(_inc(["VPC_REMOTE_ADMIN_EXPOSED"], evs))["verdict"], "risky_not_attack")


if __name__ == "__main__":
    unittest.main()

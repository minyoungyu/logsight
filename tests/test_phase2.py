"""2단계 기능 테스트: GuardDuty 입력, 기간 필터, 반복 사건 묶기, 되돌리기 명령, AI 전송 미리 보기."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.config_audit import rollback  # noqa: E402
from logsight.correlate import group_repeats  # noqa: E402
from logsight.normalize import detect_kind, load_paths, parse_guardduty, parse_when  # noqa: E402
from logsight.pipeline import run, run_paths  # noqa: E402

GD = ROOT / "samples" / "guardduty"


def ct(name, ts, ip="203.0.113.7"):
    return {"eventTime": ts, "eventSource": "iam.amazonaws.com", "eventName": name, "sourceIPAddress": ip,
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev",
                             "accessKeyId": "AKIAIOSFODNN7EXAMPLE"}}


class GuardDutyInput(unittest.TestCase):
    def test_three_formats(self):
        f = json.loads((GD / "guardduty_findings.json").read_text(encoding="utf-8"))["Findings"]
        a = parse_guardduty(json.dumps({"Findings": f}))
        b = parse_guardduty("\n".join(json.dumps(x) for x in f))           # S3 내보내기(JSON Lines)
        c = parse_guardduty(json.dumps({"detail-type": "GuardDuty Finding", "detail": f[0]}))  # EventBridge
        self.assertEqual((len(a), len(b), len(c)), (2, 2, 1))
        e = a[0]
        self.assertEqual((e.src_ip, e.instance_id, e.access_key), ("203.0.113.9", "i-0abc123def456",
                                                                    "ASIAEXAMPLEEXAMPLE01"))
        self.assertIn("CT_INSTANCE_CRED_OUTSIDE", e.extra["gd_alias"])
        self.assertEqual(a[1].dst_port, 22)
        self.assertEqual(detect_kind("findings.json", (GD / "guardduty_findings.json").read_text()), "guardduty")

    def test_findings_become_fixes(self):
        res = run_paths([str(GD)], use_ai=False)
        inc = res["results"][0]["incident"]
        sev = {f["severity"] for f in inc["findings"]}
        self.assertEqual(sev, {"high", "medium"})   # GuardDuty 심각도 8 → high, 5 → medium
        checks = {c["id"] for c in res["results"][0]["checks"]}
        self.assertTrue({"SG_ADMIN_PORT_OPEN", "IMDSV1_ENABLED", "IAM_OVERBROAD"} <= checks, checks)

    def test_links_with_other_logs(self):
        # GuardDuty 결과와 데모 로그(같은 IP·인스턴스)가 한 사건으로 묶인다
        res = run_paths([str(GD / "guardduty_findings.json"), str(ROOT / "samples" / "demo")], use_ai=False)
        srcs = res["results"][0]["incident"]["sources"]
        self.assertIn("guardduty", srcs)
        self.assertGreater(len(srcs), 2)


class TimeFilter(unittest.TestCase):
    def test_since_until_and_path_skip(self):
        with tempfile.TemporaryDirectory() as d:
            for day in ("2017/02/10", "2017/02/12", "2017/02/20"):
                p = Path(d, "AWSLogs", "111122223333", "CloudTrail", "us-west-2", *day.split("/"))
                p.mkdir(parents=True)
                y, m, dd = day.split("/")
                (p / "x_CloudTrail.json").write_text(json.dumps(
                    {"Records": [ct("ListUsers", f"{y}-{m}-{dd}T10:00:00Z")]}))
            ev, stats = load_paths([Path(d)], since=parse_when("2017-02-12"), until=parse_when("2017-02-12", end=True))
            self.assertEqual(len(ev), 1)
            self.assertEqual(sum(1 for s in stats if s.get("skipped")), 2)  # 기간 밖 파일은 읽지 않음

    def test_parse_when(self):
        self.assertEqual(parse_when("2017-02-12", end=True).hour, 23)
        self.assertEqual(parse_when("2017-02-12T10:00:00Z").hour, 10)
        self.assertIsNone(parse_when(None))


class Grouping(unittest.TestCase):
    def test_repeats_fold_into_one(self):
        recs = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for day in range(5):  # 같은 IP가 매일 같은 권한 변경 시도
            t = base + timedelta(days=day)
            recs += [ct("CreateUser", t.isoformat().replace("+00:00", "Z")),
                     ct("CreateAccessKey", (t + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"))]
        from logsight.normalize import parse_cloudtrail
        res = run(parse_cloudtrail(json.dumps({"Records": recs})), use_ai=False)
        self.assertEqual(res["n_incidents"], 5)
        self.assertEqual(res["n_groups"], 1)
        self.assertEqual(res["incident_index"][0]["repeats"], 5)

    def test_group_keeps_distinct_actors(self):
        a = {"id": "INC-001", "score": 300, "start": "1", "end": "2", "src_ips": ["203.0.113.1"],
             "instances": [], "actors": [], "findings": [{"rule": "X"}]}
        b = dict(a, id="INC-002", src_ips=["203.0.113.2"])
        self.assertEqual(len(group_repeats([a, b])), 2)


class Rollback(unittest.TestCase):
    def test_inverse_commands(self):
        cli = ["aws ec2 revoke-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0",
               "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 192.0.2.10/32",
               "# 메모"]
        self.assertEqual(rollback(cli), [
            "aws ec2 revoke-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 192.0.2.10/32",
            "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0"])
        self.assertEqual(rollback(["aws ec2 create-network-acl-entry --network-acl-id acl-1 --ingress "
                                   "--rule-number 50 --protocol -1 --rule-action deny --cidr-block 203.0.113.9/32"]),
                         ["aws ec2 delete-network-acl-entry --network-acl-id acl-1 --ingress --rule-number 50"])

    def test_demo_checks_have_rollback(self):
        res = run_paths([str(ROOT / "samples" / "demo")], use_ai=False)
        for c in res["results"][0]["checks"]:
            self.assertTrue(c["rollback"], c["id"])


class DryRun(unittest.TestCase):
    def test_payload_saved_and_masked(self):
        from logsight.__main__ import main
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["analyze", str(ROOT / "samples" / "demo"), "--out", d, "--dry-run"]), 0)
            payload = json.loads(Path(d, "ai_payload.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["incidents"] and payload["system"])
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(payload))
            rep = json.loads(Path(d, "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["results"][0]["meta"]["mode"], "rules")  # Claude 호출 안 함


if __name__ == "__main__":
    unittest.main()

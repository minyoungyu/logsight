"""경보 연동(logsight/alert.py) 테스트. AWS는 moto로 흉내 내므로 실제 계정·키가 필요 없다."""
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

from logsight import alert as al  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:
    boto3 = None

GD_EVENT = json.loads((ROOT / "samples/alerts/guardduty_event.json").read_text(encoding="utf-8"))
REGION = "ap-northeast-2"


def cw_event(state="ALARM", name="web-5xx-rate"):
    return {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change", "id": "e1",
            "time": "2026-11-04T01:00:00Z", "account": "111122223333", "region": REGION,
            "detail": {"alarmName": name, "state": {"value": state, "timestamp": "2026-11-04T01:00:00Z"},
                       "previousState": {"value": "OK", "timestamp": "2026-11-04T00:40:00Z"}}}


def ct_event(name="StopLogging"):
    return {"source": "aws.cloudtrail", "detail-type": "AWS API Call via CloudTrail", "id": "e2",
            "time": "2026-11-04T02:00:00Z", "account": "111122223333", "region": REGION,
            "detail": {"eventVersion": "1.08", "eventTime": "2026-11-04T02:00:00Z",
                       "eventSource": "cloudtrail.amazonaws.com", "eventName": name, "eventID": "abc",
                       "sourceIPAddress": "198.51.100.7", "awsRegion": REGION,
                       "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev",
                                        "accessKeyId": "AKIAEXAMPLE"}}}


class Parse(unittest.TestCase):
    def test_guardduty(self):
        a = al.parse_event(GD_EVENT)
        self.assertEqual((a.source, a.severity), ("guardduty", "high"))
        self.assertEqual(a.first_seen, datetime(2026, 1, 13, 4, 30, tzinfo=timezone.utc))
        self.assertTrue(a.id.startswith("gd-a1b2"))

    def test_guardduty_severity_bands(self):
        self.assertEqual([al.gd_severity(x) for x in (2, 4, 6.9, 7, 9.5)], ["low", "medium", "medium", "high", "high"])

    def test_cloudwatch_only_alarm_state(self):
        self.assertEqual(al.parse_event(cw_event()).severity, "medium")
        self.assertEqual(al.parse_event(cw_event(name="db-critical")).severity, "high")
        self.assertIsNone(al.parse_event(cw_event(state="OK")))

    def test_cloudtrail_api(self):
        self.assertEqual(al.parse_event(ct_event()).severity, "high")
        self.assertEqual(al.parse_event(ct_event("CreateAccessKey")).severity, "medium")
        self.assertEqual(al.parse_event(ct_event("DescribeInstances")).severity, "low")

    def test_sns_wrapped(self):
        body = json.dumps({"Type": "Notification", "Message": json.dumps(GD_EVENT)})
        self.assertEqual(al.parse_event(al.unwrap(body)).source, "guardduty")

    def test_not_json(self):
        self.assertIsNone(al.unwrap("hello"))


class Handle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "alerts"

    def tearDown(self):
        self.tmp.cleanup()

    def opt(self, **kw):
        return al.Options(logs=[str(ROOT / "samples/demo")], out=str(self.out), use_ai=False, **kw)

    def test_report_from_guardduty_alert(self):
        r = al.handle(al.parse_event(GD_EVENT), self.opt())
        self.assertEqual(r["status"], "done")
        d = Path(r["out"])
        for f in ("report.html", "report.json", "summary.txt", "run.json", "alert.json"):
            self.assertTrue((d / f).is_file(), f)
        rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(rep["events_by_source"].get("guardduty"), 1)  # 경보 자체도 분석 입력
        self.assertGreaterEqual(rep["n_incidents"], 1)
        self.assertIn("[LogFinder] 높음 경보", (d / "summary.txt").read_text(encoding="utf-8"))

    def test_low_severity_skipped(self):
        r = al.handle(al.parse_event(ct_event("DescribeInstances")), self.opt())
        self.assertEqual(r["status"], "skipped")
        self.assertFalse(self.out.exists() and any(self.out.glob("*_cloudtrail_*")))

    def test_cooldown_dedupe(self):
        a = al.parse_event(GD_EVENT)
        self.assertEqual(al.handle(a, self.opt())["status"], "done")
        self.assertEqual(al.handle(a, self.opt())["status"], "skipped")
        later = lambda: datetime.now(timezone.utc) + timedelta(minutes=61)  # noqa: E731
        self.assertEqual(al.handle(a, self.opt(), now=later)["status"], "done")

    def test_window_excludes_old_logs(self):
        # 경보가 2026-11 이고 24시간 앞부터 보므로, 2026-01 의 샘플 로그는 들어가지 않는다
        r = al.handle(al.parse_event(ct_event()), self.opt())
        rep = json.loads((Path(r["out"]) / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(rep["events_by_source"], {"cloudtrail": 1})

    def test_notify_cmd_gets_summary(self):
        marker = Path(self.tmp.name) / "notified.txt"
        script = Path(self.tmp.name) / "n.py"
        script.write_text("import os,shutil;shutil.copy(os.environ['LOGSIGHT_SUMMARY'], r'%s')" % marker)
        r = al.handle(al.parse_event(GD_EVENT), self.opt(notify_cmd=f'"{sys.executable}" "{script}"'))
        self.assertEqual(r["notify"]["returncode"], 0, r["notify"])
        self.assertIn("보고서:", marker.read_text(encoding="utf-8"))

    def test_failure_keeps_message(self):
        with mock.patch.object(al, "handle", side_effect=RuntimeError("boom")):
            self.assertIsNone(al.process_message(json.dumps(GD_EVENT), self.opt(), log=lambda s: None))


@unittest.skipIf(boto3 is None, "moto 없음")
class WithAws(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "alerts"
        self.env = mock.patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                                                "AWS_DEFAULT_REGION": REGION})
        self.env.start()
        self.mock = mock_aws()
        self.mock.start()

    def tearDown(self):
        self.mock.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_fetch_s3_by_date_prefix(self):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="logsight-test-logs", CreateBucketConfiguration={"LocationConstraint": REGION})
        today = datetime.now(timezone.utc)
        key = f"AWSLogs/111122223333/CloudTrail/{REGION}/{today:%Y/%m/%d}/x.json"
        s3.put_object(Bucket="logsight-test-logs", Key=key, Body=b'{"Records":[]}')
        s3.put_object(Bucket="logsight-test-logs", Key=f"AWSLogs/111122223333/CloudTrail/{REGION}/2020/01/01/old.json", Body=b"{}")
        r = al.fetch_s3(f"s3://logsight-test-logs/AWSLogs/111122223333/CloudTrail/{REGION}/{{date}}/",
                        today - timedelta(hours=2), today, Path(self.tmp.name) / "dl", s3=s3)
        self.assertEqual(r["objects"], 1)
        self.assertTrue((Path(self.tmp.name) / "dl" / "logsight-test-logs" / key).is_file())

    def test_watch_sqs_end_to_end(self):
        sqs = boto3.client("sqs", region_name=REGION)
        q = sqs.create_queue(QueueName="logsight-alerts")["QueueUrl"]
        sqs.send_message(QueueUrl=q, MessageBody=json.dumps(GD_EVENT))
        sqs.send_message(QueueUrl=q, MessageBody=json.dumps(cw_event(state="OK")))  # 경보 아님 → 지움
        opt = al.Options(logs=[str(ROOT / "samples/demo")], out=str(self.out), use_ai=False)
        done = al.watch(q, opt, sqs=sqs, once=True, wait_s=0, log=lambda s: None)
        self.assertEqual(sorted(d["status"] for d in done), ["done", "skipped"])
        left = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["ApproximateNumberOfMessages",
                                                                    "ApproximateNumberOfMessagesNotVisible"])
        self.assertEqual(sum(int(v) for v in left["Attributes"].values()), 0)
        self.assertEqual(len(list(self.out.glob("*_guardduty_*/report.html"))), 1)

    def test_heartbeat_stale_host_raises_alert(self):
        from logsight.heartbeat import check
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="logsight-test-archive", CreateBucketConfiguration={"LocationConstraint": REGION})
        now = datetime.now(timezone.utc)
        s3.put_object(Bucket="logsight-test-archive", Key=f"heartbeat/web1/{now:%Y/%m/%d}/a.txt", Body=b"hb")
        s3.put_object(Bucket="logsight-test-archive", Key="heartbeat/web2/2020/01/01/a.txt", Body=b"hb")
        uri = "s3://logsight-test-archive/heartbeat/"
        rows = {r["host"]: r for r in check(uri, s3=s3)}
        self.assertTrue(rows["web1"]["ok"])
        self.assertFalse(rows["web2"]["ok"])
        self.assertIsNone(rows["web2"]["last"])
        self.assertFalse(check(uri, s3=s3, now=now + timedelta(minutes=10))[0]["ok"])  # 10분 신호 없음 → 끊김

        sqs = boto3.client("sqs", region_name=REGION)
        q = sqs.create_queue(QueueName="logsight-alerts")["QueueUrl"]
        opt = al.Options(logs=[str(ROOT / "samples/demo")], out=str(self.out), use_ai=False, heartbeat=uri)
        done = al.watch(q, opt, sqs=sqs, s3=s3, once=True, wait_s=0, log=lambda s: None)
        self.assertEqual([(d["status"], d["alert"]["source"]) for d in done], [("done", "heartbeat")])
        self.assertIn("web2", (Path(done[0]["out"]) / "summary.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

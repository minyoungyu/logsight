"""고객 설치 링크(logsight/onboard.py)와 다계정 접두어 채우기 테스트."""
from __future__ import annotations

import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import alert as al  # noqa: E402
from logsight import onboard as ob  # noqa: E402

ARGS = dict(template_url="https://t.s3.ap-northeast-2.amazonaws.com/v1/logsight-onboard.yaml",
            bus_arn="arn:aws:events:ap-northeast-2:111122223333:event-bus/logsight-intake",
            archive_bucket="logsight-archive-111122223333-ap-northeast-2",
            principal_arn="arn:aws:iam::111122223333:role/logsight-server")


def params(url: str) -> dict:
    frag = urlsplit(url).fragment
    return {k: v[0] for k, v in parse_qs(frag.split("?", 1)[1], keep_blank_values=True).items()}


def template_params() -> set[str]:
    text = (ROOT / "deploy/aws/logsight-onboard.yaml").read_text(encoding="utf-8")
    block = text.split("\nParameters:\n", 1)[1].split("\nConditions:\n", 1)[0]
    return set(re.findall(r"^  (\w+):$", block, re.M))


class Onboard(unittest.TestCase):
    def test_links_fill_every_template_parameter(self):
        r = ob.make(**ARGS, vpc_id="vpc-0abc12345", isolation=True)
        full, iam = r["links"]
        p = params(full["url"])
        self.assertEqual({k[6:] for k in p if k.startswith("param_")}, template_params())
        self.assertEqual(p["param_EnableAutoIsolation"], "true")
        self.assertEqual(p["param_ExternalId"], r["external_id"])
        self.assertTrue(full["url"].startswith("https://ap-northeast-2.console.aws.amazon.com/"))
        q = params(iam["url"])
        self.assertEqual((iam["region"], q["param_Part"]), ("us-east-1", "alerts-only"))
        self.assertEqual(q["param_ExternalId"], r["external_id"])

    def test_external_id_is_new_each_time(self):
        self.assertNotEqual(ob.make(**ARGS)["external_id"], ob.make(**ARGS)["external_id"])

    def test_us_east_1_customer_gets_one_link(self):
        self.assertEqual(len(ob.make(**ARGS, region="us-east-1")["links"]), 1)

    def test_rejects_bad_values(self):
        for k, v in [("bus_arn", "arn:aws:sqs:x"), ("principal_arn", "arn:aws:iam::1:user/a"),
                     ("template_url", "http://evil.example.com/a.yaml"), ("archive_bucket", "A")]:
            with self.assertRaises(ValueError, msg=k):
                ob.make(**{**ARGS, k: v})


class FillPrefix(unittest.TestCase):
    def a(self, account="444455556666", region="ap-northeast-2"):
        t = datetime(2026, 11, 4, tzinfo=timezone.utc)
        return al.Alert(id="x", source="guardduty", severity="high", title="t", time=t, first_seen=t,
                        account=account, region=region)

    def test_fills_account_and_region(self):
        u = "s3://b/AWSLogs/{account}/CloudTrail/{region}/{date}/"
        self.assertEqual(al.fill_prefix(u, self.a()), "s3://b/AWSLogs/444455556666/CloudTrail/ap-northeast-2/{date}/")

    def test_missing_or_odd_account_is_refused(self):
        for acct in ("", "../other", "12345"):
            with self.assertRaises(ValueError):
                al.fill_prefix("s3://b/AWSLogs/{account}/", self.a(account=acct))

    def test_plain_prefix_unchanged(self):
        self.assertEqual(al.fill_prefix("s3://b/x/{date}/", self.a(account="")), "s3://b/x/{date}/")


if __name__ == "__main__":
    unittest.main()

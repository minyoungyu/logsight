"""LogSight 단위·통합 테스트.  실행: python -m unittest discover -s tests -v"""
from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEMO = ROOT / "samples" / "demo"

from logsight import analyze as an  # noqa: E402
from logsight.normalize import (detect_kind, load_paths, mask_text, parse_cloudtrail,  # noqa: E402
                                parse_vpcflow, parse_waf)
from logsight.pipeline import run, run_paths  # noqa: E402
from logsight.report import render  # noqa: E402


def ct(name, src="s3.amazonaws.com", ip="192.0.2.10", ts="2026-10-14T10:00:00Z", **kw):
    r = {"eventTime": ts, "eventSource": src, "eventName": name, "sourceIPAddress": ip,
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev",
                          "accessKeyId": "AKIAIOSFODNN7EXAMPLE"}}
    r.update(kw)
    return r


class ParserTests(unittest.TestCase):
    def test_cloudtrail_records_and_instance_id(self):
        evs = parse_cloudtrail((DEMO / "cloudtrail.json").read_text(encoding="utf-8"), "ct")
        self.assertEqual(len(evs), 3)
        self.assertEqual(evs[0].instance_id, "i-0abc123def456")
        self.assertEqual(evs[2].outcome, "failure")
        self.assertEqual(evs[0].raw_ref, "ct:1")

    def test_cloudtrail_jsonlines_and_bad_records(self):
        text = "\n".join([json.dumps(ct("ListBuckets")), "not json",
                          json.dumps({"eventTime": "bad"}), json.dumps({"Records": [ct("GetObject")]})])
        evs = parse_cloudtrail(text)
        self.assertEqual([e.action for e in evs], ["s3:ListBuckets", "s3:GetObject"])

    def test_cloudtrail_root_identity(self):
        r = ct("ConsoleLogin", src="signin.amazonaws.com")
        r["userIdentity"] = {"type": "Root", "accountId": "111122223333"}
        e = parse_cloudtrail(json.dumps({"Records": [r]}))[0]
        self.assertEqual(e.actor, "arn:aws:iam::111122223333:root")

    def test_vpcflow_skips_nodata_and_header(self):
        text = ("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets "
                "bytes start end action log-status\n"
                "2 111122223333 eni-1 - - - - - - - 1768278000 1768278060 - NODATA\n"
                "2 111122223333 eni-1 198.51.100.7 10.0.1.10 5000 443 6 3 120 1768278000 1768278060 ACCEPT OK\n")
        evs = parse_vpcflow(text)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].dst_port, 443)
        self.assertEqual(evs[0].raw_ref, "vpcflow:3")

    def test_waf_counted_rules(self):
        rec = {"timestamp": 1768278000000, "action": "ALLOW", "terminatingRuleId": "Default_Action",
               "ruleGroupList": [{"ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
                                  "nonTerminatingMatchingRules": [{"ruleId": "SQLi_QUERYARGUMENTS",
                                                                   "action": "COUNT"}]}],
               "httpRequest": {"clientIp": "203.0.113.9", "uri": "/search", "args": "q=1",
                               "httpMethod": "GET", "headers": [{"name": "User-Agent", "value": "x"}]}}
        e = parse_waf(json.dumps(rec) + "\n{broken")[0]
        self.assertEqual(e.outcome, "allow")
        self.assertIn("SQLi_QUERYARGUMENTS", e.extra["counted_rules"])

    def test_detect_kind(self):
        self.assertEqual(detect_kind("x.json", '{"Records":[{"eventTime":1}]}'), "cloudtrail")
        self.assertEqual(detect_kind("a.log", "Jan  1 00:00:00 h sshd[1]: Failed password"), "sshauth")
        self.assertEqual(detect_kind("data.txt", "2 1 eni-1 a b 1 2 6 1 1 1 1 ACCEPT OK"), "vpcflow")

    def test_gzip_and_folder_loading(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "flaws_cloudtrail00.json.gz"
            p.write_bytes(gzip.compress(json.dumps({"Records": [ct("ListBuckets")] * 3}).encode()))
            (Path(d) / "notes.txt").write_text("hello", encoding="utf-8")
            evs, stats = load_paths([Path(d)])
            self.assertEqual(len(evs), 3)
            self.assertTrue(any(s.get("error") for s in stats))


class WindowsFileTests(unittest.TestCase):
    """Windows 메모장 저장 파일(BOM + CRLF)도 읽히는지."""

    def test_bom_crlf_files(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("cloudtrail.json", "auth.log", "vpcflow.log", "environment.json"):
                raw = (DEMO / name).read_text(encoding="utf-8").replace("\n", "\r\n")
                (Path(d) / name).write_bytes(b"\xef\xbb\xbf" + raw.encode("utf-8"))
            res = run_paths([d], use_ai=False)
            self.assertEqual(res["events_by_source"],
                             {"cloudtrail": 3, "sshauth": 3, "vpcflow": 3})
            self.assertTrue(res["has_environment"])
            self.assertTrue(res["results"][0]["checks"])


class MaskTests(unittest.TestCase):
    def test_masks_keys_and_secrets(self):
        s = mask_text("key AKIAIOSFODNN7EXAMPLE password=hunter2 token: abc")
        self.assertNotIn("IOSFODNN", s)
        self.assertIn("AKIAIOSF********", s)  # 앞 8자는 남아 구분 가능
        self.assertNotIn("hunter2", s)
        self.assertNotIn("abc", s)

    def test_pipeline_masks_access_key(self):
        evs = parse_cloudtrail(json.dumps({"Records": [ct("ListBuckets")]}))
        res = run(evs, use_ai=False)
        self.assertNotIn("IOSFODNN7", json.dumps(res))


class DemoPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        cls.res = run_paths([str(DEMO)])

    def test_one_incident_links_all_sources(self):
        self.assertEqual(self.res["n_incidents"], 1)
        inc = self.res["results"][0]["incident"]
        self.assertEqual(set(inc["sources"]), {"vpcflow", "sshauth", "cloudtrail", "alb"})
        self.assertIn("203.0.113.9", inc["src_ips"])

    def test_expected_rules_and_checks(self):
        r = self.res["results"][0]
        rules = {f["rule"] for f in r["incident"]["findings"]}
        self.assertTrue({"CT_INSTANCE_CRED_OUTSIDE", "SSH_SUCCESS_AFTER_FAIL",
                         "WEB_SQLI_PATTERN"} <= rules)
        checks = {c["id"] for c in r["checks"]}
        self.assertTrue({"SG_ADMIN_PORT_OPEN", "IMDSV1_ENABLED", "IAM_OVERBROAD"} <= checks)
        self.assertTrue(r["meta"]["validation"]["passed"])

    def test_report_renders(self):
        html = render(self.res)
        self.assertIn("INC-001", html)
        self.assertIn("aws ec2 revoke-security-group-ingress", html)

    def test_no_env_still_works(self):
        evs, _ = load_paths([DEMO / "cloudtrail.json", DEMO / "auth.log"])
        res = run(evs, {}, use_ai=False)
        self.assertGreaterEqual(res["n_incidents"], 1)
        self.assertEqual(res["results"][0]["checks"], [])


class DetectionTests(unittest.TestCase):
    def _run(self, recs):
        return run(parse_cloudtrail(json.dumps({"Records": recs})), use_ai=False)

    def test_benign_activity_has_no_incident(self):
        recs = [ct("GetObject", ts=f"2026-10-14T10:{m:02d}:00Z") for m in range(30)]
        self.assertEqual(self._run(recs)["n_incidents"], 0)

    def test_logging_tamper_is_high(self):
        recs = [ct("StopLogging", src="cloudtrail.amazonaws.com"),
                ct("DeleteTrail", src="cloudtrail.amazonaws.com", ts="2026-10-14T10:01:00Z")]
        res = self._run(recs)
        self.assertEqual(res["results"][0]["incident"]["severity"], "high")

    def test_access_denied_burst(self):
        recs = [ct(n, src="iam.amazonaws.com", ts=f"2026-10-14T10:00:{i:02d}Z", errorCode="AccessDenied")
                for i, n in enumerate(["ListUsers", "ListRoles", "GetUser", "ListPolicies", "ListGroups"])]
        rules = {f["rule"] for r in self._run(recs)["results"] for f in r["incident"]["findings"]}
        self.assertIn("CT_ACCESS_DENIED_BURST", rules)

    def test_failed_run_instances_is_not_hijack(self):
        recs = [ct("RunInstances", src="ec2.amazonaws.com", ts=f"2026-10-14T10:00:{i:02d}Z",
                   errorCode="Client.UnauthorizedOperation") for i in range(10)]
        rules = {f["rule"] for r in self._run(recs)["results"] for f in r["incident"]["findings"]}
        self.assertNotIn("CT_RUN_INSTANCES_BURST", rules)
        self.assertIn("CT_ACCESS_DENIED_BURST", rules)

    def test_service_principal_ip_is_ignored(self):
        recs = [ct(n, src="iam.amazonaws.com", ip="ec2.amazonaws.com", errorCode="AccessDenied",
                   ts=f"2026-10-14T10:00:{i:02d}Z") for i, n in enumerate(["A", "B", "C", "D", "E", "F"])]
        self.assertEqual(self._run(recs)["n_incidents"], 0)


class ScaleTests(unittest.TestCase):
    def test_bursts_linear_matches_naive(self):
        from datetime import datetime, timedelta, timezone
        from logsight.detect import _bursts
        from logsight.normalize import Event
        t = datetime(2026, 1, 1, tzinfo=timezone.utc)
        evs = [Event(ts=t + timedelta(seconds=37 * i), source="cloudtrail", action=f"a{i % 7}",
                     raw_ref=f"x:{i}") for i in range(400)]
        evs += [Event(ts=t + timedelta(hours=5, seconds=i), source="cloudtrail", action="a1",
                      raw_ref=f"y:{i}") for i in range(50)]
        segs = _bursts(evs, timedelta(minutes=10), 5)
        self.assertEqual(len(segs), 1)                 # 5시간 뒤 단일 API 반복은 해당 없음
        self.assertEqual(len(segs[0]), 400)

    def test_long_activity_is_split(self):
        recs = [ct(n, src="iam.amazonaws.com", ip="203.0.113.50", errorCode="AccessDenied",
                   ts=f"2026-10-14T{h:02d}:{m:02d}:00Z")
                for h in range(10, 16) for m in range(0, 60, 2)
                for n in ("ListUsers", "ListRoles", "GetUser", "ListPolicies", "ListGroups")]
        res = run(parse_cloudtrail(json.dumps({"Records": recs})), use_ai=False, top=10)
        self.assertGreaterEqual(res["n_incidents"], 3)  # 6시간 활동 → 2시간 단위로 나뉨
        for r in res["results"]:
            f = r["incident"]["findings"][0]
            self.assertLessEqual(f["n_events"], r["incident"]["n_events"])


class ClaudePathTests(unittest.TestCase):
    """실제 API를 부르지 않고, 응답 처리·근거 검증 코드를 검사한다."""

    def _fake_client(self, payload: dict, stop="end_turn"):
        block = mock.Mock(type="text", text=json.dumps(payload, ensure_ascii=False))
        resp = mock.Mock(content=[block], stop_reason=stop, stop_details=None,
                         usage=mock.Mock(input_tokens=1200, output_tokens=400))
        client = mock.Mock()
        client.messages.create.return_value = resp
        return client

    def setUp(self):
        res = run_paths([str(DEMO)], use_ai=False)
        self.r = res["results"][0]

    def test_claude_response_is_validated(self):
        good = an.rule_based(self.r["incident"], self.r["checks"])
        good["attack_flow"][0]["evidence"].append("cloudtrail.json:999")  # 없는 근거(환각)
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}), \
                mock.patch("anthropic.Anthropic", return_value=self._fake_client(good)) as ctor:
            out = an.analyze(self.r["incident"], self.r["checks"])
        kwargs = ctor.return_value.messages.create.call_args.kwargs
        self.assertEqual(kwargs["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(out["meta"]["mode"], "claude")
        self.assertEqual(out["meta"]["validation"]["evidence_invalid"], 1)
        self.assertFalse(out["meta"]["validation"]["passed"])
        self.assertIn("cloudtrail.json:999", out["report"]["attack_flow"][0]["unverified_evidence"])

    def test_refusal_falls_back_to_rules(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}), \
                mock.patch("anthropic.Anthropic", return_value=self._fake_client({}, stop="refusal")):
            out = an.analyze(self.r["incident"], self.r["checks"])
        self.assertEqual(out["meta"]["mode"], "rules")
        self.assertIn("거절", out["meta"]["ai_error"])

    def test_schema_has_no_unsupported_constraints(self):
        def walk(o):
            if isinstance(o, dict):
                if o.get("type") == "object":
                    self.assertIs(o.get("additionalProperties"), False)
                    self.assertEqual(set(o["required"]), set(o["properties"]))
                for bad in ("minLength", "maxLength", "minimum", "maximum", "minItems"):
                    self.assertNotIn(bad, o)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(an.REPORT_SCHEMA)


class InterfaceTests(unittest.TestCase):
    def test_cli(self):
        from logsight.__main__ import main
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["analyze", str(DEMO), "--out", d, "--no-ai"]), 0)
            self.assertTrue((Path(d) / "report.html").is_file())
        self.assertEqual(main(["analyze", "no/such/path"]), 2)

    def test_web_app(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest("fastapi/httpx 없음")
        sys.path.insert(0, str(ROOT))
        import app as webapp
        c = TestClient(webapp.app)
        self.assertEqual(c.get("/").status_code, 200)
        self.assertIn("INC-001", c.get("/demo").text)
        files = [("cloudtrail", ("cloudtrail.json", (DEMO / "cloudtrail.json").read_bytes())),
                 ("sshauth", ("auth.log", (DEMO / "auth.log").read_bytes())),
                 ("environment", ("environment.json", (DEMO / "environment.json").read_bytes()))]
        r = c.post("/analyze", files=files, data={"no_ai": "1"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("IMDSv1", r.text)


if __name__ == "__main__":
    unittest.main()

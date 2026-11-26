"""보고서 이해(사양서 v2.1 FR-23~33, NFR-22~25, FR-21). 체크리스트 TC-UX-*, TC-IN-07, TC-NFR-17~20, TC-AUD-*.

모의 사용자 시험(docs/사용자평가/모의시험_2026-11-21.md)에서 막힌 곳을 뒤집은 기대값이다.
입력은 저장소 샘플(samples/combined, samples/web)과 합성 줄, 규칙 모드(AI 없음).
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import PRODUCT_NAME, aisend, briefing as bf  # noqa: E402
from logsight import outcome as oc  # noqa: E402
from logsight.normalize import detect_kind, parse_cloudtrail_csv  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402
from logsight.report import render  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402
from logsight.web.webreport import render as render_web  # noqa: E402

PLACEHOLDERS = ("(서버)", "(웹 애플리케이션)", "(웹 서버)", "표시된 파일", "해당 계정", "해당 파라미터")


@lru_cache(maxsize=1)
def combined() -> dict:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    return run_paths([str(ROOT / "samples/combined")], use_ai=False)


@lru_cache(maxsize=1)
def web() -> dict:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    return assess(SiteProfile.load(str(ROOT / "samples/web/profile.json")), use_ai=False)


def text(html: str) -> str:
    html = re.sub(r"<(style|svg)\b.*?</\1>", " ", html, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def by_id(result: dict, iid: str) -> dict:
    return next(r for r in result["results"] if r["incident"]["id"] == iid)


class ConclusionTests(unittest.TestCase):
    def test_headline_names_key_leak_and_s3_read(self):  # TC-UX-01
        hl = bf.headline(combined())
        s = hl["sentence"]
        self.assertTrue(s.startswith("공격이 있었습니다"), s)
        self.assertIn("ec2-app-role 역할 키가 서버 밖", s)
        self.assertIn("s3:GetObject", s)

    def test_blocked_single_attempt_counted_apart(self):  # TC-UX-02
        hl = bf.headline(combined())
        self.assertEqual((hl["n_check"], hl["n_blocked"], hl["blocked_ids"]), (2, 1, ["INC-003"]))
        t = text(render(combined()))
        self.assertIn("막힌 단발 시도", t)

    def test_conclusion_comes_before_metadata(self):  # NFR-22 (HTML 순서. 화면 크기는 scripts/first_screen_check.py)
        for html in (render(combined()), render_web(web())):
            self.assertLess(html.index("id=conclusion"), html.index("class=metaline"))


class ActionTests(unittest.TestCase):
    def test_three_ordered_concrete_actions(self):  # TC-UX-03
        first, rest = bf.actions(combined())
        self.assertLessEqual(len(first), 3)
        self.assertEqual(first[0]["id"], "IAM_ROLE_SESSION_REVOKE")
        self.assertEqual([x["phase"] for x in first], sorted(x["phase"] for x in first))
        joined = " ".join(x["text"] + " " + x["target"] for x in first)
        self.assertIn("ubuntu", joined)
        self.assertIn("203.0.113.9", joined)
        self.assertTrue(rest)

    def test_no_placeholder_targets_anywhere(self):  # TC-UX-04
        for html in (render(combined()), render_web(web())):
            t = text(html)
            for p in PLACEHOLDERS:
                self.assertNotIn(p, t)

    def test_web_actions_name_webshell_and_root(self):  # TC-UX-05
        first, _ = bf.actions(web())
        joined = " ".join(x["text"] for x in first)
        self.assertIn("/uploads/shell.phtml", joined)
        self.assertIn("root", joined)


class ImpactTests(unittest.TestCase):
    def test_impact_lists_s3_reads_and_says_object_unknown(self):  # TC-UX-06
        imp = bf.impact(by_id(combined(), "INC-001")["incident"])
        whats = {d["what"] for d in imp["done"]}
        self.assertTrue({"s3:ListBuckets", "s3:GetObject"} <= whats, whats)
        self.assertTrue(any("이름이 로그에 없습니다" in u and "데이터 이벤트" in u for u in imp["unknown"]))

    def test_sensitive_resource_marked(self):  # FR-25: 프로필의 민감 자원 표시
        inc = {"id": "X", "events": [{"ref": "a:1", "source": "weblog", "status": "success",
                                       "action": "GET /backup/.env", "rules": ["WEBLOG_BACKUP_LEAK"]}]}
        imp = bf.impact(inc, [".env"])
        self.assertTrue(imp["done"][0]["sensitive"])
        self.assertFalse(bf.impact(inc)["done"][0]["sensitive"])

    def test_api_target_from_params(self):
        e = {"source": "cloudtrail", "status": "success", "action": "s3:GetObject",
             "params": json.dumps({"bucketName": "customer-data", "key": "2026/orders.csv"})}
        self.assertEqual(oc.api_target(e), "버킷 customer-data, 객체 2026/orders.csv")


class WordingTests(unittest.TestCase):
    def test_accept_is_allowed_not_success(self):  # TC-UX-07
        r = by_id(combined(), "INC-002")
        c = oc.counts(r["incident"]["events"])
        self.assertEqual(c["success"], 0)
        self.assertGreater(c["allowed"], 0)
        s = r["report"]["summary"]
        self.assertNotIn("성공하거나 통과된", s)
        self.assertIn("성공한 근거는 보이지 않습니다", s)

    def test_no_waf_fix_from_nginx_only_evidence(self):  # TC-UX-08
        r = by_id(combined(), "INC-002")
        self.assertNotIn("WAF_SQLI_COUNT", {c["id"] for c in r["checks"]})
        self.assertIn("WAF_SQLI_COUNT", {c["id"] for c in by_id(combined(), "INC-001")["checks"]})

    def test_breached_has_no_cannot_tell_line(self):  # FR-26: '침해 확인' 옆에 '단정하기 어렵다' 없음
        r = by_id(web(), "INC-001")
        self.assertEqual(r["report"]["verdict"], "breached")
        self.assertFalse(any("단정하기 어렵다" in u for u in r["report"]["unknowns"]))


class FixEvalTests(unittest.TestCase):
    def test_no_unrelated_fix_on_samples(self):  # TC-FIX-04(S5 개발 점수, scripts/fix_eval.py)
        sys.path.insert(0, str(ROOT / "scripts"))
        import fix_eval
        r = fix_eval.evaluate()
        self.assertEqual(r["unrelated_total"], 0, r["rows"])
        self.assertGreaterEqual(r["root_rate"], 0.8)


class TitleGlossaryTests(unittest.TestCase):
    def test_incident_title_is_worst_step(self):  # TC-UX-09
        self.assertIn("역할 키가 서버 밖", bf.title(by_id(combined(), "INC-001")["incident"]))
        self.assertIn("/uploads/shell.phtml", bf.title(by_id(web(), "INC-001")["incident"]))

    def test_glossary_and_attack_ids_folded(self):  # TC-UX-10
        html = render(combined())
        self.assertIn("이 보고서의 낯선 말", html)
        self.assertIn("<dt>IMDS</dt>", html)
        self.assertNotIn("<span class=tech>", html)
        self.assertIn("전문가용: ATT&amp;CK", html)

    def test_web_report_lists_every_incident(self):  # TC-UX-11
        r = web()
        t = text(render_web(r))
        for i in r["incident_index"]:
            self.assertIn(i["id"], t)
        self.assertEqual(len(r["incident_index"]), r["n_groups"])

    def test_pii_note_without_legal_judgement(self):  # TC-UX-12
        hl = bf.headline(web())
        self.assertTrue(hl["pii"])
        t = text(render_web(web()))
        self.assertIn("통지·신고 대상인지 법무 담당과 확인", t)
        self.assertIn("법적 판단을 하지 않습니다", t)

    def test_one_product_name(self):  # TC-UX-13
        other = {"LogFinder": "LogSight", "LogSight": "LogFinder"}[PRODUCT_NAME]
        for html in (render(combined()), render_web(web())):
            self.assertIn(PRODUCT_NAME, html)
            self.assertNotIn(other, html)


class ExcludedTests(unittest.TestCase):
    def test_excluded_activity_listed_and_kept_in_incident(self):  # TC-UX-14
        env = {"trusted_ips": ["203.0.113.9/32"]}
        with tempfile.TemporaryDirectory() as d:
            Path(d, "env.json").write_text(json.dumps(env), encoding="utf-8")
            r = run_paths([str(ROOT / "samples/combined")], str(Path(d, "env.json")), use_ai=False)
        ex = r["excluded_activity"]
        self.assertTrue(ex and ex[0]["n"] > 0, ex)
        self.assertIn("판정에서 뺀 활동", render(r))
        refs = {e["ref"] for x in r["results"] for e in x["incident"]["events"]}
        self.assertIn("auth.log:3", refs)  # 뺀 이벤트도 사건에는 남는다


class ConsoleCsvTests(unittest.TestCase):
    CSV = ("Event ID,Event time,User name,Event name,Event source,Resource type,Resource name,AWS access key,"
           "AWS region,Error code,Source IP address\n"
           "a1,2026-10-11T05:00:00Z,dev-kim,CreateUser,iam.amazonaws.com,AWS::IAM::User,backdoor,AKIAEXAMPLEKEY000001,"
           "us-east-1,,198.51.100.7\n"
           "a2,2026-10-11T05:01:00Z,dev-kim,ListBuckets,s3.amazonaws.com,,,AKIAEXAMPLEKEY000001,us-east-1,"
           "AccessDenied,198.51.100.7\n")

    def test_console_csv_read_as_cloudtrail(self):  # TC-IN-07
        self.assertEqual(detect_kind("event_history.csv", self.CSV), "cloudtrail_csv")
        evs = parse_cloudtrail_csv(self.CSV, "event_history.csv")
        self.assertEqual([(e.action, e.status) for e in evs],
                         [("iam:CreateUser", "success"), ("s3:ListBuckets", "failure")])
        self.assertEqual(evs[0].actor, "dev-kim")

    def test_console_csv_warns_lossy(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "event_history.csv").write_text(self.CSV, encoding="utf-8")
            r = run_paths([d], use_ai=False)
        self.assertTrue(any("이벤트 기록(CSV)" in a and "us-east-1" in a for a in r["assumptions"]))


class TimeAndNoticeTests(unittest.TestCase):
    def test_web_report_times_have_kst(self):  # TC-NFR-18
        t = text(render_web(web()))
        self.assertIn("한국", t)
        self.assertIsNone(re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?!Z)", t.replace(web()["generated_at"], "")))

    def test_file_sensitivity_notice(self):  # TC-NFR-19
        for html in (render(combined()), render_web(web())):
            self.assertIn("원본 로그 일부(IP·요청 경로·계정 이름)가 들어 있습니다", html)

    def test_ai_send_announced_before_sending(self):  # TC-NFR-20
        buf = io.StringIO()
        aisend.SENT.clear()
        with redirect_stderr(buf):
            aisend.announce("재검토", {"incidents": [{"events": [{}, {}]}, {"events": [{}]}]}, "m")
        out = buf.getvalue()
        self.assertIn("사건 2개", out)
        self.assertIn("이벤트 3건", out)
        self.assertIn("--no-ai", out)
        self.assertEqual(aisend.total()["calls"], 1)
        aisend.SENT.clear()


class SelfLogTests(unittest.TestCase):
    def test_analyze_writes_audit_line(self):  # TC-AUD-01
        from logsight.__main__ import main
        with tempfile.TemporaryDirectory() as d:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            # 다른 시험(예: test_pipeline의 AI 모의 호출)이 남긴 전송 기록을 비운다. 실제 명령은 실행마다 새 프로세스라 해당 없음
            from logsight import aisend
            aisend.SENT.clear()
            with redirect_stderr(io.StringIO()), unittest.mock.patch("sys.stdout", new=io.StringIO()):
                main(["analyze", str(ROOT / "samples/combined"), "--no-ai", "--out", d])
            lines = Path(d, "logsight_audit.jsonl").read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[-1])
        self.assertEqual(rec["command"], "analyze")
        self.assertTrue(all(len(f["sha256"]) == 64 for f in rec["inputs"]))
        self.assertEqual(rec["ai"], {"calls": 0})
        self.assertEqual(rec["result"]["incidents"], combined()["n_incidents"])


if __name__ == "__main__":
    unittest.main()

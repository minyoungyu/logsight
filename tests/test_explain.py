"""AI 없이 동작하는 판정·설명(explain.py): 정상 작업 목록, 규칙 판정, 로그 범위, 문장 템플릿, 보고서 표시."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import explain as X  # noqa: E402
from logsight.detect import RULES  # noqa: E402
from logsight.normalize import Event  # noqa: E402
from logsight.pipeline import run, run_paths  # noqa: E402
from logsight.report import render  # noqa: E402
from logsight.triage import coverage_summary  # noqa: E402

T0 = datetime(2026, 10, 11, 5, 0, tzinfo=timezone.utc)


def _ev(i, **kw):
    d = dict(ts=T0 + timedelta(minutes=i), source="cloudtrail", raw_ref=f"ct:{i}")
    d.update(kw)
    return Event(**d)


def _inc(rules, events, iid="INC-001", stages=("discovery",), **kw):
    inc = {"id": iid, "start": events[0]["ts"], "end": events[-1]["ts"], "severity": "high",
           "stages": list(stages), "src_ips": sorted({e["src_ip"] for e in events if e.get("src_ip")}),
           "instances": [], "actors": [], "sources": ["cloudtrail"], "n_events": len(events),
           "findings": [{"rule": r, "title": RULES[r][2], "detail": "d", "key": "", "n_events": len(events),
                         "first": events[0]["ts"], "stage": RULES[r][1], "technique": RULES[r][0],
                         "evidence": [e["ref"] for e in events]} for r in rules],
           "events": events, "omitted_events": 0}
    inc.update(kw)
    return inc


def _cev(i, rule, **kw):
    d = {"ref": f"ct:{i}", "ts": (T0 + timedelta(minutes=i)).isoformat(), "source": "cloudtrail",
         "action": "ec2:DescribeInstances", "status": "success", "disposition": "none",
         "src_ip": "198.18.0.1", "rules": [rule]}
    d.update(kw)
    return d


class KnownActivityTests(unittest.TestCase):
    def test_actor_pattern_ip_and_trusted_ips(self):
        env = {"known_activity": [{"label": "운영자", "actors": ["blue-team-*"]},
                                  {"label": "모니터링", "ips": ["10.0.9.0/24"]},
                                  {"label": "배포 키", "access_keys": ["AKIAEXAMPLE"]}],
               "trusted_ips": [{"cidr": "192.0.2.10/32", "label": "사무실"}]}
        evs = [_ev(0, actor="arn:aws:iam::111122223333:user/blue-team-1"),
               _ev(1, src_ip="10.0.9.5"), _ev(2, access_key="AKIAEXAMPLE"),
               _ev(3, src_ip="192.0.2.10"), _ev(4, actor="arn:aws:iam::111122223333:user/attacker",
                                                 src_ip="198.18.7.1")]
        self.assertEqual(X.mark_known(evs, env), 4)
        self.assertEqual([e.extra.get("known") for e in evs],
                         ["운영자", "모니터링", "배포 키", "사무실 IP", None])

    def test_no_list_marks_nothing(self):
        evs = [_ev(0, actor="blue-team-1")]
        self.assertEqual(X.mark_known(evs, {}), 0)
        self.assertNotIn("known", evs[0].extra)


class VerdictTests(unittest.TestCase):
    def test_all_known_is_benign_partial_known_stays_attack(self):
        evs = [_cev(i, "CT_DISCOVERY_BURST", known="운영자") for i in range(3)]
        v = X.verdict_for(_inc(["CT_DISCOVERY_BURST"], evs, n_known=3, known_labels=["운영자"]))
        self.assertEqual(v["verdict"], "benign_activity")
        v = X.verdict_for(_inc(["CT_DISCOVERY_BURST"], evs, n_events=5, n_known=3, known_labels=["운영자"]))
        self.assertEqual(v["verdict"], "attack")  # 2건은 목록 밖이라 정상으로 내리지 않는다
        self.assertIn("3건은 정상 작업 목록", v["reason"])

    def test_hygiene_only_is_risky(self):
        v = X.verdict_for(_inc(["CT_ROOT_USAGE"], [_cev(0, "CT_ROOT_USAGE")]))
        self.assertEqual(v["verdict"], "risky_not_attack")

    def test_identity_only_credential_use_is_unclear(self):
        evs = [_cev(i, "CT_INSTANCE_CRED_MULTI_IP", action="sts:GetCallerIdentity") for i in range(2)]
        self.assertEqual(X.verdict_for(_inc(["CT_INSTANCE_CRED_MULTI_IP"], evs))["verdict"], "unclear")
        evs.append(_cev(2, "CT_INSTANCE_CRED_MULTI_IP", action="ssm:SendCommand", status="failure"))
        self.assertEqual(X.verdict_for(_inc(["CT_INSTANCE_CRED_MULTI_IP"], evs))["verdict"], "attack")

    def test_all_blocked_attack_has_low_confidence(self):
        evs = [_cev(i, "WAF_BLOCKED", source="waf", status="failure", disposition="blocked") for i in range(3)]
        v = X.verdict_for(_inc(["WAF_BLOCKED"], evs))
        self.assertEqual((v["verdict"], v["confidence"]), ("attack", "low"))

    def test_campaign_links_same_ip(self):
        a = _inc(["WAF_BLOCKED"], [_cev(0, "WAF_BLOCKED", src_ip="198.18.7.1")], iid="INC-001")
        b = _inc(["CT_INSTANCE_CRED_MULTI_IP"], [_cev(5, "CT_INSTANCE_CRED_MULTI_IP", src_ip="198.18.7.1",
                                                     action="iam:CreateUser")], iid="INC-002")
        c = _inc(["CT_ROOT_USAGE"], [_cev(9, "CT_ROOT_USAGE", src_ip="198.18.7.1")], iid="INC-003")
        res = X.rule_triage([a, b, c])
        self.assertEqual(res["mode"], "rules")
        self.assertEqual([sorted(x["incident_ids"]) for x in res["campaigns"]], [["INC-001", "INC-002"]])


class CoverageTests(unittest.TestCase):
    def test_missing_substitute_early_end_and_s3(self):
        evs = [_ev(i, access_key="ASIAKEY", action="ec2:DescribeInstances", outcome="success",
                   findings=["CT_INSTANCE_CRED_MULTI_IP"]) for i in range(0, 120, 10)]
        evs += [_ev(i, source="weblog", raw_ref=f"web:{i}") for i in range(0, 20, 5)]
        notes = X.coverage_notes(coverage_summary(evs),
                                 [{"id": "INC-001", "end": evs[11].ts.isoformat(),
                                   "rules": ["CT_INSTANCE_CRED_MULTI_IP"]}])
        text = "\n".join(notes)
        self.assertIn("WAF 로그가 없어 웹 공격 요청이 막혔는지는 웹서버 로그로 일부만", text)
        self.assertIn("SSH 인증 로그가 없어 누가 서버에 로그인했는지 알 수 없습니다", text)
        self.assertIn("웹서버 로그는", text)  # 웹서버 로그가 CloudTrail보다 먼저 끝남
        self.assertIn("INC-001의 활동이 로그가 끝나는 무렵", text)
        self.assertIn("S3 파일 읽기·쓰기 기록이 0건", text)

    def test_separate_periods_are_not_called_early_end(self):
        evs = [_ev(0), _ev(5)] + [_ev(60 * 24 * 3 + i, source="weblog", raw_ref=f"w:{i}") for i in (0, 5)]
        text = "\n".join(X.coverage_notes(coverage_summary(evs)))
        self.assertIn("서로 떨어진 기간 2개", text)
        self.assertNotIn("CloudTrail 로그는", text)


class TemplateTests(unittest.TestCase):
    def test_every_rule_gets_a_sentence_without_raw_title_concat(self):
        for r in RULES:
            evs = [_cev(0, r, dst_port=22)]
            s = X.describe_finding(_inc([r], evs)["findings"][0], _inc([r], evs))
            self.assertTrue(s.endswith(".") or s.endswith(")"), (r, s))
            self.assertFalse(s.startswith(RULES[r][2] + ":"), (r, s))

    def test_summary_shape_by_verdict(self):
        evs = [_cev(0, "SSH_SUCCESS_AFTER_FAIL", source="sshauth", status="success")]
        inc = _inc(["SSH_SUCCESS_AFTER_FAIL"], evs)
        checks = [{"title": "보안그룹이 22번을 전체에 허용", "severity": "high"}]
        s = X.summarize(inc, {"verdict": "attack"}, checks)
        self.assertTrue(s.startswith("외부 공격으로 보입니다."))
        self.assertIn("UTC(한국 14:00)", s)
        self.assertIn("먼저 고칠 설정: 보안그룹이 22번을 전체에 허용", s)
        s = X.summarize(inc, {"verdict": "benign_activity", "reason": "목록과 일치"}, checks)
        self.assertTrue(s.startswith("정상 작업으로 보입니다.") and "목록과 일치" in s)
        self.assertNotIn("먼저 고칠", s)


class PipelineAndReportTests(unittest.TestCase):
    def test_rules_mode_report_shows_mode_coverage_and_verdict(self):
        r = run_paths([str(ROOT / "samples" / "combined")], use_ai=False, year=2026) \
            if "year" in run_paths.__code__.co_varnames else run_paths([str(ROOT / "samples" / "combined")], use_ai=False)
        self.assertEqual(r["explain_mode"]["report"], "rules")
        self.assertEqual(r["triage"]["mode"], "rules")
        self.assertTrue(all(i["verdict_by"] == "rules" for i in r["incident_index"]))
        html = render(r)
        self.assertIn("설명 방식: 규칙 기반 · AI 사용 안 함", html)
        self.assertIn("로그로 볼 수 있는 범위", html)
        self.assertIn("class='vd attack'", html)
        self.assertNotIn(" — ", r["results"][0]["report"]["attack_flow"][0]["what"])

    def test_known_list_demotes_operator_incident(self):
        evs = [_ev(i, actor="arn:aws:iam::111122223333:user/blue-team-1", src_ip="198.18.2.1",
                   action=a, outcome="success")
               for i, a in enumerate(["cloudtrail:StopLogging"] + ["ec2:DescribeInstances"] * 3)]
        env = {"known_activity": [{"label": "운영자", "actors": ["blue-team-*"]}]}
        base = run([Event(**{k: getattr(e, k) for k in ("ts", "source", "src_ip", "actor", "action",
                                                         "outcome", "raw_ref")}) for e in evs], {}, use_ai=False)
        self.assertEqual(base["incident_index"][0]["verdict"], "attack")
        out = run(evs, env, use_ai=False)
        self.assertEqual(out["n_known"], 4)
        self.assertEqual(out["incident_index"][0]["verdict"], "benign_activity")
        self.assertIn("정상 작업 목록 일치 1건", render(out))  # 사건에는 규칙에 걸린 이벤트만 들어간다


class CompareScriptTests(unittest.TestCase):
    def test_side_by_side_page(self):
        r = run_paths([str(ROOT / "samples" / "demo")], use_ai=False)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report.json"
            p.write_text(json.dumps(r, ensure_ascii=False, default=str), encoding="utf-8")
            out = Path(d) / "cmp.html"
            subprocess.run([sys.executable, str(ROOT / "scripts" / "compare_modes.py"),
                            "--col", f"규칙={p}:rule_triage", "--col", f"같은 것={p}:triage",
                            "--out", str(out)], check=True, capture_output=True)
            html = out.read_text(encoding="utf-8")
        self.assertIn("AI 사용 안 함", html)
        self.assertEqual(html.count("<th>규칙</th>"), 1)
        self.assertIn("INC-001", html)


if __name__ == "__main__":
    unittest.main()

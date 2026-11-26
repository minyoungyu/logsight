"""Panther 시험 이벤트 측정 도구(scripts/public/eval_panther.py). 직접 만든 규칙 파일만 쓴다."""
import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("eval_panther", ROOT / "scripts" / "public" / "eval_panther.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _rule(d, stem, enabled=True):
    log = {"eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging", "awsRegion": "us-east-1",
           "sourceIPAddress": "198.51.100.7", "userIdentity": {"type": "IAMUser", "userName": "x",
                                                               "arn": "arn:aws:iam::111122223333:user/x"},
           "requestParameters": {"name": "t"}, "eventTime": "2026-01-01T00:00:00Z", "eventID": "1"}
    ok = dict(log, eventName="DescribeTrails", eventID="2")
    (d / f"{stem}.yml").write_text(yaml.safe_dump({
        "AnalysisType": "rule", "RuleID": stem, "Enabled": enabled, "LogTypes": ["AWS.CloudTrail"],
        "Severity": "High", "Tests": [{"Name": "stop", "ExpectedResult": True, "Log": log},
                                      {"Name": "describe", "ExpectedResult": False, "Log": ok}]}))


def test_half_split_and_counts(tmp_path):
    m = _load()
    d = tmp_path / "rules" / "aws_cloudtrail_rules"
    d.mkdir(parents=True)
    stems = [f"r{i}" for i in range(12)]
    for s in stems:
        _rule(d, s)
    _rule(d, "off", enabled=False)
    a, b = m.measure(tmp_path, "A"), m.measure(tmp_path, "B")
    na, nb = a["machine"]["rules_with_positive_tests"], b["machine"]["rules_with_positive_tests"]
    assert na + nb == 12 and na and nb  # 꺼진 규칙은 빼고, 두 반이 겹치지 않음
    assert {i["file"] for i in a["items"]}.isdisjoint({i["file"] for i in b["items"]})
    assert a["machine"]["rules_any_flagged"] == na  # StopLogging은 잡힘
    assert a["machine"]["negative_flagged"] == 0
    assert all(m.half_of(s) == m.half_of(s) for s in stems)

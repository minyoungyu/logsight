"""사양서 v2에서 '테스트가 요구사항을 실제로 확인하지 않는다'고 지적된 항목을 직접 확인한다.

- TC-NFR-05a/b: AI에 보내는 양의 상한(사건 30개, 재검토 사건당 12건, 설명 사건당 60건)
- TC-NFR-16b: 보고서 문장이 한국어(코드·명령·식별자는 빼고, 다섯 낱말 넘는 문장마다 한글이 있다)
- TC-HB-02: 로그 전송 끊김 기준 5분의 바로 위·아래(가짜 S3, moto 없이도 돈다)
- TC-VER-03: 판정 정확도 세트(scripts/verdict_eval.py)가 재현율 90%·정밀도 80% 아래로 떨어지지 않는다
"""
from __future__ import annotations

import html
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from logsight.analyze import build_payload  # noqa: E402
from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import parse_sshauth  # noqa: E402
from logsight.triage import build_triage_payload  # noqa: E402


def _fake_incident(i: int, n_events: int) -> dict:
    return {"id": f"INC-{i:03d}", "start": "2026-11-02T01:00:00Z", "end": "2026-11-02T01:30:00Z",
            "severity": "high", "stages": ["초기 침투"], "src_ips": ["198.51.100.7"], "instances": [],
            "actors": [], "sources": ["sshauth"], "n_events": n_events, "findings": [],
            "events": [{"ref": f"auth:{j}", "src_ip": "198.51.100.7", "action": "ssh_login"} for j in range(n_events)]}


def test_triage_payload_caps_incidents_and_events():  # TC-NFR-05a
    incs = [_fake_incident(i, 100) for i in range(45)]
    p = build_triage_payload(incs)
    assert len(p["incidents"]) == 30
    assert p["n_incidents_total"] == 45
    assert max(len(x["events"]) for x in p["incidents"]) <= 12


def test_explain_payload_keeps_at_most_60_events():  # TC-NFR-05b
    lines = [f"Nov  2 01:{i // 60:02d}:{i % 60:02d} web sshd[{i}]: Failed password for root from 198.51.100.7 "
             f"port {40000 + i} ssh2" for i in range(300)]
    evs = parse_sshauth("\n".join(lines), "auth", year=2026)
    incs = build_incidents(evs, run_detections(evs, {}))
    assert incs, "대입 300건이면 사건이 있어야 한다"
    big = max(incs, key=lambda x: x["n_events"])
    assert big["n_events"] == 300
    assert len(big["events"]) <= 60 and big["omitted_events"] >= 240
    assert len(build_payload(big, [])["events"]) <= 60


def _report_text() -> str:
    from logsight.pipeline import run_paths
    from logsight.report import render
    h = render(run_paths([str(ROOT / "samples/combined")], use_ai=False))
    t = re.sub(r"(?is)<(script|style|code|pre|svg)\b.*?</\1>", " ", h)
    return html.unescape(re.sub(r"<[^>]+>", "\n", t))


def _is_prose(s: str) -> bool:
    """다섯 낱말 이상이고, 식별자(ARN·IP·규칙 ID·경로)처럼 보이는 낱말이 절반 미만이면 사람이 읽는 문장."""
    w = s.split()
    return len(w) >= 5 and sum(1 for x in w if re.search(r"[:/_=\d%@.-]", x)) < len(w) / 2


def test_report_sentences_are_korean():  # TC-NFR-16b
    sents = [s.strip() for s in _report_text().split("\n") if _is_prose(s.strip())]
    assert len(sents) >= 50
    no_ko = [s for s in sents if not re.search(r"[가-힣]", s)]
    assert not no_ko, f"한글 없는 문장: {no_ko[:3]}"


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kw):
        return self.pages(**kw)


class _FakeS3:
    """heartbeat.check가 쓰는 list_objects_v2 페이지만 흉내 낸다."""

    def __init__(self, objects: dict[str, datetime]):
        self.objects = objects

    def get_paginator(self, _name):
        def pages(Bucket, Prefix, Delimiter=None):  # noqa: N803 — boto3 인자 이름
            keys = [k for k in self.objects if k.startswith(Prefix)]
            if Delimiter:
                subs = sorted({Prefix + k[len(Prefix):].split(Delimiter)[0] + Delimiter for k in keys})
                return [{"CommonPrefixes": [{"Prefix": s} for s in subs]}]
            return [{"Contents": [{"Key": k, "LastModified": self.objects[k]} for k in keys]}]
        return _Pager(pages)


def test_heartbeat_five_minute_boundary():  # TC-HB-02
    from logsight.heartbeat import check
    now = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
    s3 = _FakeS3({f"heartbeat/fresh/{now:%Y/%m/%d}/a": now - timedelta(minutes=4, seconds=50),
                  f"heartbeat/stale/{now:%Y/%m/%d}/a": now - timedelta(minutes=5, seconds=10)})
    rows = {r["host"]: r for r in check("s3://archive/heartbeat/", s3=s3, now=now)}
    assert rows["fresh"]["ok"] is True
    assert rows["stale"]["ok"] is False


def test_verdict_accuracy_floor():  # TC-VER-03, NFR-20
    from verdict_eval import evaluate
    r = evaluate()
    assert r["n_cases"] >= 30 and r["n_not_attack"] >= 10
    assert r["recall"] >= 0.9, r
    assert r["precision"] >= 0.8, r


def test_study_kit_hides_answers_and_balances_groups(tmp_path):  # TC-NFR-14b
    import csv
    import shutil

    from study_prepare import build
    a = tmp_path / "A"
    shutil.copytree(ROOT / "samples/demo", a)
    (a / "ground_truth.json").write_text("{}", encoding="utf-8")
    made = build({"A": a, "B": ROOT / "samples/combined"}, 8, tmp_path / "kit", year=2026)
    assert made["A"]["events"] > 0 and made["B"]["events"] > 0
    assert not list((tmp_path / "kit").rglob("ground_truth*"))
    assert (tmp_path / "kit/A/logsight/report.html").is_file()
    assert not (tmp_path / "kit/A/baseline/report.html").exists()
    rows = list(csv.DictReader(open(tmp_path / "kit/배정표.csv", encoding="utf-8-sig")))
    assert len(rows) == 16
    # 시나리오×조건 네 칸이 4명씩 고르게
    from collections import Counter
    assert set(Counter((r["scenario"], r["condition"]) for r in rows).values()) == {4}


def test_checklist_round_does_not_count_skips_as_pass(tmp_path):  # TC-RUN-01, NFR-21
    from checklist_run import outcomes, status_of
    x = tmp_path / "j.xml"
    x.write_text("""<testsuites><testsuite>
      <testcase classname="tests.test_a.Cls" name="test_ok"/>
      <testcase classname="tests.test_a.Cls" name="test_skip"><skipped message="moto 없음"/></testcase>
      <testcase classname="tests.test_b" name="test_fn"/>
      <testcase classname="tests.test_b" name="test_bad"><failure message="x"/></testcase>
    </testsuite></testsuites>""", encoding="utf-8")
    res = outcomes(x)
    assert status_of(("tests/test_a.py", "Cls"), res) == "건너뜀"
    assert status_of(("tests/test_a.py", "test_ok"), res) == "통과"
    assert status_of(("tests/test_b.py", "test_fn"), res) == "통과"
    assert status_of(("tests/test_b.py", "test_bad"), res) == "실패"
    assert status_of(("tests/test_b.py", "test_missing"), res) == "찾지 못함"

"""AI 재검토(triage): 근거 검증, 정렬, 파이프라인 연결. Claude 호출은 가짜로 바꾼다."""
from datetime import datetime, timedelta, timezone

from logsight import triage as T
from logsight.normalize import Event
from logsight.pipeline import run


def _brute(ip, hour):
    t0 = datetime(2026, 10, 11, hour, tzinfo=timezone.utc)
    return [Event(ts=t0 + timedelta(seconds=10 * i), source="sshauth", src_ip=ip, actor="root",
                  action="ssh:login", outcome="failure", raw_ref=f"auth-{ip}:{i + 1}")
            for i in range(6)]


def _inc(i, refs, sev="high"):
    return {"id": i, "start": "2026-10-11T05:00:00+00:00", "end": "2026-10-11T05:10:00+00:00",
            "severity": sev, "stages": ["discovery"], "src_ips": ["198.18.0.1"], "instances": [],
            "actors": [], "sources": ["cloudtrail"], "n_events": len(refs),
            "findings": [{"rule": "R", "title": "t", "detail": "d", "key": "k", "n_events": 1}],
            "context": {"top_actions": []},
            "events": [{"ref": r} for r in refs]}


def test_validate_drops_unknown_ids_and_refs():
    incs = [_inc("INC-001", ["ct:1", "ct:2"]), _inc("INC-002", ["ct:3"])]
    payload = T.build_triage_payload(incs)
    res = {"incidents": [
        {"id": "INC-001", "verdict": "benign_activity", "confidence": "high", "reason": "",
         "evidence": ["ct:1", "ct:3"]},  # ct:3은 INC-002의 근거
        {"id": "INC-009", "verdict": "attack", "confidence": "high", "reason": "", "evidence": []}],
        "campaigns": [{"incident_ids": ["INC-002", "INC-404"], "summary": "", "link_reason": "",
                       "steps": [{"incident_id": "INC-002", "time": "", "what": "",
                                  "evidence": ["ct:3", "made-up:9"]}]}],
        "cannot_tell": []}
    v = T.validate_triage(res, payload)
    assert res["incidents"][0]["evidence"] == ["ct:1"]
    assert [x["id"] for x in res["incidents"]] == ["INC-001"]
    assert res["campaigns"][0]["incident_ids"] == ["INC-002"]
    assert res["campaigns"][0]["steps"][0]["evidence"] == ["ct:3"]
    assert v["evidence_invalid"] == 2 and set(v["unknown_ids"]) == {"INC-009", "INC-404"}
    assert v["incidents_without_verdict"] == ["INC-002"] and not v["passed"]


def test_reorder_keeps_rule_order_within_verdict():
    incs = [_inc(f"INC-00{i}", [f"r{i}"]) for i in range(1, 5)]
    res = {"incidents": [{"id": "INC-001", "verdict": "benign_activity"},
                         {"id": "INC-002", "verdict": "attack"},
                         {"id": "INC-004", "verdict": "attack"}]}
    out = T.reorder(incs, res)
    assert [i["id"] for i in out] == ["INC-002", "INC-004", "INC-003", "INC-001"]
    assert out[2]["ai_verdict"] == "unclear"  # 판정이 없으면 판단 불가로 둔다
    assert T.reorder(incs, None) is incs


def test_sample_spreads_over_incident():
    ev = [{"ref": str(i)} for i in range(100)]
    s = T._sample(ev, 5)
    assert [e["ref"] for e in s] == ["0", "25", "50", "74", "99"]


def test_no_key_means_rule_order(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert T.triage([_inc("INC-001", ["a"])]) is None


def test_pipeline_uses_triage_order(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    seen = {}

    def fake(payload, model):
        seen["payload"] = payload
        last = payload["incidents"][-1]["id"]
        return ({"incidents": [{"id": i["id"], "verdict": "attack" if i["id"] == last
                                else "benign_activity", "confidence": "high", "reason": "",
                                "evidence": [i["events"][0]["ref"]]}
                               for i in payload["incidents"]],
                 "campaigns": [], "cannot_tell": ["키 유출 경로"]},
                {"input_tokens": 1, "output_tokens": 1, "served_by": model})

    monkeypatch.setattr(T, "_call_claude", fake)
    monkeypatch.setattr("logsight.pipeline.analyze",
                        lambda inc, checks, model=None, use_ai=True: {"report": {}, "meta": {}})
    out = run(_brute("203.0.113.5", 1) + _brute("203.0.113.6", 5), top=1)
    ids = [i["id"] for i in seen["payload"]["incidents"]]
    assert len(ids) == 2
    assert out["triage"]["validation"]["passed"]
    # 규칙 순서로는 마지막이던 사건이 AI 판정으로 맨 위에 오고, 상세 분석도 그 사건을 한다
    assert [i["id"] for i in out["incident_index"]] == [ids[1], ids[0]]
    assert out["incident_index"][0]["ai_verdict"] == "attack"
    assert out["results"][0]["incident"]["id"] == ids[1]


def _alb(ip, path, status, sec):
    t0 = datetime(2026, 10, 11, 5, 40, tzinfo=timezone.utc)
    return Event(ts=t0 + timedelta(seconds=sec), source="alb", src_ip=ip,
                 action=f"GET {path}", outcome="failure",
                 raw_ref=f"alb:{sec}", extra={"http_status": int(status)})


def test_object_enum_on_api_logs():
    from logsight.detect import run_detections
    probe = [_alb("198.18.7.2", f"/api/jobs/job-{n}/download", s, i * 20)
             for i, (n, s) in enumerate([(58152, "403"), (58143, "403"), (0, "404"),
                                          (1, "404"), (5000, "404")])]
    # 같은 번호를 다시 여는 것, 객체 번호 없는 경로의 404는 세지 않는다
    normal = [_alb("198.18.9.9", "/api/jobs/job-7/download", "404", i * 20) for i in range(6)]
    normal += [_alb("198.18.9.8", f"/static/x{i}.js", "404", i * 20) for i in range(6)]
    fs = run_detections(probe + normal)
    hits = [f for f in fs if f.rule == "WEB_OBJECT_ENUM"]
    assert len(hits) == 1 and hits[0].key == "198.18.7.2" and len(hits[0].events) == 5


def test_coverage_summary_lists_suspected_key_calls():
    t0 = datetime(2026, 10, 11, 6, 0, tzinfo=timezone.utc)
    ct = [Event(ts=t0 + timedelta(minutes=i), source="cloudtrail", src_ip=ip, actor="r",
                access_key="ASIAKEY", action="states:StartExecution", outcome="success",
                raw_ref=f"ct:{i}", findings=["CT_INSTANCE_CRED_MULTI_IP"] if i else [])
          for i, ip in enumerate(["198.18.0.1", "198.18.7.1", "198.18.7.1"])]
    ct.append(Event(ts=t0, source="cloudtrail", src_ip="198.18.0.2", actor="b", access_key="ASIAOTHER",
                    action="s3:GetObject", outcome="success", raw_ref="ct:9",
                    findings=["CT_DISCOVERY_BURST"]))
    c = T.coverage_summary(ct)
    assert c["missing_sources"] == ["vpcflow", "waf", "alb", "sshauth"]
    assert c["cloudtrail_s3_object_calls"] == 1
    assert [k["access_key"] for k in c["suspected_keys"]] == ["ASIAKEY"]  # 자격증명 규칙에 걸린 키만
    k = c["suspected_keys"][0]
    assert k["n_calls"] == 3 and k["src_ips"] == ["198.18.0.1", "198.18.7.1"]  # 사건 밖 호출까지 센다
    assert T.build_triage_payload([_inc("INC-001", ["ct:1"])], coverage=c)["coverage"] is c

"""공방전 통합로그 변환기: 형식 변환과 가명 처리(합성 입력)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "ctf"))

from convert_gongbang import convert  # noqa: E402

from logsight.normalize import load_paths  # noqa: E402

MD = """# 통합 로그

| 시각(KST) | 출처 | 이벤트/내용 | 주체 | IP | 액세스키 |
|---|---|---|---|---|---|
| 10-11 15:36:22 | event_history | StartExecution · states.amazonaws.com · OK name=case-1 | arn:aws:sts::999988887777:assumed-role/app-role/i-0abc1234 | 203.0.113.9 | ASIAABCDEFGHIJKLMNOP |
| 10-11 16:11:37 | event_history | SendCommand · ssm.amazonaws.com · AccessDenied | arn:aws:sts::999988887777:assumed-role/app-role/i-0abc1234 | 203.0.113.9 | ASIAABCDEFGHIJKLMNOP |
| 10-11 13:30:02 | event_history | GetCallerIdentity · sts.amazonaws.com · OK | blue-team-1 | 10.0.0.5 | ASIAZZZZZZZZZZZZZZZZ |
| 10-11 14:10:45 | waf | POST /api/subscriptions · WAF BLOCK (patchsignal) | 203.0.113.9 | 203.0.113.9 | - |
| 10-11 14:52:54 | apigw-pagesnap | GET /api/jobs/job-1/download · status 200 (1384B) | 203.0.113.9 | 203.0.113.9 | - |
| 10-11 15:17:28 | CLI:abc | 2026-10-11T06:17:28Z    GetCallerIdentity |  |  |  |
"""


def test_convert_and_pseudonymize(tmp_path):
    src = tmp_path / "log.md"
    src.write_text(MD, encoding="utf-8")
    out = tmp_path / "out"
    stats = convert(src, out)
    assert stats["cloudtrail"] == 3 and stats["waf"] == 1 and stats["alb"] == 1
    assert stats["skipped"] == {"CLI": 1}
    produced = "".join(p.read_text() for p in out.iterdir() if p.name != "mapping.json")
    for real in ("203.0.113.9", "999988887777", "ASIAABCDEFGHIJKLMNOP"):
        assert real not in produced
    assert "10.0.0.5" in produced  # 사설 IP는 그대로

    events, _ = load_paths([out])
    by = {e.source: e for e in events}
    assert set(by) == {"cloudtrail", "waf", "alb"}
    ct = sorted((e for e in events if e.source == "cloudtrail"), key=lambda e: e.ts)
    assert ct[1].action == "states:StartExecution" and ct[1].outcome == "success"
    assert ct[2].outcome == "failure" and ct[2].instance_id == "i-0abc1234"
    assert ct[1].src_ip == by["waf"].src_ip == by["alb"].src_ip  # 같은 IP는 같은 가명
    assert ct[1].ts.isoformat() == "2026-10-11T06:36:22+00:00"  # KST → UTC
    mapping = json.loads((out / "mapping.json").read_text())
    assert mapping["ip"]["203.0.113.9"] == ct[1].src_ip


def test_pseudonyms_keep_slash24(tmp_path):
    from convert_gongbang import Pseudo
    ps = Pseudo()
    a, b, c = ps.ip_of("203.0.113.9"), ps.ip_of("198.51.100.7"), ps.ip_of("203.0.113.200")
    assert a.rsplit(".", 1)[0] == c.rsplit(".", 1)[0] != b.rsplit(".", 1)[0]  # 같은 /24는 같은 가명 대역
    assert a != c and ps.ip_of("203.0.113.9") == a
    assert all(x.startswith("198.18.") for x in (a, b, c))
    assert "113" not in a and ".9" not in a.rsplit(".", 1)[1:]  # 실제 대역·호스트 번호는 남기지 않는다

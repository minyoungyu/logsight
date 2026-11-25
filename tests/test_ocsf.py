"""OCSF 1.3.0 Detection Finding 내보내기와 ATT&CK 표 검사.

필수 항목은 ocsf-schema v1.3.0 저장소의 정의에서 옮겼다(2026-11-25 확인):
base_event(metadata, severity_id) + classification(activity_id, category_uid, class_uid, type_uid)
+ occurrence(time) + finding(finding_info), finding_info(title, uid), metadata(product, version),
product(vendor_name), observable(name, type_id), analytic(type_id).
"""
import json
import subprocess
import sys
from pathlib import Path

from logsight import ocsf
from logsight.attack_v15 import TECHNIQUES
from logsight.detect import RULES

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOP = {"metadata", "severity_id", "activity_id", "category_uid", "class_uid", "type_uid", "time",
                "finding_info"}


def _check(f: dict):
    assert REQUIRED_TOP <= set(f), REQUIRED_TOP - set(f)
    assert f["class_uid"] == 2004 and f["category_uid"] == 2 and f["type_uid"] == 200401
    assert f["severity_id"] in {0, 1, 2, 3, 4, 5, 6, 99} and f["status_id"] in {0, 1, 2, 3, 4, 99}
    assert {"title", "uid"} <= set(f["finding_info"])
    assert {"product", "version"} <= set(f["metadata"]) and f["metadata"]["version"] == "1.3.0"
    assert "vendor_name" in f["metadata"]["product"]
    for o in f.get("observables", []):
        assert {"name", "type_id"} <= set(o) and o["type_id"] in {2, 4, 10}
    an = f["finding_info"].get("analytic")
    if an:
        assert an["type_id"] == 1
    for a in f["finding_info"].get("attacks", []):
        t = a.get("sub_technique", a["technique"])["uid"]
        tac = a["tactic"]["name"].lower().replace(" ", "-")
        assert tac in TECHNIQUES[t]["tactics"], (t, tac)  # ATT&CK과 맞는 전술만
    json.dumps(f)


def test_every_rule_technique_is_a_current_attack_technique():
    for rule, (tech, *_rest) in RULES.items():
        if tech.startswith("T"):
            assert tech in TECHNIQUES, (rule, tech)


def test_attack_tactic_follows_attack_when_stage_differs():
    # 웹 스캔(T1595.002)은 화면에서 '정찰·탐색(discovery)'이지만 ATT&CK에서는 reconnaissance
    assert ocsf.attack_tactic("T1595.002", "discovery") == "reconnaissance"
    assert ocsf.attack_tactic("T1110", "credential-access") == "credential-access"


def test_analyze_writes_valid_ocsf_findings(tmp_path):
    out = tmp_path / "r"
    subprocess.run([sys.executable, "-m", "logsight", "analyze", str(ROOT / "samples" / "combined"),
                    "--out", str(out), "--no-ai", "--year", "2026"], check=True, cwd=ROOT,
                   capture_output=True)
    findings = json.loads((out / "findings.ocsf.json").read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(findings) == len(report["results"]) > 0
    for f in findings:
        _check(f)
        assert f["unmapped"]["logfinder"]["verdict"] in {"attack", "risky_not_attack", "unclear", "benign_activity"}


def test_attack_layer_shape():
    layer = ocsf.attack_layer()
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    for t in layer["techniques"]:
        assert t["techniqueID"] in TECHNIQUES
        if "tactic" in t:
            assert t["tactic"] in TECHNIQUES[t["techniqueID"]]["tactics"]

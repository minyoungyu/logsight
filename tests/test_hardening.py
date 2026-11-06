"""B-1·B-2 합의 사항 회귀 테스트: 격리와 AI의 분리, AI 제안 표시, 세션 무효화 수정안, 순서 바닥."""
import inspect

from logsight import respond as rs
from logsight.analyze import validate
from logsight.config_audit import audit
from logsight.triage import reorder


def test_respond_has_no_ai_path():
    """자동 격리(respond)는 AI를 절대 쓰지 않는다 — 소스에 모델 호출 흔적이 없어야 한다."""
    src = inspect.getsource(rs)
    for bad in ("anthropic", "_call_claude", "ANTHROPIC_API_KEY", "import analyze", "import triage",
                "from .analyze", "from .triage"):
        assert bad not in src, f"respond.py가 AI 경로를 참조함: {bad}"


def test_ai_new_changes_are_flagged_separately():
    """AI가 코드 점검 밖에서 제안한 변경(check_id=NEW)은 '검증 안 된 제안'으로 따로 표시된다."""
    incident = {"events": [{"ref": "E1"}], "findings": []}
    checks = [{"id": "SG_ADMIN_PORT_OPEN"}]
    report = {"attack_flow": [], "root_causes": [],
              "firewall_changes": [
                  {"check_id": "NEW", "resource": "x", "change": "새 제안", "target": "other", "priority": "soon"},
                  {"check_id": "SG_ADMIN_PORT_OPEN", "resource": "sg", "change": "z", "target": "security_group",
                   "priority": "now"}],
              "unknowns": []}
    v = validate(report, incident, checks)
    assert v["ai_new_changes"] == [{"resource": "x", "change": "새 제안"}]
    assert v["passed"] is True  # NEW는 허용하되 따로 세어 둔다


def test_session_revoke_remediation_for_stolen_role_creds():
    """역할 자격증명이 밖에서 쓰인 사건에는 '세션 무효화' 수정안이 나오고 되돌리기가 붙는다."""
    incident = {"events": [{"ref": "E1", "rules": ["CT_INSTANCE_CRED_OUTSIDE"]}],
                "findings": [{"rule": "CT_INSTANCE_CRED_OUTSIDE"}],
                "src_ips": ["203.0.113.9"], "instances": ["i-0abc"], "actors": []}
    env = {"instances": [{"instance_id": "i-0abc", "iam_role": "ec2-app-role", "imds": "required"}],
           "trusted_ips": []}
    checks = audit(incident, env)
    revoke = [c for c in checks if c["id"] == "IAM_ROLE_SESSION_REVOKE"]
    assert len(revoke) == 1
    c = revoke[0]
    assert c["resource"] == "ec2-app-role" and c["severity"] == "high"
    assert any("put-role-policy" in line and "AWSRevokeOlderSessions" in line for line in c["cli"])
    assert c["rollback"] == ["aws iam delete-role-policy --role-name ec2-app-role "
                             "--policy-name AWSRevokeOlderSessions"]


def test_reorder_keeps_rule_attack_above_benign_when_ai_downgrades():
    """규칙이 '공격'으로 본 사건을 AI가 '정상'으로 낮춰도(contested), 진짜 정상 사건보다 아래로 가지 않는다."""
    incidents = [{"id": "INC-benign", "events": []}, {"id": "INC-contested", "events": []}]
    result = {"mode": "claude", "incidents": [
        {"id": "INC-benign", "verdict": "benign_activity"},
        {"id": "INC-contested", "verdict": "benign_activity",
         "contested": {"rules": "attack", "ai": "benign_activity"}}]}
    ordered = reorder(incidents, result)
    assert [i["id"] for i in ordered][0] == "INC-contested", "contested 사건이 바닥(정상)으로 밀렸다"

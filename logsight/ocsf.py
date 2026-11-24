"""사건을 OCSF(Open Cybersecurity Schema Framework) 1.3.0 Detection Finding으로 내보낸다.

OCSF는 AWS·Splunk·IBM 등이 함께 만든 보안 이벤트 공용 형식이다(https://schema.ocsf.io, Linux Foundation).
Security Lake, Security Hub(OCSF 형식), Splunk 등 다른 제품이 이 형식을 읽는다.

- 사건 하나 = Detection Finding 하나(class_uid 2004, category_uid 2 Findings, activity Create).
- 규칙은 finding_info.analytic(첫 규칙)과 related_analytics(나머지), MITRE ATT&CK 기법은 finding_info.attacks.
- LogFinder만의 값(판정·판정 주체·성공/실패 건수·근거 줄)은 버리지 않고 `unmapped.logfinder`에 둔다.
- 필드 이름과 필수 항목은 ocsf-schema v1.3.0 저장소의 정의로 맞췄다(tests/test_ocsf.py가 필수 항목을 검사).
"""
from __future__ import annotations

import hashlib
from datetime import datetime

from . import __version__
from .attack_v15 import ATTACK_VERSION, TECHNIQUES
from .detect import RULES

OCSF_VERSION = "1.3.0"
CLASS_UID, CATEGORY_UID, ACTIVITY_CREATE = 2004, 2, 1

SEVERITY = {"info": (1, "Informational"), "low": (2, "Low"), "medium": (3, "Medium"),
            "high": (4, "High"), "critical": (5, "Critical")}
# LogFinder 단계 이름 → ATT&CK 전술(Enterprise)
TACTICS = {
    "initial-access": ("TA0001", "Initial Access"), "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"), "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"), "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"), "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"), "exfiltration": ("TA0010", "Exfiltration"),
    "command-and-control": ("TA0011", "Command and Control"), "impact": ("TA0040", "Impact"),
    "reconnaissance": ("TA0043", "Reconnaissance"), "resource-development": ("TA0042", "Resource Development"),
}
VERDICT_EN = {"attack": "attack", "risky_not_attack": "risky configuration (not an attack)",
              "unclear": "needs review", "benign_activity": "benign activity"}
# 판정 → OCSF 위험 수준(risk_level_id)
RISK = {"attack": (3, "High"), "risky_not_attack": (2, "Medium"), "unclear": (1, "Low"),
        "benign_activity": (0, "Info")}
# 관찰값 종류(OCSF dictionary types의 observable 번호)
OBS_IP, OBS_USER, OBS_RESOURCE = 2, 4, 10


def _ms(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def attack_tactic(tech: str, stage: str) -> str:
    """ATT&CK 전술 이름. 규칙의 단계가 그 기법의 ATT&CK 전술 중 하나면 그대로, 아니면 ATT&CK의 첫 전술.
    LogFinder의 단계는 화면용 묶음이라 ATT&CK과 다를 수 있다(예: 웹 스캔을 '정찰·탐색(discovery)'으로 보이지만
    ATT&CK에서 T1595는 reconnaissance). 내보낼 때는 ATT&CK을 따른다."""
    tactics = TECHNIQUES.get(tech, {}).get("tactics") or []
    return stage if stage in tactics or not tactics else tactics[0]


def _attacks(findings: list[dict]) -> list[dict]:
    out, seen = [], set()
    for f in findings:
        tech = f.get("technique") or RULES.get(f.get("rule", ""), ("",))[0]
        stage = f.get("stage") or (RULES.get(f.get("rule", ""), ("", ""))[1])
        if not tech.startswith("T"):
            continue
        tac = attack_tactic(tech, stage)
        if (tech, tac) in seen:
            continue
        seen.add((tech, tac))
        a: dict = {"version": ATTACK_VERSION}
        base, _, sub = tech.partition(".")
        a["technique"] = {"uid": base, "name": TECHNIQUES.get(base, {}).get("name")}
        if sub:
            a["sub_technique"] = {"uid": tech, "name": TECHNIQUES.get(tech, {}).get("name")}
        if tac in TACTICS:
            uid, name = TACTICS[tac]
            a["tactic"] = {"uid": uid, "name": name}
        out.append(a)
    return out


def _analytic(rule: str) -> dict:
    title = RULES.get(rule, ("", "", rule))[2]
    return {"uid": rule, "name": rule, "desc": title, "type_id": 1, "type": "Rule"}


def incident_to_ocsf(inc: dict, run_uid: str = "") -> dict:
    """사건 하나(report.json의 results[].incident)를 Detection Finding으로."""
    sev = SEVERITY.get(inc.get("severity", ""), (0, "Unknown"))
    verdict = inc.get("verdict") or "unclear"
    rules = sorted({f["rule"] for f in inc.get("findings", [])})
    start, end = _ms(inc.get("start")), _ms(inc.get("end"))
    title = (RULES.get(rules[0], ("", "", rules[0]))[2] if rules else inc.get("id", ""))
    if len(rules) > 1:
        title += f" 외 {len(rules) - 1}개 규칙"
    obs = ([{"name": "src_endpoint.ip", "type_id": OBS_IP, "type": "IP Address", "value": ip}
            for ip in inc.get("src_ips", [])[:20]]
           + [{"name": "actor.user.name", "type_id": OBS_USER, "type": "User Name", "value": a}
              for a in inc.get("actors", [])[:20]]
           + [{"name": "resources.uid", "type_id": OBS_RESOURCE, "type": "Resource UID", "value": i}
              for i in inc.get("instances", [])[:20]])
    evidences = []
    for e in inc.get("events", [])[:20]:
        ev: dict = {"data": {k: e[k] for k in ("ref", "source", "action", "outcome") if e.get(k)}}
        if e.get("src_ip"):
            ev["src_endpoint"] = {"ip": e["src_ip"]}
        if e.get("actor"):
            ev["actor"] = {"user": {"name": e["actor"]}}
        evidences.append(ev)
    outcome = {}
    for e in inc.get("events", []):
        o = e.get("outcome") or "unknown"
        outcome[o] = outcome.get(o, 0) + 1
    uid = f"{run_uid}:{inc.get('id', '')}" if run_uid else inc.get("id", "")
    out = {
        "class_uid": CLASS_UID, "class_name": "Detection Finding",
        "category_uid": CATEGORY_UID, "category_name": "Findings",
        "activity_id": ACTIVITY_CREATE, "activity_name": "Create",
        "type_uid": CLASS_UID * 100 + ACTIVITY_CREATE, "type_name": "Detection Finding: Create",
        "severity_id": sev[0], "severity": sev[1],
        "status_id": 1, "status": "New",
        "time": end or start or 0,
        "start_time": start, "end_time": end,
        "message": title,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "LogFinder", "vendor_name": "LogFinder (logsight)", "version": __version__,
                        "url_string": "https://github.com/minyoungyu/logsight"},
            "uid": uid,
        },
        "finding_info": {
            "uid": uid, "title": title,
            "desc": "단계: " + ", ".join(inc.get("stages", [])),
            "types": rules,
            "first_seen_time": start, "last_seen_time": end,
            "data_sources": sorted(inc.get("sources", [])),
            "attacks": _attacks(inc.get("findings", [])),
        },
        "risk_level_id": RISK.get(verdict, (99, "Other"))[0],
        "risk_level": RISK.get(verdict, (99, "Other"))[1],
        "observables": obs,
        "evidences": evidences,
        "resources": [{"uid": i, "type": "AWS::EC2::Instance"} for i in inc.get("instances", [])[:20]],
        "unmapped": {"logfinder": {
            "incident_id": inc.get("id"), "verdict": verdict, "verdict_en": VERDICT_EN.get(verdict, verdict),
            "verdict_by": inc.get("verdict_by"), "score": inc.get("score"), "n_events": inc.get("n_events"),
            "event_outcomes": outcome,
            "contested": inc.get("contested"), "injection": bool(inc.get("injection")),
        }},
    }
    if rules:
        out["finding_info"]["analytic"] = _analytic(rules[0])
        if len(rules) > 1:
            out["finding_info"]["related_analytics"] = [_analytic(r) for r in rules[1:]]
    return _drop_none(out)


def _drop_none(x):
    if isinstance(x, dict):
        return {k: _drop_none(v) for k, v in x.items() if v is not None and v != [] and v != {}}
    if isinstance(x, list):
        return [_drop_none(v) for v in x]
    return x


def to_ocsf(result: dict) -> list[dict]:
    """report.json 전체 → 상세 분석한 사건마다 Detection Finding 하나."""
    run_uid = hashlib.sha256((result.get("generated_at", "") + str(result.get("files", ""))).encode()
                             ).hexdigest()[:12]
    return [incident_to_ocsf(r["incident"], run_uid) for r in result.get("results", [])]


# ---- MITRE ATT&CK Navigator 레이어(규칙이 덮는 기법) ----
def attack_layer() -> dict:
    """규칙 표(RULES)를 ATT&CK Navigator 레이어(4.5 형식)로. 웹 https://mitre-attack.github.io/attack-navigator/ 에서 연다."""
    techs: dict[tuple[str, str], list[str]] = {}
    for rule, (tech, stage, _title, _sev) in RULES.items():
        if not tech or not tech.startswith("T"):
            continue
        tac = attack_tactic(tech, stage)
        tac = tac if tac in TACTICS else ""
        techs.setdefault((tech, tac), []).append(rule)
    return {
        "name": f"LogFinder {__version__} 규칙 범위",
        "versions": {"attack": ATTACK_VERSION.split(".")[0], "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "LogFinder(logsight) 규칙이 표시하는 ATT&CK 기법. 탐지 범위이지 탐지 정확도가 아니다.",
        "techniques": [
            {"techniqueID": t, **({"tactic": tac} if tac else {}), "score": len(rs), "color": "",
             "comment": ", ".join(sorted(rs)), "enabled": True}
            for (t, tac), rs in sorted(techs.items())],
        "gradient": {"colors": ["#e7f1fb", "#3b7dd8"], "minValue": 0, "maxValue": 4},
        "legendItems": [], "showTacticRowBackground": False,
    }

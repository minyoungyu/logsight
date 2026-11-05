"""
사건 묶음(Incident)과 설정 점검 결과를 Claude에 넘겨 한국어 공격 흐름 해석과
방화벽/권한 수정안을 받는다.

- 원본 로그를 통째로 보내지 않는다. 탐지 표시가 붙은 축약 이벤트 + 맥락 집계만 보낸다.
- 구조화 출력(JSON 스키마)으로 형식을 강제하고, 돌아온 evidence가 실제 입력에 있는
  ref인지 코드로 다시 검사한다(환각 검증).
- ANTHROPIC_API_KEY가 없거나 호출이 실패하면 규칙 기반 분석(mock)으로 같은 형식을 만든다.
"""
from __future__ import annotations

import json
import os
import time

from .detect import RULES, STAGE_ORDER
from .guard import SYSTEM_RULE, fence

DEFAULT_MODEL = os.environ.get("LOGSIGHT_MODEL", "claude-haiku-5-5")

STAGE_KO = {
    "discovery": "정찰·탐색", "initial-access": "초기 침투", "credential-access": "자격증명 탈취",
    "persistence": "지속성 확보", "privilege-escalation": "권한 상승",
    "defense-evasion": "방어 회피", "collection": "데이터 수집", "exfiltration": "유출",
    "impact": "피해", "other": "기타",
}

_STR = {"type": "string"}
_STRS = {"type": "array", "items": _STR}

# Claude 구조화 출력 스키마. 제약: object마다 additionalProperties false, enum은 문자열만,
# minLength·maximum 같은 수치/길이 제약은 쓰지 않는다(클라이언트에서 검증).
REPORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": _STR,
        "severity": {"type": "string", "enum": ["low", "medium", "high"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "attack_flow": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "stage": {"type": "string", "enum": STAGE_ORDER},
                    "technique": _STR,
                    "time": _STR,
                    "what": _STR,
                    "evidence": _STRS,
                },
                "required": ["stage", "technique", "time", "what", "evidence"],
            },
        },
        "root_causes": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"setting": _STR, "why": _STR, "evidence": _STRS},
                "required": ["setting", "why", "evidence"],
            },
        },
        "firewall_changes": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "check_id": _STR,
                    "target": {"type": "string",
                               "enum": ["security_group", "nacl", "waf", "iam", "ec2",
                                        "cloudtrail", "other"]},
                    "resource": _STR,
                    "change": _STR,
                    "priority": {"type": "string", "enum": ["now", "soon", "later"]},
                },
                "required": ["check_id", "target", "resource", "change", "priority"],
            },
        },
        "unknowns": _STRS,
    },
    "required": ["summary", "severity", "confidence", "attack_flow", "root_causes",
                 "firewall_changes", "unknowns"],
}

SYSTEM = (
    "너는 보안 담당자가 없는 소규모 팀을 돕는 클라우드 보안 분석가다. 입력으로 받은 사건 "
    "(코드가 탐지·연결한 AWS 로그 이벤트 묶음)과 설정 점검 결과만 근거로 판단한다.\n"
    "규칙:\n"
    "1. 로그에 없는 사실은 추측하지 않는다. 확인할 수 없는 것은 unknowns에 적는다.\n"
    "2. 모든 evidence에는 입력 events의 ref 값만 그대로 적는다. 새로 만들지 않는다.\n"
    "3. attack_flow는 시간순으로, technique에는 MITRE ATT&CK 기법 ID를 적는다.\n"
    "4. firewall_changes는 입력 config_checks 중에서 골라 check_id를 그대로 쓰고, 우선순위를 "
    "정해 쉬운 한국어로 무엇을 바꾸는지 설명한다. 입력에 없는 변경이 꼭 필요하면 check_id를 "
    "'NEW'로 적는다. 변경은 사람이 검토 후 적용한다는 전제다.\n"
    "5. 비전문가가 읽는다. 짧고 쉬운 한국어로 쓴다.\n"
    "6. " + SYSTEM_RULE
)


def build_payload(incident: dict, checks: list[dict]) -> dict:
    """AI에 넘길 최소 입력."""
    return {
        "incident": {k: incident[k] for k in (
            "id", "start", "end", "severity", "stages", "src_ips", "instances", "actors",
            "n_events", "omitted_events", "findings", "context")},
        "events": fence(incident["events"]),
        "config_checks": [{k: c[k] for k in ("id", "target", "resource", "title", "why",
                                             "severity", "evidence")} for c in checks],
        "rule_catalog": {r: {"technique": v[0], "stage": v[1], "title": v[2]}
                         for r, v in RULES.items()
                         if r in {f["rule"] for f in incident["findings"]}},
    }


def analyze(incident: dict, checks: list[dict], model: str | None = None,
            use_ai: bool = True, verdict: dict | None = None) -> dict:
    """반환: {"report": ..., "meta": {...}}
    verdict: 규칙 판정(explain.verdict_for). 규칙 기반 설명의 첫 문장과 확신도에 쓴다."""
    payload = build_payload(incident, checks)
    meta = {"mode": "rules", "model": None, "payload_chars": len(json.dumps(payload, ensure_ascii=False))}
    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        t = time.time()
        try:
            report, usage = _call_claude(payload, model or DEFAULT_MODEL)
            meta.update(mode="claude", model=model or DEFAULT_MODEL, usage=usage,
                        seconds=round(time.time() - t, 1))
        except Exception as exc:  # noqa: BLE001 — 시연 중 실패하면 규칙 기반으로 계속
            meta.update(mode="rules", ai_error=f"{type(exc).__name__}: {exc}"[:300])
            report = rule_based(incident, checks, verdict)
    else:
        if use_ai:
            meta["note"] = "ANTHROPIC_API_KEY가 없어 규칙 기반 분석으로 생성"
        report = rule_based(incident, checks, verdict)
    meta["validation"] = validate(report, incident, checks)
    return {"report": report, "meta": meta}


def _call_claude(payload: dict, model: str) -> tuple[dict, dict]:
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=16000,
        system=SYSTEM,
        messages=[{"role": "user", "content":
                   "다음 사건을 분석해 보고서를 작성하라.\n\n"
                   + json.dumps(payload, ensure_ascii=False)}],
        output_config={"format": {"type": "json_schema", "schema": REPORT_SCHEMA}},
    )
    if resp.stop_reason == "refusal":
        cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise RuntimeError(f"모델이 응답을 거절함(category={cat})")
    if resp.stop_reason == "max_tokens":
        raise RuntimeError("출력이 max_tokens에서 잘림")
    text = next(b.text for b in resp.content if b.type == "text")
    usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
    return json.loads(text), usage


def validate(report: dict, incident: dict, checks: list[dict]) -> dict:
    """AI 판단의 근거가 실제 입력에 있는지 검사하고, 없는 근거는 표시한다."""
    refs = {e["ref"] for e in incident["events"]}
    for f in incident["findings"]:
        refs.update(f["evidence"])
    check_ids = {c["id"] for c in checks} | {"NEW"}
    total = bad = 0
    for sec in ("attack_flow", "root_causes"):
        for item in report.get(sec, []):
            ok = [r for r in item.get("evidence", []) if r in refs]
            wrong = [r for r in item.get("evidence", []) if r not in refs]
            total += len(item.get("evidence", []))
            bad += len(wrong)
            item["evidence"] = ok
            if wrong:
                item["unverified_evidence"] = wrong
    unknown_checks = [c.get("check_id") for c in report.get("firewall_changes", [])
                      if c.get("check_id") not in check_ids]
    no_evidence = sum(1 for it in report.get("attack_flow", []) if not it.get("evidence"))
    return {"evidence_total": total, "evidence_invalid": bad,
            "steps_without_evidence": no_evidence, "unknown_check_ids": unknown_checks,
            "passed": bad == 0 and no_evidence == 0 and not unknown_checks}


def rule_based(incident: dict, checks: list[dict], verdict: dict | None = None) -> dict:
    """API 키 없이 돌리는 분석기. 사건 유형별 문장 템플릿(explain.py)으로 같은 보고서 형식을 만든다.
    같은 입력이면 항상 같은 문장이 나온다."""
    from .explain import describe_finding, summarize, verdict_for
    verdict = verdict or verdict_for(incident)
    flow = []
    for f in sorted(incident["findings"], key=lambda f: f["first"]):
        flow.append({"stage": f["stage"], "technique": f["technique"], "time": f["first"],
                     "what": describe_finding(f, incident), "evidence": f["evidence"][:8]})
    pr = {"high": "now", "medium": "soon", "low": "later"}
    v = verdict["verdict"]
    unknowns = []
    if v == "attack":
        unknowns.append("규칙 기반 판정이라 공격 의도와 실제 피해 범위는 사람이 확인해야 합니다.")
        if not any(e.get("status") == "success" for e in incident["events"]):
            unknowns.append("보이는 시도는 모두 실패·차단이지만, 로그가 없는 다른 경로로 성공했는지는 알 수 없습니다.")
    elif v == "unclear":
        unknowns.append(verdict["reason"])
    elif v == "benign_activity":
        unknowns.append("정상 작업 목록과 일치해 정상으로 보았습니다. 목록의 계정·IP가 도용됐다면 판단이 틀릴 수 있습니다.")
    if incident.get("omitted_events"):
        unknowns.append(f"비슷한 이벤트 {incident['omitted_events']}건은 생략하고 대표 이벤트만 보았습니다.")
    return {
        "summary": summarize(incident, verdict, checks),
        "severity": incident["severity"],
        "confidence": verdict.get("confidence", "medium"),
        "verdict": v,
        "verdict_reason": verdict["reason"],
        "attack_flow": flow,
        "root_causes": [{"setting": c["title"], "why": c["why"], "evidence": c["evidence"][:6]}
                        for c in checks],
        "firewall_changes": [{"check_id": c["id"], "target": c["target"], "resource": c["resource"],
                              "change": c["title"], "priority": pr.get(c["severity"], "later")}
                             for c in checks],
        "unknowns": unknowns,
    }

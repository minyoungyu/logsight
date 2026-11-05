"""
사건 전체를 한 번에 Claude에 보여 주고 두 가지를 받는다.

1. 오탐 재검토: 사건마다 공격인지, 정상 활동인지, 공격은 아니지만 위험한 설정인지 판정
2. 공격 연결: 규칙이 따로 나눈 사건 중 같은 공격으로 보이는 것을 묶고 순서를 설명

규칙이 만든 사건만 보낸다(원본 로그 전체는 보내지 않는다). 돌아온 근거 ref와 사건 ID가
실제 입력에 있는지 코드로 다시 검사하고, 없는 것은 버린다. 판정은 순서만 바꾼다.
사건을 지우지 않으므로 AI가 틀려도 사람이 아래쪽에서 다시 볼 수 있다.
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict

from .guard import RANK, SYSTEM_RULE, fence, find_injection

TRIAGE_MODEL = os.environ.get("LOGSIGHT_TRIAGE_MODEL", "claude-opus-5-5")
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
VERDICTS = ["attack", "risky_not_attack", "unclear", "benign_activity"]
VERDICT_KO = {"attack": "공격", "risky_not_attack": "공격 아님·위험 설정",
              "unclear": "판단 불가", "benign_activity": "정상 활동"}

_STR = {"type": "string"}
_STRS = {"type": "array", "items": _STR}
_LEVEL = {"type": "string", "enum": ["low", "medium", "high"]}

TRIAGE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "incidents": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "id": _STR,
                    "verdict": {"type": "string", "enum": VERDICTS},
                    "confidence": _LEVEL,
                    "reason": _STR,
                    "evidence": _STRS,
                },
                "required": ["id", "verdict", "confidence", "reason", "evidence"],
            },
        },
        "campaigns": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "incident_ids": _STRS,
                    "summary": _STR,
                    "link_reason": _STR,
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object", "additionalProperties": False,
                            "properties": {"incident_id": _STR, "time": _STR, "what": _STR,
                                           "evidence": _STRS},
                            "required": ["incident_id", "time", "what", "evidence"],
                        },
                    },
                },
                "required": ["incident_ids", "summary", "link_reason", "steps"],
            },
        },
        "cannot_tell": _STRS,
    },
    "required": ["incidents", "campaigns", "cannot_tell"],
}

SYSTEM = (
    "너는 AWS 로그를 보는 보안 분석가다. 입력은 규칙 기반 탐지가 만든 사건 목록이다. "
    "규칙은 행동만 보고 표시하므로, 운영자·대응팀의 정상 작업과 실제 공격이 섞여 있다.\n"
    "할 일:\n"
    "1. 사건마다 verdict를 정한다. attack: 외부 공격자의 행위. benign_activity: 계정 주인이나 "
    "운영·대응팀의 정상 작업, AWS 서비스 자체 동작. risky_not_attack: 공격은 아니지만 고쳐야 할 "
    "위험한 사용(예: 루트 계정 일상 사용). unclear: 입력만으로 판단할 수 없음.\n"
    "2. 같은 공격자가 한 것으로 보이는 사건들을 campaigns로 묶고, 무엇이 둘을 잇는지 link_reason에 "
    "적는다(같은 IP, 같은 키, 같은 인스턴스, 같은 대역과 시간 연속성 등). 공격 사건이 하나뿐이면 "
    "그 하나로 campaign을 만든다. 정상 활동 사건은 넣지 않는다.\n"
    "3. 이 로그만으로는 알 수 없는 것(예: 키가 어떻게 유출됐는지, 로그가 끊긴 뒤의 일)을 "
    "cannot_tell에 적는다. coverage에는 입력 로그의 종류·기간과, 탈취가 의심되는 키의 전체 사용 "
    "내역이 있다. 공격 흐름상 있을 법한 단계(공격자의 정찰, 데이터 읽기·반출 등)가 이 로그에 "
    "남을 수 없거나 남아 있지 않으면, 없었다고 단정하지 말고 무엇이 왜 보이지 않는지 적는다.\n"
    "규칙: 입력에 없는 사실을 만들지 않는다. evidence에는 입력 events의 ref만 그대로 쓴다. "
    "IP 대역의 소유자는 입력에 적혀 있을 때만 근거로 쓰고, 그 밖에는 입력에 적힌 사실(주체 이름, "
    "호출 종류, 성공·실패, 시간)로 판단한다. 짧고 쉬운 한국어로 쓴다.\n"
    + SYSTEM_RULE
)


def _sample(events: list[dict], n: int) -> list[dict]:
    """사건 안의 이벤트를 앞·중간·뒤에서 고르게 n개 고른다."""
    if len(events) <= n:
        return events
    step = (len(events) - 1) / (n - 1)
    return [events[round(i * step)] for i in range(n)]


EXPECTED_SOURCES = ("cloudtrail", "vpcflow", "waf", "alb", "sshauth")
S3_OBJECT_CALLS = {"s3:GetObject", "s3:PutObject", "s3:CopyObject", "s3:DeleteObject",
                   "s3:HeadObject"}


def coverage_summary(events: list, max_keys: int = 10) -> dict:
    """입력 로그가 무엇을 담고 무엇을 못 담는지 요약한다. AI가 '로그에 없음'과 '일어나지 않음'을
    구별하게 하려는 것이다. 탈취가 의심되는 키(자격증명 규칙에 걸린 키)는 사건 밖의 호출까지
    모두 센다. 규칙이 사건에 넣지 않은 정찰·조회 호출이 있는지 AI가 직접 보게 한다."""
    by_src: dict[str, list] = defaultdict(list)
    for e in events:
        by_src[e.source].append(e.ts)
    ct = [e for e in events if e.source == "cloudtrail"]
    sus = Counter(e.access_key for e in ct if e.access_key and any(
        r.startswith(("CT_INSTANCE_CRED", "CT_UNTRUSTED_IP")) for r in e.findings))
    keys = []
    for k, _ in sus.most_common(max_keys):
        evs = [e for e in ct if e.access_key == k]
        acts = Counter((e.action, e.outcome) for e in evs)
        keys.append({
            "access_key": k, "n_calls": len(evs),
            "first": min(e.ts for e in evs).isoformat(), "last": max(e.ts for e in evs).isoformat(),
            "src_ips": sorted({e.src_ip or "?" for e in evs})[:10],
            "calls": [{"action": a, "outcome": o, "n": n} for (a, o), n in acts.most_common(20)],
        })
    return {
        "sources": {s: {"n_events": len(ts), "first": min(ts).isoformat(), "last": max(ts).isoformat()}
                    for s, ts in sorted(by_src.items())},
        "missing_sources": [s for s in EXPECTED_SOURCES if s not in by_src],
        "cloudtrail_s3_object_calls": sum(1 for e in ct if e.action in S3_OBJECT_CALLS),
        "suspected_keys": keys,
    }


def build_triage_payload(incidents: list[dict], max_incidents: int = 30,
                         events_per_incident: int = 12, coverage: dict | None = None) -> dict:
    out = []
    for inc in incidents[:max_incidents]:
        out.append({
            "id": inc["id"], "start": inc["start"], "end": inc["end"],
            "rule_severity": inc["severity"], "stages": inc["stages"],
            "src_ips": inc["src_ips"][:10], "instances": inc["instances"][:10],
            "actors": inc["actors"][:10], "sources": inc["sources"], "n_events": inc["n_events"],
            "findings": [{k: f[k] for k in ("rule", "title", "detail", "key", "n_events")}
                         for f in inc["findings"]],
            "top_actions_nearby": inc.get("context", {}).get("top_actions", []),
            "events": fence(_sample(inc["events"], events_per_incident)),
        })
    payload = {"incidents": out, "n_incidents_total": len(incidents)}
    if coverage:
        payload["coverage"] = coverage
    return payload


def triage(incidents: list[dict], model: str | None = None, use_ai: bool = True,
           events: list | None = None) -> dict | None:
    """키가 없거나 AI를 끄면 None(규칙 순서 그대로). 실패해도 None과 오류를 돌려준다.
    events를 주면 로그 범위 요약(coverage)을 함께 보낸다."""
    if not incidents or not use_ai or not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    payload = build_triage_payload(incidents, coverage=coverage_summary(events) if events else None)
    model = model or TRIAGE_MODEL
    t = time.time()
    try:
        result, usage = _call_claude(payload, model)
    except Exception as exc:  # noqa: BLE001 — AI가 실패해도 규칙 결과는 그대로 쓴다
        return {"error": f"{type(exc).__name__}: {exc}"[:300], "model": model}
    result["validation"] = validate_triage(result, payload)
    result["meta"] = {"model": model, "usage": usage, "seconds": round(time.time() - t, 1),
                      "payload_chars": len(json.dumps(payload, ensure_ascii=False))}
    return result


def _call_claude(payload: dict, model: str) -> tuple[dict, dict]:
    import anthropic

    client = anthropic.Anthropic()
    extra = {}
    if model in FALLBACK_MODELS:
        # 안전 분류기가 거절하면 서버가 다른 모델로 다시 돌린다(공격 로그는 오인되기 쉽다)
        extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
    resp = client.beta.messages.create(
        model=model,
        max_tokens=16000,
        system=SYSTEM,
        messages=[{"role": "user", "content":
                   "다음 사건들을 재검토하라.\n\n" + json.dumps(payload, ensure_ascii=False)}],
        output_config={"effort": "high",
                       "format": {"type": "json_schema", "schema": TRIAGE_SCHEMA}},
        **extra,
    )
    if resp.stop_reason == "refusal":
        cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise RuntimeError(f"모델이 응답을 거절함(category={cat})")
    if resp.stop_reason == "max_tokens":
        raise RuntimeError("출력이 max_tokens에서 잘림")
    text = next(b.text for b in resp.content if b.type == "text")
    usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens,
             "served_by": resp.model}
    return json.loads(text), usage


def validate_triage(result: dict, payload: dict) -> dict:
    """없는 사건 ID와 입력에 없는 근거 ref를 걸러 낸다(결과를 고쳐 쓴다)."""
    ids = {i["id"] for i in payload["incidents"]}
    refs_of = {i["id"]: {e["ref"] for e in i["events"]} for i in payload["incidents"]}
    all_refs = set().union(*refs_of.values()) if refs_of else set()
    bad_ids, bad_refs, total_refs = [], 0, 0
    seen, verdicts = set(), []
    for v in result.get("incidents", []):
        if v.get("id") not in ids or v["id"] in seen:
            bad_ids.append(v.get("id"))
            continue
        seen.add(v["id"])
        ok = [r for r in v.get("evidence", []) if r in refs_of[v["id"]]]
        total_refs += len(v.get("evidence", []))
        bad_refs += len(v.get("evidence", [])) - len(ok)
        v["evidence"] = ok
        verdicts.append(v)
    result["incidents"] = verdicts
    camps = []
    for c in result.get("campaigns", []):
        members = [i for i in c.get("incident_ids", []) if i in ids]
        bad_ids += [i for i in c.get("incident_ids", []) if i not in ids]
        if not members:
            continue
        c["incident_ids"] = members
        for s in c.get("steps", []):
            ok = [r for r in s.get("evidence", []) if r in all_refs]
            total_refs += len(s.get("evidence", []))
            bad_refs += len(s.get("evidence", [])) - len(ok)
            s["evidence"] = ok
        camps.append(c)
    result["campaigns"] = camps
    missing = sorted(ids - seen)
    return {"unknown_ids": bad_ids, "evidence_total": total_refs, "evidence_invalid": bad_refs,
            "incidents_without_verdict": missing,
            "passed": not bad_ids and not bad_refs and not missing}


def reorder(incidents: list[dict], result: dict | None) -> list[dict]:
    """공격 → 위험 설정 → 판단 불가 → 정상 활동 순으로 정렬. 같은 판정 안에서는 규칙 순서를
    지킨다. 판정이 없는 사건은 '판단 불가'로 둔다. 사건 자체는 지우지 않는다.
    판정은 inc["verdict"]와 inc["verdict_by"]("claude" 또는 "rules")에 적는다.
    Claude 판정이면 inc["ai_verdict"]에도 같은 값을 적는다(이전 형식 호환).
    규칙이 공격으로 본 것을 AI가 낮춘 사건(guard.hold의 contested)은 '판단 불가'보다 아래로 가지 않는다.
    로그에 AI를 속이려는 문장이 있으면 inc["injection"]에 적는다(규칙 판정일 때도)."""
    if not result or "incidents" not in result:
        return incidents
    by = "rules" if result.get("mode") == "rules" else "claude"
    rows = {x["id"]: x for x in result["incidents"]}
    for inc in incidents:
        row = rows.get(inc["id"], {})
        inc["verdict"] = row.get("verdict", "unclear")
        inc["verdict_by"] = by
        if by == "claude":
            inc["ai_verdict"] = inc["verdict"]
        else:
            inc.pop("ai_verdict", None)
        for k in ("contested", "ai_said"):
            if row.get(k):
                inc[k] = row[k]
            else:
                inc.pop(k, None)
        hits = row.get("injection") or find_injection(inc["events"])
        if hits:
            inc["injection"] = hits
        else:
            inc.pop("injection", None)

    def key(i):
        r = RANK[i["verdict"]]
        return min(r, RANK["unclear"]) if i.get("contested") else r
    return sorted(incidents, key=key)  # 안정 정렬

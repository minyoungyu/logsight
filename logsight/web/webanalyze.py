"""
웹 사건을 Claude에 넘겨 "이미 뚫렸는가?" 판정과 조치안을 받는다.

원칙은 AWS 분석(analyze.py)과 같다: 원본 로그를 통째로 보내지 않고 탐지된 축약 이벤트와
맥락 집계만 보낸다. 돌아온 근거(evidence ref)가 실제 입력에 있는지 코드로 다시 검사하고,
API 키가 없거나 호출이 실패하면 규칙 기반으로 같은 형식을 만든다.

AWS 분석과 다른 점은 (1) 침해 여부 판정(verdict)을 맨 앞에 두고, (2) 조치안의 대상이
방화벽·IAM이 아니라 파일·앱·서버·계정이라는 점이다.
"""
from __future__ import annotations

import json
import os
import time

from ..detect import RULES, STAGE_ORDER
from ..analyze import STAGE_KO

DEFAULT_MODEL = os.environ.get("LOGSIGHT_MODEL", "claude-haiku-5-5")

VERDICT_KO = {
    "breached": "침해 확인",
    "likely_breached": "침해 가능성 높음",
    "suspicious": "공격 시도 있음(성공 근거 불명확)",
    "no_evidence": "뚜렷한 침해 근거 없음",
}

# 침해가 "성공했을" 가능성을 강하게 가리키는 규칙(정찰·단순 시도와 구분)
SUCCESS_SIGNAL = {
    "FILE_WEBSHELL", "WEBLOG_WEBSHELL_ACCESS", "WEBLOG_UPLOAD_EXEC",
    "WEBLOG_AUTH_SUCCESS_AFTER_FAIL", "SSH_SUCCESS_AFTER_FAIL",
    "WEBLOG_EXPLOIT_5XX", "WEBLOG_LARGE_EXFIL", "WEBLOG_ADMIN_ACCESS", "WEBLOG_CODE_IN_HEADER",
    "WEBLOG_ADMIN_FORGED", "WEBLOG_IDOR_ENUM", "WEBLOG_BACKUP_LEAK", "WEBLOG_SSRF",
}
ATTEMPT_SIGNAL = {
    "WEBLOG_SQLI", "WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION",
    "WEBLOG_XSS", "WEBLOG_AUTH_BRUTE", "SSH_BRUTE_FORCE", "FILE_SUSPICIOUS",
    "WEBLOG_SENSITIVE_FILE", "WEBLOG_OPEN_REDIRECT", "WEBLOG_CSRF_SUSPECT",
    "WEBLOG_EXPLOIT_PROBE", "WEBLOG_DIR_LISTING",
}

_STR = {"type": "string"}
_STRS = {"type": "array", "items": _STR}

WEB_REPORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["breached", "likely_breached", "suspicious", "no_evidence"]},
        "summary": _STR,
        "severity": {"type": "string", "enum": ["low", "medium", "high"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "attack_flow": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "stage": {"type": "string", "enum": STAGE_ORDER},
                    "technique": _STR, "time": _STR, "what": _STR, "evidence": _STRS,
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
        "remediation": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "action": _STR,
                    "target": {"type": "string",
                               "enum": ["file", "app", "server", "waf", "account",
                                        "network", "patch", "other"]},
                    "detail": _STR,
                    "priority": {"type": "string", "enum": ["now", "soon", "later"]},
                    "evidence": _STRS,
                },
                "required": ["action", "target", "detail", "priority", "evidence"],
            },
        },
        "unknowns": _STRS,
    },
    "required": ["verdict", "summary", "severity", "confidence", "attack_flow",
                 "root_causes", "remediation", "unknowns"],
}

SYSTEM = (
    "너는 보안 담당자가 없는 소규모 팀의 리눅스 웹서버를 봐 주는 침해사고 분석가다. 입력으로 "
    "받은 사건(코드가 탐지·연결한 웹·인증 로그와 웹 루트 파일 점검 결과)만 근거로 판단한다.\n"
    "규칙:\n"
    "1. 로그·파일 점검에 없는 사실은 추측하지 않는다. 확인 못 한 것은 unknowns에 적는다.\n"
    "2. verdict는 근거로 고른다. 웹셸 파일·업로드 스크립트 실행·공격 뒤 로그인 성공·공격에 "
    "500 응답·큰 응답 유출처럼 '성공' 근거가 있으면 breached/likely_breached, 공격 '시도'만 "
    "보이면 suspicious, 뚜렷한 근거가 없으면 no_evidence.\n"
    "3. 모든 evidence에는 입력 events의 ref 값만 그대로 적는다. 새로 만들지 않는다.\n"
    "4. attack_flow는 시간순, technique에는 MITRE ATT&CK 기법 ID.\n"
    "5. remediation은 지금 당장 할 일(now)부터. 웹셸 삭제·계정 잠금·취약 코드 수정처럼 구체적으로.\n"
    "6. 비전문가가 읽는다. 짧고 쉬운 한국어로, 겁주지 말고 사실만."
)


def rule_verdict(findings: list[dict]) -> tuple[str, str]:
    rules = {f["rule"] for f in findings}
    hit_success = rules & SUCCESS_SIGNAL
    hit_attempt = rules & ATTEMPT_SIGNAL
    if "FILE_WEBSHELL" in rules or "WEBLOG_UPLOAD_EXEC" in rules:
        return "breached", "high"
    if hit_success:
        return "likely_breached", "high"
    if hit_attempt:
        return "suspicious", "medium"
    return "no_evidence", "low"


def build_payload(incident: dict, profile_dict: dict | None = None) -> dict:
    return {
        "site": {k: profile_dict.get(k) for k in ("name", "stack")} if profile_dict else {},
        "incident": {k: incident[k] for k in (
            "id", "start", "end", "severity", "stages", "src_ips", "actors",
            "n_events", "omitted_events", "findings", "context")},
        "events": incident["events"],
        "rule_catalog": {r: {"technique": v[0], "stage": v[1], "title": v[2]}
                         for r, v in RULES.items()
                         if r in {f["rule"] for f in incident["findings"]}},
    }


def analyze_web(incident: dict, profile_dict: dict | None = None, model: str | None = None,
                use_ai: bool = True) -> dict:
    payload = build_payload(incident, profile_dict)
    meta = {"mode": "rules", "model": None,
            "payload_chars": len(json.dumps(payload, ensure_ascii=False))}
    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        t = time.time()
        try:
            report, usage = _call_claude(payload, model or DEFAULT_MODEL)
            meta.update(mode="claude", model=model or DEFAULT_MODEL, usage=usage,
                        seconds=round(time.time() - t, 1))
        except Exception as exc:  # noqa: BLE001 — 시연 중 실패하면 규칙 기반으로 계속
            meta.update(mode="rules", ai_error=f"{type(exc).__name__}: {exc}"[:300])
            report = rule_based(incident)
    else:
        if use_ai:
            meta["note"] = "ANTHROPIC_API_KEY가 없어 규칙 기반 분석으로 생성"
        report = rule_based(incident)
    meta["validation"] = validate(report, incident)
    return {"report": report, "meta": meta}


def _call_claude(payload: dict, model: str) -> tuple[dict, dict]:
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model, max_tokens=16000, system=SYSTEM,
        messages=[{"role": "user", "content":
                   "다음 사건을 분석해 침해 여부를 판정하라.\n\n"
                   + json.dumps(payload, ensure_ascii=False)}],
        output_config={"format": {"type": "json_schema", "schema": WEB_REPORT_SCHEMA}},
    )
    if resp.stop_reason == "refusal":
        cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise RuntimeError(f"모델이 응답을 거절함(category={cat})")
    if resp.stop_reason == "max_tokens":
        raise RuntimeError("출력이 max_tokens에서 잘림")
    text = next(b.text for b in resp.content if b.type == "text")
    usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
    return json.loads(text), usage


def validate(report: dict, incident: dict) -> dict:
    """AI 판단의 근거가 실제 입력 events에 있는지 검사한다(환각 거르기)."""
    refs = {e["ref"] for e in incident["events"]}
    for f in incident["findings"]:
        refs.update(f.get("evidence", []))
    total = bad = 0
    for sec in ("attack_flow", "root_causes", "remediation"):
        for item in report.get(sec, []):
            ev = item.get("evidence", [])
            ok = [r for r in ev if r in refs]
            wrong = [r for r in ev if r not in refs]
            total += len(ev)
            bad += len(wrong)
            item["evidence"] = ok
            if wrong:
                item["unverified_evidence"] = wrong
    no_evidence = sum(1 for it in report.get("attack_flow", []) if not it.get("evidence"))
    return {"evidence_total": total, "evidence_invalid": bad,
            "steps_without_evidence": no_evidence,
            "passed": bad == 0 and no_evidence == 0}


def rule_based(incident: dict) -> dict:
    """API 키 없이 돌리는 분석기. 탐지 결과를 같은 보고서 형식으로 옮기고 verdict를 계산한다."""
    findings = incident["findings"]
    verdict, sev = rule_verdict(findings)
    flow = []
    for f in sorted(findings, key=lambda f: f["first"]):
        flow.append({"stage": f["stage"], "technique": f["technique"], "time": f["first"],
                     "what": f"{f['title']} — {f['detail']}" + (f" (대상: {f['key']})" if f.get("key") else ""),
                     "evidence": f["evidence"][:8]})
    who = ", ".join(incident["src_ips"][:3]) or "알 수 없는 출발지"
    stages = " → ".join(STAGE_KO.get(s, s) for s in incident["stages"])
    verdict_line = {
        "breached": "웹셸 등 침해 성공의 직접 근거가 보인다.",
        "likely_breached": "공격이 성공했을 가능성이 큰 근거가 보인다.",
        "suspicious": "공격 시도는 보이지만 성공 근거는 로그에서 확인되지 않는다.",
        "no_evidence": "뚜렷한 침해 근거는 보이지 않는다.",
    }[verdict]
    summary = (f"{incident['start'][:16].replace('T', ' ')}~{incident['end'][11:16]}(UTC) "
               f"{who}의 활동 {incident['n_events']}건이 하나로 이어진다. 흐름: {stages}. {verdict_line}")
    remediation = _remediation(findings)
    return {
        "verdict": verdict, "summary": summary, "severity": sev, "confidence": "medium",
        "attack_flow": flow,
        "root_causes": [],
        "remediation": remediation,
        "unknowns": ["규칙 기반 분석이라 실제 피해 범위와 공격 성공 여부는 사람이 확인해야 한다."
                     " (웹 로그는 보통 POST 본문을 남기지 않아 공격 성공을 로그만으로 단정하기 어렵다.)"],
    }


def _remediation(findings: list[dict]) -> list[dict]:
    rules = {f["rule"]: f for f in findings}
    out: list[dict] = []
    if "FILE_WEBSHELL" in rules or "WEBLOG_WEBSHELL_ACCESS" in rules or "WEBLOG_UPLOAD_EXEC" in rules:
        f = rules.get("FILE_WEBSHELL") or rules.get("WEBLOG_WEBSHELL_ACCESS") or rules["WEBLOG_UPLOAD_EXEC"]
        out.append({"action": "웹셸 의심 파일 격리", "target": "file", "priority": "now",
                    "detail": "표시된 파일을 삭제하지 말고 먼저 복사해 보관한 뒤 서비스에서 분리하고, "
                              "업로드 폴더에서 스크립트 실행을 막는다.",
                    "evidence": f["evidence"][:6]})
    if "WEBLOG_AUTH_SUCCESS_AFTER_FAIL" in rules or "SSH_SUCCESS_AFTER_FAIL" in rules:
        f = rules.get("WEBLOG_AUTH_SUCCESS_AFTER_FAIL") or rules["SSH_SUCCESS_AFTER_FAIL"]
        out.append({"action": "탈취 의심 계정 잠그고 비밀번호·키 교체", "target": "account", "priority": "now",
                    "detail": "해당 계정의 세션을 끊고 비밀번호와 SSH 키를 바꾼다. 가능하면 다중 인증을 켠다.",
                    "evidence": f["evidence"][:6]})
    if "WEBLOG_SQLI" in rules:
        out.append({"action": "SQL 인젝션 취약 코드 수정", "target": "app", "priority": "soon",
                    "detail": "해당 파라미터를 매개변수화된 질의(prepared statement)로 바꾸고, DB 계정 권한을 최소화한다.",
                    "evidence": rules["WEBLOG_SQLI"]["evidence"][:6]})
    if rules.keys() & {"WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION"}:
        f = next(rules[r] for r in ("WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION") if r in rules)
        out.append({"action": "입력값 검증·경로 제한 적용", "target": "app", "priority": "soon",
                    "detail": "파일 경로·외부 URL·명령에 사용자 입력이 그대로 들어가지 않게 막고, 화이트리스트로 검증한다.",
                    "evidence": f["evidence"][:6]})
    if rules.keys() & {"WEBLOG_SCANNER", "WEBLOG_ENUM_404", "WEBLOG_AUTH_BRUTE", "SSH_BRUTE_FORCE"}:
        out.append({"action": "비정상 출발지 차단·요청 제한", "target": "network", "priority": "soon",
                    "detail": "공격 출발지 IP를 방화벽/fail2ban으로 제한하고, 로그인·관리자 경로에 접근 제어와 시도 제한을 둔다.",
                    "evidence": []})
    out.append({"action": "로그 보존 기간 늘리기", "target": "server", "priority": "later",
                "detail": "웹·인증 로그 보관 기간을 늘려(기본 14일은 너무 짧다) 다음 사고 때 더 멀리 되짚을 수 있게 한다.",
                "evidence": []})
    return out

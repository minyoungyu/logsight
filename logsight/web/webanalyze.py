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
from ..guard import SYSTEM_RULE, fence, find_injection

DEFAULT_MODEL = os.environ.get("LOGSIGHT_MODEL", "claude-haiku-5-5")

VERDICT_KO = {
    "breached": "침해 확인",
    "likely_breached": "침해 가능성 높음",
    "suspicious": "공격 시도 있음(성공 근거 불명확)",
    "no_evidence": "뚜렷한 침해 근거 없음",
}

VERDICT_RANK = {"no_evidence": 0, "suspicious": 1, "likely_breached": 2, "breached": 3}

# 침해가 "성공했을" 가능성을 강하게 가리키는 규칙(정찰·단순 시도와 구분)
SUCCESS_SIGNAL = {
    "FILE_WEBSHELL", "WEBLOG_WEBSHELL_ACCESS", "WEBLOG_UPLOAD_EXEC",
    "WEBLOG_AUTH_SUCCESS_AFTER_FAIL", "SSH_SUCCESS_AFTER_FAIL",
    "WEBLOG_EXPLOIT_5XX", "WEBLOG_LARGE_EXFIL", "WEBLOG_ADMIN_ACCESS", "WEBLOG_CODE_IN_HEADER",
    "WEBLOG_ADMIN_FORGED", "WEBLOG_IDOR_ENUM", "WEBLOG_BACKUP_LEAK", "WEBLOG_SSRF", "WEBLOG_SSRF_IMDS",
    "HOST_PRIV_ESC", "HOST_ACCOUNT_CREATED",
}
WEAK_SUCCESS = {"WEBLOG_WEBSHELL_ACCESS", "WEBLOG_LARGE_EXFIL", "WEBLOG_ADMIN_ACCESS"}
ATTEMPT_SIGNAL = {
    "WEBLOG_SQLI", "WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION",
    "WEBLOG_XSS", "WEBLOG_AUTH_BRUTE", "SSH_BRUTE_FORCE", "FILE_SUSPICIOUS",
    "WEBLOG_SENSITIVE_FILE", "WEBLOG_OPEN_REDIRECT", "WEBLOG_CSRF_SUSPECT",
    "WEBLOG_EXPLOIT_PROBE", "WEBLOG_DIR_LISTING", "HOST_PRIV_ESC_FAIL",
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
    "6. 비전문가가 읽는다. 짧고 쉬운 한국어로, 겁주지 말고 사실만.\n"
    "7. " + SYSTEM_RULE
)


def rule_verdict(findings: list[dict]) -> tuple[str, str]:
    rules = {f["rule"] for f in findings}
    hit_success = rules & SUCCESS_SIGNAL
    hit_attempt = rules & ATTEMPT_SIGNAL
    if "FILE_WEBSHELL" in rules or "WEBLOG_UPLOAD_EXEC" in rules:
        return "breached", "high"
    # 약한 성공 신호 하나만으로는 "침해 가능성 높음"으로 올리지 않는다. 같은 사건에 공격 시도나
    # 다른 성공 신호가 함께 있어야 한다(정상 앱의 요청이 패턴 하나에 걸린 오탐을 막는다).
    if hit_success and (hit_success - WEAK_SUCCESS or hit_attempt or len(hit_success) >= 2):
        return "likely_breached", "high"
    if hit_success:
        return "suspicious", "medium"
    if hit_attempt:
        return "suspicious", "medium"
    return "no_evidence", "low"


def build_payload(incident: dict, profile_dict: dict | None = None) -> dict:
    return {
        "site": {k: profile_dict.get(k) for k in ("name", "stack")} if profile_dict else {},
        "incident": {k: incident[k] for k in (
            "id", "start", "end", "severity", "stages", "src_ips", "actors",
            "n_events", "omitted_events", "findings", "context")},
        "events": fence(incident["events"]),  # 공격자가 쓴 값은 untrusted 아래로(guard.py)
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
    _hold(report, incident, meta)
    return {"report": report, "meta": meta}


def _hold(report: dict, incident: dict, meta: dict) -> None:
    """AI 판정이 규칙 판정보다 낮을 때 로그를 통한 프롬프트 주입을 막는다(guard.hold의 웹 점검판).
    - 로그에 AI 판정을 바꾸려는 문장이 있으면: 규칙 판정으로 되돌리고 AI가 낸 값은 ai_said에 남긴다.
    - 그런 문장이 없으면: AI 판정을 보여 주되 contested(규칙과 의견 다름)로 표시한다.
    주입 문장은 AI를 쓰지 않았을 때도 사건의 공격 정황으로 기록한다."""
    hits = find_injection(incident["events"])
    if hits:
        report["injection"] = hits
    if meta.get("mode") != "claude":
        return
    rule_v, _ = rule_verdict(incident["findings"])
    ai_v = report.get("verdict")
    if VERDICT_RANK.get(ai_v, 0) >= VERDICT_RANK[rule_v]:
        return
    if hits:
        report["ai_said"] = ai_v
        report["verdict"] = rule_v
        report["summary"] = (f"로그에 AI 판정을 바꾸려는 문장이 있어 AI의 '{VERDICT_KO.get(ai_v, ai_v)}' 판정을 "
                             f"따르지 않았습니다({hits[0]['ref']}). " + report.get("summary", ""))
        meta["guard"] = "restored"
    else:
        report["contested"] = {"rules": rule_v, "ai": ai_v}
        meta["guard"] = "contested"


def _call_claude(payload: dict, model: str) -> tuple[dict, dict]:
    import anthropic
    from ..aisend import announce

    announce("웹서버 점검", payload, model)  # 사양서 NFR-25: 보내기 전에 무엇을 얼마나 어디로

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
    from ..explain import _span
    summary = (f"{_span(incident['start'], incident['end'])} "
               f"{who}의 활동 {incident['n_events']}건이 하나로 이어진다. 흐름: {stages}. {verdict_line}")
    remediation = _remediation(findings, incident.get("events", []))
    return {
        "verdict": verdict, "summary": summary, "severity": sev, "confidence": "medium",
        "attack_flow": flow,
        "root_causes": [],
        "remediation": remediation,
        "unknowns": [_unknown_line(verdict)],
    }


def _unknown_line(verdict: str) -> str:
    """판정과 어긋나지 않는 '확인할 점'(사양서 FR-26: '침해 확인' 옆에 '단정하기 어렵다'를 쓰지 않는다)."""
    if verdict == "breached":
        return ("침해의 직접 근거가 있어 침해로 판정했다. 다만 공격자가 서버에서 무엇을 더 했는지(읽은 파일, 바꾼 설정)는 "
                "웹 로그에 남지 않으므로 서버를 직접 확인해야 한다.")
    if verdict == "likely_breached":
        return ("성공했을 가능성이 큰 근거가 있지만 웹 로그는 요청 본문과 응답 내용을 남기지 않아 확정하지 못했다. "
                "응답 크기·서버 오류 로그와 DB 기록을 함께 확인한다.")
    return ("규칙 기반 분석이라 공격이 성공했는지는 사람이 확인해야 한다. "
            "웹 로그는 보통 POST 본문을 남기지 않아 공격 성공을 로그만으로 단정하기 어렵다.")


def _remediation(findings: list[dict], events: list[dict] = ()) -> list[dict]:
    """조치안. 사건 이벤트에서 계정·파일·파라미터·IP 이름을 채운다(사양서 FR-24: 자리 표시 문구 금지)."""
    from .. import outcome as oc
    rules = {f["rule"]: f for f in findings}
    out: list[dict] = []
    events = list(events)
    files, abused = oc.webshell_files(events)
    accounts = oc.logged_in_accounts(events)
    created = sorted({f.get("key") for f in findings if f["rule"] == "HOST_ACCOUNT_CREATED" and f.get("key")})
    ips = oc.attacker_ips(events)
    if "FILE_WEBSHELL" in rules or "WEBLOG_WEBSHELL_ACCESS" in rules or "WEBLOG_UPLOAD_EXEC" in rules:
        f = rules.get("FILE_WEBSHELL") or rules.get("WEBLOG_WEBSHELL_ACCESS") or rules["WEBLOG_UPLOAD_EXEC"]
        if files:
            res = ", ".join(files[:3])
            detail = (f"{res} 파일을 삭제하지 말고 먼저 복사해 보관한 뒤 서비스에서 분리하고, "
                      "업로드 폴더에서 스크립트 실행을 막는다.")
        elif abused:
            res = ", ".join(abused[:3])
            detail = (f"{res}가 명령 실행에 악용됐다(앱 파일이므로 지우지 말 것). 이 파일이 사용자 입력으로 다른 파일을 "
                      "읽거나 실행하지 못하게 코드를 고치고, 접속 로그처럼 공격자가 글을 남길 수 있는 파일을 포함하지 않게 한다.")
        else:
            res = "로그에 파일 경로 없음"
            detail = "웹 루트에서 최근 바뀐 스크립트 파일을 찾아 복사해 보관한 뒤 서비스에서 분리한다."
        out.append({"id": "WEB_FIX_WEBSHELL", "action": "웹셸 의심 파일 격리: " + res if files else
                    ("악용된 앱 파일 고치기: " + res if abused else "웹셸 의심 파일 찾아 격리"),
                    "target": "file", "priority": "now", "resource": res, "detail": detail,
                    "evidence": f["evidence"][:6]})
    if "WEBLOG_AUTH_SUCCESS_AFTER_FAIL" in rules or "SSH_SUCCESS_AFTER_FAIL" in rules:
        f = rules.get("WEBLOG_AUTH_SUCCESS_AFTER_FAIL") or rules["SSH_SUCCESS_AFTER_FAIL"]
        res = ", ".join(accounts[:3]) or "로그에 계정 이름 없음"
        out.append({"id": "WEB_FIX_ACCOUNT", "action": f"탈취 의심 계정 잠그고 비밀번호·키 교체: {res}",
                    "target": "account", "priority": "now", "resource": res,
                    "detail": (f"{res} 계정의 세션을 끊고 비밀번호와 SSH 키를 바꾼다" if accounts else
                               "로그인에 성공한 계정의 세션을 끊고 비밀번호와 SSH 키를 바꾼다")
                              + (f"(공격 출발지 {', '.join(ips[:2])})" if ips else "") + ". 가능하면 다중 인증을 켠다.",
                    "evidence": f["evidence"][:6]})
    if rules.keys() & {"HOST_PRIV_ESC", "HOST_PRIV_ESC_FAIL", "HOST_ACCOUNT_CREATED"}:
        f = next(rules[r] for r in ("HOST_PRIV_ESC", "HOST_ACCOUNT_CREATED", "HOST_PRIV_ESC_FAIL") if r in rules)
        res = ", ".join(created[:3]) if created else "sudoers"
        lock = (f"새로 생긴 계정 {', '.join(created[:3])}은 잠그고(usermod -L {created[0]}), " if created else
                "모르는 계정은 잠그고(usermod -L), ")
        out.append({"id": "WEB_FIX_PRIVESC", "action": "서버 sudo 권한 정리와 새 계정 잠금" + (f": {res}" if created else ""),
                    "target": "account", "priority": "now", "resource": res,
                    "detail": lock + "웹 서비스 계정(www-data 등)의 sudo 권한과 NOPASSWD 줄을 sudoers에서 지운다(visudo). "
                              "root를 얻었을 수 있으므로 서버를 깨끗한 이미지로 다시 만드는 것을 검토한다.",
                    "evidence": f["evidence"][:6]})
    if "WEBLOG_SQLI" in rules:
        where = oc.vulnerable_params(events, {"WEBLOG_SQLI", "WAF_SQLI_NOT_BLOCKED"})
        res = ", ".join(where[:3]) or "로그에 경로 없음"
        out.append({"id": "WEB_FIX_SQLI", "action": "SQL 인젝션 취약 코드 수정" + (f": {res}" if where else ""),
                    "target": "app", "priority": "soon", "resource": res,
                    "detail": (f"{res}의 파라미터를" if where else "공격 문자열이 들어간 파라미터를")
                              + " 매개변수화된 질의(prepared statement)로 바꾸고, DB 계정 권한을 최소화한다.",
                    "evidence": rules["WEBLOG_SQLI"]["evidence"][:6]})
    if rules.keys() & {"WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION"}:
        f = next(rules[r] for r in ("WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION") if r in rules)
        where = [w for w in oc.vulnerable_params(events, {"WEBLOG_TRAVERSAL", "WEBLOG_RFI", "WEBLOG_CMD_INJECTION"})
                 if w.split("(")[0] not in files]  # 웹셸 자체에 넣은 명령은 앱 코드의 입력 검증 문제가 아니다
        res = ", ".join(where[:3]) or "로그에 경로 없음"
        out.append({"id": "WEB_FIX_INPUT", "action": "입력값 검증·경로 제한 적용" + (f": {res}" if where else ""),
                    "target": "app", "priority": "soon", "resource": res,
                    "detail": (f"{res}에서 " if where else "") +
                              "파일 경로·외부 URL·명령에 사용자 입력이 그대로 들어가지 않게 막고, 화이트리스트로 검증한다.",
                    "evidence": f["evidence"][:6]})
    if rules.keys() & {"WEBLOG_SCANNER", "WEBLOG_ENUM_404", "WEBLOG_AUTH_BRUTE", "SSH_BRUTE_FORCE"}:
        res = ", ".join(ips[:3]) or "로그에 IP 없음"
        out.append({"id": "WEB_FIX_RATE_LIMIT", "action": "비정상 출발지 차단·요청 제한" + (f": {res}" if ips else ""),
                    "target": "network", "priority": "soon", "resource": res,
                    "detail": (f"공격 출발지 {res}를" if ips else "공격 출발지 IP를") +
                              " 방화벽/fail2ban으로 제한하고, 로그인·관리자 경로에 접근 제어와 시도 제한을 둔다.",
                    "evidence": []})
    out.append({"id": "WEB_FIX_LOG_RETENTION", "action": "로그 보존 기간 늘리기", "target": "server", "priority": "later",
                "resource": "웹·인증 로그",
                "detail": "웹·인증 로그 보관 기간을 늘려(기본 14일은 너무 짧다) 다음 사고 때 더 멀리 되짚을 수 있게 한다.",
                "evidence": []})
    return out

"""보고서 첫 화면의 결론과 사건별 요약(사양서 FR-23·24·25·27·28·30).

사후 분석(report.py)과 웹서버 점검(web/webreport.py)이 같은 함수를 쓴다. 입력은 두 파이프라인의 결과 dict이고,
AI 없이 규칙만으로 같은 문장을 만든다(같은 입력이면 같은 결과).
"""
from __future__ import annotations

from . import outcome as oc
from .analyze import STAGE_KO
from .detect import RULES

# 단계의 무게: 피해에 가까울수록 크다(사건 제목에 쓸 '가장 심각한 단계' 고르기)
STAGE_WEIGHT = {"impact": 9, "exfiltration": 8, "collection": 7, "privilege-escalation": 6, "persistence": 5,
                "credential-access": 5, "execution": 5, "lateral-movement": 5, "initial-access": 3,
                "defense-evasion": 3, "discovery": 1, "other": 0}
SEV_WEIGHT = {"high": 3, "medium": 2, "low": 1}
KIND_WEIGHT = {"success": 3, "pass": 1, "allowed": 1, "blocked": 0, None: 0}

PHASE = oc.PHASE
PHASE_KO = {0: "번지는 것 막기", 1: "들어온 길 닫기", 2: "원인 고치기", 3: "다음을 위해"}

# 개인정보가 공격자에게 갔을 수 있다는 근거가 되는 규칙(FR-30)
PII_RULES = {"WEBLOG_IDOR_ENUM", "WEBLOG_LARGE_EXFIL", "WEBLOG_BACKUP_LEAK"}

GLOSSARY = {  # FR-28: 보고서에 나오면 '낯선 말' 칸에 풀이를 붙인다
    "IMDS": "서버 안에서 역할 키를 꺼내는 주소. v1은 토큰 없이 꺼낼 수 있어 웹 취약점으로 키가 새기 쉽다.",
    "COUNT": "WAF 규칙이 공격을 알아보고도 기록만 하고 막지 않는 모드.",
    "NACL": "서브넷 단위 방화벽. 보안그룹과 달리 특정 IP를 거부할 수 있다.",
    "보안그룹": "서버마다 붙는 방화벽. 허용 규칙만 있다.",
    "세션 무효화": "이미 발급된 임시 키를 지금 시각 이전 것은 모두 못 쓰게 막는 것.",
    "임시 자격증명": "역할이 쓰는 몇 시간짜리 키(ASIA로 시작). 새면 만료 전까지 어디서든 쓰인다.",
    "역할": "서버·서비스에 붙이는 IAM 권한 묶음. 서버가 이 권한으로 AWS를 호출한다.",
    "웹셸": "공격자가 웹서버에 올려 명령을 실행하는 파일.",
    "무차별 대입": "비밀번호를 여러 번 바꿔 넣어 맞히려는 공격.",
    "SQL 인젝션": "입력값에 DB 명령을 섞어 데이터를 빼내는 공격.",
    "IDOR": "주소의 번호만 바꿔 남의 데이터를 여는 공격.",
    "와일드카드": "권한 정책의 *. 필요한 것보다 훨씬 많은 일을 허락한다.",
    "확신도": "판정이 맞을 가능성에 대한 프로그램의 판단. 근거 수와 성공 여부로 정한다.",
    "심각도": "이 사건의 행동이 얼마나 위험한가. 자원이 회사에 얼마나 중요한지는 반영하지 않는다.",
    "허용": "방화벽이 연결을 받아들였다는 뜻. 침투에 성공했다는 뜻은 아니다.",
    "통과": "WAF·웹서버가 요청을 막지 않았다는 뜻. 공격이 성공했다는 뜻은 아니다.",
}


def verdict_of(r: dict) -> str:
    """공격 판정(사후 분석의 4종). 웹 점검 결과는 report.attack_verdict에 같은 값이 있다."""
    inc, rep = r["incident"], r.get("report", {})
    return inc.get("verdict") or rep.get("attack_verdict") or inc.get("ai_verdict") or rep.get("verdict") or "unclear"


def blocked_single(inc: dict) -> bool:
    """막힌 단발 시도: 이벤트 1~2건이 모두 실패·차단(FR-23)."""
    evs = [e for e in inc["events"] if not e.get("known")]
    return 0 < len(evs) <= 2 and all(oc.kind(e) == "blocked" for e in evs)


def _finding_weight(f: dict, by_ref: dict) -> tuple:
    kinds = [oc.kind(by_ref[r]) for r in f.get("evidence", []) if r in by_ref]
    best = max((KIND_WEIGHT[k] for k in kinds), default=0)
    return (best, STAGE_WEIGHT.get(f.get("stage"), 0), SEV_WEIGHT.get(f.get("severity"), 0))


def worst_finding(inc: dict) -> dict | None:
    by_ref = {e["ref"]: e for e in inc["events"]}
    fs = [f for f in inc.get("findings", []) if f.get("rule") != "GD_FINDING"] or inc.get("findings", [])
    return max(fs, key=lambda f: _finding_weight(f, by_ref)) if fs else None


def title(inc: dict) -> str:
    """사건 제목: 가장 심각한 단계와 주체·대상(FR-27)."""
    f = worst_finding(inc)
    if not f:
        return ""
    t = f.get("title") or RULES.get(f.get("rule"), ("", "", f.get("rule", "")))[2]
    evs = inc["events"]
    ips = oc.attacker_ips(evs)
    if f["rule"] == "CT_INSTANCE_CRED_OUTSIDE":
        roles = sorted({str(e.get("actor") or "").split("/")[1] for e in evs
                        if e.get("source") == "cloudtrail" and "assumed-role/" in str(e.get("actor") or "")})
        who = roles[0] if roles else (f.get("key") or "서버")
        return f"{who} 역할 키가 서버 밖" + (f"({ips[0]})" if ips else "") + "에서 쓰임"
    if f["rule"] in ("SSH_SUCCESS_AFTER_FAIL", "WEBLOG_AUTH_SUCCESS_AFTER_FAIL"):
        acc = oc.logged_in_accounts(evs)
        return f"비밀번호 대입 뒤 '{acc[0]}' 계정으로 로그인" if acc else t
    if f["rule"] in ("WEBLOG_UPLOAD_EXEC", "WEBLOG_WEBSHELL_ACCESS", "FILE_WEBSHELL"):
        files, abused = oc.webshell_files(evs)
        if files:
            return f"웹셸 {files[0]} 실행"
        if abused:
            return f"{abused[0]}를 통해 명령 실행"
    key = f.get("key")
    if key and key not in ips:
        return f"{t} ({key})"
    return t + (f" · 출발지 {ips[0]}" if ips else "")


def impact(inc: dict, sensitive: tuple | list = ()) -> dict:
    """피해 범위(FR-25): 성공한 일과 닿은 자원, 로그에 대상이 없어 모르는 것.
    sensitive: 사이트 프로필이 민감하다고 적은 경로 조각. 대상에 들어 있으면 sensitive=True로 표시."""
    done: dict[str, dict] = {}
    unknown: list[str] = []
    for e in inc["events"]:
        if e.get("known") or oc.kind(e) != "success":
            continue
        src, act = e.get("source"), str(e.get("action") or "")
        rules = set(e.get("rules", []))
        if src == "cloudtrail":
            tgt = oc.api_target(e)
            what = act
            if not tgt and act in oc.OBJECT_LEVEL:
                tgt = "로그에 이름 없음"
                unknown.append(f"{act}로 읽거나 바꾼 버킷·객체 이름이 로그에 없습니다. CloudTrail 원본의 "
                               "requestParameters를 보고, 없으면 S3 데이터 이벤트(객체 단위 기록)를 켜 두세요.")
            elif not tgt and act == "s3:ListBuckets":
                tgt = "계정의 버킷 목록 전체"
        elif src in ("sshauth", "auth"):
            if act == "ssh_login" or "login" in act:
                what, tgt = "서버 로그인", e.get("actor")
            elif act in ("sudo", "su"):
                what, tgt = f"{act}로 관리자 권한 사용", e.get("actor")
            else:
                what, tgt = act or "서버 명령", e.get("actor")
        elif src in oc.WEB or src == "file":
            path, _ = oc.request_path(act)
            if rules & {"WEBLOG_UPLOAD_EXEC", "WEBLOG_WEBSHELL_ACCESS"}:
                what = "웹셸로 명령 실행"
            elif "WEBLOG_LARGE_EXFIL" in rules:
                what = "공격 요청에 큰 응답(데이터가 나갔을 수 있음)"
            elif "WEBLOG_IDOR_ENUM" in rules:
                what = "남의 데이터 열람"
            elif "WEBLOG_BACKUP_LEAK" in rules:
                what = "백업·소스 파일 내려받기"
            elif rules & {"WEBLOG_ADMIN_ACCESS", "WEBLOG_ADMIN_FORGED"}:
                what = "관리자 화면 접근"
            elif "WEBLOG_AUTH_SUCCESS_AFTER_FAIL" in rules:
                what = "웹 로그인"
            else:
                what = "요청 성공"
            tgt = path or act
        else:
            what, tgt = act or src, e.get("actor")
        d = done.setdefault(f"{what}\0{tgt}", {"what": what, "target": tgt or "로그에 이름 없음", "n": 0, "refs": []})
        d["n"] += 1
        if len(d["refs"]) < 4:
            d["refs"].append(e["ref"])
    order = {"cloudtrail": 0, "access": 1, "weblog": 1, "alb": 1, "file": 1}
    first_src: dict[str, str] = {}
    for e in inc["events"]:
        for d in done.values():
            if e["ref"] in d["refs"]:
                first_src.setdefault(d["what"] + str(d["target"]), e.get("source"))
    marks = [m.lower() for m in sensitive if m]
    for d in done.values():
        d["sensitive"] = any(m in str(d["target"]).lower() for m in marks)
    items = sorted(done.values(), key=lambda d: (not d["sensitive"],
                                                 order.get(first_src.get(d["what"] + str(d["target"])), 2)))
    return {"done": items[:8], "more": max(0, len(items) - 8), "unknown": list(dict.fromkeys(unknown))}


def impact_phrase(imp: dict, limit: int = 2) -> str:
    """'s3:GetObject(로그에 이름 없음) 성공, s3:ListBuckets(계정의 버킷 목록 전체) 성공'."""
    parts = [f"{d['what']}({d['target']})" for d in imp["done"][:limit]]
    return ", ".join(parts) + (" 성공" if parts else "")


def pii_risk(results: list[dict]) -> list[str]:
    """개인정보가 든 응답이 공격자에게 갔을 수 있는 사건 ID(FR-30)."""
    out = []
    for r in results:
        evs = r["incident"]["events"]
        if any(oc.kind(e) == "success" and set(e.get("rules", [])) & PII_RULES for e in evs):
            out.append(r["incident"]["id"])
    return out


PII_NOTE = ("개인정보가 담긴 응답이 공격자에게 갔을 수 있습니다. 개인정보 유출 통지·신고 대상인지 법무 담당과 확인하세요"
            "(신고 기한과 대상은 법령으로 확인해야 하며, 이 보고서는 법적 판단을 하지 않습니다).")


def headline(result: dict) -> dict:
    """첫 화면 결론(FR-23): 한 문장 + 확인할 사건 수 + 막힌 단발 시도 수."""
    rs = result.get("results", [])
    attacks = [r for r in rs if verdict_of(r) == "attack"]
    blocked = [r for r in attacks if blocked_single(r["incident"])]
    real = [r for r in attacks if not blocked_single(r["incident"])]
    risky = [r for r in rs if verdict_of(r) == "risky_not_attack"]
    unclear = [r for r in rs if verdict_of(r) == "unclear"]
    if real:
        breach = {"breached": 3, "likely_breached": 2, "suspicious": 1}  # 웹서버 점검의 침해 판정이 있으면 먼저
        top = max(real, key=lambda r: (breach.get(r.get("report", {}).get("verdict"), 0),
                                       _finding_weight(worst_finding(r["incident"]) or {},
                                                       {e["ref"]: e for e in r["incident"]["events"]})))
        imp = impact(top["incident"])
        s = f"공격이 있었습니다. 가장 심각한 일은 {top['incident']['id']}의 '{title(top['incident'])}'입니다"
        ip = impact_phrase(imp)
        s += f"({ip})." if ip else "."
        if imp["unknown"]:
            s += " 무엇을 가져갔는지는 로그에 이름이 없어 확인이 필요합니다."
        elif imp["done"]:
            s += f" 피해 범위는 {top['incident']['id']}의 '성공한 일과 닿은 자원'을 확인하세요."
        elif any(e.get("source") == "guardduty" for e in top["incident"]["events"]):
            s += (" GuardDuty 결과에는 성공 여부가 없어, 실제 피해는 같은 시각의 CloudTrail·웹·서버 로그로 "
                  "확인해야 합니다.")
        else:
            s += " 성공한 근거는 아직 보이지 않습니다."
        tone = "attack"
    elif blocked:
        s = f"공격 시도가 {len(blocked)}건 있었지만 보이는 것은 모두 막히거나 실패했습니다. 급하지 않습니다."
        tone = "low"
    elif risky:
        s = f"공격 증거는 없지만 고쳐야 할 위험한 설정·사용이 {len(risky)}건 있습니다."
        tone = "medium"
    elif unclear:
        s = f"공격인지 규칙만으로 판단하기 어려운 사건이 {len(unclear)}건 있습니다. 누가 했는지 확인하세요."
        tone = "medium"
    else:
        s = "올린 로그 범위에서 공격으로 보이는 사건이 없습니다."
        tone = "low"
    return {"sentence": s, "tone": tone, "n_check": len(real) + len(risky) + len(unclear),
            "n_blocked": len(blocked), "blocked_ids": [r["incident"]["id"] for r in blocked],
            "pii": list(dict.fromkeys(pii_risk(real) + [i["id"] for i in result.get("incident_index", []) if i.get("pii")]))}


def _item(fix_id: str, text: str, target: str, iid: str, priority: str) -> dict:
    return {"id": fix_id, "text": text, "target": target, "incident": iid, "priority": priority,
            "phase": PHASE.get(fix_id, 2)}


# GuardDuty 유형(부분 문자열) → 같은 일을 하는 설정 수정안. 그 수정안이 이미 있으면 GuardDuty 조치를 따로 넣지 않는다
GD_COVERED = {
    "CredentialExfiltration": {"IAM_ROLE_SESSION_REVOKE"}, "MetadataDNSRebind": {"IMDSV1_ENABLED"},
    "SSHBruteForce": {"SG_ADMIN_PORT_OPEN"}, "RDPBruteForce": {"SG_ADMIN_PORT_OPEN"}, "PortProbe": {"SG_ADMIN_PORT_OPEN"},
    "CompromisedCredentials": {"IAM_KEY_COMPROMISED"}, "PenTest:IAMUser": {"IAM_KEY_COMPROMISED"},
    "CloudTrailLoggingDisabled": {"TRAIL_UNPROTECTED"},
}


def _gd_actions(inc: dict, iid: str, seen: set, fixes: set = frozenset()) -> list[dict]:
    """GuardDuty 결과의 유형별 먼저 할 일(gd_types). 설정 스냅샷이 없어도 나온다.
    대상은 결과가 가리키는 키·서버·버킷 등. 설정 수정안(명령)이 이미 같은 일을 하면 사건별 설명에서 본다."""
    from .gd_types import describe
    out = []
    for e in inc["events"]:
        if e.get("source") != "guardduty" or e.get("known"):
            continue
        typ = e.get("gd_type", "")
        if any(k in typ and ids & fixes for k, ids in GD_COVERED.items()):
            continue
        d = describe(typ)
        if not d["action"]:
            continue
        tgt = ", ".join(x for x in (e.get("access_key"), e.get("actor"), e.get("instance_id"), e.get("gd_target")) if x) \
            or "로그에 이름 없음"
        k = ("GD", d["action"], tgt)
        if k in seen:
            continue
        seen.add(k)
        sev = float(e.get("gd_severity") or 0)
        pr = "now" if sev >= 7 or (d["phase"] == 0 and sev >= 4) else "soon" if sev >= 4 else "later"
        out.append({"id": "GD_" + d["title"], "text": d["action"], "target": f"{tgt} (GuardDuty: {d['title']})",
                    "incident": iid, "priority": pr, "phase": d["phase"]})
    return out


def actions(result: dict, limit: int = 3) -> tuple[list[dict], list[dict]]:
    """먼저 할 일(최대 3개, 순서대로)과 나머지(FR-24). 막힌 단발 시도와 정상 활동 사건의 조치는 넣지 않는다."""
    items: list[dict] = []
    seen = set()
    for r in result.get("results", []):
        inc = r["incident"]
        if verdict_of(r) not in ("attack", "risky_not_attack") or blocked_single(inc):
            continue
        ips = oc.attacker_ips(inc["events"])
        iid = inc["id"]
        for fc in r.get("report", {}).get("firewall_changes", []):  # 사후 분석
            k = (fc["check_id"], fc["resource"])
            if k in seen:
                continue
            seen.add(k)
            tgt = fc["resource"]
            if PHASE.get(fc["check_id"]) == 1 and ips and fc["check_id"] != "NACL_BLOCK_ATTACKER":
                tgt += f" · 공격 출발지 {', '.join(ips[:3])}"
            items.append(_item(fc["check_id"], fc["change"], tgt, iid, fc.get("priority", "soon")))
        for c in r.get("report", {}).get("remediation", []):  # 웹서버 점검
            k = (c["id"], c.get("resource", ""))
            if k in seen:
                continue
            seen.add(k)
            items.append(_item(c["id"], c["action"], c.get("resource", ""), iid, c.get("priority", "soon")))
        fixes = {fc["check_id"] for fc in r.get("report", {}).get("firewall_changes", [])}
        items += _gd_actions(inc, iid, seen, fixes)
    pri = {"now": 0, "soon": 1, "later": 2}
    items.sort(key=lambda x: (x["phase"], pri.get(x["priority"], 3)))
    first = [x for x in items if x["priority"] == "now" or x["phase"] == 0][:limit]
    rest = [x for x in items if x not in first]
    return first, rest


def glossary(text: str) -> list[tuple[str, str]]:
    """보고서 본문에 나온 낯선 말만 골라 풀이(FR-28)."""
    return [(k, v) for k, v in GLOSSARY.items() if k in text]


def stage_ko(s: str) -> str:
    return STAGE_KO.get(s, s)

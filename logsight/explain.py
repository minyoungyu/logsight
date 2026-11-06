"""
AI 없이 동작하는 설명·판정 (규칙 기반 모드의 품질을 올리는 부분).

1. 정상 작업 목록(known_activity): 설정 스냅샷에 적은 운영자·배포 계정·관리 IP와 맞는 이벤트에
   표시를 붙인다. 사건을 지우지 않고, 판정과 순서만 바꾼다.
2. 규칙 판정(rule_triage): Claude 재검토(triage.py)와 같은 형식으로 사건마다
   공격 / 공격 아님·위험 설정 / 판단 불가 / 정상 활동을 정한다. 근거는 아래의 명시적 규칙뿐이다.
3. 로그 범위(coverage_notes): 어떤 로그가 없고 언제 끝나는지, 그래서 무엇을 알 수 없는지 적는다.
4. 문장 템플릿(describe_finding, summarize): 규칙 이름을 이어 붙이는 대신 사건 유형별로
   "무슨 일이 → 왜 중요한지 → 먼저 할 일"을 쉬운 한국어로 쓴다.

같은 입력이면 항상 같은 결과가 나온다(테스트·재현 가능).
"""
from __future__ import annotations

import fnmatch
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

# 공격 증거 없이 "위험한 사용"만 뜻하는 규칙
HYGIENE_RULES = {"CT_ROOT_USAGE", "CT_CONSOLE_NO_MFA"}
# 공격 행동이 아니라 "열려 있음"을 보여 주는 규칙(인터넷 스캐너가 열린 관리 포트에 접속)
EXPOSURE_RULES = {"VPC_REMOTE_ADMIN_EXPOSED", "GD_FINDING"}
# 정상 작업 목록의 계정이 했어도 위험한 설정 변경
RISKY_CHANGE_RULES = {"CT_SG_OPENED", "CT_S3_PUBLIC", "CT_SNAPSHOT_SHARE", "CT_LOGGING_TAMPER"}
# 자격증명 오용 규칙
CRED_RULES = {"CT_INSTANCE_CRED_MULTI_IP", "CT_INSTANCE_CRED_OUTSIDE", "CT_UNTRUSTED_IP"}
# 정상 작업 목록 계정이라도 키 유출 때 흔한 모습. 이름만 보고 정상으로 넘기지 않는다(BOTSv3 측정에서 확인)
KEY_MISUSE_RULES = {"CT_ACCESS_DENIED_BURST", "CT_INSTANCE_CRED_MULTI_IP", "CT_INSTANCE_CRED_OUTSIDE"}
# 신원 확인만 하는 호출(무해). 이것만 있으면 규칙으로는 공격이라 단정하지 않는다
IDENTITY_ONLY = {"sts:GetCallerIdentity", "GetCallerIdentity"}

VERDICT_KO = {"attack": "공격 의심", "risky_not_attack": "공격 아님·위험 설정",
              "unclear": "판단 불가", "benign_activity": "정상 활동"}
# 이 로그가 없으면 알 수 없는 것("~는지" 꼴로 써서 조사 걱정 없이 문장에 넣는다)
SOURCE_SEES = {
    "cloudtrail": "AWS 계정에서 누가 어떤 API를 썼는지",
    "vpcflow": "어느 IP가 서버에 접속했고 데이터가 밖으로 나갔는지",
    "waf": "웹 공격 요청이 막혔는지",
    "alb": "웹 요청이 어떤 응답을 받았는지",
    "sshauth": "누가 서버에 로그인했는지",
}
# 뒤에 항상 " 로그"를 붙여 쓴다(조사는 '로그'에 맞춘다)
SOURCE_KO = {"cloudtrail": "CloudTrail", "vpcflow": "VPC Flow", "waf": "WAF", "alb": "ALB",
             "sshauth": "SSH 인증", "hostfw": "서버 방화벽", "weblog": "웹서버",
             "guardduty": "GuardDuty"}
# 없어도 다른 로그가 일부 대신하는 경우
SUBSTITUTE = {"vpcflow": "hostfw", "waf": "weblog", "alb": "weblog"}


# ------------------------------------------------------------------ 1. 정상 작업 목록
def _entries(env: dict) -> list[dict]:
    out = [dict(e) for e in env.get("known_activity", []) if isinstance(e, dict)]
    for t in env.get("trusted_ips", []):  # 관리자 IP도 정상 작업 목록으로 본다
        cidr, lab = (t.get("cidr"), t.get("label")) if isinstance(t, dict) else (t, None)
        if cidr:
            out.append({"label": f"{lab or '관리자'} IP", "ips": [cidr]})
    return out


def _ip_match(ip: str | None, cidrs: list[str]) -> bool:
    if not ip or not cidrs:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if a in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _actor_match(actor: str | None, pats: list[str]) -> bool:
    if not actor or not pats:
        return False
    a = actor.lower()
    short = a.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(a, p.lower()) or fnmatch.fnmatchcase(short, p.lower()) for p in pats)


def known_label(e, entries: list[dict]) -> str | None:
    for ent in entries:
        if (_actor_match(e.actor, ent.get("actors", []))
                or _ip_match(e.src_ip, ent.get("ips", []))
                or (e.access_key and e.access_key in ent.get("access_keys", []))):
            return ent.get("label") or "정상 작업"
    return None


def mark_known(events: list, env: dict) -> int:
    """정상 작업 목록과 맞는 이벤트에 extra['known']을 붙인다. 붙인 개수를 돌려준다."""
    entries = _entries(env)
    if not entries:
        return 0
    n = 0
    for e in events:
        lab = known_label(e, entries)
        if lab:
            e.extra["known"] = lab
            n += 1
    return n


# ------------------------------------------------------------------ 3. 로그 범위
def _hm(iso: str) -> str:
    d = datetime.fromisoformat(iso)
    return f"{d.astimezone(timezone.utc):%m-%d %H:%M} UTC(한국 {d.astimezone(KST):%H:%M})"


def _periods(srcs: dict, gap: timedelta = timedelta(hours=6)) -> list[dict]:
    """로그 종류별 기간을 겹치는 것끼리 묶는다. 서로 다른 날의 로그를 한꺼번에 올리면
    '먼저 끝난 로그'를 잘못 지적하지 않도록 기간별로 따로 비교한다."""
    iv = sorted(((datetime.fromisoformat(v["first"]), datetime.fromisoformat(v["last"]), k)
                 for k, v in srcs.items()), key=lambda x: x[0])
    out: list[dict] = []
    for a, b, k in iv:
        if out and a <= out[-1]["last"] + gap:
            out[-1]["last"] = max(out[-1]["last"], b)
            out[-1]["sources"].append(k)
        else:
            out.append({"first": a, "last": b, "sources": [k]})
    return out


GD_BLIND = ("waf", "alb", "weblog", "sshauth", "hostfw")  # GuardDuty가 읽지 않는 로그


def guardduty_note(cov: dict) -> str | None:
    """GuardDuty 결과와 GuardDuty가 읽지 않는 로그를 함께 넣었는지 한 문장으로."""
    srcs = cov.get("sources", {})
    blind = [SOURCE_KO[s] for s in GD_BLIND if s in srcs]
    if "guardduty" in srcs and blind:
        n = srcs["guardduty"].get("n_events", 0)
        return (f"GuardDuty 결과 {n}건에 GuardDuty가 읽지 않는 로그({', '.join(blind)})를 더해 분석했습니다. "
                "웹·서버 안쪽에서 일어난 일은 이 로그들로 보았습니다.")
    if "guardduty" in srcs:
        return ("GuardDuty 결과만으로는 웹·서버 안쪽에서 일어난 일을 알 수 없습니다. "
                "WAF·ALB·웹서버·SSH 로그가 있으면 함께 넣어 주세요.")
    if blind:
        return (f"GuardDuty 결과가 없습니다. GuardDuty 결과 파일도 함께 넣으면 "
                f"이 로그({', '.join(blind)})와 한 사건으로 묶어 볼 수 있습니다.")
    return None


def coverage_notes(cov: dict, attack_incidents: list[dict] | None = None) -> list[str]:
    """coverage_summary(triage.py)의 결과를 '이 로그로는 알 수 없는 것' 문장으로 바꾼다."""
    notes = []
    srcs = cov.get("sources", {})
    attack_incidents = attack_incidents or []
    for s in cov.get("missing_sources", []):
        sub = SUBSTITUTE.get(s)
        if sub and sub in srcs:
            notes.append(f"{SOURCE_KO[s]} 로그가 없어 {SOURCE_SEES[s]}는 {SOURCE_KO[sub]} 로그로 일부만 볼 수 있습니다.")
        else:
            notes.append(f"{SOURCE_KO[s]} 로그가 없어 {SOURCE_SEES[s]} 알 수 없습니다.")
    periods = _periods(srcs) if srcs else []
    if len(periods) > 1:
        notes.append(f"올린 로그가 서로 떨어진 기간 {len(periods)}개로 나뉩니다("
                     + ", ".join(f"{p['first']:%m-%d}" + (f"~{p['last']:%m-%d}" if p["last"].date() != p["first"].date() else "")
                               for p in periods)
                     + "). 기간 사이에 무슨 일이 있었는지는 알 수 없습니다.")
    for p in periods:
        for s in sorted(p["sources"]):
            last = datetime.fromisoformat(srcs[s]["last"])
            if p["last"] - last > timedelta(minutes=30):
                notes.append(f"{SOURCE_KO.get(s, s)} 로그는 {_hm(srcs[s]['last'])}에 끝나고, 같은 기간의 다른 로그는 "
                             f"{_hm(p['last'].isoformat())}까지 있습니다. 그 사이의 {SOURCE_KO.get(s, s)} 기록은 없습니다.")
    for inc in attack_incidents[:3]:
        end = datetime.fromisoformat(inc["end"])
        p = next((p for p in periods if p["first"] <= end <= p["last"]), None)
        if p and p["last"] - end <= timedelta(minutes=10):
            notes.append(f"{inc['id']}의 활동이 로그가 끝나는 무렵({_hm(p['last'].isoformat())})까지 이어집니다. "
                         "그 뒤에도 계속됐는지는 알 수 없습니다.")
    keys = cov.get("suspected_keys", [])
    if cov.get("cloudtrail_s3_object_calls") == 0 and "cloudtrail" in srcs and (keys or any(
            set(i.get("rules", [])) & CRED_RULES for i in attack_incidents)):
        notes.append("CloudTrail에 S3 파일 읽기·쓰기 기록이 0건입니다. S3 데이터 이벤트를 켜지 않았을 수 있어, "
                     "훔친 키로 데이터를 읽거나 가져갔는지는 확인도 부정도 할 수 없습니다.")
    for k in keys[:3]:
        top = ", ".join(f"{c['action']} {c['n']}건" for c in k["calls"][:3])
        notes.append(f"의심 키 {str(k['access_key'])[:8]}…는 {_hm(k['first'])}부터 {_hm(k['last'])}까지 "
                     f"모두 {k['n_calls']}건 쓰였습니다(주로 {top}). 사건에 들어가지 않은 호출도 확인하세요.")
    return notes


# ------------------------------------------------------------------ 2. 규칙 판정
def _inc_rules(inc: dict) -> set[str]:
    return {f["rule"] for f in inc["findings"]}


def _public(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return not any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def verdict_for(inc: dict) -> dict:
    """사건 하나의 규칙 판정. 반환: {id, verdict, confidence, reason, evidence}"""
    evs = inc["events"]
    rules = _inc_rules(inc)
    refs = [e["ref"] for e in evs][:6]
    known = [e for e in evs if e.get("known")]
    # 상세 이벤트는 잘릴 수 있으므로 사건 전체 기준 수(n_known)를 먼저 쓴다
    n_all = inc.get("n_events", len(evs))
    n_known = inc.get("n_known", len(known))
    labels = inc.get("known_labels") or sorted({e["known"] for e in known})
    out = {"id": inc["id"], "evidence": refs}
    if n_all and n_known == n_all and rules & KEY_MISUSE_RULES:
        ips = sorted({e.get("src_ip") for e in evs if e.get("src_ip")})[:3]
        return out | {"verdict": "unclear", "confidence": "low",
                      "reason": f"정상 작업 목록({', '.join(labels)})의 계정이지만 권한 거부가 몰리거나 한 키가 여러 곳에서 "
                                f"쓰이는 등 키가 유출됐을 때 흔한 모습입니다. 접속 IP({', '.join(ips) or '없음'})가 "
                                "우리 것인지, 그 사람이 실제로 한 작업인지 확인하세요."}
    if n_all and n_known == n_all and rules & RISKY_CHANGE_RULES:
        what = ", ".join(sorted({f["title"] for f in inc["findings"] if f["rule"] in RISKY_CHANGE_RULES}))
        return out | {"verdict": "risky_not_attack", "confidence": "medium",
                      "reason": f"정상 작업 목록({', '.join(labels)})의 계정이 했지만 위험한 설정 변경입니다({what}). "
                                "의도한 변경인지 확인하고, 아니라면 되돌리세요."}
    if n_all and n_known == n_all:
        return out | {"verdict": "benign_activity", "confidence": "high",
                      "reason": f"이벤트 {n_all}건이 모두 설정의 정상 작업 목록({', '.join(labels)})과 일치합니다. "
                                "목록이 틀렸다면(예: 그 계정 키가 유출) 공격일 수 있으니 목록을 주기적으로 점검하세요."}
    if rules and rules <= HYGIENE_RULES:
        ok = sum(1 for e in evs if e.get("status") == "success")
        return out | {"verdict": "risky_not_attack", "confidence": "medium",
                      "reason": f"루트·MFA 없는 로그인처럼 위험한 사용({ok}건 성공)만 있고, 함께 나타난 공격 행동은 "
                                "없습니다. 누가 왜 썼는지 확인하고 일상 작업에서는 쓰지 않게 바꾸세요."}
    if rules and rules <= EXPOSURE_RULES and all(
            e.get("source") != "guardduty" or "PortProbe" in str(e.get("action")) for e in evs):
        return out | {"verdict": "risky_not_attack", "confidence": "medium",
                      "reason": "인터넷에서 관리 포트(SSH·RDP)로 들어온 접속만 있고, 로그인 성공이나 다른 공격 행동은 "
                                "보이지 않습니다. 인터넷 스캐너가 흔히 남기는 기록입니다. 관리 포트를 인터넷 전체에 "
                                "열어 둔 설정을 닫으세요."}
    if rules and rules <= CRED_RULES:
        acts = {e.get("action") for e in evs}
        if acts and acts <= IDENTITY_ONLY:
            return out | {"verdict": "unclear", "confidence": "low",
                          "reason": "역할 키가 다른 IP에서 쓰였지만 호출이 신원 확인(GetCallerIdentity)뿐입니다. "
                                    "같은 서비스의 다른 출구 IP일 수도, 공격자의 첫 확인일 수도 있어 규칙만으로는 "
                                    "판단할 수 없습니다. 그 IP가 우리 것인지 확인하세요."}
    success = sum(1 for e in evs if e.get("status") == "success" and not e.get("known")
                  and e.get("disposition") != "blocked")
    blocked = sum(1 for e in evs if e.get("disposition") == "blocked" or e.get("status") == "failure")
    part = f" 단, {n_known}건은 정상 작업 목록({', '.join(labels)})과 일치합니다." if n_known else ""
    what = ", ".join(list(dict.fromkeys(f["title"] for f in inc["findings"]))[:3])
    if success:
        conf = "high" if len(inc["stages"]) >= 2 else "medium"
        tail = f"성공·허용 {success}건, 실패·차단 {blocked}건."
    else:
        conf = "low"
        tail = f"보이는 시도 {blocked}건은 모두 막히거나 실패했습니다. 공격 시도이지만 급하지 않을 수 있습니다."
    return out | {"verdict": "attack", "confidence": conf, "reason": f"{what}. {tail}{part}"}


def _campaigns(incs: list[dict], verdicts: dict[str, str]) -> list[dict]:
    """공격 판정 사건 중 같은 IP·액세스 키로 이어지는 것을 묶는다.
    같은 /24 대역에서 2시간 안에 일어난 것은 '추정'으로 묶는다."""
    att = [i for i in incs if verdicts.get(i["id"]) == "attack"]
    parent = {i["id"]: i["id"] for i in att}
    why: dict[frozenset, str] = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def keys(i):
        ks = {("ip", ip) for ip in i["src_ips"] if _public(ip)}
        # 같은 서버만으로는 잇지 않는다(여러 스캐너가 같은 서버를 두드리면 다른 공격도 한 덩어리가 된다)
        ks |= {("key", e["access_key"]) for e in i["events"] if e.get("access_key")}
        return ks

    ks = {i["id"]: keys(i) for i in att}
    for a_i, a in enumerate(att):
        for b in att[a_i + 1:]:
            common = ks[a["id"]] & ks[b["id"]]
            reason = None
            if common:
                kind = {"ip": "같은 IP", "inst": "같은 서버", "key": "같은 액세스 키"}
                reason = ", ".join(sorted({kind[k[0]] for k in common}))
            else:
                na = {".".join(ip.split(".")[:3]) for ip in a["src_ips"] if _public(ip) and "." in ip}
                nb = {".".join(ip.split(".")[:3]) for ip in b["src_ips"] if _public(ip) and "." in ip}
                ta, tb = datetime.fromisoformat(a["start"]), datetime.fromisoformat(b["start"])
                if na & nb and abs(ta - tb) <= timedelta(hours=2):
                    reason = "같은 /24 대역, 2시간 안(추정)"
            if reason:
                why[frozenset((a["id"], b["id"]))] = reason
                parent[find(a["id"])] = find(b["id"])
    groups: dict[str, list[str]] = defaultdict(list)
    for i in att:
        groups[find(i["id"])].append(i["id"])
    out = []
    for ids in groups.values():
        reasons = sorted({r for pair, r in why.items() if pair <= set(ids)})
        out.append({"incident_ids": ids, "link_reason": "; ".join(reasons) or "사건 하나",
                    "summary": f"공격 의심 사건 {len(ids)}개" + (" (" + ", ".join(ids) + ")" if len(ids) > 1 else "")})
    return out


def rule_triage(incidents: list[dict], events: list | None = None, max_incidents: int = 500,
                max_campaign: int = 30) -> dict:
    """Claude 재검토와 같은 형식의 규칙 판정. AI 키가 없을 때도 순서·판정·알 수 없는 것을 보여 준다.
    판정은 가벼워 상위 max_incidents개 모두에, 공격 연결은 상위 max_campaign개에만 한다."""
    from .triage import coverage_summary
    incs = incidents[:max_incidents]
    rows = [verdict_for(i) for i in incs]
    v = {r["id"]: r["verdict"] for r in rows}
    cov = coverage_summary(events) if events else {}
    att = [{"id": i["id"], "end": i["end"], "rules": sorted(_inc_rules(i))}
           for i in incs[:max_campaign] if v[i["id"]] == "attack"]
    return {"mode": "rules", "incidents": rows, "campaigns": _campaigns(incs[:max_campaign], v),
            "cannot_tell": coverage_notes(cov, att) if cov else [],
            "coverage": cov, "validation": {"passed": True, "note": "규칙 판정은 입력 ref만 씁니다"},
            "meta": {"model": "rules", "usage": {}}}


# ------------------------------------------------------------------ 4. 문장 템플릿
def _n(evs, pred) -> int:
    return sum(1 for e in evs if pred(e))


def _who(inc: dict, evs: list[dict]) -> str:
    ips = sorted({e["src_ip"] for e in evs if e.get("src_ip")})
    if ips:
        return ", ".join(ips[:2]) + (f" 외 {len(ips) - 2}곳" if len(ips) > 2 else "")
    actors = sorted({e["actor"].rsplit("/", 1)[-1] for e in evs if e.get("actor")})
    return ", ".join(actors[:2]) or "알 수 없는 주체"


def _acts(evs: list[dict], k: int = 3) -> str:
    c = Counter(e.get("action") for e in evs if e.get("action"))
    return ", ".join(f"{a} {n}건" if n > 1 else str(a) for a, n in c.most_common(k))


def describe_finding(f: dict, inc: dict) -> str:
    """탐지 하나를 쉬운 문장으로. 사건 안의 해당 이벤트에서 성공·실패를 센다.
    출발지는 'OOO에서' 꼴로만 써서 IP·영문 이름 뒤의 조사가 어색하지 않게 한다."""
    evs = [e for e in inc["events"] if f["rule"] in e.get("rules", [])]
    n = f["n_events"]
    ok = _n(evs, lambda e: e.get("status") == "success" and e.get("disposition") != "blocked")
    bad = _n(evs, lambda e: e.get("status") == "failure" or e.get("disposition") == "blocked")
    who = _who(inc, evs)
    r = f["rule"]
    inst = ", ".join(sorted({e.get("instance_id") or e.get("target_instance") for e in evs
                             if e.get("instance_id") or e.get("target_instance")})) or "서버"
    ports = ", ".join(sorted({str(e.get("dst_port")) for e in evs if e.get("dst_port")}, key=lambda x: int(x) if x.isdigit() else 0))
    known = f" 이 중 {_n(evs, lambda e: e.get('known'))}건은 정상 작업 목록과 일치합니다." \
        if any(e.get("known") for e in evs) else ""
    res = f"성공 {ok}건, 거부 {bad}건"
    t = {
        "CT_INSTANCE_CRED_OUTSIDE": f"{inst}에 붙은 역할 키가 서버 밖({who})에서 {n}번 쓰였습니다"
                                    f"({res}: {_acts(evs)}). 키가 유출됐을 가능성이 큽니다.",
        "CT_INSTANCE_CRED_MULTI_IP": f"{inst}의 역할 키가 여러 IP({who})에서 {n}번 쓰였습니다"
                                     f"({res}: {_acts(evs)}). 한 서버의 키는 보통 한곳에서만 쓰입니다.",
        "CT_UNTRUSTED_IP": f"등록된 관리자 IP가 아닌 {who}에서 자격증명이 {n}번 쓰였습니다({_acts(evs)}).",
        "CT_IAM_PERSISTENCE": f"{who}에서 IAM 사용자·키·권한을 만들거나 바꾸려 했습니다({_acts(evs)}, {res}). "
                              "다시 들어올 문을 만드는 단계일 수 있습니다.",
        "CT_LOGGING_TAMPER": f"{who}에서 감사 로그를 끄거나 바꾸려 했습니다({_acts(evs)}, {res}). "
                             "흔적을 지우려는 행동일 수 있습니다.",
        "CT_ROOT_USAGE": f"루트 계정으로 {n}건을 호출했습니다(성공 {ok}건). 루트는 모든 권한을 가져 일상 작업에 쓰면 위험합니다.",
        "CT_CONSOLE_NO_MFA": f"{who}에서 MFA 없이 콘솔에 로그인했습니다. 비밀번호만 알면 누구나 들어올 수 있는 상태입니다.",
        "CT_ACCESS_DENIED_BURST": f"{who}에서 권한 없는 API를 짧은 시간에 {n}번 시도했습니다. 쓸 수 있는 권한을 떠보는 모습일 수 있습니다.",
        "CT_DISCOVERY_BURST": f"{who}에서 계정·자원 목록을 짧은 시간에 {n}번 조회했습니다({_acts(evs)}). 공격 전 정찰일 수도, 관리 도구의 점검일 수도 있습니다.",
        "CT_S3_BULK_READ": f"{who}에서 S3 파일을 짧은 시간에 {n}건 읽었습니다. 데이터를 가져가는 단계일 수 있습니다.",
        "CT_SG_OPENED": f"{who}에서 보안그룹을 인터넷 전체(0.0.0.0/0)에 열었습니다.",
        "CT_S3_PUBLIC": f"{who}에서 S3 버킷을 누구나 읽거나 쓸 수 있게 공개했습니다.",
        "CT_SNAPSHOT_SHARE": f"{who}에서 디스크 스냅샷·이미지를 다른 계정과 공유했습니다. 데이터 반출 경로가 될 수 있습니다.",
        "CT_RUN_INSTANCES_BURST": f"인스턴스를 짧은 시간에 {n}대 만들었습니다(코인 채굴 등 자원 탈취 의심).",
        "VPC_PORT_SCAN": f"{who}에서 서버 포트 {len({e.get('dst_port') for e in evs})}개에 접속을 시도했습니다(포트 스캔). "
                         f"그중 {ok}건은 허용됐습니다.",
        "VPC_REMOTE_ADMIN_EXPOSED": f"{who}에서 관리 포트({ports or '22/3389'})로 접속한 것이 {ok}건 허용됐습니다. "
                                    "관리 포트가 인터넷에 열려 있다는 뜻입니다.",
        "WAF_SQLI_NOT_BLOCKED": f"SQL 인젝션 요청 {n}건을 WAF가 알아봤지만 기록만 하고 통과시켰습니다.",
        "WAF_BLOCKED": f"{who}에서 보낸 공격 요청 {n}건을 WAF가 막았습니다.",
        "SSH_BRUTE_FORCE": f"{who}에서 SSH 비밀번호를 {n}번 틀렸습니다(무차별 대입).",
        "SSH_SUCCESS_AFTER_FAIL": f"{who}에서 SSH 비밀번호를 {bad}번 틀린 뒤 로그인에 성공했습니다. 비밀번호가 뚫렸을 수 있습니다.",
        "WEB_SQLI_PATTERN": f"{who}에서 보낸 웹 요청 {n}건에 SQL 인젝션 문자열이 있었습니다(정상 응답 {ok}건, 오류·거부 {bad}건)."
                            + _sqli_signal_sentence(f.get("detail", "")),
        "WEB_PATH_PROBE": f"{who}에서 없는 경로 {n}곳을 연달아 요청했습니다({_acts(evs, 2)} 등). 취약한 파일을 찾는 스캐너입니다.",
        "WEB_OBJECT_ENUM": f"{who}에서 같은 API의 번호만 바꿔 다른 사람의 데이터 {n}건을 열어 보려 했습니다(IDOR 탐색, 거부 {bad}건).",
        "GD_FINDING": f"GuardDuty 탐지: {f['title'].replace('GuardDuty: ', '')} ({f['detail']}).",
    }.get(r)
    if not t:  # 템플릿이 없는 규칙(웹서버 로그 규칙 등)도 같은 꼴로
        t = f"{who}에서 {f['title']}에 해당하는 요청이 {n}건 있었습니다({f['detail']})."
    return t + known


def _sqli_signal_sentence(detail: str) -> str:
    """detect.sqli_success_signal이 detail 뒤에 붙인 코드 판단을 문장으로."""
    if " · " not in detail:
        return ""
    return " 응답 크기로 본 판단: " + detail.split(" · ", 1)[1] + "."


def _span(a_iso: str, b_iso: str) -> str:
    """'01-13 04:20~04:27 UTC(한국 13:20~13:27)'"""
    a, b = datetime.fromisoformat(a_iso), datetime.fromisoformat(b_iso)
    def one(tz, first):
        x, y = a.astimezone(tz), b.astimezone(tz)
        txt = x.strftime("%m-%d %H:%M" if first else "%H:%M")
        if y != x:
            txt += "~" + y.strftime("%H:%M" if y.date() == x.date() else "%m-%d %H:%M")
        return txt
    return f"{one(timezone.utc, True)} UTC(한국 {one(KST, False) if a.astimezone(KST).date() == a.date() else one(KST, True)})"


def summarize(inc: dict, verdict: dict | None, checks: list[dict]) -> str:
    """'판정 → 누가 언제 무엇을 → 결과 → 먼저 고칠 것' 순서의 요약."""
    v = (verdict or {}).get("verdict", "unclear")
    head = {"attack": "외부 공격으로 보입니다.",
            "risky_not_attack": "공격 증거는 없지만 위험한 사용입니다.",
            "benign_activity": "정상 작업으로 보입니다.",
            "unclear": "규칙만으로는 공격인지 판단하기 어렵습니다."}[v]
    evs = inc["events"]
    who = _who(inc, evs)
    first = sorted(inc["findings"], key=lambda f: f["first"])
    steps = " → ".join(dict.fromkeys(f["title"] for f in first[:4]))
    ok = _n(evs, lambda e: e.get("status") == "success" and e.get("disposition") != "blocked"
            and not e.get("known"))
    blocked = _n(evs, lambda e: e.get("disposition") == "blocked" or e.get("status") == "failure")
    if v == "attack" and not ok:
        head = "외부 공격 시도로 보입니다."
    parts = [head, f"{_span(inc['start'], inc['end'])}, 출발지 {who}: {steps}."]
    if v == "attack":
        if ok:
            parts.append(f"성공하거나 통과된 시도가 {ok}건 있어 실제 피해가 있었는지 확인해야 합니다.")
        elif blocked:
            parts.append(f"보이는 시도 {len(evs)}건은 모두 막히거나 실패했습니다(올린 로그 범위 안에서).")
    elif v in ("benign_activity", "unclear", "risky_not_attack"):
        parts.append((verdict or {}).get("reason", ""))
    if checks and v in ("attack", "risky_not_attack"):
        top = sorted(checks, key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c["severity"], 3))[0]
        parts.append(f"먼저 고칠 설정: {top['title']}(아래 수정안).")
    return " ".join(p for p in parts if p)

"""수정안을 적용하면 무엇이 함께 바뀌나(조치 전 영향 미리보기, 사양서 FR-35).

설정 스냅샷(environment.json, `logsight collect`)과 사건 이벤트만으로 센다. AWS를 새로 호출하지 않고,
적용을 흉내 내지도 않는다. 셀 수 없으면 빈 목록을 돌려주고 지어내지 않는다.

예: "이 보안그룹은 서버 3대(web-1, web-2, batch)와 그 밖의 네트워크 인터페이스 1개에 붙어 있어 모두에 적용됩니다."
"""
from __future__ import annotations

import ipaddress


def _servers(env: dict, pred) -> list[dict]:
    return [i for i in env.get("instances", []) if pred(i)]


def _names(insts: list[dict], n: int = 3) -> str:
    out = [f"{i.get('name')}({i['instance_id']})" if i.get("name") else i["instance_id"] for i in insts[:n]]
    return ", ".join(out) + (f" 외 {len(insts) - n}대" if len(insts) > n else "")


def _in(ip: str, cidrs: list[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(c, strict=False) for c in cidrs if c)
    except ValueError:
        return False


def _trusted(env: dict) -> list[str]:
    return [t["cidr"] if isinstance(t, dict) else t for t in env.get("trusted_ips", [])]


def _sg(fix: dict, inc: dict, env: dict) -> list[str]:
    sg = fix["resource"]
    insts = _servers(env, lambda i: sg in (i.get("security_groups") or []))
    others = [n for n in env.get("network_interfaces", [])
              if sg in (n.get("security_groups") or []) and not n.get("instance_id")]
    out = []
    if insts or others:
        s = f"이 보안그룹은 서버 {len(insts)}대" + (f"({_names(insts)})" if insts else "")
        if others:
            kinds = sorted({n.get("type") or n.get("description", "")[:20] or "기타" for n in others})
            s += f"와 서버가 아닌 네트워크 인터페이스 {len(others)}개({', '.join(kinds[:3])})"
        out.append(s + ("에 붙어 있어 모두에 함께 적용됩니다." if len(insts) + len(others) > 1 else "에 붙어 있습니다."))
    if not _trusted(env):
        out.append("설정에 관리자 IP(trusted_ips)가 없습니다. 명령의 <관리자 IP>를 채우지 않고 적용하면 이 포트로 들어오는 "
                   "모든 접속이 끊깁니다.")
    else:
        out.append(f"적용 뒤에는 관리자 IP({', '.join(_trusted(env)[:2])})에서만 이 포트에 들어올 수 있습니다. "
                   "그 밖에서 접속하던 사람·배포 도구는 끊깁니다.")
    return out


def _nacl(fix: dict, inc: dict, env: dict) -> list[str]:
    acl = next((a for a in env.get("network_acls", []) if a.get("nacl_id") == fix["resource"]), None)
    if not acl:
        return []
    subnets = set(acl.get("subnet_ids") or [])
    insts = _servers(env, lambda i: i.get("subnet_id") in subnets)
    enis = [n for n in env.get("network_interfaces", []) if n.get("subnet_id") in subnets and not n.get("instance_id")]
    out = []
    sn = ", ".join(sorted(subnets)[:3]) + (" 등" if len(subnets) > 3 else "")
    if any(i.get("subnet_id") for i in env.get("instances", [])) or env.get("network_interfaces"):
        s = (f"이 NACL이 걸린 서브넷 {len(subnets)}개({sn}) 안의 서버 {len(insts)}대"
             + (f"({_names(insts)})" if insts else "")
             + (f"와 서버가 아닌 네트워크 인터페이스 {len(enis)}개" if enis else "")
             + "는 이 IP와 주고받는 모든 통신이 막힙니다(응답 포함).")
    else:
        s = (f"이 NACL이 걸린 서브넷 {len(subnets)}개({sn}) 안의 모든 자원이 이 IP와 주고받는 통신이 막힙니다(응답 포함). "
             "설정 스냅샷에 서버의 서브넷 정보가 없어 서버 수는 세지 못했습니다.")
    out.append(s)
    vpc_cidrs = [c for v in env.get("vpcs", []) for c in v.get("cidrs", [])]
    for cidr in (fix.get("proposed") or {}).get("deny", []):
        ip = str(cidr).split("/")[0]
        if _in(ip, _trusted(env)):
            out.append(f"주의: {ip}는 설정의 관리자 IP 대역 안에 있습니다. 막으면 우리 접속도 끊깁니다.")
        if _in(ip, vpc_cidrs):
            out.append(f"주의: {ip}는 우리 VPC 대역 안의 주소입니다. 막으면 그 서버와의 내부 통신도 끊깁니다.")
    n = len([e for e in acl.get("entries", []) if not e.get("egress")])
    if n >= 18:
        out.append(f"이 NACL의 들어오는 규칙이 이미 {n}개입니다. 기본 상한(20개)에 가까워 더 넣지 못할 수 있습니다.")
    return out


def _role(fix: dict, inc: dict, env: dict) -> list[str]:
    role = fix["resource"]
    insts = _servers(env, lambda i: role in (i.get("iam_role"), i.get("instance_profile")))
    if not insts:
        return []
    if fix["id"] == "IAM_ROLE_SESSION_REVOKE":
        return [f"이 역할을 쓰는 서버 {len(insts)}대({_names(insts)})의 앱도 지금 가진 키가 거부됩니다. "
                "새 키를 받을 때까지(보통 몇 분) AWS 호출이 실패할 수 있습니다."]
    return [f"이 역할을 쓰는 서버 {len(insts)}대({_names(insts)})에 함께 적용됩니다. "
            "제안 권한에 없는 API를 쓰던 앱은 거부됩니다."]


def _imds(fix: dict, inc: dict, env: dict) -> list[str]:
    inst = next((i for i in env.get("instances", []) if i["instance_id"] == fix["resource"]), None)
    if not inst:
        return []
    out = [f"{_names([inst])}에서 토큰 없이 메타데이터를 부르는 앱(오래된 SDK·직접 만든 스크립트)은 키를 받지 못합니다."]
    role = inst.get("iam_role")
    same = _servers(env, lambda i: i is not inst and role and i.get("iam_role") == role and i.get("imds") != "required")
    if same:
        out.append(f"같은 역할({role})을 쓰는 다른 서버 {len(same)}대({_names(same)})도 IMDSv1이 켜져 있습니다. "
                   "이 명령은 그 서버들을 바꾸지 않습니다.")
    return out


def _key(fix: dict, inc: dict, env: dict) -> list[str]:
    cur = fix.get("current") if isinstance(fix.get("current"), dict) else {}
    keys = {k.get("id") if isinstance(k, dict) else k for k in cur.get("keys", [])} - {None}
    evs = [e for e in inc.get("events", []) if e.get("access_key") and
           (e["access_key"] in keys or str(e.get("actor") or "").split("/")[-1] == fix["resource"])]
    if not evs:
        return []
    ips = sorted({e.get("src_ip") for e in evs if e.get("src_ip")})
    ours = [e for e in evs if e.get("known") or (e.get("src_ip") and _in(e["src_ip"], _trusted(env)))]
    s = f"사건 로그에서 이 키는 IP {len(ips)}곳에서 {len(evs)}번 쓰였습니다."
    if ours:
        s += f" 그중 {len(ours)}번은 우리 팀·관리자 IP의 호출이라, 이 키를 쓰는 우리 작업(배포 등)도 멈춥니다."
    return [s]


def _isolate(fix: dict, inc: dict, env: dict) -> list[str]:
    inst = next((i for i in env.get("instances", []) if i["instance_id"] == fix["resource"]), None)
    if not inst:
        return []
    return [f"{_names([inst])}의 모든 네트워크 통신이 끊겨 이 서버의 서비스가 멈춥니다. "
            f"원래 보안그룹({', '.join(inst.get('security_groups') or ['없음'])})을 쓰는 다른 서버는 바뀌지 않습니다."]


HANDLERS = {
    "SG_ADMIN_PORT_OPEN": _sg, "SG_DB_PORT_OPEN": _sg, "NACL_BLOCK_ATTACKER": _nacl,
    "IAM_ROLE_SESSION_REVOKE": _role, "IAM_OVERBROAD": _role, "IMDSV1_ENABLED": _imds,
    "IAM_KEY_COMPROMISED": _key, "ISOLATE_COMPROMISED_SERVER": _isolate,
}


def preview(fix: dict, incident: dict, env: dict) -> list[str]:
    """수정안 하나를 적용하면 함께 바뀌는 것. 설정 스냅샷이 없거나 셀 수 없으면 []."""
    h = HANDLERS.get(fix.get("id"))
    if not h or not env or env.get("_error"):
        return []
    try:
        return h(fix, incident, env)
    except (KeyError, TypeError, ValueError):
        return []

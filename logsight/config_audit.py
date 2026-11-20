"""
설정 점검: 사건에서 드러난 공격이 "어떤 설정 때문에 가능했는지"를 찾고,
보안그룹·NACL·WAF·IAM 수정안을 만든다.

입력은 environment.json(감시 대상 계정의 설정 스냅샷). 형식은 samples/environment.json 참고.
수정안은 사람이 검토한 뒤 직접 적용한다. 이 모듈은 어떤 AWS API도 호출하지 않는다.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

ANY = ("0.0.0.0/0", "::/0")


def _int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _rule_ports(r: dict) -> range:
    if str(r.get("protocol", "tcp")) in ("-1", "all"):
        return range(0, 65536)
    lo = _int(r.get("from_port"), 0)
    hi = _int(r.get("to_port"), lo)
    return range(lo, max(lo, hi) + 1)


def _perm(r: dict, cidr: str | None = None) -> str:
    """보안그룹 규칙 하나를 AWS CLI --ip-permissions 형식으로. revoke는 원래 규칙과 정확히 같아야 지워진다."""
    proto = str(r.get("protocol", "tcp"))
    cidr = cidr or r["cidr"]
    rng = f"Ipv6Ranges=[{{CidrIpv6={cidr}}}]" if ":" in cidr else f"IpRanges=[{{CidrIp={cidr}}}]"
    if proto in ("-1", "all"):
        return f"IpProtocol=-1,{rng}"
    lo = _int(r.get("from_port"), 0)
    hi = _int(r.get("to_port"), lo)
    return f"IpProtocol={proto},FromPort={lo},ToPort={hi},{rng}"


def _sg_cmd(verb: str, gid: str, r: dict, cidr: str | None = None) -> str:
    """단일 포트·IPv4·tcp면 짧은 형식, 아니면(포트 범위, IPv6, 모든 프로토콜) --ip-permissions."""
    c = cidr or r["cidr"]
    lo, hi = _int(r.get("from_port"), -1), _int(r.get("to_port"), _int(r.get("from_port"), -1))
    if str(r.get("protocol", "tcp")) in ("tcp", "udp") and lo == hi and ":" not in c:
        return f"aws ec2 {verb}-security-group-ingress --group-id {gid} --protocol {r.get('protocol', 'tcp')} --port {lo} --cidr {c}"
    return f"aws ec2 {verb}-security-group-ingress --group-id {gid} --ip-permissions '{_perm(r, c)}'"


def _resources(env: dict) -> dict[str, dict]:
    """서버 ID → 보안그룹·서브넷·VPC. EC2 인스턴스와 네트워크 인터페이스(ENI: RDS·ALB·Lambda 등)를 함께 본다.
    인스턴스에 ENI가 여러 개면 보안그룹·서브넷을 합친다."""
    out: dict[str, dict] = {}

    def put(rid, sgs, subnet, vpc):
        r = out.setdefault(rid, {"security_groups": set(), "subnets": set(), "vpc_id": vpc})
        r["security_groups"] |= set(sgs or [])
        if subnet:
            r["subnets"].add(subnet)
        r["vpc_id"] = r["vpc_id"] or vpc

    for i in env.get("instances", []):
        if i.get("instance_id"):
            put(i["instance_id"], i.get("security_groups"), i.get("subnet_id"), i.get("vpc_id"))
    for n in env.get("network_interfaces", []):
        rid = n.get("instance_id") or n.get("eni_id")
        if rid:
            put(rid, n.get("security_groups"), n.get("subnet_id"), n.get("vpc_id"))
    return out


def _incident_sgs(env: dict, inst_ids: set) -> set | None:
    """사건 서버에 붙은 보안그룹. 사건 서버를 모르거나 서버와 보안그룹의 연결을 모르면 None(전체를 본다)."""
    res = _resources(env)
    sgs = {g for i in inst_ids for g in res.get(i, {}).get("security_groups", ())}
    return sgs or None


def _incident_nacls(env: dict, inst_ids: set) -> tuple[list[dict], str]:
    """사건 서버들이 있는 모든 서브넷의 NACL. 서버가 서브넷 여러 곳에 걸치면 NACL도 여러 개다.
    반환: (NACL 목록, 근거) 근거 = "subnet"(서브넷으로 확인) | "only"(계정에 NACL이 하나뿐) | "unknown"(못 찾음)"""
    nacls = [n for n in env.get("network_acls", []) if n.get("nacl_id")]
    res = _resources(env)
    subnets = {sn for i in inst_ids for sn in res.get(i, {}).get("subnets", ())}
    hit = [n for n in nacls if subnets & set(n.get("subnet_ids", []))]
    if hit:
        return hit, "subnet"
    if len(nacls) == 1:
        return nacls, "only"
    # NACL이 여러 개인데 사건 서버의 서브넷을 모르면 고르지 않는다(예전엔 첫 NACL을 골라 엉뚱한 서브넷을 막았다)
    return [], "unknown"


MAX_SAME = 5  # 같은 종류 수정안을 이보다 많이 내면 하나로 묶는다(서브넷·보안그룹이 수천 개인 계정)


def _collapse(checks: list[dict], cid: str, what: str) -> list[dict]:
    """같은 id의 수정안이 MAX_SAME개를 넘으면 하나로 묶는다. 수천 개를 나열하면 보고서와 AI 입력이 커지고
    사람도 검토할 수 없다. 앞의 MAX_SAME개 명령만 싣고 나머지는 자원 목록으로 남긴다."""
    same = [c for c in checks if c["id"] == cid]
    if len(same) <= MAX_SAME:
        return checks
    head = same[0]
    resources = list(dict.fromkeys(c["resource"] for c in same))
    merged = {**head,
              "resource": f"{resources[0]} 외 {len(resources) - 1}개",
              "resources": resources,
              "title": f"{what} {len(resources)}개: {head['title']} 등",
              "evidence": list(dict.fromkeys(r for c in same for r in c.get("evidence", [])))[:10],
              "cli": [x for c in same[:MAX_SAME] for x in c["cli"]]
              + [f"# 나머지 {len(same) - MAX_SAME}개도 같은 방식으로 고친다(대상 목록은 resources)"],
              "caution": head.get("caution", "") + f" 같은 문제가 {what} {len(resources)}개에 있어 하나로 묶었다. "
                         "한꺼번에 적용하기 전에 몇 개로 먼저 확인한다."}
    out, done = [], False
    for c in checks:
        if c["id"] != cid:
            out.append(c)
        elif not done:
            out.append(merged)
            done = True
    return out


def _zone(env: dict, res: dict, rid: str) -> str:
    """서버가 있는 서브넷이 퍼블릭(인터넷 게이트웨이 경로 있음)인지 프라이빗인지. 모르면 빈 문자열."""
    pub = {sn["subnet_id"]: sn.get("public") for sn in env.get("subnets", []) if sn.get("subnet_id")}
    kinds = {pub.get(sn) for sn in res.get(rid, {}).get("subnets", ())} - {None}
    if not kinds:
        return ""
    return "퍼블릭 서브넷" if True in kinds else "프라이빗 서브넷"


def _own_sources(incident: dict) -> dict[str, str]:
    """사건의 출발지 중 우리 서버인 것 {IP: 서버 ID}. 우리 서버가 다른 서버를 공격했다면 그 서버가 침해된 것이다."""
    return {e["src_ip"]: e["src_instance"] for e in incident.get("events", [])
            if e.get("src_ip") and e.get("src_instance")}


def _has_rule(inc: dict, *rules: str) -> list[str]:
    """사건 안에서 해당 규칙이 붙은 근거 ref 목록."""
    return [e["ref"] for e in inc["events"]
            if (set(e.get("rules", [])) | set(e.get("gd_alias", []))) & set(rules)]


def _attacker_ips(inc: dict) -> list[str]:
    return [ip for ip in inc.get("src_ips", [])]


# 애플리케이션까지 들어온 웹 공격 요청(WAF가 막을 수 있는 종류). WEB_NO_WAF·NACL 차단의 근거가 된다
WEB_ATTACK_RULES = ("WAF_SQLI_NOT_BLOCKED", "WEBLOG_SQLI", "WEBLOG_TRAVERSAL", "WEBLOG_RFI",
                    "WEBLOG_CMD_INJECTION", "WEBLOG_XSS", "WEBLOG_SSRF", "WEBLOG_EXPLOIT_PROBE",
                    "WEBLOG_CODE_IN_HEADER", "WEBLOG_SENSITIVE_FILE")
# 출발지 IP를 막을 근거가 되는 규칙(위의 웹 공격 + 스캐너·무차별 대입·웹셸 접근)
BLOCK_IP_RULES = frozenset({"VPC_PORT_SCAN", "SSH_BRUTE_FORCE", "SSH_SUCCESS_AFTER_FAIL", "VPC_REMOTE_ADMIN_EXPOSED",
                            "WEBLOG_SCANNER", "WEBLOG_ENUM_404", "WEBLOG_AUTH_BRUTE",
                            "WEBLOG_AUTH_SUCCESS_AFTER_FAIL", "WEBLOG_WEBSHELL_ACCESS", "WEBLOG_UPLOAD_EXEC",
                            *WEB_ATTACK_RULES})
_WEB_KO = {"WAF_SQLI_NOT_BLOCKED": "SQL 인젝션", "WEBLOG_SQLI": "SQL 인젝션",
           "WEBLOG_TRAVERSAL": "경로 조작", "WEBLOG_RFI": "원격 파일 포함", "WEBLOG_CMD_INJECTION": "명령 삽입",
           "WEBLOG_XSS": "XSS", "WEBLOG_SSRF": "SSRF", "WEBLOG_EXPLOIT_PROBE": "알려진 취약점 공격 문자열",
           "WEBLOG_CODE_IN_HEADER": "헤더 코드 삽입", "WEBLOG_SENSITIVE_FILE": "설정 파일 열람"}


def web_app_fixes(incident: dict) -> list[dict]:
    """웹 규칙이 걸린 사건의 애플리케이션·서버 쪽 수정(웹셸 격리, 계정 잠금, 취약 코드 수정, 입력값 검증).
    웹서버 점검(web/webanalyze._remediation)과 같은 내용을 수정안 형식으로 낸다. 방화벽 쪽(차단·요청 제한·
    로그 보존)은 위의 NACL·WAF 수정안이 맡으므로 뺀다. 환경 설정이 없어도 낸다."""
    from .web.webanalyze import _remediation
    alias = {"WAF_SQLI_NOT_BLOCKED": "WEBLOG_SQLI"}
    found: dict[str, dict] = {}
    for f in incident["findings"]:
        r = alias.get(f["rule"], f["rule"])
        found.setdefault(r, {"rule": r, "evidence": []})["evidence"] += f.get("evidence", [])
    sev = {"now": "high", "soon": "medium", "later": "low"}
    return [{"id": x["id"], "target": x["target"], "resource": x.get("resource") or "로그에 이름 없음",
             "severity": sev.get(x["priority"], "low"), "title": x["action"],
             "why": x["detail"], "evidence": x["evidence"][:10], "current": None, "proposed": None,
             "cli": [], "rollback": [], "caution": "코드·계정·파일을 사람이 직접 고치는 일이라 적용 명령은 없다."}
            for x in _remediation(list(found.values()), incident.get("events", [])) if x["target"] in ("app", "file", "account")]


def _web_server_name(incident: dict) -> str:
    """WAF가 없는 웹서버의 이름: 사건의 인스턴스 → 로그의 호스트 이름 → 공격받은 도메인."""
    web = [e for e in incident["events"] if e.get("source") in ("weblog", "access", "alb", "waf")]
    names = [e["target_instance"] for e in web if e.get("target_instance")]  # 웹 로그가 가리키는 서버를 먼저
    names += [e.get(k) for e in web for k in ("host", "http_host") if e.get(k)]
    if names:  # 내부 확산으로 엮인 다른 서버(DB 등)는 웹서버가 아니다
        names = list(dict.fromkeys(str(n) for n in names))
        return ", ".join(names[:2])
    names += list(incident.get("instances") or [])
    names += [e.get(k) for e in incident["events"] for k in ("host", "http_host") if e.get(k)]
    names = list(dict.fromkeys(str(n) for n in names if n))
    return ", ".join(names[:2]) if names else "웹서버(로그에 이름 없음)"


def audit(incident: dict, env: dict) -> list[dict]:
    """사건 + 환경 설정 → 원인 설정과 수정안 목록."""
    web_fixes = web_app_fixes(incident)
    if not env or env.get("_error"):
        return web_fixes
    out: list[dict] = []
    trusted = [t["cidr"] if isinstance(t, dict) else t for t in env.get("trusted_ips", [])]
    admin_cidr = trusted[0] if trusted else "<관리자 IP>/32"
    rules_in_inc = {f["rule"] for f in incident["findings"]}
    rules_in_inc |= {r for e in incident["events"] for r in e.get("gd_alias", [])}  # GuardDuty 결과의 대응 규칙
    inst_ids = set(incident.get("instances", []))
    attackers = _attacker_ips(incident)

    # 1) 보안그룹: 관리 포트(22/3389)가 전 세계에 열림
    ev = _has_rule(incident, "SSH_BRUTE_FORCE", "SSH_SUCCESS_AFTER_FAIL",
                   "VPC_REMOTE_ADMIN_EXPOSED", "VPC_PORT_SCAN")
    linked = _incident_sgs(env, inst_ids)
    n_sg_before = len(out)
    for sg in env.get("security_groups", []):
        if not sg.get("group_id") or (linked is not None and sg["group_id"] not in linked):
            continue  # 사건 서버에 붙지 않은 보안그룹은 이 사건의 원인이 아니다
        for r in sg.get("ingress", []):
            if r.get("cidr") in ANY and any(p in _rule_ports(r) for p in (22, 3389)) and ev:
                port = 22 if 22 in _rule_ports(r) else 3389
                wide = len(_rule_ports(r)) > 1
                out.append({
                    "id": "SG_ADMIN_PORT_OPEN", "target": "security_group",
                    "resource": sg["group_id"], "severity": "high",
                    "title": f"보안그룹 {sg.get('name', sg['group_id'])}이 {port}번 포트를 0.0.0.0/0에 허용",
                    "why": "외부 누구나 관리 포트에 접속할 수 있어 무차별 대입·로그인이 가능했다.",
                    "evidence": ev[:10],
                    "current": r,
                    "proposed": {**r, "cidr": admin_cidr,
                                 "description": "관리자 IP만 허용(또는 SSM Session Manager로 대체)"},
                    "cli": [
                        _sg_cmd("revoke", sg["group_id"], r),
                        _sg_cmd("authorize", sg["group_id"], {"protocol": "tcp", "from_port": port,
                                                              "to_port": port}, admin_cidr),
                    ],
                    "caution": "관리자 IP가 바뀌면 접속이 끊긴다. 적용 전 현재 관리자 IP와 "
                               "SSM 접속 경로를 확인한다."
                               + (f" 이 규칙은 {port}번만이 아니라 포트 {_rule_ports(r).start}~{_rule_ports(r).stop - 1}"
                                  "(프로토콜 전체일 수 있음)를 함께 열고 있어, 지우면 그 포트들도 닫힌다. "
                                  "서비스에 필요한 포트(예: 80, 443)는 따로 다시 열어야 한다." if wide else ""),
                })
            # 스캔에서 응답한 불필요 포트(DB 등)
            if r.get("cidr") in ANY and any(p in _rule_ports(r) for p in (3306, 5432, 6379, 27017, 9200)) \
                    and "VPC_PORT_SCAN" in rules_in_inc \
                    and not any(c.get("current") is r for c in out):  # 같은 규칙을 이미 지우라고 했으면 생략
                out.append({
                    "id": "SG_DB_PORT_OPEN", "target": "security_group",
                    "resource": sg["group_id"], "severity": "high",
                    "title": f"보안그룹 {sg.get('name', sg['group_id'])}이 데이터베이스 포트를 외부에 허용",
                    "why": "포트 스캔 대상이 된 DB 포트가 인터넷에 노출되어 있다.",
                    "evidence": _has_rule(incident, "VPC_PORT_SCAN")[:10],
                    "current": r, "proposed": None,
                    "cli": [_sg_cmd("revoke", sg["group_id"], r)],
                    "caution": "애플리케이션 서버의 보안그룹만 참조하도록 바꾼다.",
                })

    if linked is None and not inst_ids:
        for c in out[n_sg_before:]:
            c["caution"] += (" 공격 대상 서버를 설정에서 찾지 못해 계정 전체 보안그룹에서 찾은 것이다. "
                             "사건과 관계없는 보안그룹일 수 있으니 대상 서버를 먼저 확인한다.")
    out = _collapse(_collapse(out, "SG_ADMIN_PORT_OPEN", "보안그룹"), "SG_DB_PORT_OPEN", "보안그룹")

    # 2) 우리 서버가 출발지: 침해된 서버로 보고 격리(내부 확산). 사설 IP를 NACL로 막으면 정상 통신까지 끊기고
    #    침해된 서버는 다른 경로로 계속 움직인다
    own = _own_sources(incident) if rules_in_inc & BLOCK_IP_RULES else {}
    res = _resources(env)
    for ip, rid in list(own.items())[:5]:
        r = res.get(rid, {})
        sgs = sorted(r.get("security_groups", ()))
        is_ec2 = rid.startswith("i-")
        victims = sorted({e.get("target_instance") for e in incident["events"]
                          if e.get("src_ip") == ip and e.get("target_instance") and e.get("target_instance") != rid})
        src_z = _zone(env, res, rid)
        path = (f"{src_z + '의 ' if src_z else ''}{rid}에서 "
                + ", ".join(f"{(_zone(env, res, v) + '의 ') if _zone(env, res, v) else ''}{v}" for v in victims[:3])
                + "(으)로") if victims else ""
        out.append({
            "id": "ISOLATE_COMPROMISED_SERVER", "target": "instance", "resource": rid, "severity": "high",
            "title": f"우리 서버 {rid}({ip})에서 다른 서버로 공격이 나감: 침해된 서버로 보고 격리",
            "why": "공격 출발지가 우리 서버다. 이 서버가 먼저 침해되어 다른 서버로 넘어가는 중(내부 확산)으로 보인다"
                   + (f": {path} 공격이 나갔다" if path else "") + ". "
                   "출발지 IP를 NACL로 막으면 그 서브넷의 정상 통신까지 끊기므로 서버 자체를 격리한다.",
            "evidence": [e["ref"] for e in incident["events"] if e.get("src_ip") == ip][:10],
            "current": {"security_groups": sgs, "subnets": sorted(r.get("subnets", ())), "vpc_id": r.get("vpc_id")},
            "proposed": {"security_groups": ["(들어오고 나가는 규칙이 없는 격리 그룹)"]},
            "cli": ([f"aws ec2 create-snapshot --volume-id <{rid}의 EBS 볼륨 ID> --description 'LogSight 격리 전 증거 보존'",
                     f"aws ec2 create-security-group --group-name logsight-isolate-{rid} "
                     f"--description 'LogSight isolation' --vpc-id {r.get('vpc_id') or '<VPC ID>'}",
                     "aws ec2 revoke-security-group-egress --group-id <위에서 만든 그룹 ID> --ip-permissions "
                     "'[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'",
                     f"aws ec2 modify-instance-attribute --instance-id {rid} --groups <위에서 만든 그룹 ID>"
                     + (f"  # 원래 그룹: {' '.join(sgs)}" if sgs else "")] if is_ec2 else []),
            "caution": ("격리하면 이 서버의 서비스가 멈춘다. 격리 전 디스크 스냅샷으로 증거를 남기고, "
                        "이 서버의 역할(IAM) 키도 함께 무효화한다." if is_ec2 else
                        "EC2가 아닌 자원(네트워크 인터페이스)이라 명령을 만들지 않았다. 자원 종류에 맞게 사람이 격리한다."),
        })

    # 3) NACL: 공격 IP 임시 차단. 사건 서버가 있는 서브넷마다(서브넷 여러 곳에 걸친 공격)
    ext = [ip for ip in attackers if ip not in own]
    if ext and env.get("network_acls") and rules_in_inc & BLOCK_IP_RULES:
        nacls, how = _incident_nacls(env, inst_ids)
    else:
        nacls, how = [], ""
    ev_refs = [e["ref"] for e in incident["events"] if e.get("src_ip") in ext][:10]
    base_caution = ("NACL 규칙 수에는 한도(기본 20개)가 있고 공격 IP는 쉽게 바뀐다. 임시 조치로 쓰고 "
                    "근본 원인(열린 포트, WAF 설정)을 함께 고친다. 번호가 50보다 작은 허용 규칙이 있으면 "
                    "그 규칙이 먼저 적용되니 번호를 확인한다.")
    for nacl in nacls:
        used = {_int(x.get("rule_number"), 0) for x in nacl.get("entries", [])}
        cmds, n = [], 50
        for ip in ext[:5]:
            while n in used:
                n += 1
            used.add(n)
            block = f"--ipv6-cidr-block {ip}/128" if ":" in ip else f"--cidr-block {ip}/32"
            cmds.append(f"aws ec2 create-network-acl-entry --network-acl-id {nacl['nacl_id']} "
                        f"--ingress --rule-number {n} --protocol -1 --rule-action deny {block}")
        out.append({
            "id": "NACL_BLOCK_ATTACKER", "target": "nacl", "resource": nacl["nacl_id"],
            "severity": "medium",
            "title": f"서브넷 NACL에 공격 IP {', '.join(ext[:5])} 차단 규칙 추가",
            "why": "보안그룹은 허용만 할 수 있어 특정 IP를 거부하려면 NACL 거부 규칙이 필요하다.",
            "evidence": ev_refs,
            "current": {"entries": len(nacl.get("entries", [])), "subnets": nacl.get("subnet_ids", [])[:10]},
            "proposed": {"deny": [f"{ip}/32" for ip in ext[:5]]},
            "cli": cmds,
            "caution": base_caution + (" 사건 서버의 서브넷을 설정에서 찾지 못해, 계정에 하나뿐인 NACL로 적었다. "
                                       "서버가 있는 서브넷의 NACL인지 확인한다."
                                       if how == "only" else ""),
        })
    if ext and how == "unknown":
        out.append({
            "id": "NACL_BLOCK_ATTACKER", "target": "nacl", "resource": "(서버가 있는 서브넷의 NACL 확인 필요)",
            "severity": "medium",
            "title": f"공격 IP {', '.join(ext[:5])} 차단: 서버가 있는 서브넷의 NACL에 거부 규칙 추가",
            "why": "보안그룹은 허용만 할 수 있어 특정 IP를 거부하려면 NACL 거부 규칙이 필요하다.",
            "evidence": ev_refs, "current": None, "proposed": {"deny": [f"{ip}/32" for ip in ext[:5]]},
            "cli": ["# 공격받은 서버의 서브넷 NACL ID를 확인한 뒤(aws ec2 describe-network-acls "
                    "--filters Name=association.subnet-id,Values=<서브넷 ID>):"]
            + [f"# aws ec2 create-network-acl-entry --network-acl-id <NACL ID> --ingress --rule-number <빈 번호> "
               f"--protocol -1 --rule-action deny --cidr-block {ip}/32" for ip in ext[:5]],
            "caution": base_caution + " 공격 대상 서버의 서브넷을 설정에서 찾지 못했다. NACL이 여러 개라 "
                       "임의로 고르지 않았다(엉뚱한 서브넷을 막게 된다). collect environment로 다시 수집하면 찾는다.",
        })
    out = _collapse(out, "NACL_BLOCK_ATTACKER", "NACL")

    # 4) WAF: SQLi 규칙 그룹이 COUNT 모드
    # 근거는 WAF를 거친 로그(WAF·ALB)에서만 쓴다(사양서 FR-26: nginx 로그만으로 WAF 수정안을 내지 않음)
    via_waf = {e["ref"] for e in incident["events"] if e.get("source") in ("waf", "alb")}
    ev = [r for r in _has_rule(incident, "WAF_SQLI_NOT_BLOCKED", "WEBLOG_SQLI") if r in via_waf]
    if ev:
        for acl in env.get("waf_web_acls", []):
            if not acl.get("name"):
                continue
            for r in acl.get("rules", []):
                if "SQLi" in str(r.get("managed_rule_group", "")) and \
                        str(r.get("override_action", "")).lower() == "count":
                    out.append({
                        "id": "WAF_SQLI_COUNT", "target": "waf", "resource": acl["name"],
                        "severity": "high",
                        "title": f"WAF {acl['name']}의 {r['name']} 규칙이 COUNT(기록만) 모드",
                        "why": "SQL 인젝션을 탐지하고도 차단하지 않아 요청이 서버까지 도달했다.",
                        "evidence": ev[:10],
                        "current": {"Name": r["name"], "OverrideAction": {"Count": {}}},
                        "proposed": {"Name": r["name"], "OverrideAction": {"None": {}}},
                        "cli": [
                            f"aws wafv2 get-web-acl --scope REGIONAL --name {acl['name']} "
                            f"--id {acl.get('id', '<web-acl-id>')} > acl.json",
                            "# acl.json의 Rules에서 위 규칙의 OverrideAction을 {\"None\": {}}로 바꾼 뒤",
                            f"aws wafv2 update-web-acl --scope REGIONAL --name {acl['name']} "
                            f"--id {acl.get('id', '<web-acl-id>')} --lock-token {acl.get('lock_token') or '<LockToken>'} "
                            f"--default-action {'Block' if str(acl.get('default_action', 'ALLOW')).upper() == 'BLOCK' else 'Allow'}={{}} "
                            "--rules file://rules.json "
                            "--visibility-config <기존 값>",
                        ],
                        "caution": "정상 요청이 막히는지 먼저 COUNT 로그에서 오탐을 확인한다.",
                    })
        if not any(c["id"] == "WAF_SQLI_COUNT" for c in out) and env.get("waf_web_acls") \
                and env["waf_web_acls"][0].get("name"):
            acl = env["waf_web_acls"][0]
            if not any("SQLi" in str(r.get("managed_rule_group", "")) for r in acl.get("rules", [])):
                out.append({
                    "id": "WAF_SQLI_MISSING", "target": "waf", "resource": acl["name"],
                    "severity": "high", "title": f"WAF {acl['name']}에 SQLi 관리형 규칙이 없음",
                    "why": "SQL 인젝션 요청을 막을 규칙이 없다.", "evidence": ev[:10],
                    "current": None,
                    "proposed": {"Name": "AWS-AWSManagedRulesSQLiRuleSet",
                                 "Statement": {"ManagedRuleGroupStatement": {
                                     "VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}},
                                 "OverrideAction": {"None": {}}},
                    "cli": ["# get-web-acl → Rules에 위 규칙 추가 → update-web-acl"],
                    "caution": "COUNT로 먼저 배포해 오탐을 확인한 뒤 차단으로 바꾼다.",
                })

    # WAF가 없는 계정: 웹 공격 요청이 애플리케이션까지 들어왔으면 유료 WAF와 무료 대안을 같이 제시
    web_ev = _has_rule(incident, *WEB_ATTACK_RULES)
    if web_ev and not env.get("waf_web_acls"):
        kinds = "·".join(dict.fromkeys(_WEB_KO[f["rule"]] for f in incident["findings"] if f["rule"] in _WEB_KO))
        out.append({
            "id": "WEB_NO_WAF", "target": "waf", "resource": _web_server_name(incident),
            "severity": "medium", "title": "웹 공격을 막는 장치(WAF)가 없음",
            "why": f"{kinds} 요청이 걸러지지 않고 애플리케이션까지 그대로 들어왔다.",
            "evidence": web_ev[:10], "current": None,
            "proposed": {"options": [
                "무료: 서버에 ModSecurity + OWASP Core Rule Set 설치(nginx/apache)",
                "유료: AWS WAF + AWSManagedRulesCommonRuleSet·SQLiRuleSet (월 약 5달러 + 규칙·요청 과금)",
                "공통: 입력값을 그대로 쿼리·경로·명령에 넣는 코드를 고친다(근본 해결)"]},
            "cli": ["# Ubuntu + nginx 예: sudo apt install libnginx-mod-http-modsecurity modsecurity-crs",
                    "# 처음엔 SecRuleEngine DetectionOnly로 오탐 확인 후 On으로 전환"],
            "caution": "WAF는 보조 수단이다. 취약한 코드 자체를 고쳐야 한다.",
        })

    # 4) 인스턴스: IMDSv1 허용 + 역할 자격증명 외부 사용
    ev = _has_rule(incident, "CT_INSTANCE_CRED_OUTSIDE", "CT_INSTANCE_CRED_MULTI_IP")
    for inst in env.get("instances", []):
        if ev and inst.get("instance_id") in inst_ids and inst.get("imds", "optional") != "required":
            out.append({
                "id": "IMDSV1_ENABLED", "target": "ec2", "resource": inst["instance_id"],
                "severity": "high",
                "title": f"인스턴스 {inst['instance_id']}가 IMDSv1을 허용",
                "why": "토큰 없이 메타데이터에서 역할 자격증명을 꺼낼 수 있어 탈취 위험이 크다.",
                "evidence": ev[:10],
                "current": {"HttpTokens": inst.get("imds") or "확인 안 됨(설정에 없음)"},
                "proposed": {"HttpTokens": "required"},
                "cli": [f"aws ec2 modify-instance-metadata-options --instance-id {inst['instance_id']} "
                        "--http-tokens required --http-endpoint enabled"],
                "caution": "오래된 SDK를 쓰는 앱은 IMDSv2를 지원하는지 먼저 확인한다.",
            })

    # 4.5) 탈취된 인스턴스 역할 세션 무효화 — 즉시 봉쇄, 사람이 실행(서버만 내려도 임시 키는 계속 작동)
    ev = _has_rule(incident, "CT_INSTANCE_CRED_OUTSIDE", "CT_INSTANCE_CRED_MULTI_IP")
    if ev:
        inst_roles = {inst.get("iam_role") for inst in env.get("instances", [])
                      if inst["instance_id"] in inst_ids and inst.get("iam_role")}
        if not inst_roles:  # 사건에 인스턴스가 특정 안 되면 환경의 인스턴스 역할을 모두 본다
            inst_roles = {inst.get("iam_role") for inst in env.get("instances", []) if inst.get("iam_role")}
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for role in sorted(r for r in inst_roles if r):
            out.append({
                "id": "IAM_ROLE_SESSION_REVOKE", "target": "iam", "resource": role, "severity": "high",
                "title": f"역할 {role}의 탈취된 세션 무효화(이전에 발급된 임시 자격증명 차단)",
                "why": "인스턴스에서 빠져나간 임시 자격증명은 서버를 꺼도 세션 만료까지(기본 수 시간) "
                       "공격자 PC에서 계속 작동한다. 지금까지 발급된 세션을 끊어야 멈춘다.",
                "evidence": ev[:10],
                "current": None,
                "proposed": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Deny", "Action": "*", "Resource": "*",
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": now_iso}}}]},
                "cli": [
                    f"# 위 proposed를 policy.json으로 저장(aws:TokenIssueTime={now_iso}=지금 UTC, 그 이전 발급 세션만 거부)",
                    f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions "
                    "--policy-document file://policy.json",
                    "# 같은 역할을 쓰는 정상 앱도 잠깐 끊긴다(인스턴스 프로필이 남아 있으면 재시작 때 새 자격증명을 받는다).",
                    "# 다음 할 일(복구): 새 역할로 인스턴스 프로필을 교체(스왑)한 뒤, 확인되면 이 거부 정책을 뗀다.",
                ],
                "caution": "같은 역할을 쓰는 운영 앱도 끊기므로 사람이 판단해 실행한다. 되돌리기는 거부 정책을 떼는 것이다.",
            })

    # 5) IAM: 역할/사용자 권한이 과도
    ev = _has_rule(incident, "CT_S3_BULK_READ", "CT_IAM_PERSISTENCE", "CT_DISCOVERY_BURST",
                   "CT_ACCESS_DENIED_BURST", "CT_INSTANCE_CRED_OUTSIDE", "CT_INSTANCE_CRED_MULTI_IP",
                   "CT_UNTRUSTED_IP", "CT_LOGGING_TAMPER")
    actors = set(incident.get("actors", []))
    for kind in ("iam_roles", "iam_users"):
        for p in env.get(kind, []):
            name = p.get("role_name") or p.get("user_name")
            if not ev or not any(a == name or f"/{name}/" in a or a.endswith(f"/{name}") for a in actors):
                continue
            wild = []
            for pol in p.get("policies", []):
                for st in _statements(pol.get("document", {})):
                    acts = st.get("Action", [])
                    acts = [acts] if isinstance(acts, str) else acts
                    res = st.get("Resource", [])
                    res = [res] if isinstance(res, str) else res
                    if st.get("Effect") == "Allow" and (
                            any(a == "*" or a.endswith(":*") for a in acts) and "*" in res):
                        wild.append({"policy": pol.get("name"), "statement": st})
            if wild or any(pol.get("name") == "AdministratorAccess" for pol in p.get("policies", [])):
                out.append({
                    "id": "IAM_OVERBROAD", "target": "iam", "resource": name, "severity": "high",
                    "title": f"{'역할' if kind == 'iam_roles' else '사용자'} {name}의 권한이 과도(와일드카드)",
                    "why": "탈취된 자격증명으로 필요 이상의 자원 조회·변경이 가능했다.",
                    "evidence": ev[:10],
                    "current": wild or [{"policy": "AdministratorAccess"}],
                    "proposed": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Action": p.get("needed_actions", ["s3:GetObject"]),
                        "Resource": p.get("needed_resources", ["arn:aws:s3:::<필요한 버킷>/*"])}]},
                    "cli": [f"aws iam {'put-role-policy --role-name' if kind == 'iam_roles' else 'put-user-policy --user-name'} "
                            f"{name} --policy-name least-privilege --policy-document file://policy.json",
                            "# 이후 와일드카드 정책 분리(detach/delete)"],
                    "caution": "실제로 쓰는 API는 IAM Access Analyzer의 '마지막 사용' 정보로 확인한다.",
                })
            if kind == "iam_users" and rules_in_inc & {"CT_UNTRUSTED_IP", "CT_IAM_PERSISTENCE",
                                                       "CT_LOGGING_TAMPER"}:
                keys = sorted({e.get("access_key") for e in incident["events"] if e.get("access_key")})
                out.append({
                    "id": "IAM_KEY_COMPROMISED", "target": "iam", "resource": name,
                    "severity": "high",
                    "title": f"사용자 {name}의 액세스 키 비활성화·교체",
                    "why": "신뢰 목록 밖에서 이 키로 권한 변경·로깅 중지가 시도됐다.",
                    "evidence": ev[:10], "current": {"keys": keys}, "proposed": {"Status": "Inactive"},
                    "cli": [f"aws iam list-access-keys --user-name {name}",
                            f"aws iam update-access-key --user-name {name} --access-key-id <키 ID> --status Inactive"],
                    "caution": "새 키를 발급해 배포 파이프라인에 반영한 뒤 기존 키를 삭제한다.",
                })

    # 6) CloudTrail 자체 보호
    ev = _has_rule(incident, "CT_LOGGING_TAMPER")
    trail = env.get("cloudtrail") or {}
    if ev and trail:
        out.append({
            "id": "TRAIL_UNPROTECTED", "target": "cloudtrail", "resource": trail.get("trail_name", "trail"),
            "severity": "high", "title": "CloudTrail 중지·삭제 시도에 대한 보호와 알림 부재",
            "why": "공격자가 흔적을 지우려 했다. 중지 권한 제한과 즉시 알림이 필요하다.",
            "evidence": ev[:10],
            "current": {k: trail.get(k) for k in ("multi_region", "log_file_validation")},
            "proposed": {"multi_region": True, "log_file_validation": True,
                         "scp_deny": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"]},
            "cli": [f"aws cloudtrail update-trail --name {trail.get('trail_name', '<trail>')} "
                    "--is-multi-region-trail --enable-log-file-validation",
                    "# EventBridge 규칙: eventName in [StopLogging, DeleteTrail] → SNS 알림"],
            "caution": "조직(Organizations)을 쓰면 SCP로 중지를 막는다.",
        })
    out += web_fixes
    for c in out:
        c["rollback"] = rollback(c["cli"])
    sev = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda c: sev.get(c["severity"], 3))
    return out


_RB = [  # (찾을 패턴, 되돌리는 명령 만들기)
    (re.compile(r"aws ec2 revoke-security-group-ingress (.*)"),
     lambda m: f"aws ec2 authorize-security-group-ingress {m[1]}"),
    (re.compile(r"aws ec2 authorize-security-group-ingress (.*)"),
     lambda m: f"aws ec2 revoke-security-group-ingress {m[1]}"),
    (re.compile(r"aws ec2 create-network-acl-entry --network-acl-id (\S+) (--ingress|--egress) "
                r"--rule-number (\d+)"),
     lambda m: f"aws ec2 delete-network-acl-entry --network-acl-id {m[1]} {m[2]} --rule-number {m[3]}"),
    (re.compile(r"aws ec2 modify-instance-metadata-options --instance-id (\S+) --http-tokens required(.*)"),
     lambda m: f"aws ec2 modify-instance-metadata-options --instance-id {m[1]} --http-tokens optional{m[2]}"),
    (re.compile(r"aws ec2 modify-instance-attribute --instance-id (\S+) --groups \S+ .*# 원래 그룹: (.+)$"),
     lambda m: f"aws ec2 modify-instance-attribute --instance-id {m[1]} --groups {m[2].strip()}"),
    (re.compile(r"aws iam update-access-key (.*)--status Inactive"),
     lambda m: f"aws iam update-access-key {m[1]}--status Active"),
    (re.compile(r"aws cloudtrail update-trail --name (\S+) --is-multi-region-trail --enable-log-file-validation"),
     lambda m: f"aws cloudtrail update-trail --name {m[1]} --no-is-multi-region-trail "
               "--no-enable-log-file-validation"),
    (re.compile(r"aws iam put-(role|user)-policy --(role|user)-name (\S+) --policy-name (\S+)"),
     lambda m: f"aws iam delete-{m[1]}-policy --{m[2]}-name {m[3]} --policy-name {m[4]}"),
    (re.compile(r"aws wafv2 update-web-acl"),
     lambda m: "# 변경 전에 저장한 acl.json의 Rules로 update-web-acl을 다시 실행(LockToken은 새로 받기)"),
]


def rollback(cli: list[str]) -> list[str]:
    """수정 명령을 되돌리는 명령(역순). 자동으로 만들 수 없는 명령은 건너뛴다."""
    out = []
    for cmd in reversed(cli):
        if cmd.startswith("#"):
            continue
        for pat, make in _RB:
            m = pat.search(cmd)
            if m:
                out.append(make(m))
                break
    return out


def _statements(doc) -> list[dict]:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return []
    st = (doc or {}).get("Statement", [])
    return [st] if isinstance(st, dict) else list(st)

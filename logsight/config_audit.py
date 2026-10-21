"""
설정 점검: 사건에서 드러난 공격이 "어떤 설정 때문에 가능했는지"를 찾고,
보안그룹·NACL·WAF·IAM 수정안을 만든다.

입력은 environment.json(감시 대상 계정의 설정 스냅샷). 형식은 samples/environment.json 참고.
수정안은 사람이 검토한 뒤 직접 적용한다. 이 모듈은 어떤 AWS API도 호출하지 않는다.
"""
from __future__ import annotations

import json

ANY = ("0.0.0.0/0", "::/0")


def _rule_ports(r: dict) -> range:
    if str(r.get("protocol", "tcp")) in ("-1", "all"):
        return range(0, 65536)
    return range(int(r.get("from_port", 0)), int(r.get("to_port", r.get("from_port", 0))) + 1)


def _has_rule(inc: dict, *rules: str) -> list[str]:
    """사건 안에서 해당 규칙이 붙은 근거 ref 목록."""
    return [e["ref"] for e in inc["events"] if set(e.get("rules", [])) & set(rules)]


def _attacker_ips(inc: dict) -> list[str]:
    return [ip for ip in inc.get("src_ips", [])]


def audit(incident: dict, env: dict) -> list[dict]:
    """사건 + 환경 설정 → 원인 설정과 수정안 목록."""
    if not env:
        return []
    out: list[dict] = []
    trusted = [t["cidr"] if isinstance(t, dict) else t for t in env.get("trusted_ips", [])]
    admin_cidr = trusted[0] if trusted else "<관리자 IP>/32"
    rules_in_inc = {f["rule"] for f in incident["findings"]}
    inst_ids = set(incident.get("instances", []))
    attackers = _attacker_ips(incident)

    # 1) 보안그룹: 관리 포트(22/3389)가 전 세계에 열림
    ev = _has_rule(incident, "SSH_BRUTE_FORCE", "SSH_SUCCESS_AFTER_FAIL",
                   "VPC_REMOTE_ADMIN_EXPOSED", "VPC_PORT_SCAN")
    for sg in env.get("security_groups", []):
        for r in sg.get("ingress", []):
            if r.get("cidr") in ANY and any(p in _rule_ports(r) for p in (22, 3389)) and ev:
                port = 22 if 22 in _rule_ports(r) else 3389
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
                        f"aws ec2 revoke-security-group-ingress --group-id {sg['group_id']} "
                        f"--protocol tcp --port {port} --cidr {r['cidr']}",
                        f"aws ec2 authorize-security-group-ingress --group-id {sg['group_id']} "
                        f"--protocol tcp --port {port} --cidr {admin_cidr}",
                    ],
                    "caution": "관리자 IP가 바뀌면 접속이 끊긴다. 적용 전 현재 관리자 IP와 "
                               "SSM 접속 경로를 확인한다.",
                })
            # 스캔에서 응답한 불필요 포트(DB 등)
            if r.get("cidr") in ANY and any(p in _rule_ports(r) for p in (3306, 5432, 6379, 27017, 9200)) \
                    and "VPC_PORT_SCAN" in rules_in_inc:
                out.append({
                    "id": "SG_DB_PORT_OPEN", "target": "security_group",
                    "resource": sg["group_id"], "severity": "high",
                    "title": f"보안그룹 {sg.get('name', sg['group_id'])}이 데이터베이스 포트를 외부에 허용",
                    "why": "포트 스캔 대상이 된 DB 포트가 인터넷에 노출되어 있다.",
                    "evidence": _has_rule(incident, "VPC_PORT_SCAN")[:10],
                    "current": r, "proposed": None,
                    "cli": [f"aws ec2 revoke-security-group-ingress --group-id {sg['group_id']} "
                            f"--protocol tcp --port {r.get('from_port')} --cidr {r['cidr']}"],
                    "caution": "애플리케이션 서버의 보안그룹만 참조하도록 바꾼다.",
                })

    # 2) NACL: 공격 IP 임시 차단
    if attackers and env.get("network_acls") and rules_in_inc & {
            "VPC_PORT_SCAN", "SSH_BRUTE_FORCE", "WAF_SQLI_NOT_BLOCKED", "SSH_SUCCESS_AFTER_FAIL",
            "VPC_REMOTE_ADMIN_EXPOSED", "WEB_SQLI_PATTERN"}:
        nacl = env["network_acls"][0]
        used = {int(x.get("rule_number", 0)) for x in nacl.get("entries", [])}
        cmds, n = [], 50
        for ip in attackers[:5]:
            while n in used:
                n += 1
            used.add(n)
            cmds.append(f"aws ec2 create-network-acl-entry --network-acl-id {nacl['nacl_id']} "
                        f"--ingress --rule-number {n} --protocol -1 --rule-action deny "
                        f"--cidr-block {ip}/32")
        out.append({
            "id": "NACL_BLOCK_ATTACKER", "target": "nacl", "resource": nacl["nacl_id"],
            "severity": "medium",
            "title": f"서브넷 NACL에 공격 IP {', '.join(attackers[:5])} 차단 규칙 추가",
            "why": "보안그룹은 허용만 할 수 있어 특정 IP를 거부하려면 NACL 거부 규칙이 필요하다.",
            "evidence": [e["ref"] for e in incident["events"] if e.get("src_ip") in attackers][:10],
            "current": {"entries": len(nacl.get("entries", []))},
            "proposed": {"deny": [f"{ip}/32" for ip in attackers[:5]]},
            "cli": cmds,
            "caution": "NACL 규칙 수에는 한도가 있고 공격 IP는 쉽게 바뀐다. 임시 조치로 쓰고 "
                       "근본 원인(열린 포트, WAF 설정)을 함께 고친다.",
        })

    # 3) WAF: SQLi 규칙 그룹이 COUNT 모드
    ev = _has_rule(incident, "WAF_SQLI_NOT_BLOCKED", "WEB_SQLI_PATTERN")
    if ev:
        for acl in env.get("waf_web_acls", []):
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
                            f"--id {acl.get('id', '<web-acl-id>')} --lock-token <LockToken> "
                            "--default-action Allow={} --rules file://rules.json "
                            "--visibility-config <기존 값>",
                        ],
                        "caution": "정상 요청이 막히는지 먼저 COUNT 로그에서 오탐을 확인한다.",
                    })
        if not any(c["id"] == "WAF_SQLI_COUNT" for c in out) and env.get("waf_web_acls"):
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

    # 4) 인스턴스: IMDSv1 허용 + 역할 자격증명 외부 사용
    ev = _has_rule(incident, "CT_INSTANCE_CRED_OUTSIDE", "CT_INSTANCE_CRED_MULTI_IP")
    for inst in env.get("instances", []):
        if ev and inst["instance_id"] in inst_ids and inst.get("imds", "optional") != "required":
            out.append({
                "id": "IMDSV1_ENABLED", "target": "ec2", "resource": inst["instance_id"],
                "severity": "high",
                "title": f"인스턴스 {inst['instance_id']}가 IMDSv1을 허용",
                "why": "토큰 없이 메타데이터에서 역할 자격증명을 꺼낼 수 있어 탈취 위험이 크다.",
                "evidence": ev[:10],
                "current": {"HttpTokens": "optional"}, "proposed": {"HttpTokens": "required"},
                "cli": [f"aws ec2 modify-instance-metadata-options --instance-id {inst['instance_id']} "
                        "--http-tokens required --http-endpoint enabled"],
                "caution": "오래된 SDK를 쓰는 앱은 IMDSv2를 지원하는지 먼저 확인한다.",
            })

    # 5) IAM: 역할/사용자 권한이 과도
    ev = _has_rule(incident, "CT_S3_BULK_READ", "CT_IAM_PERSISTENCE", "CT_DISCOVERY_BURST",
                   "CT_ACCESS_DENIED_BURST", "CT_INSTANCE_CRED_OUTSIDE", "CT_INSTANCE_CRED_MULTI_IP",
                   "CT_UNTRUSTED_IP", "CT_LOGGING_TAMPER")
    actors = set(incident.get("actors", []))
    for kind in ("iam_roles", "iam_users"):
        for p in env.get(kind, []):
            name = p.get("role_name") or p.get("user_name")
            if not ev or not any(f"/{name}/" in a or a.endswith(f"/{name}") for a in actors):
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
    sev = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda c: sev.get(c["severity"], 3))
    return out


def _statements(doc) -> list[dict]:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return []
    st = (doc or {}).get("Statement", [])
    return [st] if isinstance(st, dict) else list(st)

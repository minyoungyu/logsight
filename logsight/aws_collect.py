"""
읽기 전용 수집기 (`python -m logsight collect ...`).

1) environment: 보안그룹·NACL·WAF·인스턴스·IAM 역할·CloudTrail 설정을 읽어
   LogSight가 쓰는 environment.json 형식으로 저장한다. 손으로 쓸 필요가 없어지고,
   실제 계정에서도 방화벽 수정안이 나오게 된다.
2) cloudtrail-history: CloudTrail을 켜 두지 않았어도 AWS가 무료로 보관하는
   최근 90일 관리 이벤트(Event history)를 LookupEvents API로 내려받는다.
   추적(trail)을 만들 필요가 없는 무료 대안이다. 단 API가 초당 2회로 제한돼 느리고,
   데이터 이벤트(S3 객체 읽기 등)는 들어 있지 않다.

필요 권한(읽기 전용): ec2:Describe*, wafv2:List*/Get*, iam:Get*/List*,
cloudtrail:DescribeTrails/LookupEvents, sts:GetCallerIdentity.
AWS 관리형 정책 SecurityAudit 또는 ReadOnlyAccess로 충분하다.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator


def _session(session, region):
    import boto3  # 선택 의존성
    return session or boto3.Session(region_name=region)


def export_environment(session=None, region: str | None = None) -> dict[str, Any]:
    s = _session(session, region)
    region = region or s.region_name or "us-east-1"
    ec2 = s.client("ec2", region_name=region)
    errors: list[str] = []
    env: dict[str, Any] = {
        "_comment": "logsight collect environment 로 자동 생성. trusted_ips(관리자 IP)는 직접 채우세요.",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "region": region, "trusted_ips": [], "instances": [], "security_groups": [],
        "network_acls": [], "waf_web_acls": [], "iam_roles": [], "iam_users": [], "cloudtrail": {},
    }

    def guard(name, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", type(exc).__name__)
            errors.append(f"{name}: {code}")

    def account():
        env["account_id"] = s.client("sts", region_name=region).get_caller_identity()["Account"]

    profiles: set[str] = set()

    def instances():
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page.get("Reservations", []):
                for i in r.get("Instances", []):
                    if i.get("State", {}).get("Name") == "terminated":
                        continue
                    prof = (i.get("IamInstanceProfile") or {}).get("Arn", "")
                    prof_name = prof.rsplit("/", 1)[-1] if prof else None
                    if prof_name:
                        profiles.add(prof_name)
                    env["instances"].append({
                        "instance_id": i["InstanceId"],
                        "private_ip": i.get("PrivateIpAddress"),
                        "public_ip": i.get("PublicIpAddress"),
                        "private_dns": i.get("PrivateDnsName"),
                        "name": next((t["Value"] for t in i.get("Tags", []) if t.get("Key") == "Name"), None),
                        "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                        "instance_profile": prof_name,
                        "iam_role": prof_name,  # 아래 IAM 단계에서 실제 역할 이름으로 바꾼다
                        "imds": "required" if i.get("MetadataOptions", {}).get("HttpTokens") == "required"
                        else "optional",
                    })

    def sgs():
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for g in page.get("SecurityGroups", []):
                ingress = []
                for p in g.get("IpPermissions", []):
                    proto = p.get("IpProtocol", "-1")
                    lo = p.get("FromPort", 0 if proto == "-1" else None)
                    hi = p.get("ToPort", 65535 if proto == "-1" else None)
                    if proto == "-1":
                        lo, hi = 0, 65535
                    for r in p.get("IpRanges", []):
                        ingress.append({"protocol": proto, "from_port": lo, "to_port": hi,
                                        "cidr": r.get("CidrIp"), "description": r.get("Description", "")})
                    for r in p.get("Ipv6Ranges", []):
                        ingress.append({"protocol": proto, "from_port": lo, "to_port": hi,
                                        "cidr": r.get("CidrIpv6"), "description": r.get("Description", "")})
                    for r in p.get("UserIdGroupPairs", []):
                        ingress.append({"protocol": proto, "from_port": lo, "to_port": hi,
                                        "source_group": r.get("GroupId"), "description": r.get("Description", "")})
                env["security_groups"].append({"group_id": g["GroupId"], "name": g.get("GroupName"),
                                               "vpc_id": g.get("VpcId"), "ingress": ingress})

    def nacls():
        for n in ec2.describe_network_acls().get("NetworkAcls", []):
            env["network_acls"].append({
                "nacl_id": n["NetworkAclId"], "vpc_id": n.get("VpcId"),
                "subnet_ids": [a["SubnetId"] for a in n.get("Associations", []) if a.get("SubnetId")],
                "entries": [{"rule_number": e["RuleNumber"], "egress": e["Egress"],
                             "protocol": e.get("Protocol"), "cidr": e.get("CidrBlock") or e.get("Ipv6CidrBlock"),
                             "action": e.get("RuleAction")} for e in n.get("Entries", [])],
            })

    def waf():
        w = s.client("wafv2", region_name=region)
        for a in w.list_web_acls(Scope="REGIONAL").get("WebACLs", []):
            got = w.get_web_acl(Name=a["Name"], Scope="REGIONAL", Id=a["Id"])
            acl = got["WebACL"]
            rules = []
            for r in acl.get("Rules", []):
                mg = (r.get("Statement") or {}).get("ManagedRuleGroupStatement") or {}
                rules.append({"name": r["Name"], "priority": r.get("Priority"),
                              "managed_rule_group": mg.get("Name"),
                              "override_action": "count" if "Count" in (r.get("OverrideAction") or {}) else "none"})
            env["waf_web_acls"].append({
                "name": acl["Name"], "id": acl["Id"], "arn": acl.get("ARN"), "scope": "REGIONAL",
                "lock_token": got.get("LockToken"),
                "default_action": "BLOCK" if "Block" in (acl.get("DefaultAction") or {}) else "ALLOW",
                "rules": rules})

    def iam():
        client = s.client("iam")
        prof_to_role = {}
        for prof in profiles:
            try:
                roles = client.get_instance_profile(InstanceProfileName=prof)["InstanceProfile"]["Roles"]
                if roles:
                    prof_to_role[prof] = roles[0]["RoleName"]
            except Exception:  # noqa: BLE001
                errors.append(f"iam:GetInstanceProfile {prof}")
        for inst in env["instances"]:
            if inst.get("instance_profile") in prof_to_role:
                inst["iam_role"] = prof_to_role[inst["instance_profile"]]
        for role in sorted(set(prof_to_role.values())):
            env["iam_roles"].append({"role_name": role, "policies": _role_policies(client, role)})
        # 액세스 키를 가진 IAM 사용자(키 탈취 대응 수정안에 필요)
        for page in client.get_paginator("list_users").paginate():
            for u in page.get("Users", []):
                keys = client.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", [])
                if keys:
                    env["iam_users"].append({
                        "user_name": u["UserName"],
                        "access_keys": [k["AccessKeyId"][:8] + "…" for k in keys],  # 키 ID 일부만
                        "policies": _user_policies(client, u["UserName"])})

    def trail():
        ct = s.client("cloudtrail", region_name=region)
        trails = ct.describe_trails().get("trailList", [])
        if trails:
            t = trails[0]
            env["cloudtrail"] = {"trail_name": t["Name"], "multi_region": bool(t.get("IsMultiRegionTrail")),
                                 "log_file_validation": bool(t.get("LogFileValidationEnabled")),
                                 "s3_bucket": t.get("S3BucketName")}

    for name, fn in (("sts", account), ("ec2:instances", instances), ("ec2:security_groups", sgs),
                     ("ec2:nacls", nacls), ("wafv2", waf), ("iam", iam), ("cloudtrail", trail)):
        guard(name, fn)
    env["_errors"] = errors
    return env


def _docs(client, attached: list[dict], inline_names: list[str], get_inline) -> list[dict]:
    out = []
    for p in attached:
        try:
            ver = client.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = client.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
        except Exception:  # noqa: BLE001
            doc = {}
        out.append({"name": p["PolicyName"], "document": doc})
    for n in inline_names:
        try:
            out.append({"name": n, "document": get_inline(n)})
        except Exception:  # noqa: BLE001
            continue
    return out


def _role_policies(client, role: str) -> list[dict]:
    att = client.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
    inl = client.list_role_policies(RoleName=role).get("PolicyNames", [])
    return _docs(client, att, inl,
                 lambda n: client.get_role_policy(RoleName=role, PolicyName=n)["PolicyDocument"])


def _user_policies(client, user: str) -> list[dict]:
    att = client.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
    inl = client.list_user_policies(UserName=user).get("PolicyNames", [])
    return _docs(client, att, inl,
                 lambda n: client.get_user_policy(UserName=user, PolicyName=n)["PolicyDocument"])


# ------------------------------------------------------------------ CloudTrail 이벤트 기록(무료 90일)
def iter_event_history(session=None, region: str | None = None, days: int = 7,
                       max_events: int | None = None) -> Iterator[dict]:
    """LookupEvents로 최근 days일 관리 이벤트를 CloudTrail 원본 레코드 형식으로 돌려준다."""
    s = _session(session, region)
    region = region or s.region_name or "us-east-1"
    ct = s.client("cloudtrail", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 90))
    n = 0
    for page in ct.get_paginator("lookup_events").paginate(StartTime=start, EndTime=end):
        for e in page.get("Events", []):
            raw = e.get("CloudTrailEvent")
            try:
                rec = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                rec = None
            if not rec:  # 원본이 없으면 요약 필드로 최소 레코드를 만든다
                rec = {"eventTime": e["EventTime"].isoformat().replace("+00:00", "Z"),
                       "eventName": e.get("EventName"), "eventSource": e.get("EventSource"),
                       "userIdentity": {"type": "Unknown", "userName": e.get("Username")}}
            yield rec
            n += 1
            if max_events and n >= max_events:
                return


def collect_event_history(out_path, **kw) -> int:
    recs = list(iter_event_history(**kw))
    from pathlib import Path
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"Records": recs}, ensure_ascii=False, default=str), encoding="utf-8")
    return len(recs)

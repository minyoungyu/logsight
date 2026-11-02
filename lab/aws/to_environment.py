#!/usr/bin/env python3
"""LogSight AWS 랩 — 설정 스냅샷(environment.json) 생성기.

`aws` CLI(본인 PC의 자격증명)로 Project=LogSight 태그가 붙은 자원의 설정을 읽어
config_audit 가 쓰는 environment.json 형식으로 저장한다. describe 결과만 읽고 아무것도 바꾸지 않는다.

사용: python3 lab/aws/to_environment.py --region ap-northeast-2 --out environment.json
"""
from __future__ import annotations
import argparse, json, subprocess, sys


def aws(region: str, *args: str) -> dict | list:
    cmd = ["aws", "--region", region, "--output", "json", *args]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{out.stderr.strip()}")
    return json.loads(out.stdout or "null")


def build(region: str) -> dict:
    ident = aws(region, "sts", "get-caller-identity")
    account = ident["Account"]

    # Project=LogSight 태그가 붙은 실행 중 인스턴스만
    res = aws(region, "ec2", "describe-instances",
              "--filters", "Name=tag:Project,Values=LogSight",
              "Name=instance-state-name,Values=running,pending,stopping,stopped")
    instances, sg_ids, role_names = [], set(), set()
    for r in res.get("Reservations", []):
        for inst in r.get("Instances", []):
            sgs = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
            sg_ids.update(sgs)
            prof = inst.get("IamInstanceProfile", {}).get("Arn", "")
            role = prof.rsplit("/", 1)[-1] if prof else ""
            # instance-profile 이름이 역할 이름과 다를 수 있어 profile 에서 역할을 다시 찾는다
            if role:
                try:
                    p = aws(region, "iam", "get-instance-profile", "--instance-profile-name", role)
                    roles = p["InstanceProfile"].get("Roles", [])
                    if roles:
                        role = roles[0]["RoleName"]
                except Exception:
                    pass
                role_names.add(role)
            instances.append({
                "instance_id": inst["InstanceId"],
                "private_ip": inst.get("PrivateIpAddress", ""),
                "public_ip": inst.get("PublicIpAddress", ""),
                "security_groups": sgs,
                "iam_role": role,
                "imds": "required" if inst.get("MetadataOptions", {}).get("HttpTokens") == "required" else "optional",
            })

    security_groups = []
    if sg_ids:
        sg = aws(region, "ec2", "describe-security-groups", "--group-ids", *sorted(sg_ids))
        for g in sg.get("SecurityGroups", []):
            ingress = []
            for perm in g.get("IpPermissions", []):
                proto = perm.get("IpProtocol", "-1")
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                for rng in perm.get("IpRanges", []):
                    ingress.append({
                        "protocol": "tcp" if proto == "6" else ("udp" if proto == "17" else proto),
                        "from_port": fp, "to_port": tp,
                        "cidr": rng.get("CidrIp", ""),
                        "description": rng.get("Description", ""),
                    })
            security_groups.append({"group_id": g["GroupId"], "name": g.get("GroupName", g["GroupId"]), "ingress": ingress})

    network_acls = []
    try:
        nacl = aws(region, "ec2", "describe-network-acls",
                   "--filters", "Name=default,Values=true")
        for n in nacl.get("NetworkAcls", []):
            entries = []
            for e in n.get("Entries", []):
                entries.append({
                    "rule_number": e.get("RuleNumber"),
                    "egress": e.get("Egress", False),
                    "protocol": e.get("Protocol", "-1"),
                    "cidr": e.get("CidrBlock", ""),
                    "action": e.get("RuleAction", "allow"),
                })
            network_acls.append({
                "nacl_id": n["NetworkAclId"],
                "subnet_ids": [a["SubnetId"] for a in n.get("Associations", [])],
                "entries": entries,
            })
    except Exception as e:
        print(f"  (network_acls 건너뜀: {e})", file=sys.stderr)

    iam_roles = []
    for name in sorted(role_names):
        policies = []
        try:
            inline = aws(region, "iam", "list-role-policies", "--role-name", name)
            for pn in inline.get("PolicyNames", []):
                doc = aws(region, "iam", "get-role-policy", "--role-name", name, "--policy-name", pn)
                policies.append({"name": pn, "document": doc.get("PolicyDocument", {})})
            attached = aws(region, "iam", "list-attached-role-policies", "--role-name", name)
            for ap in attached.get("AttachedPolicies", []):
                policies.append({"name": ap["PolicyName"], "document": {"_attached": ap["PolicyArn"]}})
        except Exception as e:
            print(f"  (역할 {name} 정책 건너뜀: {e})", file=sys.stderr)
        iam_roles.append({"role_name": name, "policies": policies,
                          "needed_actions": ["s3:GetObject", "s3:ListBucket"],
                          "needed_resources": ["arn:aws:s3:::<필요한 버킷>/*"]})

    return {
        "_comment": "LogSight AWS 랩에서 aws describe-* 로 자동 수집한 설정 스냅샷. 손으로 만든 샘플이 아니다.",
        "account_id": account,
        "region": region,
        "trusted_ips": [],  # 관리자 사무실/본인 IP 가 있으면 [{"cidr":"x.x.x.x/32","label":"관리자"}] 로 채운다
        "instances": instances,
        "security_groups": security_groups,
        "network_acls": network_acls,
        "iam_roles": iam_roles,
        "iam_users": [],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        env = build(a.region)
    except Exception as e:
        print(f"[실패] {e}", file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2)
    print(f"[완료] {a.out} (인스턴스 {len(env['instances'])}, 보안그룹 {len(env['security_groups'])}, 역할 {len(env['iam_roles'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""BOTSv3에서 꺼낸 AWS·서버 로그를 이벤트(줄) 단위로 다시 라벨한다. LogSight 탐지 코드는 읽지 않는다.

예전 정답지는 공식 질문·공개 풀이에서 뽑은 3단계(B1 유출 키, B2 버킷 공개, B3 외부 업로드)였고 줄 라벨이 없었다.
여기서는 AIT-LDS 방식(줄마다 라벨 + 규칙 id)을 따르되, 공격자 식별자는 아래 두 근거로만 세운다.
  1) 공식 질문의 답(공개 풀이로 확인): 유출된 키 AKIAJOGC********XUPA, 버킷 ACL을 바꾼 사용자 bstoll·버킷 frothlywebcode
  2) 로그 줄 자체: 유출 키로 받은 GetSessionToken 응답에 든 세션 키(responseElements.credentials.accessKeyId)

클래스
  attack     공격자 식별자에서 나온 줄, 또는 줄 자체가 인증 실패 시도인 줄(SSH)
  risky      공격자가 한 일은 아니지만 공식 질문이 문제로 다룬 위험한 설정 변경(B2)
  normal     정상이라는 근거 규칙이 있는 줄(AWS 서비스, AWS 안에서 쓴 서비스 역할, 직원 콘솔 사용, ELB 상태 확인 등)
  unlabeled  어느 쪽 근거도 없는 줄. 정상으로 가정하지 않는다

  python scripts/relabel/label_botsv3.py --data <꺼낸 로그 폴더> --aws-ranges ip-ranges.json \
      --out reports/relabel/botsv3_labels.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# 공식 질문 '외부 코드 저장소에 유출된 키'의 답. 비밀 검사기에 걸리지 않게 SHA-256으로 적고, 출력에는 앞 8자·뒤 4자만 남긴다
OFFICIAL_ANSWER_DIGEST = "4f79ca17e62540d1d50db84e68fb164f6dfe46d8ac9bba95b81201dba0c92b09"
EMPLOYEES = {"bstoll", "btun"}          # 공식 질문 'IAM 사용자' 답 중 사람 계정(bstoll은 Bud Stoll로 풀이에서 확인)
PUBLIC_BUCKET = "frothlywebcode"        # 공식 질문 'bstoll이 공개로 바꾼 버킷'의 답
SOURCES = {
    "official_answers": [
        "https://github.com/chan2git/splunk-bots/tree/main/botsv3 (Q216~Q219: 유출 키, Q204~Q206: PutBucketAcl·bstoll·frothlywebcode, Q201: IAM 사용자 목록)",
        "https://github.com/crazyc4t/blog-v2/blob/HEAD/content/en/blog/botsv3.md",
    ]}
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def mask(k: str) -> str:
    return k[:8] + "********" + k[-4:] if k and len(k) > 12 else k


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--aws-ranges", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    data = Path(a.data)
    R = json.loads(Path(a.aws_ranges).read_text())
    aws = [ipaddress.ip_network(p["ip_prefix"]) for p in R["prefixes"]]

    def where(ip: str) -> str:
        if not ip or ip.endswith("amazonaws.com") or ip == "AWS Internal":
            return "service"
        try:
            x = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        if any(x in n for n in PRIVATE):
            return "private"
        return "aws" if any(x.version == n.version and x in n for n in aws) else "outside"

    rows = []

    def emit(ref, cls, labels, rules, evidence=None, note=None):
        rows.append({"ref": ref, "class": cls, "labels": labels, "rules": rules,
                     **({"evidence": evidence} if evidence else {}), **({"note": note} if note else {})})

    ct = json.loads((data / "cloudtrail.json").read_text())["Records"]
    # 1) 식별자
    anchors: dict[str, list[str]] = defaultdict(list)
    keys = {}
    for i, r in enumerate(ct, 1):
        k = r.get("userIdentity", {}).get("accessKeyId")
        if k and hashlib.sha256(k.encode()).hexdigest() == OFFICIAL_ANSWER_DIGEST:
            keys[k] = "id.key.official_leaked"
            anchors["key:" + k].append(f"cloudtrail.json:{i}")
            if r["eventName"] == "GetSessionToken" and not r.get("errorCode"):
                sk = (r.get("responseElements") or {}).get("credentials", {}).get("accessKeyId")
                if sk:
                    keys[sk] = "id.key.session_from_leaked"
                    anchors["key:" + sk].append(f"cloudtrail.json:{i}")
    att_ips: dict[str, list[str]] = defaultdict(list)
    for i, r in enumerate(ct, 1):
        if r.get("userIdentity", {}).get("accessKeyId") in keys and where(r["sourceIPAddress"]) != "service":
            att_ips[r["sourceIPAddress"]].append(f"cloudtrail.json:{i}")

    def ip_ev(ip):
        return att_ips[ip][:3]

    # 2) CloudTrail
    for i, r in enumerate(ct, 1):
        ref = f"cloudtrail.json:{i}"
        ui = r.get("userIdentity", {}); k = ui.get("accessKeyId"); ip = r["sourceIPAddress"]
        user = ui.get("userName") or ""; w = where(ip); name = r["eventName"]
        if k in keys:
            labels = ["attacker", "credential_misuse"]
            rules = {"attacker": ["origin.key"], "credential_misuse": [keys[k]]}
            if r.get("errorCode"):
                labels.append("denied_attempt"); rules["denied_attempt"] = ["step.ct.error"]
            if name in ("CreateAccessKey", "CreateUser", "DeleteAccessKey"):
                labels.append("persistence_attempt"); rules["persistence_attempt"] = ["step.ct.iam_key_user"]
            if name == "RunInstances":
                labels.append("resource_hijack_attempt"); rules["resource_hijack_attempt"] = ["step.ct.run_instances"]
            emit(ref, "attack", labels, rules, anchors["key:" + k][:2])
            continue
        if ip in att_ips:
            emit(ref, "attack", ["attacker"], {"attacker": ["origin.ip"]}, ip_ev(ip)); continue
        if name == "PutBucketAcl" and PUBLIC_BUCKET in json.dumps(r.get("requestParameters")) \
                and "AllUsers" in json.dumps(r.get("requestParameters")):
            emit(ref, "risky", ["bucket_public"], {"risky": ["risky.official_public_bucket_acl"]},
                 note="공식 질문(B2)이 다룬 버킷 공개. 요청 본문에 AllUsers 권한이 있다"); continue
        if name == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in json.dumps(r.get("requestParameters")):
            emit(ref, "risky", ["sg_open_world"], {"risky": ["risky.sg_ingress_0.0.0.0/0"]},
                 note="요청 본문에 0.0.0.0/0 허용이 있다. 공식 질문에는 없는 항목이라 단계로 세지 않는다"); continue
        if user in EMPLOYEES and ui.get("type") == "IAMUser":
            emit(ref, "normal", [], {"normal": ["normal.employee_user"]}); continue
        if w == "service" or ui.get("type") == "AWSService" or ui.get("invokedBy"):
            emit(ref, "normal", [], {"normal": ["normal.aws_service"]}); continue
        if ui.get("type") == "AssumedRole" and w in ("aws", "private", "service"):
            emit(ref, "normal", [], {"normal": ["normal.role_inside_aws"]}); continue
        if user == "splunk_access" and w == "aws":
            emit(ref, "normal", [], {"normal": ["normal.integration_user_inside_aws"]},
                 note="공식 답의 IAM 사용자 중 하나. 하루 내내 AWS 안 한 IP에서 Boto로 호출"); continue
        emit(ref, "unlabeled", [], {"unlabeled": ["unlabeled.ct"]})

    # 3) auth.log
    for i, line in enumerate((data / "auth.log").read_text(errors="replace").splitlines(), 1):
        ref = f"auth.log:{i}"
        m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        ip = m.group(1) if m else None
        if ip in att_ips:
            emit(ref, "attack", ["attacker"], {"attacker": ["origin.ip"]}, ip_ev(ip))
        elif ip and where(ip) == "outside" and re.search(r"Failed password|Invalid user|authentication failure", line):
            emit(ref, "attack", ["internet_bruteforce"], {"attack": ["step.auth.failed_or_invalid_from_internet"]},
                 note="줄 자체가 인터넷 주소의 인증 실패다. BOTSv3 시나리오 공격자와는 이어지지 않는다")
        else:
            emit(ref, "unlabeled", [], {"unlabeled": ["unlabeled.auth"]})

    # 4) 웹 접근 로그·ALB
    for fname, ipre in (("access.log", r"^(\S+) "), ("alb.log", r"^\S+ \S+ \S+ (\d+\.\d+\.\d+\.\d+):")):
        for i, line in enumerate((data / fname).read_text(errors="replace").splitlines(), 1):
            ref = f"{fname}:{i}"
            m = re.search(ipre, line); ip = m.group(1) if m else None
            if ip in att_ips:
                emit(ref, "attack", ["attacker_http"], {"attacker_http": ["origin.ip"]}, ip_ev(ip))
            elif "ELB-HealthChecker" in line and ip and where(ip) == "private":
                emit(ref, "normal", [], {"normal": ["normal.elb_health_check"]})
            else:
                emit(ref, "unlabeled", [], {"unlabeled": ["unlabeled.web"]})

    # 5) VPC Flow: 공격자 IP가 한쪽 끝이면 attack, 아니면 unlabeled
    for i, line in enumerate((data / "vpcflow.log").read_text(errors="replace").splitlines(), 1):
        f = line.split()
        ref = f"vpcflow.log:{i}"
        if len(f) > 4 and (f[3] in att_ips or f[4] in att_ips):
            ip = f[3] if f[3] in att_ips else f[4]
            emit(ref, "attack", ["attacker_net"], {"attacker_net": ["origin.ip"]}, ip_ev(ip))
        else:
            emit(ref, "unlabeled", [], {"unlabeled": ["unlabeled.vpcflow"]})

    # 6) GuardDuty 결과: 탐지기 출력이라 라벨 대상이 아니다
    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows).encode("utf-8")
    if out.name.endswith(".gz"):
        import gzip
        body = gzip.compress(body, mtime=0)
    out.write_bytes(body)
    summary = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": SOURCES,
        "inputs": [{"file": p.name, "sha256": sha(p)} for p in sorted(data.iterdir()) if p.is_file()],
        "aws_ip_ranges_createDate": R.get("createDate"),
        "attacker_keys": {mask(k): {"rule": v, "evidence": anchors["key:" + k][:5], "n": len(anchors["key:" + k])}
                          for k, v in keys.items()},
        "attacker_ips": {ip: {"rule": "id.ip.used_attacker_key", "where": where(ip), "evidence": ev[:3], "n": len(ev)}
                         for ip, ev in att_ips.items()},
        "by_class": dict(Counter(x["class"] for x in rows)),
        "by_class_and_file": dict(Counter(f'{x["ref"].split(":")[0]}:{x["class"]}' for x in rows)),
        "by_rule": dict(Counter(r for x in rows for v in x["rules"].values() for r in v)),
        "by_label": dict(Counter(l for x in rows for l in x["labels"])),
    }
    Path(str(out).replace(".jsonl.gz", ".jsonl").replace(".jsonl", "_summary.json")).write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

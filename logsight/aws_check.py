"""
로그 켜짐 사전 점검 (`python -m logsight check`).

분석할 로그가 아예 꺼져 있는 계정이 많아서(특히 보안 담당자 없는 작은 팀),
분석 전에 "어떤 로그가 켜져 있고, 꺼진 것은 얼마를 내고 켜거나 무엇으로 대신할지"를 알려 준다.

- 기본은 **읽기 전용**이다. Describe/Get/List API만 부른다.
- 켜기(--apply)는 사용자가 항목 ID를 직접 지정하고 확인('yes')해야만 실행한다.
  켜기가 지원되는 항목: CT_TRAIL, VPC_FLOW, GUARDDUTY (모두 되돌릴 수 있는 설정).
- 권한이 없어 확인 못 한 항목은 "unknown"으로 표시하고 계속 진행한다.
- 자격증명은 boto3 기본 체인(환경변수, ~/.aws, SSO, 인스턴스 역할)을 그대로 쓴다.
  LogSight는 키를 저장하거나 외부로 보내지 않는다.
"""
from __future__ import annotations

import json
from typing import Any

from .costs import PRICES

OK, MISSING, WARN, UNKNOWN, INFO = "ok", "missing", "warn", "unknown", "info"

# 점검 항목별 설명(한국어)과 무료 대안
ITEMS: dict[str, dict[str, str]] = {
    "CT_TRAIL": {
        "title": "CloudTrail 추적(trail)으로 관리 이벤트를 S3에 저장",
        "why": "누가 어떤 API를 불렀는지 남는 유일한 기록. 꺼져 있으면 사고 원인을 알 수 없다.",
        "cost": "관리 이벤트 첫 사본은 무료. S3 저장 비용만 든다(작은 계정은 보통 월 1달러 미만, 추정).",
        "alt": "켜기 전이라도 최근 90일 '이벤트 기록'은 무료로 남아 있다: "
               "python -m logsight collect cloudtrail-history",
    },
    "CT_MULTI_REGION": {
        "title": "CloudTrail을 모든 리전에 적용",
        "why": "공격자는 평소 안 쓰는 리전에서 인스턴스를 띄우는 경우가 많다.",
        "cost": "추가 비용 없음(관리 이벤트 첫 사본 무료 범위).",
        "alt": "",
    },
    "CT_VALIDATION": {
        "title": "CloudTrail 로그 파일 무결성 검증",
        "why": "로그가 조작됐는지 확인할 수 있다.",
        "cost": "추가 비용 없음.",
        "alt": "",
    },
    "VPC_FLOW": {
        "title": "VPC Flow Logs",
        "why": "어느 IP가 어느 포트로 접속했는지(포트 스캔, 관리 포트 노출) 알 수 있다.",
        "cost": "S3로 보내면 GB당 0.38달러(서울, us-east-1은 0.25) + S3 저장. CloudWatch Logs로 보내면 GB당 0.76달러(서울).",
        "alt": "서버 방화벽 로그(iptables/nftables LOG). scripts/setup_hostfw_log.sh 참고. "
               "단, 보안그룹이 막은 트래픽은 안 보인다.",
    },
    "WAF_LOGGING": {
        "title": "AWS WAF 로그",
        "why": "웹 공격(SQL 인젝션 등)이 들어왔는지, WAF가 막았는지 알 수 있다.",
        "cost": "WAF 자체가 월 5달러(ACL) + 규칙당 1달러 + 요청 100만 건당 0.60달러. "
                "로그는 요청 100만 건당 500MB까지 포함.",
        "alt": "nginx/apache 접속 로그를 그대로 분석(SQL 인젝션 패턴, 경로 탐색 규칙).",
    },
    "ALB_LOGS": {
        "title": "ALB 접속 로그",
        "why": "로드밸런서로 들어온 모든 웹 요청이 남는다.",
        "cost": "로그 기능 자체는 무료, S3 저장 비용만 든다.",
        "alt": "서버의 nginx/apache 접속 로그.",
    },
    "GUARDDUTY": {
        "title": "Amazon GuardDuty",
        "why": "AWS가 직접 위협을 탐지한다. 로그를 따로 켜지 않아도 CloudTrail·VPC·DNS를 분석한다.",
        "cost": "30일 무료 체험 후 사용량 과금(작은 계정은 월 몇 달러 수준, 추정). "
                "여러 단계를 엮는 Extended Threat Detection은 추가 비용 없음.",
        "alt": "LogSight는 GuardDuty 결과를 한국어로 풀어 설명하는 용도로 같이 쓸 수 있다(2단계).",
    },
    "IMDSV2": {
        "title": "EC2 메타데이터 IMDSv2 강제",
        "why": "IMDSv1이면 SSRF 한 번으로 인스턴스 역할 자격증명이 빠져나갈 수 있다.",
        "cost": "무료.",
        "alt": "",
    },
    "SG_ADMIN_OPEN": {
        "title": "관리 포트(22/3389)가 인터넷 전체에 열린 보안그룹",
        "why": "무차별 대입 공격의 대부분이 여기서 시작한다.",
        "cost": "무료. SSM Session Manager를 쓰면 22번을 아예 닫을 수 있다.",
        "alt": "",
    },
}

APPLY_SUPPORTED = ("CT_TRAIL", "VPC_FLOW", "GUARDDUTY")


def _err_code(exc: Exception) -> str:
    resp = getattr(exc, "response", None) or {}
    return resp.get("Error", {}).get("Code", type(exc).__name__)


def _item(id_: str, status: str, detail: str, resources: list[str] | None = None,
          cli: list[str] | None = None) -> dict[str, Any]:
    meta = ITEMS[id_]
    return {"id": id_, "status": status, "title": meta["title"], "detail": detail,
            "resources": resources or [], "why": meta["why"], "cost": meta["cost"],
            "free_alternative": meta["alt"], "enable_cli": cli or [],
            "can_apply": id_ in APPLY_SUPPORTED and status in (MISSING, WARN)}


def _safe(fn, id_: str, out: list[dict]):
    """권한 부족 등으로 실패하면 unknown 항목을 남기고 계속 진행."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - botocore 예외 종류가 많다
        out.append(_item(id_, UNKNOWN, f"확인 실패({_err_code(exc)}). 읽기 권한을 확인하세요."))


def run_checks(session=None, region: str | None = None) -> dict[str, Any]:
    """읽기 전용으로 로그·기본 보안 설정 상태를 점검한다."""
    import boto3  # 선택 의존성: check/collect를 쓸 때만 필요

    s = session or boto3.Session(region_name=region)
    region = region or s.region_name or "us-east-1"
    out: list[dict] = []
    account = None
    try:
        account = s.client("sts", region_name=region).get_caller_identity()["Account"]
    except Exception:  # noqa: BLE001
        pass
    ctx = {"account": account or "<ACCOUNT_ID>", "region": region,
           "bucket": f"logsight-logs-{account or '<ACCOUNT_ID>'}-{region}"}

    ec2 = s.client("ec2", region_name=region)

    def cloudtrail():
        ct = s.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        logging_trails = []
        for t in trails:
            try:
                st = ct.get_trail_status(Name=t.get("TrailARN") or t["Name"])
                if st.get("IsLogging"):
                    logging_trails.append(t)
            except Exception:  # noqa: BLE001
                continue
        if not logging_trails:
            out.append(_item("CT_TRAIL", MISSING,
                             "기록 중인 추적이 없음" if trails else "추적이 하나도 없음",
                             [t["Name"] for t in trails],
                             [f"aws s3api create-bucket --bucket {ctx['bucket']} "
                              f"--create-bucket-configuration LocationConstraint={region}",
                              "# 버킷 정책: cloudtrail.amazonaws.com에 s3:PutObject 허용(문서 참고)",
                              f"aws cloudtrail create-trail --name logsight-trail --s3-bucket-name {ctx['bucket']} "
                              "--is-multi-region-trail --enable-log-file-validation",
                              "aws cloudtrail start-logging --name logsight-trail"]))
            return
        names = [t["Name"] for t in logging_trails]
        out.append(_item("CT_TRAIL", OK, f"기록 중인 추적 {len(names)}개", names))
        if not any(t.get("IsMultiRegionTrail") for t in logging_trails):
            out.append(_item("CT_MULTI_REGION", WARN, "모든 추적이 단일 리전", names,
                             [f"aws cloudtrail update-trail --name {names[0]} --is-multi-region-trail"]))
        else:
            out.append(_item("CT_MULTI_REGION", OK, "다중 리전 추적 있음", names))
        if not any(t.get("LogFileValidationEnabled") for t in logging_trails):
            out.append(_item("CT_VALIDATION", WARN, "무결성 검증 꺼짐", names,
                             [f"aws cloudtrail update-trail --name {names[0]} --enable-log-file-validation"]))
        else:
            out.append(_item("CT_VALIDATION", OK, "무결성 검증 켜짐", names))

    def flow():
        vpcs = [v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", [])]
        logs = ec2.describe_flow_logs().get("FlowLogs", [])
        covered = {f.get("ResourceId") for f in logs}
        missing = [v for v in vpcs if v not in covered]
        if not vpcs:
            out.append(_item("VPC_FLOW", INFO, "VPC가 없음"))
        elif missing:
            out.append(_item("VPC_FLOW", MISSING, f"VPC {len(vpcs)}개 중 {len(missing)}개에 Flow Logs 없음",
                             missing,
                             [f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {' '.join(missing)} "
                              f"--traffic-type ALL --log-destination-type s3 "
                              f"--log-destination arn:aws:s3:::{ctx['bucket']}"]))
        else:
            out.append(_item("VPC_FLOW", OK, f"VPC {len(vpcs)}개 모두 켜짐", vpcs))

    def waf():
        w = s.client("wafv2", region_name=region)
        acls = w.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        if not acls:
            out.append(_item("WAF_LOGGING", INFO, "WAF 웹 ACL이 없음(WAF 미사용)"))
            return
        nolog = []
        for a in acls:
            try:
                w.get_logging_configuration(ResourceArn=a["ARN"])
            except Exception as exc:  # noqa: BLE001
                if _err_code(exc) in ("WAFNonexistentItemException", "ResourceNotFoundException"):
                    nolog.append(a["Name"])
                else:
                    raise
        if nolog:
            out.append(_item("WAF_LOGGING", MISSING, f"웹 ACL {len(acls)}개 중 {len(nolog)}개 로그 꺼짐", nolog,
                             ["# 로그 그룹 이름은 반드시 aws-waf-logs- 로 시작",
                              "aws logs create-log-group --log-group-name aws-waf-logs-logsight",
                              "aws wafv2 put-logging-configuration --logging-configuration "
                              "ResourceArn=<웹 ACL ARN>,LogDestinationConfigs=<로그 그룹 ARN>"]))
        else:
            out.append(_item("WAF_LOGGING", OK, f"웹 ACL {len(acls)}개 모두 로그 켜짐", [a["Name"] for a in acls]))

    def alb():
        e = s.client("elbv2", region_name=region)
        lbs = [lb for lb in e.describe_load_balancers().get("LoadBalancers", [])
               if lb.get("Type") == "application"]
        if not lbs:
            out.append(_item("ALB_LOGS", INFO, "ALB가 없음"))
            return
        off = []
        for lb in lbs:
            attrs = e.describe_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]
            if not any(a["Key"] == "access_logs.s3.enabled" and a["Value"] == "true" for a in attrs):
                off.append(lb["LoadBalancerName"])
        if off:
            out.append(_item("ALB_LOGS", MISSING, f"ALB {len(lbs)}개 중 {len(off)}개 접속 로그 꺼짐", off,
                             ["# 버킷 정책에 리전별 ELB 로그 전송 주체 허용 필요(문서 참고)",
                              "aws elbv2 modify-load-balancer-attributes --load-balancer-arn <ARN> --attributes "
                              f"Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value={ctx['bucket']}"]))
        else:
            out.append(_item("ALB_LOGS", OK, f"ALB {len(lbs)}개 모두 켜짐", [lb["LoadBalancerName"] for lb in lbs]))

    def guardduty():
        g = s.client("guardduty", region_name=region)
        dets = g.list_detectors().get("DetectorIds", [])
        enabled = [d for d in dets if g.get_detector(DetectorId=d).get("Status") == "ENABLED"]
        if enabled:
            out.append(_item("GUARDDUTY", OK, "켜짐", enabled))
        else:
            out.append(_item("GUARDDUTY", MISSING, "꺼짐" if dets else "탐지기 없음", dets,
                             ["aws guardduty create-detector --enable"]))

    def instances():
        v1, sg_ids = [], set()
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page.get("Reservations", []):
                for i in r.get("Instances", []):
                    if i.get("State", {}).get("Name") == "terminated":
                        continue
                    if i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                        v1.append(i["InstanceId"])
                    sg_ids |= {g["GroupId"] for g in i.get("SecurityGroups", [])}
        if v1:
            out.append(_item("IMDSV2", WARN, f"IMDSv1 허용 인스턴스 {len(v1)}개", v1,
                             [f"aws ec2 modify-instance-metadata-options --instance-id {i} "
                              "--http-tokens required --http-endpoint enabled" for i in v1[:10]]))
        else:
            out.append(_item("IMDSV2", OK, "모든 인스턴스 IMDSv2 강제(또는 인스턴스 없음)"))

    def sgs():
        bad = []
        for g in ec2.describe_security_groups().get("SecurityGroups", []):
            for p in g.get("IpPermissions", []):
                lo, hi = p.get("FromPort"), p.get("ToPort")
                all_ports = p.get("IpProtocol") == "-1"
                hit = [port for port in (22, 3389)
                       if all_ports or (lo is not None and hi is not None and lo <= port <= hi)]
                world = any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) or \
                    any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", []))
                if hit and world:
                    bad.append((g["GroupId"], hit))
        if bad:
            cli = []
            for gid, ports in bad[:10]:
                for port in ports:
                    cli.append(f"aws ec2 revoke-security-group-ingress --group-id {gid} "
                               f"--protocol tcp --port {port} --cidr 0.0.0.0/0")
            out.append(_item("SG_ADMIN_OPEN", WARN, f"보안그룹 {len(bad)}개가 관리 포트를 전체 공개",
                             [b[0] for b in bad], cli))
        else:
            out.append(_item("SG_ADMIN_OPEN", OK, "관리 포트 전체 공개 없음"))

    for fn, id_ in ((cloudtrail, "CT_TRAIL"), (flow, "VPC_FLOW"), (waf, "WAF_LOGGING"),
                    (alb, "ALB_LOGS"), (guardduty, "GUARDDUTY"), (instances, "IMDSV2"),
                    (sgs, "SG_ADMIN_OPEN")):
        _safe(fn, id_, out)

    order = {MISSING: 0, WARN: 1, UNKNOWN: 2, INFO: 3, OK: 4}
    out.sort(key=lambda x: order[x["status"]])
    return {"account": account, "region": region, "bucket": ctx["bucket"], "items": out,
            "summary": {k: sum(1 for x in out if x["status"] == k) for k in order},
            "prices_checked": PRICES["_checked"]}


# ------------------------------------------------------------------ 켜기(명시적 동의 필요)
def _ensure_bucket(s, region: str, bucket: str, account: str) -> None:
    """CloudTrail·VPC Flow Logs가 쓸 수 있는 비공개 버킷을 만든다(이미 있으면 정책만 갱신)."""
    s3 = s.client("s3", region_name=region)
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:  # noqa: BLE001
        kw = {} if region == "us-east-1" else {
            "CreateBucketConfiguration": {"LocationConstraint": region}}
        s3.create_bucket(Bucket=bucket, **kw)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    arn = f"arn:aws:s3:::{bucket}"
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "CloudTrailAclCheck", "Effect": "Allow",
         "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": arn},
        {"Sid": "CloudTrailWrite", "Effect": "Allow",
         "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"{arn}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        {"Sid": "FlowLogsAclCheck", "Effect": "Allow",
         "Principal": {"Service": "delivery.logs.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": arn},
        {"Sid": "FlowLogsWrite", "Effect": "Allow",
         "Principal": {"Service": "delivery.logs.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"{arn}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
    ]}
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def apply(ids: list[str], session=None, region: str | None = None) -> list[dict]:
    """지정한 항목만 켠다. 반환: 항목별 결과. 호출 전에 사용자 확인을 받을 것."""
    import boto3

    s = session or boto3.Session(region_name=region)
    region = region or s.region_name or "us-east-1"
    account = s.client("sts", region_name=region).get_caller_identity()["Account"]
    bucket = f"logsight-logs-{account}-{region}"
    results = []
    for id_ in ids:
        try:
            if id_ not in APPLY_SUPPORTED:
                results.append({"id": id_, "ok": False,
                                "detail": f"자동 켜기를 지원하지 않음. check 결과의 명령을 참고하세요."})
                continue
            if id_ == "GUARDDUTY":
                g = s.client("guardduty", region_name=region)
                dets = g.list_detectors().get("DetectorIds", [])
                if dets:
                    g.update_detector(DetectorId=dets[0], Enable=True)
                    det = dets[0]
                else:
                    det = g.create_detector(Enable=True)["DetectorId"]
                results.append({"id": id_, "ok": True, "detail": f"GuardDuty 켬 ({det})"})
            elif id_ == "CT_TRAIL":
                _ensure_bucket(s, region, bucket, account)
                ct = s.client("cloudtrail", region_name=region)
                names = {t["Name"] for t in ct.describe_trails().get("trailList", [])}
                if "logsight-trail" not in names:
                    ct.create_trail(Name="logsight-trail", S3BucketName=bucket,
                                    IsMultiRegionTrail=True, EnableLogFileValidation=True)
                ct.start_logging(Name="logsight-trail")
                results.append({"id": id_, "ok": True,
                                "detail": f"추적 logsight-trail 기록 시작 (버킷 {bucket})"})
            elif id_ == "VPC_FLOW":
                _ensure_bucket(s, region, bucket, account)
                ec2 = s.client("ec2", region_name=region)
                vpcs = [v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", [])]
                covered = {f.get("ResourceId") for f in ec2.describe_flow_logs().get("FlowLogs", [])}
                todo = [v for v in vpcs if v not in covered]
                bad = []
                if todo:
                    # 버킷 루트로 보내면 AWSLogs/<계정>/vpcflowlogs/ 아래에 쌓인다(CloudTrail과 경로가 겹치지 않음)
                    r = ec2.create_flow_logs(ResourceType="VPC", ResourceIds=todo, TrafficType="ALL",
                                             LogDestinationType="s3", LogDestination=f"arn:aws:s3:::{bucket}")
                    bad = [f"{u.get('ResourceId')}: {u.get('Error', {}).get('Message')}"
                           for u in r.get("Unsuccessful") or []]
                results.append({"id": id_, "ok": not bad,
                                "detail": ("실패 " + "; ".join(bad)) if bad else
                                f"Flow Logs 켬: {', '.join(todo) or '이미 모두 켜짐'}"})
        except Exception as exc:  # noqa: BLE001
            results.append({"id": id_, "ok": False, "detail": f"실패({_err_code(exc)}): {exc}"[:300]})
    return results


STATUS_KO = {OK: "켜짐", MISSING: "꺼짐", WARN: "주의", UNKNOWN: "확인불가", INFO: "해당없음"}


def format_text(res: dict) -> str:
    lines = [f"계정 {res['account'] or '?'} / 리전 {res['region']}",
             "  " + ", ".join(f"{STATUS_KO[k]} {v}" for k, v in res["summary"].items() if v), ""]
    for it in res["items"]:
        lines.append(f"[{STATUS_KO[it['status']]}] {it['id']}: {it['title']} - {it['detail']}")
        if it["status"] in (MISSING, WARN):
            lines.append(f"    왜: {it['why']}")
            lines.append(f"    비용: {it['cost']}")
            if it["free_alternative"]:
                lines.append(f"    대안(무료·저비용): {it['free_alternative']}")
            for c in it["enable_cli"]:
                lines.append(f"    $ {c}")
            if it["can_apply"]:
                lines.append(f"    → 자동으로 켜려면: python -m logsight check --apply {it['id']}")
    return "\n".join(lines)

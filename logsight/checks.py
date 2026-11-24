"""AI가 제안한 '다음에 확인할 명령'을 코드로 검사한다.

AI는 재검토 결과의 cannot_tell(이 로그로는 알 수 없는 것)마다 확인할 수 있는 AWS CLI 명령을
next_checks로 제안할 수 있다. 이 모듈은 그 명령을 그대로 믿지 않고 세 가지를 확인한다.

1. 읽기 전용인가: `aws <서비스> <동작>` 한 줄이고, 동작이 ALLOWED_OPS에 이름으로 적힌 조회 동작이다
   (비밀값·파일 내용·인증 토큰을 내는 동작은 목록에 없다).
2. 셸에서 다른 일을 하지 않는가: 파이프·세미콜론·리다이렉트·명령 치환이 없다.
3. 지어낸 자원이 없는가: 명령에 들어간 자원 이름(버킷, 사용자, 인스턴스 ID, ARN, 키 ID, IP 등)이
   AI에 보낸 사건 입력에 그대로 있다.

하나라도 어기면 그 제안을 버리고 이유를 센다. 버린 제안은 보고서에 나오지 않는다.
"""
from __future__ import annotations

import json
import re
import shlex

MAX_CHECKS = 10

# 허용 목록: 서비스별로 이름을 하나하나 적은 조회 동작만 쓴다.
# 처음에는 describe-·get-·list-로 시작하면 받았는데, 재검토(2026-11-25)에서 그 모양으로도
# 비밀값을 화면에 내는 동작(eks get-token, ssm get-parameter-history, ssm get-command-invocation,
# ec2 describe-instance-attribute의 userData 등)이 계속 나와서 '이름을 적은 것만'으로 바꿨다.
# 목록에 없는 제안은 버린다. 쓸 만한 동작이 빠졌으면 여기에 더한다(비밀값을 내지 않는지 먼저 확인).
ALLOWED_OPS = {
    "cloudtrail": {"lookup-events", "describe-trails", "get-trail-status", "get-event-selectors", "list-trails"},
    "s3api": {"get-bucket-policy", "get-bucket-policy-status", "get-bucket-acl", "get-public-access-block",
              "get-bucket-versioning", "get-bucket-logging", "get-bucket-encryption", "get-bucket-replication",
              "get-bucket-lifecycle-configuration", "get-bucket-ownership-controls", "list-buckets",
              "list-objects-v2", "list-object-versions", "head-bucket", "get-object-acl"},
    "ec2": {"describe-instances", "describe-security-groups", "describe-security-group-rules",
            "describe-network-acls", "describe-flow-logs", "describe-snapshots", "describe-snapshot-attribute",
            "describe-images", "describe-image-attribute", "describe-key-pairs", "describe-vpcs",
            "describe-subnets", "describe-network-interfaces", "describe-addresses", "describe-volumes",
            "describe-iam-instance-profile-associations", "describe-route-tables"},
    "iam": {"list-access-keys", "get-access-key-last-used", "list-users", "get-user", "list-mfa-devices",
            "list-virtual-mfa-devices", "list-attached-user-policies", "list-user-policies", "get-user-policy",
            "list-groups-for-user", "list-roles", "get-role", "list-attached-role-policies",
            "list-role-policies", "get-role-policy", "get-policy", "get-policy-version", "list-policy-versions",
            "get-login-profile", "get-account-password-policy", "get-account-summary",
            "list-entities-for-policy", "get-credential-report", "list-saml-providers",
            "list-open-id-connect-providers", "list-instance-profiles", "list-ssh-public-keys",
            "list-service-specific-credentials", "list-signing-certificates", "get-group", "list-groups"},
    "sts": {"get-caller-identity", "get-access-key-info"},
    "guardduty": {"list-detectors", "get-detector", "list-findings", "get-findings"},
    "logs": {"describe-log-groups", "describe-log-streams", "filter-log-events", "get-log-events",
             "describe-subscription-filters", "describe-metric-filters"},
    "lambda": {"get-policy", "list-event-source-mappings", "list-function-url-configs", "list-versions-by-function"},
    "rds": {"describe-db-instances", "describe-db-clusters", "describe-db-snapshots",
            "describe-db-snapshot-attributes", "describe-db-cluster-snapshots"},
    "kms": {"list-keys", "describe-key", "get-key-policy", "list-aliases", "list-grants", "get-key-rotation-status"},
    "configservice": {"describe-configuration-recorders", "describe-configuration-recorder-status",
                      "get-resource-config-history"},
    "wafv2": {"list-web-acls", "get-web-acl", "get-logging-configuration", "list-ip-sets", "get-ip-set"},
    "elbv2": {"describe-load-balancers", "describe-load-balancer-attributes", "describe-listeners",
              "describe-target-groups", "describe-rules"},
    "ssm": {"describe-instance-information", "describe-sessions", "list-commands"},
    "organizations": {"describe-organization", "list-accounts"},
    "accessanalyzer": {"list-analyzers", "list-findings"},
    "securityhub": {"describe-hub", "get-findings"},
    "ecs": {"list-clusters", "list-services", "list-tasks", "describe-clusters", "describe-services"},
    "eks": {"list-clusters", "describe-cluster", "list-nodegroups"},
    "cloudwatch": {"describe-alarms"},
    "route53": {"list-hosted-zones", "list-resource-record-sets"},
    "secretsmanager": {"list-secrets", "describe-secret", "get-resource-policy", "list-secret-version-ids"},
}
SHELL_META = re.compile(r"[;|&`$<>\n\\]")

# 값이 곧 자원 이름인 옵션
RESOURCE_OPTS = {
    "--bucket", "--user-name", "--role-name", "--group-name", "--policy-arn", "--function-name",
    "--instance-id", "--instance-ids", "--group-ids", "--group-id", "--trail-name", "--name",
    "--detector-id", "--log-group-name", "--log-group-names", "--access-key-id", "--key-id",
    "--snapshot-id", "--snapshot-ids", "--image-id", "--image-ids", "--vpc-id", "--vpc-ids",
    "--subnet-ids", "--network-acl-ids", "--db-instance-identifier", "--load-balancer-arn",
    "--resource-arn", "--arn", "--secret-id", "--web-acl-arn", "--finding-ids", "--serial-number",
}
# 값 안에 섞여 나와도 자원으로 보는 모양
ID_PATTERNS = [
    re.compile(r"arn:aws[\w-]*:[^\s,\"']+"),
    re.compile(r"\b(?:i|sg|vpc|subnet|eni|ami|snap|vol|acl|igw|rtb|nat)-[0-9a-f]{8,17}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
]
# 자원이 아닌 흔한 값(형식, 시각, 숫자, 리전, 필터 이름)
GENERIC = re.compile(
    r"^(?:\d+|json|text|table|yaml|true|false|"
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?|"
    r"[a-z]{2}(?:-gov)?-[a-z]+-\d)$")
NON_RESOURCE_KEYS = {"EventName", "EventSource", "ReadOnly", "ResourceType"}
# 요청을 다른 곳으로 보내거나, 로컬 파일을 읽거나, 서명·응답을 화면에 쏟는 전역 옵션.
# 로그에 공격자 IP가 있으므로 --endpoint-url http://<그 IP>는 "입력에 있는 자원" 검사를 통과해 버린다.
DENY_OPTS = {"--endpoint-url", "--cli-input-json", "--cli-input-yaml", "--debug", "--no-verify-ssl",
             "--ca-bundle", "--no-sign-request", "--cli-connect-timeout", "--cli-read-timeout"}
URL_VALUE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")


def _payload_text(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _check_one(cmd: str, known: str) -> str | None:
    """문제가 없으면 None, 있으면 버린 이유."""
    if not isinstance(cmd, str) or not cmd.strip():
        return "빈 명령"
    if SHELL_META.search(cmd):
        return "셸 기호(파이프·세미콜론·리다이렉트 등)"
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return "명령을 읽을 수 없음"
    if len(toks) < 3 or toks[0] != "aws":
        return "aws CLI 명령이 아님"
    svc, op = toks[1], toks[2]
    if svc not in ALLOWED_OPS:
        return f"허용 목록 밖 서비스({svc})"
    if op not in ALLOWED_OPS[svc]:
        return f"허용 목록 밖 동작({svc} {op})"
    for t in toks[3:]:
        name = t.split("=", 1)[0]
        if name in DENY_OPTS:
            return f"허용하지 않는 옵션({name})"
        if URL_VALUE.match(t.split("=", 1)[-1] if t.startswith("--") else t):
            return "주소·파일 값(file://, http:// 등)"
    values: list[str] = []
    for i, t in enumerate(toks[3:], start=3):
        prev = toks[i - 1]
        if t.startswith("--"):
            continue
        if prev in RESOURCE_OPTS:
            values.append(t)
        for p in ID_PATTERNS:
            values += p.findall(t)
        if prev == "--lookup-attributes" or prev == "--filters":
            # AttributeKey=Username,AttributeValue=bob → bob만 자원으로 본다.
            # AttributeKey가 EventName·EventSource·ReadOnly·ResourceType이면 값은 API 이름 등이라 자원이 아니다.
            parts = dict(p.partition("=")[::2] for p in t.split(","))
            if parts.get("AttributeKey") in NON_RESOURCE_KEYS:
                continue
            for k in ("AttributeValue", "Values"):
                v = parts.get(k)
                if v and not GENERIC.match(v):
                    values.append(v)
    for v in values:
        v = v.strip("\"'")
        if "*" in v:
            return f"가린 값이라 그대로 실행할 수 없음({v[:60]})"
        if v and not GENERIC.match(v) and v not in known:
            return f"사건 입력에 없는 자원({v[:60]})"
    return None


def validate_checks(checks: list, payload: dict) -> tuple[list, dict]:
    """통과한 제안과 검사 기록을 돌려준다. 최대 MAX_CHECKS개만 본다.
    자원 이름은 AI에 보낸 입력(payload)에서만 찾는다. AI가 쓴 글(cannot_tell)은 근거로 치지 않는다."""
    known = _payload_text(payload)
    kept, dropped = [], []
    seen = set()
    for c in (checks or [])[:MAX_CHECKS]:
        cmd = (c or {}).get("command", "") if isinstance(c, dict) else ""
        why = _check_one(cmd, known)
        if why is None and cmd in seen:
            why = "같은 명령 반복"
        if why is None and not str(c.get("about", "")).strip():
            why = "무엇을 확인하는지 없음"
        if why:
            dropped.append({"command": str(cmd)[:200], "reason": why})
            continue
        seen.add(cmd)
        kept.append({"about": c["about"], "command": cmd, "purpose": c.get("purpose", "")})
    extra = max(0, len(checks or []) - MAX_CHECKS)
    return kept, {"total": len(checks or []), "kept": len(kept), "dropped": dropped,
                  "over_limit": extra}

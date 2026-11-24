"""AI가 제안한 '다음에 확인할 명령'을 코드로 검사한다.

AI는 재검토 결과의 cannot_tell(이 로그로는 알 수 없는 것)마다 확인할 수 있는 AWS CLI 명령을
next_checks로 제안할 수 있다. 이 모듈은 그 명령을 그대로 믿지 않고 세 가지를 확인한다.

1. 읽기 전용인가: `aws <서비스> <동작>` 한 줄이고, 동작이 describe-·get-·list-·lookup- 등으로
   시작하며, 비밀값을 꺼내거나 파일을 내려받는 동작(get-secret-value, get-object 등)이 아니다.
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

SERVICES = {
    "cloudtrail", "s3api", "ec2", "iam", "sts", "guardduty", "logs", "lambda", "rds", "kms",
    "configservice", "wafv2", "elbv2", "ssm", "organizations", "accessanalyzer", "securityhub",
    "ecs", "eks", "cloudwatch", "route53", "secretsmanager",
}
READ_PREFIXES = ("describe-", "get-", "list-", "lookup-", "head-")
READ_EXTRA = {"filter-log-events"}
# 읽기지만 비밀값·데이터 본문을 꺼내는 동작
DENY_OPS = {
    "get-secret-value", "batch-get-secret-value", "get-password-data", "get-object",
    "get-object-torrent", "get-parameter", "get-parameters", "get-parameters-by-path",
    "get-login-password", "get-session-token", "get-federation-token", "get-authorization-token",
    "get-function", "get-function-configuration", "get-console-output", "get-console-screenshot",
    "get-launch-template-data", "describe-task-definition",  # 환경 변수에 비밀값이 들어 있을 수 있음
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
    if svc not in SERVICES:
        return f"허용 목록 밖 서비스({svc})"
    if op in DENY_OPS:
        return f"비밀값·데이터를 꺼내는 동작({op})"
    if not (op.startswith(READ_PREFIXES) or op in READ_EXTRA):
        return f"읽기 전용이 아닌 동작({op})"
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

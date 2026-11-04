"""
고객 설치 링크: 고객이 AWS 콘솔에서 '스택 생성' 버튼 하나만 누르면 되도록 매개변수를 모두 채운 링크를 만든다.

고객 계정에는 서버 설치 없이 계정 설정만 더한다(deploy/aws/logsight-onboard.yaml):
경보를 LogSight 허브로 전달, CloudTrail을 LogSight 보관 버킷(다른 계정, 지우기 잠금)으로, 읽기 전용 역할,
고르면 격리 전용 역할. IAM 경보는 AWS가 us-east-1로만 보내므로 그 리전용 두 번째 링크(alerts-only)도 준다.
ExternalId는 고객마다 새로 만든다(남의 계정 역할을 빌려 쓰는 혼동된 대리인 문제를 막는 AWS 권장 방식).
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import quote, urlencode

STACK = "logsight"
IAM_REGION = "us-east-1"


def _check(name: str, value: str, pattern: str) -> None:
    if not re.fullmatch(pattern, value or ""):
        raise ValueError(f"{name} 형식이 맞지 않음: {value!r}")


def link(template_url: str, region: str, params: dict[str, str]) -> str:
    """CloudFormation 빠른 생성 링크. 고객은 내용 확인 뒤 IAM 체크 하나와 '스택 생성'만 누른다."""
    q = {"templateURL": template_url, "stackName": STACK, **{f"param_{k}": v for k, v in params.items()}}
    return (f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"
            f"#/stacks/quickcreate?{urlencode(q, quote_via=quote)}")


def make(template_url: str, bus_arn: str, archive_bucket: str, principal_arn: str, *, region: str = "ap-northeast-2",
         vpc_id: str = "", isolation: bool = False, min_severity: str = "MEDIUM", create_trail: bool = True,
         external_id: str | None = None) -> dict:
    _check("템플릿 주소", template_url, r"https://[A-Za-z0-9.\-]+\.amazonaws\.com/\S+\.ya?ml")
    _check("허브 버스 ARN", bus_arn, r"arn:aws[\w-]*:events:[a-z0-9-]+:\d{12}:event-bus/[\w.\-]+")
    _check("보관 버킷", archive_bucket, r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]")
    _check("분석 서버 역할 ARN", principal_arn, r"arn:aws[\w-]*:iam::\d{12}:role/[\w+=,.@/\-]+")
    _check("리전", region, r"[a-z]{2}(-[a-z]+)+-\d")
    if vpc_id:
        _check("VPC ID", vpc_id, r"vpc-[0-9a-f]{8,17}")
    if min_severity not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError("min_severity는 LOW·MEDIUM·HIGH")
    ext = external_id or f"logsight-{secrets.token_hex(12)}"
    _check("ExternalId", ext, r"[\w+=,.@:/\-]{16,1224}")
    common = {"HubBusArn": bus_arn, "ArchiveBucketName": archive_bucket, "LogSightPrincipalArn": principal_arn,
              "ExternalId": ext, "MinGuardDutySeverity": min_severity}
    full = {"Part": "full", **common, "CreateTrail": str(create_trail).lower(), "VpcId": vpc_id,
            "EnableAutoIsolation": str(isolation).lower()}
    out = {"external_id": ext, "region": region, "links": [{"region": region, "part": "full",
                                                             "url": link(template_url, region, full)}]}
    if region != IAM_REGION:
        out["links"].append({"region": IAM_REGION, "part": "alerts-only",
                             "url": link(template_url, IAM_REGION, {"Part": "alerts-only", **common})})
    return out

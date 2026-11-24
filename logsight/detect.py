"""
규칙 기반 1차 탐지.

AI에 넘기기 전에 코드가 "의심스러운 이벤트"를 먼저 골라 표시한다. 각 규칙은
MITRE ATT&CK(Enterprise, Cloud) 기법 ID에 대응한다. 이 표시가 있는 이벤트만
사건 묶음의 핵심 근거가 되고, 나머지는 집계 요약으로만 AI에 전달된다.
탐지 규칙은 GuardDuty·Sigma의 공개된 CloudTrail 규칙 유형을 참고한 최소 구현이다.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import re
from dataclasses import dataclass
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus, urlsplit

from .netaddr import is_internal
from .normalize import Event, S3_PUBLIC_CALLS

# 규칙 ID -> (ATT&CK 기법, 전술(단계), 한국어 이름, 기본 심각도)
RULES: dict[str, tuple[str, str, str, str]] = {
    "CT_LOGGING_TAMPER":  ("T1562.008", "defense-evasion", "감사 로그·보안 서비스 중지·삭제", "high"),
    "CT_ROOT_USAGE":      ("T1078.004", "initial-access", "루트 계정 사용", "high"),
    "CT_IAM_PERSISTENCE": ("T1098", "persistence", "IAM 사용자·키·권한·DB 관리자 비밀번호 생성/변경", "high"),
    "CT_SG_OPENED":       ("T1562.007", "defense-evasion", "보안그룹·네트워크 ACL을 0.0.0.0/0에 개방", "high"),
    "CT_S3_PUBLIC":       ("T1537", "exfiltration", "S3 버킷을 인터넷 전체 또는 다른 계정에 공개(ACL·정책)", "high"),
    "CT_SNAPSHOT_SHARE":  ("T1537", "exfiltration", "스냅샷·AMI(EC2·RDS)를 외부 계정과 공유", "high"),
    "CT_SECRET_ACCESS":   ("T1555.006", "credential-access", "비밀값(Secrets Manager·SSM 암호 파라미터·Windows 암호) 대량 조회", "high"),
    "CT_INSTANCE_EXEC":   ("T1651", "execution", "인스턴스에 원격 명령·접속 경로(SSM·Instance Connect·시작 스크립트)", "medium"),
    "CT_SERVERLESS_CHANGE": ("T1525", "persistence", "Lambda·SageMaker 코드·권한·실행 설정 변경", "medium"),
    "CT_DATA_DESTRUCTION": ("T1485", "impact", "데이터 대량 삭제·암호화(랜섬웨어)·복구 수단 제거", "high"),
    "CT_ACCOUNT_SECURITY": ("T1556.006", "defense-evasion", "MFA·비밀번호 정책 등 계정 보안 설정 약화", "high"),
    "CT_INSTANCE_CRED_MULTI_IP": ("T1552.005", "credential-access", "인스턴스 역할 자격증명이 여러 IP에서 사용", "high"),
    "CT_INSTANCE_CRED_OUTSIDE":  ("T1552.005", "credential-access", "인스턴스 역할 자격증명이 인스턴스 밖에서 사용", "high"),
    "CT_ACCESS_DENIED_BURST": ("T1580", "discovery", "권한 없는 API를 연속 시도(권한 탐색)", "medium"),
    "CT_DISCOVERY_BURST": ("T1580", "discovery", "계정·자원 목록 조회 연속 실행", "medium"),
    "CT_S3_BULK_READ":    ("T1530", "collection", "S3 객체 대량 조회", "medium"),
    "CT_UNTRUSTED_IP":    ("T1078.004", "initial-access", "신뢰 목록 밖 IP에서 자격증명 사용", "medium"),
    "CT_CONSOLE_NO_MFA":  ("T1078.004", "initial-access", "MFA 없는 콘솔 로그인", "low"),
    "CT_RUN_INSTANCES_BURST": ("T1496", "impact", "인스턴스 대량 생성(자원 탈취 의심)", "high"),
    "VPC_PORT_SCAN":      ("T1046", "discovery", "여러 포트에 대한 접속 시도(포트 스캔)", "medium"),
    "VPC_REMOTE_ADMIN_EXPOSED": ("T1133", "initial-access", "외부에서 관리 포트(22/3389) 접속 허용", "medium"),
    "WAF_SQLI_NOT_BLOCKED": ("T1190", "initial-access", "SQL 인젝션 탐지됐지만 차단 안 됨(COUNT/ALLOW)", "high"),
    "WAF_BLOCKED":        ("T1190", "initial-access", "WAF가 공격 요청 차단", "low"),
    "SSH_BRUTE_FORCE":    ("T1110", "credential-access", "SSH 비밀번호 연속 실패(무차별 대입)", "medium"),
    "SSH_SUCCESS_AFTER_FAIL": ("T1078", "initial-access", "연속 실패 뒤 SSH 로그인 성공", "high"),
    "HOST_PRIV_ESC":      ("T1548.003", "privilege-escalation", "서버 권한 상승(웹 서비스 계정의 sudo·su, 셸 탈출·비밀번호 해시 읽기)", "high"),
    "HOST_PRIV_ESC_FAIL": ("T1548.003", "privilege-escalation", "sudo·su 거부·연속 실패(권한 상승 시도)", "medium"),
    "HOST_ACCOUNT_CREATED": ("T1136.001", "persistence", "서버에 새 계정 생성·관리자 그룹 추가", "medium"),
    "CT_CONSOLE_BRUTE":   ("T1110", "credential-access", "AWS 콘솔 로그인 연속 실패(무차별 대입)", "medium"),
    "GD_FINDING":         ("GuardDuty", "other", "GuardDuty 탐지 결과", "medium"),
    # --- 웹서버 로그·파일 기반 규칙(logsight.web) ---
    "WEBLOG_SQLI":        ("T1190", "initial-access", "웹 요청에 SQL 인젝션 패턴", "high"),
    "WEBLOG_TRAVERSAL":   ("T1190", "initial-access", "경로 조작·파일 열람(../, 민감 파일) 시도", "high"),
    "WEBLOG_RFI":         ("T1190", "initial-access", "원격 파일 포함(RFI) 시도", "high"),
    "WEBLOG_CMD_INJECTION": ("T1190", "initial-access", "운영체제 명령 삽입 시도", "high"),
    "WEBLOG_XSS":         ("T1059.007", "initial-access", "교차 사이트 스크립트(XSS) 시도", "medium"),
    "WEBLOG_SCANNER":     ("T1595.002", "discovery", "취약점 스캐너·자동 도구 탐지", "low"),
    "WEBLOG_ENUM_404":    ("T1595.003", "discovery", "존재하지 않는 경로 연속 탐색(열거)", "low"),
    "WEBLOG_SENSITIVE_FILE": ("T1083", "discovery", "설정·비밀 파일 접근 시도(.env 등)", "medium"),
    "WEBLOG_WEBSHELL_ACCESS": ("T1505.003", "persistence", "웹셸로 보이는 경로에 접근", "high"),
    "WEBLOG_UPLOAD_EXEC": ("T1505.003", "persistence", "업로드 폴더의 스크립트 실행", "high"),
    "WEBLOG_AUTH_BRUTE":  ("T1110", "credential-access", "웹 로그인 무차별 대입", "medium"),
    "WEBLOG_AUTH_SUCCESS_AFTER_FAIL": ("T1078", "initial-access", "로그인 연속 실패 뒤 성공", "high"),
    "WEBLOG_CODE_IN_HEADER": ("T1505.003", "persistence", "요청 헤더(User-Agent 등)에 실행 코드 삽입(로그 포이즈닝 준비)", "high"),
    "WEBLOG_ADMIN_ACCESS": ("T1078", "initial-access", "관리자 영역 접근 성공(기본 계정 로그인 의심)", "high"),
    "WEBLOG_SSRF":        ("T1190", "initial-access", "서버를 이용해 내부 주소를 요청(SSRF)", "high"),
    "WEBLOG_SSRF_IMDS":   ("T1552.005", "credential-access", "SSRF로 인스턴스 메타데이터(IMDS) 요청 — 서버 역할 키 탈취 시도", "high"),
    "WEBLOG_ROBOTS_HIDDEN": ("T1594", "discovery", "robots.txt를 읽고 숨은 경로에 접근", "medium"),
    "WEBLOG_OPEN_REDIRECT": ("T1566", "initial-access", "열린 리다이렉트(외부 사이트로 보내기) 시도", "low"),
    "WEBLOG_IDOR_ENUM":   ("T1530", "collection", "다른 사람의 주문 번호를 차례로 열람(IDOR)", "high"),
    "WEBLOG_ADMIN_FORGED": ("T1078", "initial-access", "로그인 없이 관리자 영역 접근(쿠키 위조 의심)", "high"),
    "WEBLOG_CSRF_SUSPECT": ("T1190", "initial-access", "외부 사이트에서 관리자 작업 요청(CSRF 의심)", "high"),
    "WEBLOG_BACKUP_LEAK": ("T1213", "collection", "백업·덤프·소스(.git 등) 파일이 외부에 노출됨", "high"),
    "WEBLOG_DIR_LISTING": ("T1083", "discovery", "업로드 폴더 목록이 외부에 공개됨", "medium"),
    "WEBLOG_EXPLOIT_PROBE": ("T1190", "initial-access", "알려진 취약점 공격 문자열(헤더) 시도 — Log4Shell·Shellshock 등", "medium"),
    "WEBLOG_EXPLOIT_5XX": ("T1190", "initial-access", "공격 요청에 서버 오류(500) 응답 — 취약점 반응", "high"),
    "WEBLOG_LARGE_EXFIL": ("T1030", "exfiltration", "공격 요청 뒤 비정상적으로 큰 응답(데이터 유출 의심)", "high"),
    "FILE_WEBSHELL":      ("T1505.003", "persistence", "웹 루트에서 웹셸 의심 파일 발견", "high"),
    "FILE_SUSPICIOUS":    ("T1105", "persistence", "웹 루트에서 의심스러운 신규·수정 파일", "medium"),
}

# GuardDuty 탐지 유형의 앞부분(위협 목적) → 단계
GD_STAGE = {"Recon": "discovery", "Discovery": "discovery", "UnauthorizedAccess": "initial-access",
            "InitialAccess": "initial-access", "CredentialAccess": "credential-access",
            "Persistence": "persistence", "PrivilegeEscalation": "privilege-escalation",
            "DefenseEvasion": "defense-evasion", "Stealth": "defense-evasion", "Policy": "defense-evasion",
            "Exfiltration": "exfiltration", "Impact": "impact", "CryptoCurrency": "impact",
            "Backdoor": "impact", "Trojan": "impact", "Execution": "impact",
            "AttackSequence": "impact"}

STAGE_ORDER = ["discovery", "initial-access", "execution", "credential-access", "persistence",
               "privilege-escalation", "defense-evasion", "collection", "exfiltration",
               "impact", "other"]

LOGGING_TAMPER = {"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                  "cloudtrail:PutEventSelectors", "ec2:DeleteFlowLogs",
                  "guardduty:DeleteDetector", "guardduty:UpdateDetector",
                  "wafv2:DeleteLoggingConfiguration", "config:StopConfigurationRecorder",
                  "config:DeleteConfigurationRecorder", "logs:DeleteLogGroup",
                  "route53resolver:DeleteResolverQueryLogConfig",
                  "route53resolver:DisassociateResolverQueryLogConfig",
                  "securityhub:DisableSecurityHub", "access-analyzer:DeleteAnalyzer",
                  "bedrock:DeleteModelInvocationLoggingConfiguration",
                  "organizations:LeaveOrganization"}
IAM_PERSIST = {"iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
               "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
               "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
               "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion",
               "iam:SetDefaultPolicyVersion", "sts:GetFederationToken",
               "rolesanywhere:CreateTrustAnchor", "rolesanywhere:CreateProfile",
               "ec2:ImportKeyPair", "ec2:CreateKeyPair"}
DISCOVERY = {"sts:GetCallerIdentity", "s3:ListBuckets", "iam:ListUsers", "iam:ListRoles",
             "iam:ListPolicies", "iam:GetAccountAuthorizationDetails", "iam:ListAccessKeys",
             "iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies", "iam:GetUser",
             "ec2:DescribeInstances", "ec2:DescribeRegions", "ec2:DescribeSecurityGroups",
             "ec2:DescribeSnapshots", "ec2:DescribeImages", "lambda:ListFunctions",
             "rds:DescribeDBInstances", "s3:ListObjects", "s3:GetBucketAcl",
             "s3:GetBucketPolicy", "organizations:DescribeOrganization",
             "secretsmanager:ListSecrets", "ssm:DescribeParameters",
             "ses:ListIdentities", "ses:GetSendQuota", "ses:GetAccountSendingEnabled",
             "ses:ListEmailIdentities", "ses:GetAccount"}
SECRET_READ = {"secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"}
INSTANCE_EXEC = {"ssm:SendCommand", "ssm:StartSession", "ec2-instance-connect:SendSSHPublicKey",
                 "ec2-instance-connect:SendSerialConsoleSSHPublicKey"}
SERVERLESS = {"lambda:UpdateFunctionCode", "lambda:CreateFunction",
              "sagemaker:CreateNotebookInstanceLifecycleConfig",
              "sagemaker:UpdateNotebookInstanceLifecycleConfig"}
ACCOUNT_SECURITY = {"iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice",
                    "iam:UpdateAccountPasswordPolicy", "iam:DeleteAccountPasswordPolicy"}
DESTROY_ONE = {"kms:ScheduleKeyDeletion", "kms:DisableKey", "backup:DeleteRecoveryPoint",
               "backup:DeleteBackupVault", "rds:DeleteDBCluster", "rds:DeleteDBInstance"}
DESTROY_BURST = {"s3:DeleteObject", "s3:DeleteObjects", "ec2:DeregisterImage", "ec2:DeleteSnapshot",
                 "s3:DeleteBucket"}
ADMIN_PORTS = {22, 3389}



def _path(action: str | None) -> str:
    """'GET /item?id=1' → '/item'"""
    a = (action or "").split(" ", 1)[-1]
    return a.split("?", 1)[0]


def sqli_success_signal(attempts: list, events: list) -> str:
    """SQL 인젝션 요청이 실제로 먹혔는지에 대한 코드 판단(AI에 맡기지 않는다).
    응답 크기만 본다. 같은 경로의 평소 응답(인젝션 문자열이 없는 2xx)과 크기가 같으면 같은 페이지가
    돌아온 것이라 성공 근거가 없고, 크게 다르면 데이터가 더 나왔을 수 있다. 확정이 아니라 신호다."""
    ok = [e for e in attempts if str(e.extra.get("http_status", ""))[:1] == "2"]
    if not ok:
        return "성공 신호 없음: 2xx 응답이 없음"
    sized = [e for e in ok if isinstance(e.extra.get("resp_bytes"), int)]
    if not sized:
        return "성공 판단 불가: 로그에 응답 크기가 없음"
    from .web.webdetect import is_sqli  # 순환 import를 피해 여기서
    att = {id(e) for e in attempts}
    paths = {_path(e.action) for e in sized}
    base = [e.extra["resp_bytes"] for e in events
            if id(e) not in att and e.source in ("alb", "weblog", "access") and _path(e.action) in paths
            and str(e.extra.get("http_status", ""))[:1] == "2" and isinstance(e.extra.get("resp_bytes"), int)
            and not is_sqli(unquote_plus((e.action or "").split("?", 1)[-1]))]
    sizes = [e.extra["resp_bytes"] for e in sized]
    if base:
        ref = sorted(base)[len(base) // 2]
        odd = [s for s in sizes if abs(s - ref) > max(200, ref * 0.2)]
        if odd:
            return (f"성공 의심: 2xx {len(sized)}건 중 {len(odd)}건의 응답 크기가 평소({ref}바이트)와 크게 다름"
                    f"(최대 {max(odd, key=lambda s: abs(s - ref))}바이트). 데이터가 나왔을 수 있어 확인 필요")
        return f"성공 근거 없음: 2xx {len(sized)}건 모두 평소 응답({ref}바이트)과 크기가 비슷함(같은 페이지로 보임)"
    if len(set(sizes)) == 1 and len(sizes) > 1:
        return (f"성공 근거 없음: 2xx {len(sized)}건의 응답 크기가 모두 {sizes[0]}바이트로 같음"
                "(같은 페이지가 돌아온 것으로 보임). 평소 응답이 로그에 없어 확정은 못 함")
    if len(sizes) > 1 and max(sizes) - min(sizes) > max(200, min(sizes) * 0.2):
        return (f"성공 의심: 2xx {len(sized)}건의 응답 크기가 {min(sizes)}~{max(sizes)}바이트로 크게 다름. "
                "데이터가 나왔을 수 있어 확인 필요")
    return f"성공 판단 불가: 2xx {len(sized)}건, 비교할 평소 응답이 로그에 없음"


def _ok_fail(evs) -> str:
    ok = sum(1 for e in evs if e.outcome in ("success", "accept", "allow"))
    return f"{len(evs)}건(성공 {ok}, 실패·거부 {len(evs) - ok})"


@dataclass
class Finding:
    rule: str
    events: list[Event]
    detail: str
    key: str = ""      # 묶음 키(IP/주체 등) — 보고서 표시용
    override: dict | None = None  # GuardDuty처럼 결과마다 단계·제목·심각도가 다른 경우

    def _get(self, i: int, k: str) -> str:
        return (self.override or {}).get(k) or RULES[self.rule][i]

    @property
    def technique(self) -> str:
        return self._get(0, "technique")

    @property
    def stage(self) -> str:
        return self._get(1, "stage")

    @property
    def title(self) -> str:
        return self._get(2, "title")

    @property
    def severity(self) -> str:
        return self._get(3, "severity")

    def to_dict(self) -> dict:
        return {"rule": self.rule, "technique": self.technique, "stage": self.stage,
                "title": self.title, "severity": self.severity, "detail": self.detail,
                "key": self.key, "first": self.events[0].ts.isoformat(),
                "last": self.events[-1].ts.isoformat(), "n_events": len(self.events),
                "evidence": [e.raw_ref for e in self.events[:20]]}


def _is_private(ip: str | None) -> bool:
    """사내 주소인가(없으면 사내로 본다). 기준은 netaddr 한 곳(설정의 VPC 대역 포함)."""
    if not ip:
        return True
    return is_internal(ip)


@lru_cache(maxsize=65536)
def _is_ip(s: str | None) -> bool:
    if not s:
        return False
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _bursts(evs: list[Event], window: timedelta, min_count: int, key=lambda e: e.action):
    """시간창 안에서 (서로 다른 key 값 기준) min_count 이상 모인 구간을 돌려준다.
    창 안의 key 개수를 Counter로 증감시켜 O(n)으로 계산한다(대용량 로그 대응)."""
    evs = sorted(evs, key=lambda e: e.ts)
    out: list[tuple[int, int]] = []
    counts: Counter = Counter()
    start = 0
    for end, e in enumerate(evs):
        counts[key(e)] += 1
        while e.ts - evs[start].ts > window:
            k = key(evs[start])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            start += 1
        if len(counts) >= min_count:
            if out and start <= out[-1][1] + 1:
                out[-1] = (out[-1][0], end)
            else:
                out.append((start, end))
    return [evs[a:b + 1] for a, b in out]


_HAS_DIGIT = re.compile(r"\d")


def _route(action: str) -> str | None:
    """"GET https://host/api/jobs/job-58152/download" → "GET /api/jobs/{id}/download".
    숫자가 든 경로 조각을 객체 번호로 본다. 확장자가 있는 조각(app.v2.js 같은 정적 파일)은 빼고,
    객체 번호가 없는 경로는 None."""
    method, _, url = action.partition(" ")
    path = urlsplit(url).path if "://" in url else url.split("?", 1)[0]
    segs = path.split("/")
    route = ["{id}" if _HAS_DIGIT.search(s) and "." not in s else s for s in segs]
    return f"{method} {'/'.join(route)}" if route != segs else None


def _ip_in(ip: str, cidrs: list[str]) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_reply(e: Event) -> bool:
    """흐름 기록이 서버 응답 방향으로 보이면 True(출발 포트가 낮고 대상 포트가 임시 포트 범위)."""
    sp, dp = e.extra.get("src_port"), e.dst_port
    return sp is not None and dp is not None and dp >= 32768 and sp < dp


# 예전 규칙 이름 → 지금 이름. 같은 공격을 사후 분석과 웹서버 점검이 다른 이름으로 부르던 것을 하나로 합쳤다.
# 저장해 둔 결과·측정 기준 파일을 읽을 때 쓴다(canonical_rule).
RULE_ALIASES = {"WEB_SQLI_PATTERN": "WEBLOG_SQLI", "WEB_PATH_PROBE": "WEBLOG_ENUM_404",
                "WEB_OBJECT_ENUM": "WEBLOG_IDOR_ENUM"}


def canonical_rule(rule: str) -> str:
    return RULE_ALIASES.get(rule, rule)


def _web_rule_findings(events: list[Event], env: dict, prior: list[Finding]) -> list[Finding]:
    web = [e for e in events if e.source in ("weblog", "alb", "waf")]
    if not web:
        return []
    from .web.webdetect import run_web_detections  # web.webdetect가 이 모듈을 가져다 쓰므로 여기서 부른다
    from .web.webprofile import web_profile_from_env
    hosts_seen = {str(e.extra["http_host"]).lower() for e in web if e.extra.get("http_host")}
    profile = web_profile_from_env(env, hosts_seen)
    skip = set()
    # 우리 사이트 이름을 모르면 외부 Referer를 가릴 수 없다(정상 관리자 요청을 CSRF로 오인)
    if not hosts_seen and not (env.get("web") or {}).get("own_hosts"):
        skip.add("WEBLOG_CSRF_SUSPECT")
    # WAF가 SQL 인젝션을 알아보고도 통과시킨 IP는 WAF_SQLI_NOT_BLOCKED가 이미 센다
    covered = {"WEBLOG_SQLI": {f.key for f in prior if f.rule == "WAF_SQLI_NOT_BLOCKED"}}
    return run_web_detections(web, profile, sources=("weblog", "alb", "waf"), skip=frozenset(skip),
                              covered=covered, include_auth=False)


# 웹 서비스가 도는 계정. 이 계정이 sudo·su를 쓰는 일은 정상 운영에서 거의 없다(웹셸에서 권한을 올리는 모습)
SERVICE_ACCOUNTS = frozenset({"www-data", "apache", "nginx", "httpd", "http", "wwwrun", "nobody", "daemon",
                              "tomcat", "php-fpm", "lighttpd"})
# sudo로 실행했을 때 root 셸을 여는 명령(GTFOBins에서 흔한 것). 관리자가 일상적으로 쓰는 모양과 겹치지 않는 것만
SHELL_ESCAPE = re.compile(
    r"(?i)(?:\bfind\b.*\s-exec\b|\b(?:python[\d.]*|perl|ruby|php|lua|node)\s+-[ecr]\b|"
    r"\btar\b.*--checkpoint-action|\bzip\b.*\s-TT?\b|\bawk\b.*system\s*\(|\benv\s+/bin/(?:ba|da)?sh\b|"
    r"\b(?:cp|tee|dd|mv)\b.*/etc/(?:passwd|shadow|sudoers)|\bchmod\b.*(?:u?\+s\b|\s[4-7][0-7]{3}\s)|"
    r"\bnmap\b.*--(?:interactive|script)|/bin/(?:ba|da|z)?sh\s+-p\b)")
# sudo로 계정 비밀번호 해시·root의 SSH 키를 읽는 명령(자격증명 수집, ATT&CK T1003.008·T1552.004)
CRED_READ = re.compile(r"(?i)/etc/g?shadow\b|/root/\.ssh/")
# 새 계정 만들기·관리자 그룹에 넣기·root 비밀번호 바꾸기
ACCOUNT_CMD = re.compile(r"(?i)(?:^|/|\s)(?:useradd|adduser|newusers)\b|\busermod\b.*-a?G\s*\S*\b(?:sudo|wheel|admin|root)\b"
                         r"|(?:^|/)passwd\s+root\b|/etc/sudoers")


# 서버가 처음 켜질 때 cloud-init이 만드는 기본 로그인 계정(이미지마다 하나). 첫 일반 계정(UID 1000)으로 생긴다
CLOUD_DEFAULT_USERS = frozenset({"ec2-user", "ubuntu", "admin", "centos", "cloud-user", "fedora", "debian",
                                 "rocky", "almalinux", "azureuser", "opc", "bitnami", "core", "alpine", "arch"})
_NOLOGIN = re.compile(r"(?:^|/)(?:nologin|false)$")
# 명령 줄에서 계정 이름이 아닌 조각: 리다이렉트(2>/dev/null), 셸 연결 기호
_NOT_NAME = re.compile(r"[<>|;&]")


def _setup_account(e: Event) -> str | None:
    """설치·부팅 과정에서 생기는 계정이면 그 이유. sudo로 만든 계정은 여기서 빼지 않는다(sudo 줄이 따로 잡힌다).
    - 패키지가 만드는 서비스 계정: 시스템 UID(1000 미만)이고 로그인 셸이 없음(nginx, apache …)
    - cloud-init 기본 계정: ec2-user·ubuntu 등이 첫 일반 계정(UID 1000)으로 생김
    CTF 리허설에서 두 서버의 부팅 기록(ec2-user, nginx, apache)이 '새 계정 생성(지속성)'으로 잡혔다."""
    if e.action != "useradd":
        return None
    uid, shell = e.extra.get("uid"), e.extra.get("shell") or ""
    name = (e.actor or "").strip().lower()
    if isinstance(uid, int) and uid < 1000 and _NOLOGIN.search(shell):
        return "시스템 서비스 계정(패키지 설치)"
    if uid == 1000 and name in CLOUD_DEFAULT_USERS:
        return "클라우드 이미지 기본 계정(부팅)"
    return None


def _account_target(e: Event) -> str:
    """만들어지거나 권한을 받은 계정 이름. useradd 줄은 그 사용자, sudo 명령은 명령의 마지막 인자(옵션 제외).
    bash -c 'sudo useradd hacker 2>/dev/null'처럼 감싼 명령은 따옴표·리다이렉트를 걷고 useradd 뒤를 본다."""
    if e.action == "useradd":
        return (e.actor or "?").strip()
    cmd = e.extra.get("command", "")
    if "/etc/sudoers" in cmd:
        return "sudoers"
    m = re.search(r"(?:^|/|\s)(?:useradd|adduser|newusers|usermod)\b(.*)", cmd)
    tail = m.group(1) if m else " ".join(cmd.split()[1:])
    toks = [t.strip("'\"") for t in tail.split()]
    args = []
    skip_next = False
    for t in toks:
        if _NOT_NAME.search(t) or not t:
            break  # 리다이렉트·다음 명령부터는 계정 이름이 아니다
        if skip_next:
            skip_next = False
            continue
        if t.startswith("-"):
            # 값을 받는 옵션(-s /bin/bash, -G wheel, -d /home/x 등)은 다음 조각을 건너뛴다
            skip_next = len(t) == 2 and t[1] in "sGgdcekpuK" or t in ("--shell", "--groups", "--gid", "--home-dir",
                                                                    "--comment", "--uid", "--password")
            continue
        args.append(t)
    return args[-1] if args else "?"


def host_auth_findings(events: list[Event]) -> list[Finding]:
    """서버 인증 로그(auth.log)의 sudo·su·계정 생성. 사후 분석과 웹서버 점검이 같이 쓴다."""
    host = [e for e in events if e.source in ("sshauth", "auth") and e.action in ("sudo", "su", "useradd")]
    findings: list[Finding] = []
    esc: dict[str, list[Event]] = defaultdict(list)
    fail: dict[str, list[Event]] = defaultdict(list)
    acct: dict[str, list[Event]] = defaultdict(list)
    # 웹 서비스 계정이 su로 넘어간 계정. 그 뒤 이 계정의 sudo는 웹셸에서 이어진 권한 상승으로 본다
    # (AIT-LDS: www-data → su blord → sudo cat /etc/shadow 가 놓쳤던 것)
    via_service: set[str] = set()
    for e in sorted(host, key=lambda e: e.ts or datetime.min.replace(tzinfo=timezone.utc)):
        who = (e.actor or "?").strip()
        cmd = e.extra.get("command", "")
        svc = who.lower() in SERVICE_ACCOUNTS or who.lower() in via_service
        if e.action == "su" and e.outcome == "success" and who.lower() in SERVICE_ACCOUNTS:
            via_service.add(str(e.extra.get("target_user", "")).strip().lower())
        if e.action == "useradd" and _setup_account(e):
            e.extra["setup_account"] = _setup_account(e)  # 지우지 않고 표시만(보고서 근거 확인용)
        elif e.action == "useradd" or (e.action == "sudo" and e.outcome == "success" and ACCOUNT_CMD.search(cmd)):
            acct[_account_target(e)].append(e)
        if e.action in ("sudo", "su") and e.outcome == "success" and (
                svc or SHELL_ESCAPE.search(cmd) or (e.action == "sudo" and CRED_READ.search(cmd))):
            esc[who].append(e)
        elif e.action in ("sudo", "su") and e.outcome == "failure":
            fail[who].append(e)
    for who, evs in esc.items():
        cmds = ", ".join(sorted({(e.extra.get("command") or f"su → {e.extra.get('target_user', 'root')}")[:60]
                                 for e in evs})[:3])
        why = ("웹 서비스 계정" if who.lower() in SERVICE_ACCOUNTS
               else "웹 서비스 계정에서 su로 넘어간 계정" if who.lower() in via_service
               else "셸 탈출·자격증명 파일 읽기 명령")
        findings.append(Finding("HOST_PRIV_ESC", evs, f"{why} '{who}'의 권한 상승 {len(evs)}건: {cmds}", who))
    for who, evs in fail.items():
        evs.sort(key=lambda e: e.ts)
        if who.lower() in SERVICE_ACCOUNTS:  # 서비스 계정은 한 번의 시도도 의미가 있다
            findings.append(Finding("HOST_PRIV_ESC_FAIL", evs, f"웹 서비스 계정 '{who}'의 sudo·su 시도 {len(evs)}건 거부", who))
            continue
        for seg in _bursts(evs, timedelta(minutes=10), 3, key=lambda e: e.raw_ref):
            findings.append(Finding("HOST_PRIV_ESC_FAIL", seg, f"10분 안에 '{who}'의 sudo·su 실패 {len(seg)}건", who))
    for target, evs in acct.items():
        by = sorted({(e.actor or "?").strip() for e in evs if e.action == "sudo"})
        findings.append(Finding("HOST_ACCOUNT_CREATED", evs,
                                f"'{target}' 계정 생성·권한 부여 {len(evs)}건" + (f"(실행: {', '.join(by)})" if by else ""),
                                target))
    return findings


NET_SOURCES = ("vpcflow", "hostfw")
# 요청 하나가 사용자 한 명의 행동인 로그(웹·엣지·인증). 사설 IP도 그 사용자를 가리킨다
APP_SOURCES = frozenset({"weblog", "access", "weberror", "auth", "sshauth", "alb", "waf"})
# 로드밸런서·프록시가 자기 주소로 보내는 상태 확인 요청의 User-Agent
_HEALTH_UA = re.compile(r"(?i)ELB-HealthChecker|kube-probe|HealthCheck|GoogleHC|Consul Health")
# 한 사설 IP에서 이만큼 서로 다른 User-Agent가 보이면 여러 사용자가 함께 쓰는 중계 주소로 본다.
# AIT-LDS 사내 NAT 주소(공격자 + 원격 근무자)는 4일 동안 7종이었다. 인터넷 사용자를 받는
# 로드밸런서 뒤 웹서버(XFF 없음)는 수십~수백 종이 된다.
SHARED_UA_MIN = 20


def shared_private_ips(events: list[Event], env: dict | None = None) -> dict[str, str]:
    """여러 사용자가 함께 쓰는 사설 IP(로드밸런서·프록시·NAT)와 그렇게 본 이유.
    이런 주소를 연결고리로 쓰면 서로 무관한 사용자의 의심 행동이 거대한 사건 하나로 뭉친다."""
    env = env or {}
    out: dict[str, str] = {}
    conf = [c["cidr"] if isinstance(c, dict) else c for c in env.get("shared_ips", [])]
    uas: dict[str, set] = defaultdict(set)
    for e in events:
        ip = e.src_ip
        px = e.extra.get("proxy_ip")
        if px and _is_ip(px):
            out.setdefault(px, "웹 로그에서 프록시(X-Forwarded-For 앞 단계)로 확인됨")
        if e.source not in APP_SOURCES or not _is_ip(ip) or not _is_private(ip):
            continue
        if conf and ip not in out and _ip_in(ip, conf):
            out[ip] = "설정의 shared_ips에 있음"
        ua = e.extra.get("ua") or e.extra.get("userAgent")
        if ua:
            if ip not in out and _HEALTH_UA.search(ua):
                out[ip] = f"상태 확인 요청({ua[:40]})을 보냄: 로드밸런서·프록시 주소"
            uas[ip].add(ua)
    for ip, s in uas.items():
        if ip not in out and len(s) >= SHARED_UA_MIN:
            out[ip] = f"User-Agent {len(s)}종: 여러 사용자가 함께 쓰는 주소"
    return out


def anchored_private_ips(findings: list[Finding], shared: dict[str, str]) -> dict[str, tuple]:
    """웹·서버 로그에서 의심 행동이 잡힌 사설 IP(공유 주소 제외)와 그 행동의 (처음, 마지막) 시각.
    이 IP의 네트워크 기록만 탐지·엮기에 쓴다."""
    out: dict[str, tuple] = {}
    for f in findings:
        for e in f.events:
            ip = e.src_ip
            if e.source in APP_SOURCES and _is_ip(ip) and _is_private(ip) and ip not in shared:
                lo, hi = out.get(ip, (e.ts, e.ts))
                out[ip] = (min(lo, e.ts), max(hi, e.ts))
    return out


# 사내 IP의 네트워크 기록은 의심 행동 앞뒤 이 시간 안의 것만 탐지에 쓴다. 정찰은 침투보다 먼저 오므로
# 앞뒤를 넉넉히 두되, 같은 주소의 며칠 전·후 정상 통신까지 보지는 않는다
ANCHOR_SPAN = timedelta(hours=6)


def _net_rules(by_vsrc: dict[str, list[Event]], trusted: list[str]) -> list[Finding]:
    """VPC Flow·서버 방화벽 규칙(출발지 IP별)."""
    findings: list[Finding] = []
    for ip, evs in by_vsrc.items():
        # 서버가 서비스 포트(443·8088 등)에서 상대의 임시 포트(32768 이상)로 보내는 응답은 스캔이 아니다.
        # 응답을 빼지 않으면 외부 서버와 오래 통신한 기록이 '포트 스캔'으로 잡힌다(BOTSv3 측정에서 확인)
        scan = [e for e in evs if not _is_reply(e)]
        for seg in _bursts(scan, timedelta(minutes=5), 10, key=lambda e: e.dst_port):
            findings.append(Finding("VPC_PORT_SCAN", seg,
                                    f"5분 안에 포트 {len({e.dst_port for e in seg})}개, "
                                    f"거부 {sum(e.outcome == 'reject' for e in seg)}건", ip))
        adm = [e for e in evs if e.dst_port in ADMIN_PORTS and e.outcome == "accept"
               and not (trusted and _ip_in(ip, trusted))]
        if adm:
            findings.append(Finding("VPC_REMOTE_ADMIN_EXPOSED", adm,
                                    f"포트 {sorted({e.dst_port for e in adm})} 허용 {len(adm)}건"
                                    + (" (사내 IP에서)" if _is_private(ip) else ""), ip))
    return findings


def run_detections(events: list[Event], env: dict | None = None) -> list[Finding]:
    """모든 규칙을 돌려 Finding 목록을 만들고, 해당 이벤트에 규칙 ID를 붙인다."""
    env = env or {}
    trusted = [t["cidr"] if isinstance(t, dict) else t for t in env.get("trusted_ips", [])]
    inst_ips = {i["instance_id"]: {i.get("public_ip"), i.get("private_ip")}
                for i in env.get("instances", [])}
    findings: list[Finding] = []
    ct = [e for e in events if e.source == "cloudtrail"]
    by_src: dict[str, list[Event]] = defaultdict(list)
    by_actor: dict[str, list[Event]] = defaultdict(list)
    for e in ct:
        if e.src_ip:
            by_src[e.src_ip].append(e)
        if e.actor:
            by_actor[e.actor].append(e)

    # --- CloudTrail: 단건 규칙
    # 같은 기록 안에서 CloudTrail 로그 저장 버킷으로 확인된 버킷(이름에 trail·log가 없어도)
    trail_buckets = {fl.split(":", 1)[1] for e in ct for fl in (e.extra.get("flags") or ())
                     if fl.startswith("trail_bucket:")}
    singles: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in ct:
        a = e.action or ""
        params = e.extra.get("params") or {}
        flags = e.extra.get("flags") or ()
        if a in LOGGING_TAMPER or "log_bucket_expire" in flags or any(
                fl.startswith("expire_bucket:") and fl.split(":", 1)[1] in trail_buckets for fl in flags):
            singles[("CT_LOGGING_TAMPER", e.src_ip or "")].append(e)
        if a in ACCOUNT_SECURITY:
            singles[("CT_ACCOUNT_SECURITY", e.actor or "")].append(e)
        if a in INSTANCE_EXEC or "userdata" in flags:
            singles[("CT_INSTANCE_EXEC", e.actor or "")].append(e)
        if a in SERVERLESS or (a in ("lambda:AddPermission", "lambda:AddLayerVersionPermission")
                               and "external" in flags) or (
                a == "lambda:UpdateFunctionConfiguration" and "layers" in str(params).lower()):
            singles[("CT_SERVERLESS_CHANGE", e.actor or "")].append(e)
        if a == "ec2:GetPasswordData" or (a == "secretsmanager:BatchGetSecretValue" and e.outcome == "success"):
            singles[("CT_SECRET_ACCESS", e.actor or "")].append(e)
        if a in DESTROY_ONE or "versioning_off" in flags:
            if a not in ("rds:DeleteDBInstance", "rds:DeleteDBCluster") or "no_final_snapshot" in flags:
                singles[("CT_DATA_DESTRUCTION", e.actor or "")].append(e)
        if e.extra.get("identity_type") == "Root" and e.extra.get("eventType") != "AwsServiceEvent":
            singles[("CT_ROOT_USAGE", e.src_ip or "")].append(e)
        if a in IAM_PERSIST or "db_master_password" in flags:
            singles[("CT_IAM_PERSISTENCE", e.actor or "")].append(e)
        if (a == "ec2:AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in str(params)) or "nacl_open" in flags:
            singles[("CT_SG_OPENED", e.actor or "")].append(e)
        if a in S3_PUBLIC_CALLS and (e.extra.get("s3_public") or "external" in flags):
            singles[("CT_S3_PUBLIC", e.actor or "")].append(e)
        if a in ("ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute") and (
                "createVolumePermission" in str(params) or "launchPermission" in str(params)) or (
                a in ("rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute")
                and "external" in flags):
            singles[("CT_SNAPSHOT_SHARE", e.actor or "")].append(e)
        if a == "signin:ConsoleLogin" and e.extra.get("mfa") == "No" and e.outcome == "success":
            singles[("CT_CONSOLE_NO_MFA", e.actor or "")].append(e)
        if trusted and e.src_ip and _is_ip(e.src_ip) and not _ip_in(e.src_ip, trusted) \
                and e.extra.get("identity_type") in ("IAMUser", "Root"):
            singles[("CT_UNTRUSTED_IP", e.actor or "")].append(e)
        if e.instance_id and e.instance_id in inst_ips and _is_ip(e.src_ip) \
                and e.src_ip not in inst_ips[e.instance_id]:
            singles[("CT_INSTANCE_CRED_OUTSIDE", e.instance_id)].append(e)
    for (rule, key), evs in singles.items():
        findings.append(Finding(rule, evs, _ok_fail(evs), key))

    # --- CloudTrail: 콘솔 로그인 연속 실패(같은 IP 또는 같은 사용자). 실패 뒤 성공하면 높음으로 올린다
    logins = sorted((e for e in ct if e.action == "signin:ConsoleLogin"), key=lambda e: e.ts)
    for keyf in (lambda e: e.src_ip or "", lambda e: e.actor or ""):
        groups: dict[str, list[Event]] = defaultdict(list)
        for e in logins:
            if keyf(e):
                groups[keyf(e)].append(e)
        for key, evs in groups.items():
            fails = [e for e in evs if e.outcome == "failure"]
            for seg in _bursts(fails, timedelta(minutes=10), 5, key=lambda e: e.raw_ref):
                after = [e for e in evs if e.outcome == "success" and timedelta(0) < e.ts - seg[-1].ts <= timedelta(minutes=30)]
                if after:
                    findings.append(Finding("CT_CONSOLE_BRUTE", seg + after[:1],
                                            f"10분 안에 실패 {len(seg)}건 뒤 로그인 성공", key,
                                            override={"severity": "high", "title": "콘솔 로그인 연속 실패 뒤 성공(비밀번호 탈취 의심)"}))
                else:
                    findings.append(Finding("CT_CONSOLE_BRUTE", seg, f"10분 안에 실패 {len(seg)}건", key))
    # 같은 실패 묶음이 IP와 사용자 양쪽에서 두 번 잡히면 하나만 남긴다
    seen_cb: set[frozenset] = set()
    dedup: list[Finding] = []
    for f in findings:
        if f.rule == "CT_CONSOLE_BRUTE":
            k = frozenset(e.raw_ref for e in f.events)
            if k in seen_cb:
                continue
            seen_cb.add(k)
        dedup.append(f)
    findings = dedup

    # --- CloudTrail: 같은 인스턴스 세션 자격증명이 서로 다른 공인 IP에서 사용
    by_inst: dict[str, list[Event]] = defaultdict(list)
    for e in ct:
        if e.instance_id and _is_ip(e.src_ip) and not _is_private(e.src_ip):
            by_inst[e.instance_id].append(e)
    for inst, evs in by_inst.items():
        ips = defaultdict(list)
        for e in evs:
            ips[e.src_ip].append(e)
        if len(ips) >= 2 and inst not in inst_ips:
            # 인벤토리가 없으면 "가장 많이 쓴 IP"를 정상으로 보고 나머지를 의심
            normal = max(ips, key=lambda k: len(ips[k]))
            odd = [e for ip, l in ips.items() if ip != normal for e in l]
            findings.append(Finding("CT_INSTANCE_CRED_MULTI_IP", sorted(odd, key=lambda e: e.ts),
                                    f"정상 추정 IP {normal} 외 {len(ips) - 1}개 IP", inst))

    # --- CloudTrail: 같은 주체가 짧은 시간에 여러 비밀값을 읽거나 데이터를 지움
    for actor, evs in by_actor.items():
        reads = [e for e in evs if (e.action in SECRET_READ
                                    or {"decrypt", "userdata_read"} & set(e.extra.get("flags") or ()))
                 and e.outcome == "success"]
        for seg in _bursts(reads, timedelta(minutes=10), 5, key=lambda e: e.extra.get("params") or e.raw_ref):
            findings.append(Finding("CT_SECRET_ACCESS", seg, f"10분 안에 비밀값 {len(seg)}건 조회", actor))
        dels = [e for e in evs if e.action in DESTROY_BURST and e.outcome == "success"]
        for seg in _bursts(dels, timedelta(minutes=10), 20, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_DATA_DESTRUCTION", seg, f"10분 안에 삭제 {len(seg)}건", actor))
        multi = [e for e in evs if e.action == "s3:DeleteObjects" and e.outcome == "success"]
        for seg in _bursts(multi, timedelta(minutes=10), 3, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_DATA_DESTRUCTION", seg, f"10분 안에 일괄 삭제(DeleteObjects) {len(seg)}회", actor))
        enc = [e for e in evs if "sse_c" in (e.extra.get("flags") or ())]
        for seg in _bursts(enc, timedelta(minutes=10), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_DATA_DESTRUCTION", seg,
                                    f"10분 안에 고객 키(SSE-C)로 객체 {len(seg)}개를 다시 씀(랜섬웨어 수법)", actor))

    # --- CloudTrail: 시간창 기반 규칙(같은 출발지 IP 기준)
    for ip, evs in by_src.items():
        if not _is_ip(ip):
            continue  # AWS 서비스 자체 호출(예: "ec2.amazonaws.com")은 제외
        denied = [e for e in evs if e.extra.get("errorCode") in (
            "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
            "Client.UnauthorizedOperation")]
        for seg in _bursts(denied, timedelta(minutes=10), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_ACCESS_DENIED_BURST", seg,
                                    f"10분 안에 거부 {len(seg)}건, API {len({e.action for e in seg})}종", ip))
        disc = [e for e in evs if e.action in DISCOVERY]
        for seg in _bursts(disc, timedelta(minutes=10), 4):
            findings.append(Finding("CT_DISCOVERY_BURST", seg,
                                    f"10분 안에 조회 API {len({e.action for e in seg})}종", ip))
        gets = [e for e in evs if e.action == "s3:GetObject" and e.outcome == "success"]
        for seg in _bursts(gets, timedelta(minutes=10), 20, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_S3_BULK_READ", seg, f"10분 안에 GetObject {len(seg)}건", ip))
        # 실패한 생성 시도는 권한 거부 규칙이 맡고, 여기서는 실제로 만들어진 것만 센다
        runs = [e for e in evs if e.action == "ec2:RunInstances" and e.outcome == "success"]
        for seg in _bursts(runs, timedelta(minutes=30), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_RUN_INSTANCES_BURST", seg, f"30분 안에 {len(seg)}회", ip))

    # --- VPC Flow Logs
    # 서버 방화벽 로그(hostfw)는 VPC Flow Logs의 무료 대안이라 같은 규칙을 쓴다.
    # 사설 출발지는 여기서 보지 않는다(사내 통신은 대부분 정상). 웹·서버 로그에서 이미 의심 행동이
    # 잡힌 사내 IP만 아래 '사내 IP 공격자' 단계에서 같은 규칙으로 다시 본다.
    vpc = [e for e in events if e.source in NET_SOURCES]
    by_vsrc: dict[str, list[Event]] = defaultdict(list)
    for e in vpc:
        if not _is_private(e.src_ip):
            by_vsrc[e.src_ip].append(e)
    findings += _net_rules(by_vsrc, trusted)

    # --- AWS WAF
    waf = [e for e in events if e.source == "waf"]
    sqli_nb: dict[str, list[Event]] = defaultdict(list)
    blocked: dict[str, list[Event]] = defaultdict(list)
    for e in waf:
        sqli = any("sqli" in str(x).lower() or "sql-database" in str(x).lower()
                   for x in (e.extra.get("counted_rules", []) + e.extra.get("labels", [])
                             + e.extra.get("matched_groups", [])))
        if sqli and e.outcome in ("allow", "count"):
            sqli_nb[e.src_ip or ""].append(e)
        elif e.outcome == "block":
            blocked[e.src_ip or ""].append(e)
    for ip, evs in sqli_nb.items():
        findings.append(Finding("WAF_SQLI_NOT_BLOCKED", evs, f"{len(evs)}건 통과", ip))
    for ip, evs in blocked.items():
        findings.append(Finding("WAF_BLOCKED", evs, f"{len(evs)}건 차단", ip))

    # --- SSH 인증 로그
    ssh = [e for e in events if e.source == "sshauth" and e.action not in ("sudo", "useradd")]  # 로그인 줄만
    by_ssrc: dict[str, list[Event]] = defaultdict(list)
    for e in ssh:
        by_ssrc[e.src_ip or ""].append(e)
    for ip, evs in by_ssrc.items():
        evs.sort(key=lambda e: e.ts)
        fails = [e for e in evs if e.outcome == "failure"]
        for seg in _bursts(fails, timedelta(minutes=10), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("SSH_BRUTE_FORCE", seg, f"10분 안에 실패 {len(seg)}건", ip))
        for e in evs:
            if e.outcome == "success":
                prior = [f for f in fails if timedelta(0) <= e.ts - f.ts <= timedelta(minutes=30)]
                if len(prior) >= 2:
                    findings.append(Finding("SSH_SUCCESS_AFTER_FAIL", prior + [e],
                                            f"직전 30분 실패 {len(prior)}건 뒤 '{e.actor}' 성공", ip))

    # --- 서버 권한 상승·계정 생성(auth.log의 sudo·su·useradd)
    findings += host_auth_findings(events)

    # --- 웹 공격 규칙(SQL 인젝션·스캐너·경로 조작·웹셸·IDOR 등): 웹서버 점검과 같은 코드(web/webdetect)로
    # nginx·ALB·WAF 로그를 본다. SSH는 위의 SSH 규칙이 본다.
    findings += _web_rule_findings(events, env, findings)

    # --- 사내 IP 공격자: 웹·서버 로그에서 의심 행동이 잡힌 사설 IP의 네트워크 기록(VPC Flow·서버 방화벽)
    # 사내 IP끼리의 통신은 그 자체로는 보지 않는다. 같은 IP가 웹 경로 대입·SSH 무차별 대입 같은 행동을
    # 이미 보였을 때만 그 IP의 포트 스캔·관리 포트 접속을 같은 규칙으로 찾는다(AIT-LDS 측정, 사내 공격자).
    anchors = anchored_private_ips(findings, shared_private_ips(events, env))
    if anchors:
        by_psrc: dict[str, list[Event]] = defaultdict(list)
        for e in vpc:
            span = anchors.get(e.src_ip)
            if span and span[0] - ANCHOR_SPAN <= e.ts <= span[1] + ANCHOR_SPAN:
                by_psrc[e.src_ip].append(e)
        findings += _net_rules(by_psrc, trusted)

    # --- GuardDuty 탐지 결과: 결과 하나가 탐지 하나. 같은 IP·인스턴스·키로 다른 로그와 엮인다
    for e in events:
        if e.source != "guardduty":
            continue
        typ = e.extra.get("gd_type", "")
        sev_n = e.extra.get("gd_severity", 0)
        sev = "high" if sev_n >= 7 else "medium" if sev_n >= 4 else "low"
        alias = [r for r in e.extra.get("gd_alias") or [] if r in RULES]
        from .gd_types import describe  # 제목은 GuardDuty 유형을 풀어 쓴 한국어(규칙 이름의 '허용' 등과 섞이지 않게)
        name = describe(typ)["title"]
        if alias:  # 같은 의미의 LogFinder 규칙이 있으면 그 단계·기법을 쓴다
            tech, stage, _, _ = RULES[alias[0]]
        else:
            tech, stage = "", GD_STAGE.get(typ.split(":")[0], "other")
        findings.append(Finding("GD_FINDING", [e], f"{typ} (심각도 {sev_n}, {e.extra.get('gd_count') or 1}회)",
                                e.src_ip or e.instance_id or e.actor or "",
                                override={"stage": stage, "severity": sev, "technique": tech,
                                          "title": f"GuardDuty: {name}"}))

    for f in findings:
        f.events.sort(key=lambda e: e.ts)
        for e in f.events:
            if f.rule not in e.findings:
                e.findings.append(f.rule)
    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev[f.severity], f.events[0].ts))
    return findings

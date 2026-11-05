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
from datetime import timedelta
from urllib.parse import unquote_plus, urlsplit

from .normalize import Event, S3_PUBLIC_CALLS

# 규칙 ID -> (ATT&CK 기법, 전술(단계), 한국어 이름, 기본 심각도)
RULES: dict[str, tuple[str, str, str, str]] = {
    "CT_LOGGING_TAMPER":  ("T1562.008", "defense-evasion", "감사 로그·보안 서비스 중지·삭제", "high"),
    "CT_ROOT_USAGE":      ("T1078.004", "initial-access", "루트 계정 사용", "high"),
    "CT_IAM_PERSISTENCE": ("T1098", "persistence", "IAM 사용자·키·권한 생성/변경", "high"),
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
    "WEB_SQLI_PATTERN":   ("T1190", "initial-access", "웹 요청에 SQL 인젝션 패턴", "medium"),
    "WEB_PATH_PROBE":     ("T1595.003", "discovery", "없는 경로를 연속 요청(웹 스캐너)", "low"),
    "GD_FINDING":         ("GuardDuty", "other", "GuardDuty 탐지 결과", "medium"),
    "WEB_OBJECT_ENUM":    ("T1530", "collection", "남의 객체 번호를 바꿔 가며 접근 시도(IDOR 탐색)", "medium"),
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
_SQLI = re.compile(r"(?i)'\s*(or|and|union|select|;|--|#)|union\s+(all\s+)?select|"
                   r"sleep\s*\(|benchmark\s*\(|information_schema|'\s*$")



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


@lru_cache(maxsize=65536)
def _is_private(ip: str | None) -> bool:
    if not ip:
        return True
    return ip.startswith(("10.", "192.168.", "127.")) or (
        ip.startswith("172.") and ip.split(".")[1].isdigit()
        and 16 <= int(ip.split(".")[1]) <= 31)


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
    singles: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in ct:
        a = e.action or ""
        params = e.extra.get("params") or {}
        flags = e.extra.get("flags") or ()
        if a in LOGGING_TAMPER or "log_bucket_expire" in flags:
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
        if a in IAM_PERSIST:
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
    # 서버 방화벽 로그(hostfw)는 VPC Flow Logs의 무료 대안이라 같은 규칙을 쓴다
    vpc = [e for e in events if e.source in ("vpcflow", "hostfw")]
    by_vsrc: dict[str, list[Event]] = defaultdict(list)
    for e in vpc:
        if not _is_private(e.src_ip):
            by_vsrc[e.src_ip].append(e)
    for ip, evs in by_vsrc.items():
        # 서버가 서비스 포트(443·8088 등)에서 상대의 임시 포트(32768 이상)로 보내는 응답은 스캔이 아니다.
        # 응답을 빼지 않으면 외부 서버와 오래 통신한 기록이 '포트 스캔'으로 잡힌다(BOTSv3 측정에서 확인)
        scan = [e for e in evs if not _is_reply(e)]
        for seg in _bursts(scan, timedelta(minutes=5), 10, key=lambda e: e.dst_port):
            findings.append(Finding("VPC_PORT_SCAN", seg,
                                    f"5분 안에 포트 {len({e.dst_port for e in seg})}개, "
                                    f"거부 {sum(e.outcome == 'reject' for e in seg)}건", ip))
    for ip, evs in by_vsrc.items():
        adm = [e for e in evs if e.dst_port in ADMIN_PORTS and e.outcome == "accept"
               and not (trusted and _ip_in(ip, trusted))]
        if adm:
            findings.append(Finding("VPC_REMOTE_ADMIN_EXPOSED", adm,
                                    f"포트 {sorted({e.dst_port for e in adm})} 허용 {len(adm)}건", ip))

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
    ssh = [e for e in events if e.source == "sshauth"]
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

    # --- ALB·API Gateway: 같은 IP가 같은 API에서 객체 번호만 바꿔 가며 403/404를 연달아 받음.
    # 남의 객체(작업·주문·파일)를 열어 보려는 IDOR 탐색이다. 웹서버 로그의 WEBLOG_IDOR_ENUM과 달리
    # 경로 이름에 기대지 않고, 권한 거부·없음 응답이 서로 다른 번호에 몰리는지만 본다.
    probes: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        # http_status(정수)가 공통 필드다. elb_status(문자열)는 예전에 저장한 결과와 호환용
        st = e.extra.get("http_status") or e.extra.get("elb_status")
        if e.source == "alb" and e.action and str(st) in ("403", "404"):
            r = _route(e.action)
            if r:
                probes[(e.src_ip or "?", r)].append(e)
    for (ip, r), evs in probes.items():
        for seg in _bursts(evs, timedelta(minutes=10), 5, key=lambda e: e.action):
            findings.append(Finding("WEB_OBJECT_ENUM", seg,
                                    f"10분 안에 {r} 객체 {len({e.action for e in seg})}개에 "
                                    f"403/404 {len(seg)}건", ip))

    # --- 웹 요청(WAF·ALB)의 SQL 인젝션 패턴 — WAF가 놓친 경우에도 잡기 위한 보조 규칙
    web: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source in ("waf", "alb", "weblog") and e.action and "?" in e.action \
                and e.disposition != "blocked":  # WAF가 이미 막은 요청은 제외
            q = unquote_plus(e.action.split("?", 1)[1])
            if _SQLI.search(q) and "WAF_SQLI_NOT_BLOCKED" not in e.findings:
                web[e.src_ip or ""].append(e)
    for ip, evs in web.items():
        if any(f.rule == "WAF_SQLI_NOT_BLOCKED" and f.key == ip for f in findings):
            continue
        findings.append(Finding("WEB_SQLI_PATTERN", evs, _ok_fail(evs), ip))

    # --- 웹 경로 탐색: 한 IP가 5분 안에 서로 다른 경로 20개 이상에서 404/403
    probe: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source in ("alb", "weblog") and e.outcome == "failure" and \
                str(e.extra.get("http_status")) in ("403", "404"):
            probe[e.src_ip or ""].append(e)
    for ip, evs in probe.items():
        evs.sort(key=lambda e: e.ts)
        for seg in _bursts(evs, timedelta(minutes=5), 20, key=lambda e: e.action):
            findings.append(Finding("WEB_PATH_PROBE", seg,
                                    f"5분 안에 서로 다른 경로 {len({e.action for e in seg})}개 404/403", ip))

    # --- GuardDuty 탐지 결과: 결과 하나가 탐지 하나. 같은 IP·인스턴스·키로 다른 로그와 엮인다
    for e in events:
        if e.source != "guardduty":
            continue
        typ = e.extra.get("gd_type", "")
        sev_n = e.extra.get("gd_severity", 0)
        sev = "high" if sev_n >= 7 else "medium" if sev_n >= 4 else "low"
        alias = [r for r in e.extra.get("gd_alias") or [] if r in RULES]
        if alias:  # 같은 의미의 LogSight 규칙이 있으면 그 단계·기법·한국어 이름을 쓴다
            tech, stage, name, _ = RULES[alias[0]]
        else:
            tech, stage, name = "", GD_STAGE.get(typ.split(":")[0], "other"), e.extra.get("gd_title") or typ
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

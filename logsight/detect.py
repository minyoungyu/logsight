"""
규칙 기반 1차 탐지.

AI에 넘기기 전에 코드가 "의심스러운 이벤트"를 먼저 골라 표시한다. 각 규칙은
MITRE ATT&CK(Enterprise, Cloud) 기법 ID에 대응한다. 이 표시가 있는 이벤트만
사건 묶음의 핵심 근거가 되고, 나머지는 집계 요약으로만 AI에 전달된다.
탐지 규칙은 GuardDuty·Sigma의 공개된 CloudTrail 규칙 유형을 참고한 최소 구현이다.
"""
from __future__ import annotations

from collections import defaultdict
import re
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import unquote_plus

from .normalize import Event

# 규칙 ID -> (ATT&CK 기법, 전술(단계), 한국어 이름, 기본 심각도)
RULES: dict[str, tuple[str, str, str, str]] = {
    "CT_LOGGING_TAMPER":  ("T1562.008", "defense-evasion", "감사 로그(CloudTrail/Flow Logs) 중지·삭제", "high"),
    "CT_ROOT_USAGE":      ("T1078.004", "initial-access", "루트 계정 사용", "high"),
    "CT_IAM_PERSISTENCE": ("T1098", "persistence", "IAM 사용자·키·권한 생성/변경", "high"),
    "CT_SG_OPENED":       ("T1562.007", "defense-evasion", "보안그룹을 0.0.0.0/0에 개방", "high"),
    "CT_SNAPSHOT_SHARE":  ("T1537", "exfiltration", "스냅샷·AMI를 외부 계정과 공유", "high"),
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
}

STAGE_ORDER = ["discovery", "initial-access", "credential-access", "persistence",
               "privilege-escalation", "defense-evasion", "collection", "exfiltration",
               "impact", "other"]

LOGGING_TAMPER = {"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                  "cloudtrail:PutEventSelectors", "ec2:DeleteFlowLogs",
                  "guardduty:DeleteDetector", "guardduty:UpdateDetector",
                  "wafv2:DeleteLoggingConfiguration", "config:StopConfigurationRecorder"}
IAM_PERSIST = {"iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
               "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
               "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
               "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion"}
DISCOVERY = {"sts:GetCallerIdentity", "s3:ListBuckets", "iam:ListUsers", "iam:ListRoles",
             "iam:ListPolicies", "iam:GetAccountAuthorizationDetails", "iam:ListAccessKeys",
             "iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies", "iam:GetUser",
             "ec2:DescribeInstances", "ec2:DescribeRegions", "ec2:DescribeSecurityGroups",
             "ec2:DescribeSnapshots", "ec2:DescribeImages", "lambda:ListFunctions",
             "rds:DescribeDBInstances", "s3:ListObjects", "s3:GetBucketAcl",
             "s3:GetBucketPolicy", "organizations:DescribeOrganization"}
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

    @property
    def technique(self) -> str:
        return RULES[self.rule][0]

    @property
    def stage(self) -> str:
        return RULES[self.rule][1]

    @property
    def title(self) -> str:
        return RULES[self.rule][2]

    @property
    def severity(self) -> str:
        return RULES[self.rule][3]

    def to_dict(self) -> dict:
        return {"rule": self.rule, "technique": self.technique, "stage": self.stage,
                "title": self.title, "severity": self.severity, "detail": self.detail,
                "key": self.key, "first": self.events[0].ts.isoformat(),
                "last": self.events[-1].ts.isoformat(), "n_events": len(self.events),
                "evidence": [e.raw_ref for e in self.events[:20]]}


def _is_private(ip: str | None) -> bool:
    if not ip:
        return True
    return ip.startswith(("10.", "192.168.", "127.")) or (
        ip.startswith("172.") and ip.split(".")[1].isdigit()
        and 16 <= int(ip.split(".")[1]) <= 31)


def _is_ip(s: str | None) -> bool:
    if not s:
        return False
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _bursts(evs: list[Event], window: timedelta, min_count: int, key=lambda e: e.action):
    """시간창 안에서 (서로 다른 key 값 기준) min_count 이상 모인 구간을 돌려준다."""
    evs = sorted(evs, key=lambda e: e.ts)
    out, start = [], 0
    for end in range(len(evs)):
        while evs[end].ts - evs[start].ts > window:
            start += 1
        seg = evs[start:end + 1]
        if len({key(e) for e in seg}) >= min_count:
            if out and out[-1][0] == start:
                out[-1] = (start, end)
            elif out and start <= out[-1][1]:
                out[-1] = (out[-1][0], end)
            else:
                out.append((start, end))
    return [evs[a:b + 1] for a, b in out]


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
        if a in LOGGING_TAMPER:
            singles[("CT_LOGGING_TAMPER", e.src_ip or "")].append(e)
        if e.extra.get("identity_type") == "Root" and e.extra.get("eventType") != "AwsServiceEvent":
            singles[("CT_ROOT_USAGE", e.src_ip or "")].append(e)
        if a in IAM_PERSIST:
            singles[("CT_IAM_PERSISTENCE", e.actor or "")].append(e)
        if a == "ec2:AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in str(params):
            singles[("CT_SG_OPENED", e.actor or "")].append(e)
        if a in ("ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute") and (
                "createVolumePermission" in str(params) or "launchPermission" in str(params)):
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
        runs = [e for e in evs if e.action == "ec2:RunInstances"]
        for seg in _bursts(runs, timedelta(minutes=30), 5, key=lambda e: e.raw_ref):
            findings.append(Finding("CT_RUN_INSTANCES_BURST", seg, f"30분 안에 {len(seg)}회", ip))

    # --- VPC Flow Logs
    vpc = [e for e in events if e.source == "vpcflow"]
    by_vsrc: dict[str, list[Event]] = defaultdict(list)
    for e in vpc:
        if not _is_private(e.src_ip):
            by_vsrc[e.src_ip].append(e)
    for ip, evs in by_vsrc.items():
        for seg in _bursts(evs, timedelta(minutes=5), 10, key=lambda e: e.dst_port):
            findings.append(Finding("VPC_PORT_SCAN", seg,
                                    f"5분 안에 포트 {len({e.dst_port for e in seg})}개, "
                                    f"거부 {sum(e.outcome == 'reject' for e in seg)}건", ip))
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

    # --- 웹 요청(WAF·ALB)의 SQL 인젝션 패턴 — WAF가 놓친 경우에도 잡기 위한 보조 규칙
    web: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source in ("waf", "alb") and e.action and "?" in e.action:
            q = unquote_plus(e.action.split("?", 1)[1])
            if _SQLI.search(q) and "WAF_SQLI_NOT_BLOCKED" not in e.findings:
                web[e.src_ip or ""].append(e)
    for ip, evs in web.items():
        if any(f.rule == "WAF_SQLI_NOT_BLOCKED" and f.key == ip for f in findings):
            continue
        findings.append(Finding("WEB_SQLI_PATTERN", evs, _ok_fail(evs), ip))

    for f in findings:
        f.events.sort(key=lambda e: e.ts)
        for e in f.events:
            if f.rule not in e.findings:
                e.findings.append(f.rule)
    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev[f.severity], f.events[0].ts))
    return findings

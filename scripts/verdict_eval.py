"""판정 정확도 측정(사양서 S1·NFR-20): 정답을 붙인 사건 세트로 '공격 의심' 판정의 재현율·정밀도를 잰다.

세트는 이 파일 안의 합성 시나리오다. 공격 시나리오와, 작은 팀에서 흔한 '공격처럼 보이지만 공격이 아닌'
시나리오(우리 팀 작업, 위험 설정, 인터넷 스캐너, 배포 자동화)를 같이 둔다. 입력은 실제 파서를 거친다.

주의: 이 세트는 규칙을 만든 팀이 만든 **개발 데이터**다. 회귀 하한선으로만 쓰고, 독립 점수로 쓰지 않는다.
독립 점수는 규칙을 고정한 뒤 남이 만든 라벨 데이터(CTF 리허설, BOTSv3 등)로 따로 잰다.

판정 방법(규칙 모드, AI 없음)
- 사건 판정 4종 중 'attack'을 공격 의심으로 본다. 나머지(risky_not_attack, unclear, benign_activity)와
  사건 없음은 '공격 아님'이다.
- 시나리오 판정 = 그 시나리오의 사건 중 하나라도 attack이면 공격 의심.
- 공격 시나리오가 공격 의심이 아니면 놓침(FN), 공격 아닌 시나리오가 공격 의심이면 오탐(FP).

    python scripts/verdict_eval.py            # 표와 요약
    python scripts/verdict_eval.py --json     # 결과 JSON
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.normalize import (cloudtrail_record_to_event, parse_guardduty,  # noqa: E402
                                parse_sshauth, parse_vpcflow, parse_weblog)
from logsight.pipeline import run  # noqa: E402

T0 = datetime(2026, 11, 2, 1, 0, tzinfo=timezone.utc)
ACCT = "111122223333"
ATK = "198.51.100.7"      # 공격자(문서용 대역)
ATK2 = "203.0.113.50"
OFFICE = "192.0.2.10"     # 우리 사무실
CI_IP = "192.0.2.200"


def user(name="dev", key="AKIAEXAMPLEKEY01"):
    return {"type": "IAMUser", "userName": name, "arn": f"arn:aws:iam::{ACCT}:user/{name}", "accessKeyId": key}


def role(name="web", inst="i-0abc1234", key="ASIAEXAMPLEKEY01"):
    return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/{name}/{inst}", "accessKeyId": key}


ROOT_ID = {"type": "Root", "accountId": ACCT, "arn": f"arn:aws:iam::{ACCT}:root"}


class Case:
    def __init__(self, cid: str, label: str, what: str):
        assert label in ("attack", "not_attack")
        self.id, self.label, self.what = cid, label, what
        self.events: list = []
        self.env: dict = {}
        self._n = 0

    # CloudTrail 한 줄
    def ct(self, name, src="iam", ip=ATK, ident=None, sec=None, params=None, err=None, **kw):
        self._n += 1
        t = T0 + timedelta(seconds=(sec if sec is not None else self._n * 20))
        r = {"eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": f"{src}.amazonaws.com",
             "eventName": name, "sourceIPAddress": ip, "userIdentity": ident or user(),
             "requestParameters": params or {}, "eventID": f"{self.id}-{self._n}"}
        if err:
            r["errorCode"] = err
        r.update(kw)
        ev = cloudtrail_record_to_event(r, f"{self.id}.ct:{self._n}")
        if ev:
            self.events.append(ev)
        return self

    def ssh(self, lines: list[tuple[int, str, str, str]]):
        """(초, fail|ok|raw, ip, user 또는 raw 문장)"""
        out = []
        for sec, kind, ip, who in lines:
            ts = (T0 + timedelta(seconds=sec)).strftime("%b %d %H:%M:%S")
            if kind == "fail":
                out.append(f"{ts} web sshd[{100 + sec}]: Failed password for {who} from {ip} port {40000 + sec} ssh2")
            elif kind == "ok":
                out.append(f"{ts} web sshd[{100 + sec}]: Accepted password for {who} from {ip} port {40000 + sec} ssh2")
            else:
                out.append(f"{ts} web {who}")
        self.events += parse_sshauth("\n".join(out), f"{self.id}.auth", year=T0.year)
        return self

    def web(self, reqs: list[tuple]):
        """(초, ip, 요청 경로, 상태, User-Agent[, 메서드])"""
        out = []
        for sec, ip, path, st, ua, *m in reqs:
            ts = (T0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            out.append(f'{ip} - - [{ts}] "{m[0] if m else "GET"} {path} HTTP/1.1" {st} 512 "-" "{ua}"')
        self.events += parse_weblog("\n".join(out), f"{self.id}.access")
        return self

    def vpc(self, flows: list[tuple[int, str, int, str]]):
        out = []
        for sec, src, dport, act in flows:
            t = int((T0 + timedelta(seconds=sec)).timestamp())
            out.append(f"2 {ACCT} eni-0example {src} 10.0.1.10 {40000 + sec % 1000} {dport} 6 3 180 {t} {t + 5} {act} OK")
        self.events += parse_vpcflow("\n".join(out), f"{self.id}.vpc")
        return self

    def gd(self, ftype: str, sev: float):
        f = {"Id": f"{self.id}-gd", "Type": ftype, "Severity": sev, "Title": ftype,
             "AccountId": ACCT, "Region": "ap-northeast-2", "CreatedAt": T0.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "UpdatedAt": T0.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "Resource": {"ResourceType": "AccessKey",
                          "AccessKeyDetails": {"AccessKeyId": "ASIAEXAMPLEKEY01", "UserName": "web"}},
             "Service": {"Action": {"ActionType": "AWS_API_CALL",
                                    "AwsApiCallAction": {"Api": "ListBuckets",
                                                         "RemoteIpDetails": {"IpAddressV4": ATK}}},
                         "EventFirstSeen": T0.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "EventLastSeen": T0.strftime("%Y-%m-%dT%H:%M:%SZ"), "Count": 3}}
        self.events += parse_guardduty(json.dumps({"Findings": [f]}), f"{self.id}.gd")
        return self

    def team(self, *actors, ips=()):
        self.env.setdefault("known_activity", []).append(
            {"label": "우리 팀(확인됨)", "actors": list(actors), "ips": list(ips)})
        return self


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def cases() -> list[Case]:
    cs: list[Case] = []

    # ---------------- 공격 시나리오 ----------------
    c = Case("A01", "attack", "유출 키로 외부에서 정찰 뒤 새 액세스 키 생성")
    for n in ["GetCallerIdentity", "ListUsers", "ListRoles", "ListAttachedUserPolicies", "ListGroups",
              "ListPolicies", "GetAccountAuthorizationDetails"]:
        c.ct(n)
    c.ct("CreateAccessKey", params={"userName": "dev"})
    cs.append(c)

    c = Case("A02", "attack", "서버 역할 임시 키를 외부 IP에서 사용해 S3 대량 읽기")
    c.ct("ListBuckets", src="s3", ident=role())
    for i in range(40):
        c.ct("GetObject", src="s3", ident=role(), params={"bucketName": "shop-private", "key": f"cust/{i}.csv"})
    cs.append(c)

    c = Case("A03", "attack", "SSH 무차별 대입 뒤 로그인 성공")
    c.ssh([(i * 3, "fail", ATK, "admin") for i in range(12)] + [(40, "ok", ATK, "admin")])
    cs.append(c)

    c = Case("A04", "attack", "SSH 무차별 대입(실패만, 시도)")
    c.ssh([(i * 2, "fail", ATK, u) for i, u in enumerate(["root", "admin", "ubuntu", "test", "oracle"] * 4)])
    cs.append(c)

    c = Case("A05", "attack", "웹 SQL 인젝션 성공 응답")
    c.web([(i, ATK, p, 200, "sqlmap/1.7") for i, p in enumerate([
        "/product.php?id=1'", "/product.php?id=1%20OR%201=1--", "/product.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/product.php?id=1%20AND%20SLEEP(5)--"])])
    cs.append(c)

    c = Case("A06", "attack", "경로 조작으로 /etc/passwd 읽기")
    c.web([(0, ATK, "/view.php?file=../../../../etc/passwd", 200, UA),
           (5, ATK, "/view.php?file=../../../../etc/shadow", 200, UA)])
    cs.append(c)

    c = Case("A07", "attack", "업로드한 웹셸로 명령 실행")
    c.web([(0, ATK, "/uploads/shell.php?cmd=id", 200, UA),
           (10, ATK, "/uploads/shell.php?cmd=cat%20/etc/passwd", 200, UA),
           (20, ATK, "/uploads/shell.php?cmd=whoami", 200, UA)])
    cs.append(c)

    c = Case("A08", "attack", "유출 키로 CloudTrail 끄기")
    c.ct("GetCallerIdentity", src="sts")
    c.ct("DescribeTrails", src="cloudtrail")
    c.ct("StopLogging", src="cloudtrail", params={"name": "main-trail"})
    cs.append(c)

    c = Case("A09", "attack", "AWS 콘솔 로그인 연속 실패 뒤 성공")
    for i in range(6):
        c.ct("ConsoleLogin", src="signin", ident={"type": "IAMUser", "userName": "dev",
                                                  "arn": f"arn:aws:iam::{ACCT}:user/dev"},
             responseElements={"ConsoleLogin": "Failure"}, errorMessage="Failed authentication",
             additionalEventData={"MFAUsed": "No"})
    c.ct("ConsoleLogin", src="signin", ident={"type": "IAMUser", "userName": "dev",
                                              "arn": f"arn:aws:iam::{ACCT}:user/dev"},
         responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})
    cs.append(c)

    c = Case("A10", "attack", "유출 키로 권한 탐색(권한 거부 폭주)")
    for n in ["ListUsers", "ListBuckets", "DescribeInstances", "ListSecrets", "ListFunctions", "GetAccountSummary",
              "ListRoles", "DescribeDBInstances", "ListKeys", "DescribeVpcs", "ListTopics", "ListQueues"]:
        c.ct(n, err="AccessDenied")
    cs.append(c)

    c = Case("A11", "attack", "웹 서비스 계정이 sudo find -exec로 root 셸")
    c.ssh([(0, "raw", "", "sudo:  www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; "
                          "COMMAND=/usr/bin/find . -exec /bin/sh ; -quit"),
           (1, "raw", "", "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=33)")])
    cs.append(c)

    c = Case("A12", "attack", "SSH 대입 성공 뒤 sudo useradd로 계정 생성")
    c.ssh([(i * 3, "fail", ATK, "ubuntu") for i in range(8)] + [(30, "ok", ATK, "ubuntu"),
          (60, "raw", "", "sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/useradd -m backup2"),
          (61, "raw", "", "useradd[2201]: new user: name=backup2, UID=1002, GID=1002, home=/home/backup2, shell=/bin/bash")])
    cs.append(c)

    c = Case("A13", "attack", "유출 키로 버킷 데이터 삭제")
    c.ct("ListBuckets", src="s3")
    for i in range(6):
        c.ct("DeleteObject", src="s3", params={"bucketName": "shop-backup", "key": f"db/{i}.sql"})
    c.ct("DeleteBucket", src="s3", params={"bucketName": "shop-backup"})
    cs.append(c)

    c = Case("A14", "attack", "유출 키로 비밀값 대량 조회")
    c.ct("ListSecrets", src="secretsmanager")
    for i in range(6):
        c.ct("GetSecretValue", src="secretsmanager", params={"secretId": f"prod/db{i}"})
    cs.append(c)

    c = Case("A15", "attack", "같은 서버 역할 키가 여러 외부 IP에서 쓰임")
    for i, ip in enumerate([ATK, ATK2, "198.51.100.99", ATK, ATK2]):
        c.ct("ListBuckets", src="s3", ip=ip, ident=role())
        c.ct("DescribeInstances", src="ec2", ip=ip, ident=role())
    cs.append(c)

    c = Case("A16", "attack", "GuardDuty 높음: 서버 키 외부 사용")
    c.gd("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", 8.0)
    cs.append(c)

    c = Case("A17", "attack", "웹 취약점 스캐너 대량 탐색")
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin/", "/backup.zip", "/config.php.bak",
             "/server-status", "/.aws/credentials", "/xmlrpc.php", "/actuator/env", "/console", "/test.php",
             "/old/", "/db.sql", "/.htpasswd", "/cgi-bin/test.cgi", "/vendor/phpunit/", "/shell.php", "/info.php"]
    c.web([(i, ATK, p, 404, "Nikto/2.5.0") for i, p in enumerate(paths)])
    cs.append(c)

    c = Case("A18", "attack", "명령 주입")
    c.web([(0, ATK, "/ping.php?host=127.0.0.1;cat%20/etc/passwd", 200, UA),
           (5, ATK, "/ping.php?host=127.0.0.1|id", 200, UA)])
    cs.append(c)

    c = Case("A19", "attack", "유출 키로 IAM 사용자 만들고 관리자 권한 붙이기")
    c.ct("CreateUser", params={"userName": "support-backup"})
    c.ct("AttachUserPolicy", params={"userName": "support-backup",
                                     "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    c.ct("CreateLoginProfile", params={"userName": "support-backup"})
    cs.append(c)

    c = Case("A20", "attack", "웹 로그인 대입 뒤 성공")
    reqs = [(i, ATK, "/login.php", 200, "python-requests/2.31", "POST") for i in range(15)]
    reqs.append((20, ATK, "/login.php", 302, "python-requests/2.31", "POST"))
    c.web(reqs)
    cs.append(c)

    # ---------------- 공격이 아닌 시나리오 ----------------
    c = Case("B01", "not_attack", "확인된 팀원이 콘솔에서 IAM 목록을 많이 조회")
    for n in ["ListUsers", "ListRoles", "ListPolicies", "ListGroups", "ListAttachedUserPolicies",
              "GetAccountAuthorizationDetails", "ListAccessKeys", "ListMFADevices"] * 2:
        c.ct(n, ip=OFFICE, ident=user("minyoung", "ASIAEXAMPLETEAM01"))
    c.team("minyoung")
    cs.append(c)

    c = Case("B02", "not_attack", "배포 자동화(CI) 역할이 함수 코드 갱신")
    for i in range(4):
        c.ct("UpdateFunctionCode20150331v2", src="lambda", ip=CI_IP,
             ident=role("github-actions-deploy", "GitHubActions", "ASIAEXAMPLECI0001"),
             params={"functionName": f"api-{i}"})
    c.env["known_activity"] = [{"label": "배포 자동화(CI)", "actors": ["github-actions-deploy"]}]
    cs.append(c)

    c = Case("B03", "not_attack", "루트로 콘솔 로그인(MFA 있음)해 결제 화면만 봄")
    c.ct("ConsoleLogin", src="signin", ip=OFFICE, ident=ROOT_ID,
         responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "Yes"})
    c.ct("GetBillingDetails", src="billingconsole", ip=OFFICE, ident=ROOT_ID)
    cs.append(c)

    c = Case("B04", "not_attack", "인터넷 스캐너가 SSH 포트에 접속만 함(로그인 없음)")
    c.vpc([(i * 7, ip, 22, "ACCEPT") for i, ip in enumerate(["198.51.100.20", "198.51.100.21", "203.0.113.70",
                                                              "203.0.113.71", "198.51.100.22"])])
    cs.append(c)

    c = Case("B05", "not_attack", "평범한 쇼핑몰 방문(검색어에 select·etc 같은 낱말)")
    c.web([(i, f"203.0.113.{10 + i}", p, 200, UA) for i, p in enumerate([
        "/", "/search.php?q=select+shoes", "/search.php?q=etc+hosts+cable", "/product.php?id=42",
        "/about.txt", "/static/style.css", "/order.php?id=1001", "/login.php", "/search.php?q=union+jack+shirt",
        "/product.php?id=43"])])
    cs.append(c)

    c = Case("B06", "not_attack", "관리자가 평소처럼 sudo apt update")
    c.ssh([(0, "ok", OFFICE, "ubuntu"),
           (30, "raw", "", "sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update"),
           (90, "raw", "", "sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")])
    cs.append(c)

    c = Case("B07", "not_attack", "운영자 역할이 SSM으로 서버 명령 실행")
    for i in range(3):
        c.ct("SendCommand", src="ssm", ip=OFFICE, ident=role("ops-admin", "jisu", "ASIAEXAMPLEOPS01"),
             params={"documentName": "AWS-RunShellScript", "instanceIds": ["i-0abc1234"]})
    cs.append(c)

    c = Case("B08", "not_attack", "서버 역할 키로 다른 리전 출구에서 신원 확인만")
    c.ct("GetCallerIdentity", src="sts", ip="203.0.113.150", ident=role())
    c.ct("GetCallerIdentity", src="sts", ip="203.0.113.151", ident=role())
    cs.append(c)

    c = Case("B09", "not_attack", "확인 안 된 팀원이 MFA 없이 콘솔 로그인")
    c.ct("ConsoleLogin", src="signin", ip=OFFICE, ident={"type": "IAMUser", "userName": "yuchan",
                                                         "arn": f"arn:aws:iam::{ACCT}:user/yuchan"},
         responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})
    cs.append(c)

    c = Case("B10", "not_attack", "사무실에서 SSH 로그인 한 번(실패 없음)")
    c.ssh([(0, "ok", OFFICE, "ubuntu")])
    cs.append(c)

    c = Case("B11", "not_attack", "확인된 팀원이 버킷을 공개로 바꿈(위험 설정)")
    c.ct("PutBucketPolicy", src="s3", ip=OFFICE, ident=user("minyoung", "ASIAEXAMPLETEAM01"),
         params={"bucketName": "shop-static",
                 "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                 "Resource": "arn:aws:s3:::shop-static/*"}]}})
    c.team("minyoung")
    cs.append(c)

    c = Case("B12", "not_attack", "SSH 오타 2번 뒤 사무실에서 로그인")
    c.ssh([(0, "fail", OFFICE, "ubuntu"), (5, "fail", OFFICE, "ubuntu"), (10, "ok", OFFICE, "ubuntu")])
    cs.append(c)

    c = Case("B13", "not_attack", "내부 모니터링 서버가 관리자 상태 페이지를 주기적으로 조회")
    c.web([(i * 60, "10.0.9.5", "/admin/status", 200, "monitoring-agent/1.0") for i in range(10)])
    c.env["trusted_ips"] = [{"cidr": "10.0.9.5/32", "label": "모니터링 서버"}]
    cs.append(c)

    c = Case("B14", "not_attack", "확인된 팀원이 CI용 액세스 키 생성")
    c.ct("CreateUser", ip=OFFICE, ident=user("minyoung", "ASIAEXAMPLETEAM01"), params={"userName": "ci-bot"})
    c.ct("CreateAccessKey", ip=OFFICE, ident=user("minyoung", "ASIAEXAMPLETEAM01"), params={"userName": "ci-bot"})
    c.team("minyoung")
    cs.append(c)

    c = Case("B15", "not_attack", "검색 엔진 봇의 일반 크롤링")
    c.web([(i * 3, "203.0.113.200", p, 200, "Mozilla/5.0 (compatible; Googlebot/2.1)") for i, p in enumerate(
        ["/robots.txt", "/", "/product.php?id=1", "/product.php?id=2", "/product.php?id=3", "/about.txt",
         "/search.php?q=shoes", "/product.php?id=4"])])
    cs.append(c)

    c = Case("B16", "not_attack", "확인된 팀원이 보안그룹에 사무실 IP만 SSH 허용")
    c.ct("AuthorizeSecurityGroupIngress", src="ec2", ip=OFFICE, ident=user("minyoung", "ASIAEXAMPLETEAM01"),
         params={"groupId": "sg-0abc", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                                                                     "ipRanges": {"items": [{"cidrIp": "192.0.2.10/32"}]}}]}})
    c.team("minyoung")
    cs.append(c)

    return cs


@dataclass
class Row:
    id: str
    label: str
    what: str
    predicted: str
    verdicts: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        if self.label == "attack":
            return "TP" if self.predicted == "attack" else "FN"
        return "FP" if self.predicted == "attack" else "TN"


def evaluate(selected: list[Case] | None = None) -> dict:
    rows = []
    for c in selected or cases():
        res = run(list(c.events), dict(c.env), use_ai=False)
        verdicts = [x["verdict"] for x in res["rule_triage"]["incidents"]]
        rules = sorted({r for i in res["incident_index"] for r in i["rules"]})
        rows.append(Row(c.id, c.label, c.what, "attack" if "attack" in verdicts else "not_attack",
                        verdicts, rules))
    n = {k: sum(1 for r in rows if r.outcome == k) for k in ("TP", "FN", "FP", "TN")}
    recall = n["TP"] / max(1, n["TP"] + n["FN"])
    precision = n["TP"] / max(1, n["TP"] + n["FP"])
    return {"n_cases": len(rows), "n_attack": n["TP"] + n["FN"], "n_not_attack": n["FP"] + n["TN"], **n,
            "recall": round(recall, 3), "precision": round(precision, 3),
            "accuracy": round((n["TP"] + n["TN"]) / max(1, len(rows)), 3),
            "rows": [{**r.__dict__, "outcome": r.outcome} for r in rows]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = evaluate()
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    for r in out["rows"]:
        print(f"{r['id']}  {r['outcome']}  {r['label']:<10} 판정={','.join(r['verdicts']) or '사건 없음':<40} {r['what']}")
    print(f"\n시나리오 {out['n_cases']}개(공격 {out['n_attack']}, 공격 아님 {out['n_not_attack']}) · "
          f"재현율 {out['recall']:.0%} ({out['TP']}/{out['n_attack']}) · 정밀도 {out['precision']:.0%} "
          f"({out['TP']}/{out['TP'] + out['FP']}) · 오탐 {out['FP']}건 · 놓침 {out['FN']}건")
    return 0


if __name__ == "__main__":
    sys.exit(main())

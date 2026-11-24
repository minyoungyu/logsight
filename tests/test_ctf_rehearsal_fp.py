"""CTF 리허설(2026-11-23) 오탐·놓침 수정 회귀 테스트. 입력은 직접 만든 로그 줄이다.

- 상품 분류 c=mouse, 보고서 run=weekly 가 웹셸 접근으로 잡히던 것
- 검색어 "union select 1" 이 SQL 인젝션으로 잡히던 것
- 부팅 때 생긴 ec2-user·nginx·apache 가 새 계정 생성(지속성)으로 잡히던 것
- 운영자 계정 활동이 같은 IP의 공격 사건에 섞이던 것, 같은 /24 대역의 깨끗한 사용자가 공격 묶음에 들어가던 것
- F1(robots.txt 숨은 경로), F5(IMDS SSRF) 탐지

실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import Finding, host_auth_findings  # noqa: E402
from logsight.explain import _campaigns, mark_known  # noqa: E402
from logsight.normalize import Event, parse_sshauth  # noqa: E402
from logsight.web import weblog, webdetect  # noqa: E402

T0 = datetime(2026, 11, 23, 2, 40, 0, tzinfo=timezone.utc)


def line(path, ip="198.51.100.30", method="GET", st=200, by=100, sec=0, ua="Mozilla/5.0"):
    ts = (T0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {st} {by} "-" "{ua}"'


def findings(lines):
    evs = weblog.parse_access("\n".join(lines), "a.log")
    return webdetect.run_web_detections(evs)


def rules(lines):
    return {f.rule for f in findings(lines)}


class WebshellParamTests(unittest.TestCase):
    def test_category_word_is_not_webshell(self):
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/category.php?c=mouse")]))
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/report.php?run=weekly")]))
        self.assertNotIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/category.php?c=cat")]))

    def test_command_values_still_webshell(self):
        for q in ("c=/usr/local/bin/proof", "c=id", "c=cat%20/etc/passwd", "c=ls%20-la",
                  "c=sudo%20/usr/bin/find%20/var/www%20-exec%20cat%20/root/flag4.txt%20%3B", "run=whoami;uname"):
            self.assertIn("WEBLOG_WEBSHELL_ACCESS", rules([line(f"/uploads/x.phtml?{q}")]), q)

    def test_strong_param_names_unchanged(self):
        self.assertIn("WEBLOG_WEBSHELL_ACCESS", rules([line("/img/a.php?cmd=mouse")]))


class SqliTests(unittest.TestCase):
    def test_search_words_not_sqli(self):
        self.assertNotIn("WEBLOG_SQLI", rules([line("/search.php?q=union+select+1")]))

    def test_real_union_still_sqli(self):
        for p in ("/product.php?id=1+union+select+null", "/login.php?u=%27+UNION+SELECT+1,2+--",
                  "/p.php?id=-1/**/union/**/select/**/1,2", "/s.php?q=x+union+select+pw+from+users"):
            self.assertIn("WEBLOG_SQLI", rules([line(p)]), p)


BOOT = """Nov 23 02:34:21 ip-10-20-10-11 useradd[1950]: new user: name=ec2-user, UID=1000, GID=1000, home=/home/ec2-user, shell=/bin/bash, from=none
Nov 23 02:34:53 ip-10-20-10-11 useradd[2104]: new user: name=nginx, UID=993, GID=993, home=/var/lib/nginx, shell=/sbin/nologin, from=none
Nov 23 02:34:54 ip-10-20-10-11 useradd[2186]: new user: name=apache, UID=48, GID=48, home=/usr/share/httpd, shell=/sbin/nologin, from=none
"""
ATTACK = """Nov 23 07:33:33 ip-10-20-10-11 sudo[53605]:    root : PWD=/usr/bin ; USER=root ; COMMAND=/usr/sbin/useradd -M -s /bin/bash backdoor
Nov 23 07:33:34 ip-10-20-10-11 useradd[53617]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=none
Nov 23 07:33:34 ip-10-20-10-11 sudo[53624]:    root : PWD=/usr/bin ; USER=nginx ; COMMAND=/usr/bin/bash -c 'sudo /usr/sbin/useradd hacker 2>/dev/null'
"""


class AccountTests(unittest.TestCase):
    def _targets(self, text):
        evs = parse_sshauth(text, "auth.log", year=2026)
        return {f.key for f in host_auth_findings(evs) if f.rule == "HOST_ACCOUNT_CREATED"}

    def test_boot_and_package_accounts_not_flagged(self):
        self.assertEqual(self._targets(BOOT), set())

    def test_attacker_accounts_flagged_with_clean_names(self):
        self.assertEqual(self._targets(BOOT + ATTACK), {"backdoor", "hacker"})

    def test_cloud_default_name_with_other_uid_is_flagged(self):
        t = "Nov 23 07:00:00 h useradd[1]: new user: name=ubuntu, UID=1005, GID=1005, home=/home/ubuntu, shell=/bin/bash\n"
        self.assertEqual(self._targets(t), {"ubuntu"})


class ImdsAndRobotsTests(unittest.TestCase):
    def test_imds_ssrf(self):
        fs = findings([line("/admin/fetch.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                            ip="203.0.113.50")])
        imds = [f for f in fs if f.rule == "WEBLOG_SSRF_IMDS"]
        self.assertEqual(len(imds), 1)
        self.assertIn("역할 키", imds[0].detail)

    def test_internal_ssrf_is_not_imds(self):
        self.assertNotIn("WEBLOG_SSRF_IMDS", rules([line("/fetch.php?url=http://127.0.0.1/internal/stats.php")]))

    def _site(self):
        return [line(p, ip=f"198.51.100.{30 + i}", sec=i) for i in range(4) for p in ("/", "/category.php?c=mouse")]

    def test_robots_hidden_path(self):
        ls = self._site() + [line("/robots.txt", ip="203.0.113.50", sec=10),
                             line("/9cf787dfb273/", ip="203.0.113.50", sec=11)]
        fs = [f for f in findings(ls) if f.rule == "WEBLOG_ROBOTS_HIDDEN"]
        self.assertEqual([f.key for f in fs], ["203.0.113.50"])

    def test_robots_then_public_pages_not_flagged(self):
        ls = self._site() + [line("/robots.txt", ip="203.0.113.50", sec=10),
                             line("/category.php?c=mouse", ip="203.0.113.50", sec=11),
                             line("/static/style.css", ip="203.0.113.50", sec=12)]
        self.assertNotIn("WEBLOG_ROBOTS_HIDDEN", rules(ls))

    def test_robots_hidden_needs_failed_access_excluded(self):
        ls = self._site() + [line("/robots.txt", ip="203.0.113.50", sec=10),
                             line("/9cf787dfb273/", ip="203.0.113.50", sec=11, st=401)]
        self.assertNotIn("WEBLOG_ROBOTS_HIDDEN", rules(ls))


def _ct(sec, ip, actor, action):
    return Event(ts=T0 + timedelta(seconds=sec), source="cloudtrail", src_ip=ip, actor=actor, action=action,
                 outcome="success", raw_ref=f"ct:{sec}")


class OperatorAndCampaignTests(unittest.TestCase):
    def test_known_operator_not_merged_with_attack_by_ip(self):
        op = "arn:aws:iam::111122223333:user/ctf-deployer"
        role = "arn:aws:sts::111122223333:assumed-role/ctf-t01/i-0abc"
        a = _ct(0, "160.79.106.144", op, "ssm:SendCommand")
        b = _ct(60, "160.79.106.144", role, "s3:GetObject")
        mark_known([a, b], {"known_activity": [{"label": "운영진", "actors": ["ctf-deployer"]}]})
        fs = [Finding("CT_INSTANCE_EXEC", [a], "x", op), Finding("CT_DISCOVERY_BURST", [b], "y", "160.79.106.144")]
        incs = build_incidents([a, b], fs)
        self.assertEqual(len(incs), 2)
        known = [i for i in incs if i["n_known"]]
        self.assertEqual(len(known), 1)
        self.assertEqual(known[0]["n_known"], known[0]["n_events"])

    def test_same_subnet_different_technique_not_linked(self):
        def inc(i, ip, rule, minute):
            t = (T0 + timedelta(minutes=minute)).isoformat()
            return {"id": i, "src_ips": [ip], "events": [], "start": t, "findings": [{"rule": rule}]}
        incs = [inc("A", "198.51.100.20", "WEBLOG_SQLI", 0), inc("B", "198.51.100.30", "WEBLOG_SCANNER", 5),
                inc("C", "198.51.100.40", "WEBLOG_SQLI", 10)]
        groups = _campaigns(incs, {"A": "attack", "B": "attack", "C": "attack"})
        merged = [g for g in groups if len(g["incident_ids"]) > 1]
        self.assertEqual(len(merged), 1)
        self.assertEqual(sorted(merged[0]["incident_ids"]), ["A", "C"])


if __name__ == "__main__":
    unittest.main()

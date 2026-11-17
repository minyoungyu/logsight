"""auth.log(리눅스 인증 로그)는 사후 분석(normalize.parse_sshauth)과 웹서버 점검(web/weblog.parse_auth)이
같은 파서로 읽는다. 오류 로그는 사후 분석도 알아본다."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import detect_kind, load_uploads, parse_sshauth  # noqa: E402
from logsight.web.weblog import parse_auth  # noqa: E402

LINES = [
    "Nov 17 04:40:36 ip-10-0-1-10 sshd[101]: Failed password for root from 203.0.113.5 port 5555 ssh2",
    # rsyslog RFC 3339 형식(Debian 12 이후 기본)
    "2026-11-17T04:40:37.123456+00:00 ip-10-0-1-10 sshd[102]: Failed password for invalid user admin "
    "from 203.0.113.5 port 5556 ssh2",
    # 키 인증만 허용한 서버: Invalid user 줄만 남음
    "Nov 17 04:40:38 ip-10-0-1-10 sshd[103]: Invalid user oracle from 203.0.113.5 port 5557",
    # 같은 접속(pid 101)의 Invalid user 줄은 위 Failed 줄과 한 시도
    "Nov 17 04:40:36 ip-10-0-1-10 sshd[101]: Invalid user root from 203.0.113.5 port 5555",
    "Nov 17 04:41:00 ip-10-0-1-10 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
    "Nov 17 04:42:00 ip-10-0-1-10 useradd[300]: new user: name=backdoor, UID=1001, GID=1001",
]
TEXT = "\n".join(LINES) + "\n"


class AuthParityTest(unittest.TestCase):
    def test_same_events_both_paths(self):
        a = parse_sshauth(TEXT, "auth.log", year=2026)
        w = parse_auth(TEXT, "auth.log", year=2026)
        self.assertEqual([(e.ts, e.src_ip, e.actor, e.action, e.outcome, e.raw_ref) for e in a],
                         [(e.ts, e.src_ip, e.actor, e.action, e.outcome, e.raw_ref) for e in w])
        self.assertEqual({e.source for e in w}, {"auth"})

    def test_formats(self):
        a = parse_sshauth(TEXT, "auth.log", year=2026)
        refs = {e.raw_ref: e for e in a}
        self.assertEqual(refs["auth.log:2"].ts.isoformat(), "2026-11-17T04:40:37.123456+00:00")
        self.assertIn("auth.log:3", refs)          # Invalid user 줄
        self.assertNotIn("auth.log:4", refs)       # 같은 pid의 Failed 줄로 이미 셈
        self.assertEqual(refs["auth.log:5"].action, "sudo")
        self.assertEqual(refs["auth.log:6"].actor, "backdoor")
        self.assertEqual(refs["auth.log:1"].dst_ip, "10.0.1.10")

    def test_sudo_is_not_ssh_success(self):
        fails = "".join(f"Nov 17 04:3{i}:00 h sshd[{i}]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
                        for i in range(3))
        sudo = "Nov 17 04:39:00 h sudo:   root : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id\n"
        rules = {f.rule for f in run_detections(parse_sshauth(fails + sudo, "auth.log", year=2026), {})}
        self.assertNotIn("SSH_SUCCESS_AFTER_FAIL", rules)


class ErrorLogTest(unittest.TestCase):
    NGINX = ('2026/10/10 13:55:36 [error] 12#0: *5 open() "/var/www/x.php" failed (2: No such file), '
             'client: 203.0.113.5, server: _, request: "GET /x.php HTTP/1.1"\n')

    def test_analyze_reads_error_log(self):
        self.assertEqual(detect_kind("nginx_error.log", self.NGINX), "weberror")
        self.assertEqual(detect_kind("server.log", self.NGINX), "weberror")
        evs, stats = load_uploads({"f": ("nginx_error.log", self.NGINX.encode())})
        self.assertEqual(stats[0]["kind"], "weberror")
        self.assertEqual(evs[0].src_ip, "203.0.113.5")

    def test_access_log_still_weblog(self):
        line = '203.0.113.9 - - [13/Jan/2026:05:01:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n'
        self.assertEqual(detect_kind("nginx_access.log", line), "weblog")


if __name__ == "__main__":
    unittest.main()

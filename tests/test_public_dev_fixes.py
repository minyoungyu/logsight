"""처음 보는 공개 데이터(개발용 묶음)에서 찾은 놓침·오탐 고침(2026-11-24).

- AIT-LDS v2 wardbeck·wilson: www-data → su blord → sudo cat /etc/shadow 를 놓침
- AIT-LDS v2 wardbeck·wilson: Nextcloud에서 사용자가 Documents/*.zip 을 내려받은 것을 '백업 노출'로 잡음
- Splunk security_content aws_credential_access_rds_password_reset: ModifyDBInstance의 masterUserPassword를 놓침
입력은 모두 합성이고 IP는 문서용 대역만 쓴다. 보류(holdout) 데이터는 보지 않고 만들었다.
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import cloudtrail_record_to_event, parse_sshauth  # noqa: E402
from logsight.web import webdetect, weblog  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

T0 = datetime(2026, 10, 11, 5, 0, tzinfo=timezone.utc)


def line(i, proc, msg):
    return f"{(T0 + timedelta(seconds=i * 10)).strftime('%b %d %H:%M:%S')} web {proc}[{500 + i}]: {msg}"


def rules_of(fs):
    return {f.rule for f in fs}


class SuChainPrivEsc(unittest.TestCase):
    def run_auth(self, lines):
        return run_detections(parse_sshauth("\n".join(lines), year=2026), {})

    def test_sudo_after_su_from_web_account(self):
        f = self.run_auth([
            line(0, "su", "Successful su for blord by www-data"),
            line(1, "sudo", "blord : TTY=pts/1 ; PWD=/var/www/html/wp-content/uploads ; USER=root ; COMMAND=list"),
            line(2, "sudo", "blord : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/ls -laR /root/"),
        ])
        hit = [x for x in f if x.rule == "HOST_PRIV_ESC" and x.key == "blord"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(len(hit[0].events), 2)
        self.assertIn("su로 넘어간", hit[0].detail)

    def test_sudo_before_su_is_not_chained(self):
        f = self.run_auth([
            line(0, "sudo", "blord : TTY=pts/1 ; PWD=/home/blord ; USER=root ; COMMAND=/usr/bin/apt update"),
            line(1, "su", "Successful su for blord by www-data"),
        ])
        self.assertFalse([x for x in f if x.rule == "HOST_PRIV_ESC" and x.key == "blord"])

    def test_sudo_reads_shadow(self):
        f = self.run_auth([line(0, "sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow")])
        self.assertIn("HOST_PRIV_ESC", rules_of(f))

    def test_admin_daily_sudo_still_quiet(self):
        f = self.run_auth([line(0, "su", "Successful su for root by alice"),
                           line(1, "sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")])
        self.assertNotIn("HOST_PRIV_ESC", rules_of(f))


class FileAppDownloadIsNotBackupLeak(unittest.TestCase):
    @staticmethod
    def _rules(path, method="GET"):
        ln = f'192.0.2.10 - - [10/Oct/2026:13:55:40 +0000] "{method} {path} HTTP/1.1" 200 120000 "-" "Mozilla/5.0"'
        return rules_of(webdetect.run_web_detections(weblog.parse_access(ln), SiteProfile()))

    def test_nextcloud_paths(self):
        for p in ("/remote.php/webdav/Documents/must.zip?downloadStartSecret=abc",
                  "/remote.php/dav/files/kim/Documents/a.zip",
                  "/index.php/apps/files/api/v1/files/Documents/despite.zip",
                  "/index.php/s/AbC123xyz/download"):
            with self.subTest(p=p):
                self.assertNotIn("WEBLOG_BACKUP_LEAK", self._rules(p, "POST" if "api/v1" in p else "GET"))

    def test_webroot_backup_still_caught(self):
        for p in ("/backup.zip", "/files/site-backup.tar.gz", "/remote.zip", "/apps/backup.sql"):
            with self.subTest(p=p):
                self.assertIn("WEBLOG_BACKUP_LEAK", self._rules(p))


class RdsMasterPassword(unittest.TestCase):
    @staticmethod
    def _rec(action, params):
        return {"eventTime": "2026-10-11T05:00:00Z", "eventSource": "rds.amazonaws.com", "eventName": action,
                "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.7", "recipientAccountId": "111122223333",
                "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/x/y",
                                 "accountId": "111122223333"},
                "requestParameters": params}

    def test_master_password_reset(self):
        for a in ("ModifyDBInstance", "ModifyDBCluster"):
            e = cloudtrail_record_to_event(self._rec(a, {"dBInstanceIdentifier": "database-1",
                                                         "masterUserPassword": "****", "applyImmediately": True}), "t:1")
            with self.subTest(a=a):
                self.assertIn("CT_IAM_PERSISTENCE", rules_of(run_detections([e], {})))

    def test_other_modify_is_quiet(self):
        e = cloudtrail_record_to_event(self._rec("ModifyDBInstance", {"dBInstanceIdentifier": "database-1",
                                                                      "allocatedStorage": 50}), "t:1")
        self.assertNotIn("CT_IAM_PERSISTENCE", rules_of(run_detections([e], {})))


if __name__ == "__main__":
    unittest.main()

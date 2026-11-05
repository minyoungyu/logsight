"""우리 팀 알아보기(logsight/team.py) 테스트."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import team  # noqa: E402
from logsight.__main__ import main  # noqa: E402
from logsight.normalize import Event  # noqa: E402

T0 = datetime(2026, 11, 4, 0, 0, tzinfo=timezone.utc)
ACCT = "arn:aws:iam::111122223333"


def ev(minute, actor, action="ec2:DescribeInstances", key="ASIAXXXX", findings=(), ip="203.0.113.5"):
    return Event(ts=T0 + timedelta(minutes=minute), source="cloudtrail", actor=actor, action=action,
                 access_key=key, src_ip=ip, outcome="success", findings=list(findings))


def sample():
    admin, brief = f"{ACCT}:user/admin-kim", f"{ACCT}:user/temp"
    role = f"{ACCT}:assumed-role/web-role/i-0abc"
    stolen = f"{ACCT}:user/ci-bot"
    out = [ev(m, admin) for m in range(0, 180, 10)] + [ev(5, admin, "cloudshell:CreateSession")]
    out += [ev(100, brief, "cloudshell:CreateSession"), ev(110, brief)]          # 잠깐만 나타남
    out += [ev(m, role, key="ASIAROLE") for m in range(0, 180, 20)]              # 사람 계정 아님
    out += [ev(m, stolen, "signin:ConsoleLogin") for m in range(0, 180, 30)]     # 콘솔이지만
    out += [ev(170, stolen, findings=["CT_UNTRUSTED_IP"])]                        # 수상한 모습
    return out


class Team(unittest.TestCase):
    def test_proposes_only_long_running_console_humans(self):
        names = [p["name"] for p in team.propose(sample())]
        self.assertEqual(names, ["admin-kim"])

    def test_suspicious_human_is_excluded_and_reported(self):
        self.assertEqual([x["name"] for x in team.excluded(sample())], ["ci-bot"])

    def test_env_user_counts_as_presence(self):
        evs = [ev(0, f"{ACCT}:user/park", "cloudshell:CreateSession"), ev(1, f"{ACCT}:user/park"),
               ev(0, f"{ACCT}:user/other", key="AKIAOTHER"), ev(100, f"{ACCT}:user/other", key="AKIAOTHER")]
        self.assertEqual(team.propose(evs), [])
        got = team.propose(evs, {"iam": {"users": [{"UserName": "park"}]}})
        self.assertEqual([p["name"] for p in got], ["park"])

    def test_no_wildcards_in_confirmed_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.json"
            p.write_text(json.dumps({"known_activity": [{"actors": ["blue-*"]}]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                team.load(p)

    def test_cli_confirms_only_proposed_names(self):
        with tempfile.TemporaryDirectory() as d:
            recs = [{"eventTime": e.ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": e.action.split(":")[0] + ".amazonaws.com",
                     "eventName": e.action.split(":")[1], "sourceIPAddress": e.src_ip,
                     "userIdentity": {"type": "IAMUser", "arn": e.actor, "accessKeyId": e.access_key}}
                    for e in sample() if ":user/" in e.actor]
            (Path(d) / "ct.json").write_text(json.dumps({"Records": recs}), encoding="utf-8")
            out = Path(d) / "team.json"
            self.assertEqual(main(["team", d, "--confirm", "temp", "--out", str(out)]), 2)
            self.assertFalse(out.exists())
            self.assertEqual(main(["team", d, "--confirm", "admin-kim", "--out", str(out)]), 0)
            self.assertEqual(team.load(out)["known_activity"][0]["actors"], ["admin-kim"])


if __name__ == "__main__":
    unittest.main()

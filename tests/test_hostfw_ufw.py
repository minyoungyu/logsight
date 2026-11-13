"""실제 ufw 로그(tests/fixtures/ufw, lab/ufw/run.sh로 만든 것)를 서버 방화벽 파서가 맞게 읽는지 확인한다.
시나리오: 정상 사용자 HTTP, ping, 포트 스캔(TCP 22개·UDP 4개), SSH 연속 접속 25회, 웹 경로 탐색, 서버에서 바깥 4444로 나간 연결.
ufw: 기본 차단, 22·80 허용, 443 허용(log). 자세한 설명은 docs/ufw_실측.md."""
from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.normalize import parse_hostfw  # noqa: E402
from logsight.pipeline import run_paths  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "ufw"
ATTACKER, SERVER = "203.0.113.50", "203.0.113.10"
BLOCKED_TCP = {21, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}


def load(name):
    return parse_hostfw((FIX / name).read_text(), name, year=2026)


class UfwRealLogTest(unittest.TestCase):
    def test_every_line_is_read_in_both_time_formats(self):
        iso, trad = load("ufw_low.log"), load("ufw_low_traditional.log")
        self.assertEqual(len(iso), 13)
        self.assertEqual([(e.src_ip, e.dst_port, e.outcome) for e in iso],
                         [(e.src_ip, e.dst_port, e.outcome) for e in trad])
        self.assertEqual(iso[0].ts.replace(microsecond=0), trad[0].ts)

    def test_low_default_block_and_logged_allow(self):
        c = Counter((e.extra["prefix"], e.outcome) for e in load("ufw_low.log"))
        self.assertEqual(c, {("[UFW BLOCK]", "reject"): 10, ("[UFW ALLOW]", "accept"): 3})

    def test_audit_line_is_not_a_second_accept_of_a_blocked_packet(self):
        for name in ("ufw_medium.log", "ufw_full.log"):
            evs = load(name)
            for e in evs:
                if e.src_ip == ATTACKER and e.extra["protocol"] == "tcp" and e.dst_port in BLOCKED_TCP:
                    self.assertEqual(e.outcome, "reject", (name, e.dst_port, e.extra["prefix"]))
            # BLOCK 줄과 같은 패킷의 AUDIT 줄은 이벤트가 되지 않는다(패킷 하나 = 이벤트 하나)
            per_packet = Counter((e.src_ip, e.extra["src_port"], e.dst_port) for e in evs if e.outcome == "reject")
            self.assertEqual(max(per_packet.values()), 1, name)

    def test_full_logging_counts_connections_not_packets(self):
        evs = load("ufw_full.log")
        self.assertLess(len(evs), 100)  # 원본 404줄은 대부분 같은 연결의 패킷
        ssh = [e for e in evs if e.src_ip == ATTACKER and e.dst_port == 22 and e.outcome == "accept"]
        self.assertGreaterEqual(len(ssh), 25)
        # 서버가 보낸 응답(80→임시 포트)은 이벤트가 되지 않고, 서버가 먼저 연 4444 연결만 남는다
        out = Counter(e.dst_port for e in evs if e.src_ip == SERVER and e.extra["protocol"] == "tcp")
        self.assertEqual(out, {4444: 1})

    def test_ufw_silent_drop_ports_are_rejects(self):
        smb = [e for e in load("ufw_full.log") if e.dst_port in (139, 445)]
        self.assertEqual({e.outcome for e in smb}, {"reject"})

    def test_pipeline_finds_one_incident_from_the_attacker_only(self):
        for name in ("ufw_low.log", "ufw_medium.log", "ufw_full.log"):
            res = run_paths([str(FIX / name)], use_ai=False)
            self.assertEqual(res["events_by_source"].keys(), {"hostfw"}, name)
            self.assertEqual([i["src_ips"] for i in res["incident_index"]], [[ATTACKER]], name)


if __name__ == "__main__":
    unittest.main()

"""사내(사설) IP 공격자 엮기와 공유 주소 오탐 방지 테스트.

배경: AIT-LDS russellmitchell(공격자 172.19.131.174, 사내 대역)을 돌리면 경로 대입 7,627건이
사건 7,627개로 흩어지고 같은 공격자의 VPC Flow와도 엮이지 않았다(docs/사내IP_엮기_측정.md).
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import anchored_private_ips, run_detections, shared_private_ips  # noqa: E402
from logsight.normalize import parse_vpcflow, parse_weblog  # noqa: E402
from logsight.pipeline import run  # noqa: E402

T0 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
ATT = "10.20.0.66"


def web(ip, n=25, start=T0, ua="dirb/2.22", status=404, prefix="/probe", xff=None, step=2):
    lines = []
    for i in range(n):
        t = (start + timedelta(seconds=i * step)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = f'{ip} - - [{t}] "GET {prefix}{i} HTTP/1.1" {status} 100 "-" "{ua}"'
        if xff is not None:
            line += f' "{xff}"'
        lines.append(line)
    return lines


def flows(src, dst="10.20.1.10", ports=range(20, 40), start=T0, action="ACCEPT"):
    out = []
    for i, p in enumerate(ports):
        t = int((start + timedelta(seconds=i)).timestamp())
        out.append(f"2 111122223333 eni-1 {src} {dst} 40000 {p} 6 3 180 {t} {t + 1} {action} OK")
    return out


def analyze(web_lines, flow_lines=(), env=None):
    events = parse_weblog("\n".join(web_lines), "access.log") if web_lines else []
    if flow_lines:
        events += parse_vpcflow("\n".join(flow_lines), "vpcflow.log")
    findings = run_detections(events, env)
    return events, findings, build_incidents(events, findings, env=env)


class PrivateAttackerLinked(unittest.TestCase):
    def test_web_probe_from_private_ip_is_one_incident(self):
        """사내 IP의 경로 대입이 요청마다 사건 하나로 흩어지지 않는다(전: 25개)."""
        _, _, incs = analyze(web(ATT))
        self.assertEqual(len(incs), 1)
        self.assertEqual(incs[0]["n_events"], 25)

    def test_private_scan_and_web_attack_join(self):
        """같은 사내 IP의 포트 스캔(VPC Flow)과 웹 경로 대입이 한 사건으로 엮인다."""
        _, findings, incs = analyze(web(ATT, start=T0 + timedelta(minutes=1)), flows(ATT))
        self.assertIn("VPC_PORT_SCAN", {f.rule for f in findings})
        self.assertEqual(len(incs), 1)
        self.assertEqual(set(incs[0]["sources"]), {"weblog", "vpcflow"})
        self.assertEqual(incs[0]["stages"][0], "discovery")

    def test_admin_port_detail_says_internal(self):
        _, findings, _ = analyze(web(ATT), flows(ATT, ports=[22]))
        adm = [f for f in findings if f.rule == "VPC_REMOTE_ADMIN_EXPOSED"]
        self.assertEqual(len(adm), 1)
        self.assertIn("사내 IP", adm[0].detail)


class InternalTrafficNotClumped(unittest.TestCase):
    def test_private_network_only_is_not_detected(self):
        """웹·서버 로그에서 의심 행동이 없는 사내 IP의 네트워크 기록은 그대로 보지 않는다(전과 같음)."""
        _, findings, incs = analyze([], flows("10.20.0.9"))
        self.assertEqual(findings, [])
        self.assertEqual(incs, [])

    def test_unrelated_internal_hosts_not_attached(self):
        """공격자와 같은 시각의 다른 사내 서버 통신은 맥락에도 붙지 않는다."""
        other = flows("10.20.0.9", ports=[5432] * 30)
        _, _, incs = analyze(web(ATT), flows(ATT) + other)
        self.assertEqual(len(incs), 1)
        self.assertNotIn("10.20.0.9", incs[0]["src_ips"])
        self.assertEqual(incs[0]["context"]["n_events"], 0)

    def test_anchor_is_time_bounded(self):
        """같은 사내 IP라도 의심 행동과 하루 떨어진 네트워크 기록은 탐지하지 않는다."""
        _, findings, _ = analyze(web(ATT), flows(ATT, start=T0 - timedelta(days=1)))
        self.assertNotIn("VPC_PORT_SCAN", {f.rule for f in findings})

    def test_load_balancer_health_check_is_shared(self):
        """XFF 없는 로드밸런서 뒤 웹서버: 서로 다른 두 공격자가 한 사건으로 뭉치지 않는다."""
        lb = "10.20.0.5"
        a = web(lb, ua="sqlmap/1.7", prefix="/a")
        b = web(lb, ua="nikto/2.5", prefix="/b", start=T0 + timedelta(seconds=1))
        hc = web(lb, n=3, ua="ELB-HealthChecker/2.0", status=200, prefix="/health")
        events, findings, incs = analyze(a + b + hc)
        self.assertIn(lb, shared_private_ips(events))
        for inc in incs:
            uas = {e.get("ua") for e in inc["events"]}
            self.assertLessEqual(len(uas - {None}), 1, inc["events"][:3])
        self.assertEqual(anchored_private_ips(findings, shared_private_ips(events)), {})

    def test_many_user_agents_is_shared(self):
        lb = "10.20.0.5"
        lines = [ln for i in range(25) for ln in web(lb, n=1, ua=f"Browser/{i}", status=200,
                                                       start=T0 + timedelta(seconds=i))]
        events = parse_weblog("\n".join(lines))
        self.assertIn("User-Agent 25종", shared_private_ips(events)[lb])

    def test_nat_with_few_users_is_not_shared(self):
        """AIT의 사내 NAT 주소처럼 사용자 몇 명이 함께 쓰는 주소는 공격자 연결고리로 남긴다."""
        lines = web(ATT) + [ln for i in range(6) for ln in web(ATT, n=1, ua=f"Firefox/{i}", status=200)]
        self.assertNotIn(ATT, shared_private_ips(parse_weblog("\n".join(lines))))

    def test_proxy_seen_in_xff_is_shared(self):
        lines = web("10.20.0.5", n=2, status=200, xff="198.51.100.7") + web("10.20.0.5", prefix="/x")
        events = parse_weblog("\n".join(lines))
        self.assertIn("10.20.0.5", shared_private_ips(events))

    def test_configured_shared_ips(self):
        env = {"shared_ips": ["10.20.0.0/24"]}
        events, _, incs = analyze(web(ATT), env=env)
        self.assertIn(ATT, shared_private_ips(events, env))
        self.assertEqual(len(incs), 25)  # 연결고리 없이 요청마다 따로(반복 접기에서 하나로 접힘)

    def test_report_explains_shared_ip(self):
        lb = "10.20.0.5"
        events = parse_weblog("\n".join(web(lb) + web(lb, n=1, ua="ELB-HealthChecker/2.0", status=200)))
        res = run(events, use_ai=False)
        self.assertTrue(any(lb in a and "함께 쓰는 주소" in a for a in res["assumptions"]))


if __name__ == "__main__":
    unittest.main()

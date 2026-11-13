"""정규화 점검: 8가지 로그를 한 폴더에 넣었을 때 같은 의미가 같은 필드·값으로 맞춰지는지,
그리고 보고서가 그 값을 사람이 읽는 말로 보여 주는지 확인한다(samples/combined, 합성 데이터)."""
from __future__ import annotations

import sys
import unittest
from datetime import timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import normalize  # noqa: E402
from logsight.normalize import Event, load_paths, parse_alb, parse_sshauth  # noqa: E402
from logsight.pipeline import enrich, run_paths  # noqa: E402
from logsight.report import render  # noqa: E402

COMBINED = ROOT / "samples" / "combined"
STATUS = {"success", "failure", "unknown"}
DISPOSITION = {"allowed", "blocked", "detected", "none"}


class SyslogYear(unittest.TestCase):
    """연도가 없는 syslog 줄은 테스트가 언제 돌든 같은 결과가 나오게 연도를 고정한다."""
    def setUp(self):
        self._saved = dict(normalize.SYSLOG)
        normalize.SYSLOG.update(year=2026, tz=timezone.utc)

    def tearDown(self):
        normalize.SYSLOG.clear()
        normalize.SYSLOG.update(self._saved)


class CommonFields(SyslogYear):
    def test_every_source_maps_to_common_vocabulary(self):
        events, _ = load_paths([COMBINED])
        kinds = {e.source for e in events}
        self.assertEqual(kinds, {"cloudtrail", "vpcflow", "waf", "alb", "sshauth", "hostfw",
                                 "weblog", "guardduty"})
        for e in events:
            self.assertIn(e.status, STATUS, (e.source, e.outcome))
            self.assertIn(e.disposition, DISPOSITION, (e.source, e.outcome))
            self.assertIsNotNone(e.ts.tzinfo)
            self.assertEqual(e.ts.utcoffset(), timedelta(0))
            d = e.to_dict()
            self.assertIn("status", d)
            self.assertIn("disposition", d)

    def test_same_meaning_same_value(self):
        def ev(src, out):
            return Event(ts=normalize.datetime.now(timezone.utc), source=src, outcome=out)
        self.assertEqual(ev("vpcflow", "REJECT").disposition, "blocked")
        self.assertEqual(ev("waf", "BLOCK").disposition, "blocked")
        self.assertEqual(ev("hostfw", "reject").disposition, "blocked")
        self.assertEqual(ev("waf", "COUNT").disposition, "allowed")  # 기록만 하고 통과시킴
        self.assertEqual(ev("cloudtrail", "Success").status, "success")
        self.assertEqual(ev("sshauth", "failure").status, "failure")
        self.assertEqual(ev("guardduty", "detected").disposition, "detected")

    def test_http_status_unified(self):
        events, _ = load_paths([COMBINED])
        web = [e for e in events if e.source in ("alb", "weblog")]
        self.assertTrue(web)
        for e in web:
            self.assertIsInstance(e.extra.get("http_status"), int, e.source)
            self.assertNotIn("elb_status", e.extra)


class AlbAction(unittest.TestCase):
    def test_path_not_full_url(self):
        line = ('https 2026-01-13T04:20:10.1Z app/demo/abc 203.0.113.9:443 10.0.1.10:8443 0 0 0 404 404 1 1 '
                '"GET https://demo.example.com:8443/a/b?x=1 HTTP/1.1" "curl" - - arn:x "Root" "-" "-" 0 '
                '2026-01-13T04:20:10Z "forward" "-" "-" "10.0.1.10:8443" "404" "-" "-"')
        e = parse_alb(line)[0]
        self.assertEqual(e.action, "GET /a/b?x=1")
        self.assertEqual(e.dst_port, 8443)
        self.assertEqual(e.extra["http_host"], "demo.example.com")
        self.assertEqual(e.extra["http_status"], 404)


class SyslogTime(unittest.TestCase):
    def setUp(self):
        self._saved = dict(normalize.SYSLOG)

    def tearDown(self):
        normalize.SYSLOG.clear()
        normalize.SYSLOG.update(self._saved)

    def test_timezone_and_year(self):
        line = "Jan 13 13:21:05 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"
        normalize.SYSLOG.update(year=2026, tz=timezone(timedelta(hours=9)))
        e = parse_sshauth(line)[0]
        self.assertEqual(e.ts.isoformat(), "2026-01-13T04:21:05+00:00")  # 한국 13시 = UTC 4시

    def test_future_date_means_last_year(self):
        normalize.SYSLOG.update(year=None, tz=timezone.utc)
        now = normalize.datetime.now(timezone.utc)
        future = now + timedelta(days=40)
        line = future.strftime("%b %d %H:%M:%S") + " h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"
        e = parse_sshauth(line)[0]
        self.assertLess(e.ts, now + timedelta(days=1))


class Enrich(unittest.TestCase):
    def test_network_target_gets_instance(self):
        e = Event(ts=normalize.datetime.now(timezone.utc), source="vpcflow", dst_ip="10.0.1.10")
        enrich([e], {"instances": [{"instance_id": "i-0abc", "private_ip": "10.0.1.10"}]})
        self.assertEqual(e.extra["target_instance"], "i-0abc")


class CombinedRun(SyslogYear):
    def setUp(self):
        super().setUp()
        self.res = run_paths([str(COMBINED)], use_ai=False)

    def test_linking_across_sources(self):
        first = self.res["results"][0]["incident"]
        self.assertEqual(first["severity"], "high")
        self.assertTrue({"cloudtrail", "guardduty", "sshauth", "vpcflow", "waf"}
                        <= {e["source"] for e in first["events"]})
        self.assertIn("i-0abc123def456", first["instances"])

    def test_guardduty_uses_logsight_stage(self):
        flows = [s for r in self.res["results"] for s in r["report"]["attack_flow"]
                 if "GuardDuty" in s["what"]]
        cred = [s for s in flows if "InstanceCredentialExfiltration" in s["what"]]
        self.assertTrue(cred)
        self.assertEqual(cred[0]["stage"], "credential-access")
        self.assertIn("인스턴스 역할 자격증명", cred[0]["what"])

    def test_waf_blocked_request_is_not_sqli_finding(self):
        for r in self.res["results"]:
            for e in r["incident"]["events"]:
                if e["source"] == "waf" and e["disposition"] == "blocked":
                    self.assertNotIn("WEB_SQLI_PATTERN", e["rules"])

    def test_assumptions_shown(self):
        self.assertTrue(any("UTC" in a for a in self.res["assumptions"]))

    def test_report_is_readable(self):
        html = render(self.res)
        self.assertIn("먼저 할 일", html)
        self.assertIn("이렇게 해석했습니다", html)
        self.assertIn("원인과 수정안", html)
        self.assertIn("한국 ", html)          # UTC 옆에 한국 시각
        self.assertIn(">차단<", html)         # 결과를 한국어로
        self.assertNotIn("(대상:", html)      # 흐름 문장의 '기준'이 대상처럼 읽히지 않게
        self.assertNotIn("원인으로 보이는 설정", html)  # 원인과 수정안이 한 카드로 합쳐짐


class RealClientIp(unittest.TestCase):
    """ALB 뒤 nginx: 실제 사용자 IP는 X-Forwarded-For에서, 위조할 수 있는 경우는 무시."""
    def line(self, remote, xff):
        return (f'{remote} - - [13/Jan/2026:04:20:10 +0000] "GET /a HTTP/1.1" 200 5 "-" "curl" "{xff}"')

    def test_behind_alb_uses_xff(self):
        e = normalize.parse_weblog(self.line("10.0.1.5", "203.0.113.9"))[0]
        self.assertEqual(e.src_ip, "203.0.113.9")
        self.assertEqual(e.extra["proxy_ip"], "10.0.1.5")

    def test_rightmost_public_hop(self):  # 맨 왼쪽은 사용자가 마음대로 넣을 수 있음
        e = normalize.parse_weblog(self.line("10.0.1.5", "198.18.0.1, 203.0.113.9"))[0]
        self.assertEqual(e.src_ip, "203.0.113.9")

    def test_direct_request_ignores_xff(self):
        e = normalize.parse_weblog(self.line("203.0.113.50", "198.51.100.1"))[0]
        self.assertEqual(e.src_ip, "203.0.113.50")

    def test_behind_proxy_without_xff_is_reported(self):
        evs = normalize.parse_weblog(self.line("10.0.1.5", "-"))
        self.assertTrue(evs[0].extra["behind_proxy"])
        from logsight.pipeline import run
        res = run(evs, {}, use_ai=False)
        self.assertTrue(any("http_x_forwarded_for" in a for a in res["assumptions"]))


class SshHost(unittest.TestCase):
    def test_ec2_hostname_maps_to_instance(self):
        e = parse_sshauth("Jan 13 04:21:05 ip-10-0-1-10 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
                          year=2026)[0]
        self.assertEqual(e.dst_ip, "10.0.1.10")
        enrich([e], {"instances": [{"instance_id": "i-0abc", "private_ip": "10.0.1.10"}]})
        self.assertEqual(e.extra["target_instance"], "i-0abc")

    def test_name_tag_maps_to_instance(self):
        e = parse_sshauth("Jan 13 04:21:05 web1 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
                          year=2026)[0]
        self.assertIsNone(e.dst_ip)
        enrich([e], {"instances": [{"instance_id": "i-0web", "name": "web1"}]})
        self.assertEqual(e.extra["target_instance"], "i-0web")


if __name__ == "__main__":
    unittest.main()


class ApacheVhost(unittest.TestCase):
    """Apache vhost_combined(줄 앞에 '가상호스트:포트')도 읽는다. 전에는 줄이 통째로 버려졌다(AIT 데이터 12.7~26.6%)."""
    LINE = ('cloud.dmz.example.com:443 203.0.113.68 - - [23/Jan/2022:06:25:19 +0000] '
            '"GET /ocs/v2.php?format=json HTTP/1.1" 200 4912 "-" "Mozilla/5.0"')

    def test_vhost_line_is_parsed(self):
        e = normalize.parse_weblog(self.LINE)[0]
        self.assertEqual(e.src_ip, "203.0.113.68")
        self.assertEqual(e.extra["vhost"], "cloud.dmz.example.com:443")
        self.assertEqual(e.action, "GET /ocs/v2.php?format=json")
        self.assertEqual(e.extra["http_status"], 200)

    def test_vhost_variants(self):
        for vhost in ("localhost:80", "10.0.0.1:8080", "[2001:db8::5]:443"):
            e = normalize.parse_weblog(self.LINE.replace("cloud.dmz.example.com:443", vhost))
            self.assertEqual([x.src_ip for x in e], ["203.0.113.68"], vhost)
        e = normalize.parse_weblog(self.LINE.replace("203.0.113.68", "2001:db8::9"))[0]
        self.assertEqual(e.src_ip, "2001:db8::9")

    def test_plain_ipv6_client_is_not_taken_as_vhost(self):
        for ip in ("2001:db8::1", "fe80::1", "::1"):
            line = f'{ip} - - [23/Jan/2022:06:25:19 +0000] "GET / HTTP/1.1" 404 1 "-" "x"'
            e = normalize.parse_weblog(line)[0]
            self.assertEqual(e.src_ip, ip)
            self.assertNotIn("vhost", e.extra)

    def test_detected_without_filename_hint(self):
        self.assertEqual(normalize.detect_kind("other_vhosts.txt", self.LINE), "weblog")

    def test_web_path_parser_too(self):
        from logsight.web.weblog import parse_access
        e = parse_access(self.LINE)[0]
        self.assertEqual(e.src_ip, "203.0.113.68")
        self.assertEqual(e.extra["vhost"], "cloud.dmz.example.com:443")
        self.assertEqual(e.extra["path"], "/ocs/v2.php")


class VpcFlowCustom(unittest.TestCase):
    """VPC Flow 사용자 지정 형식: 머리줄이 있으면 그 순서로 읽고, 없으면 틀리게 읽지 말고 못 읽은 줄로 센다."""
    HDR = ("version vpc-id subnet-id instance-id interface-id account-id type srcaddr dstaddr srcport dstport "
           "pkt-srcaddr pkt-dstaddr protocol bytes packets start end action tcp-flags log-status")
    ROW = ("5 vpc-1 subnet-1 i-0abc eni-1 111122223333 IPv4 203.0.113.4 10.0.0.1 40000 22 "
           "203.0.113.4 10.0.0.1 6 60 1 1700000000 1700000060 REJECT 2 OK")

    def test_header_order_is_used(self):
        evs, bad = normalize._run_parser("vpcflow", f"{self.HDR}\n{self.ROW}\n", "f")
        self.assertEqual(bad, {})
        e = evs[0]
        self.assertEqual((e.src_ip, e.dst_ip, e.dst_port), ("203.0.113.4", "10.0.0.1", 22))
        self.assertEqual(e.ts.timestamp(), 1700000000)
        self.assertEqual((e.action, e.outcome, e.disposition), ("tcp/22 REJECT", "reject", "blocked"))
        self.assertEqual(e.extra["src_port"], 40000)
        self.assertEqual(e.extra["vpc_id"], "vpc-1")
        self.assertEqual(e.extra["instance_id"], "i-0abc")
        self.assertIsNone(e.instance_id)  # 흐름 로그의 인스턴스 ID는 연결고리로 쓰지 않는다

    def test_header_with_underscores_and_nodata(self):
        hdr = "account_id action srcaddr dstaddr dstport protocol start log_status"
        text = (f"{hdr}\n1 ACCEPT 203.0.113.4 10.0.0.1 443 6 1700000000 OK\n"
                "1 - - - - - 1700000000 NODATA\n")
        evs, bad = normalize._run_parser("vpcflow", text, "f")
        self.assertEqual([e.action for e in evs], ["tcp/443 ACCEPT"])
        self.assertEqual(bad, {})
        self.assertEqual(normalize.detect_kind("x.txt", text), "vpcflow")

    def test_headerless_custom_is_counted_not_misread(self):
        for row in (self.ROW, "203.0.113.4 10.0.0.1 5 22 6 1 1 1700000000 1700000060 ACCEPT OK eni-1 1 2"):
            evs, bad = normalize._run_parser("vpcflow", row + "\n", "f")
            self.assertEqual(evs, [])  # 1970년 시각, IP가 아닌 출발지를 만들지 않는다
            self.assertEqual(bad["count"], 1)

    def test_default_format_unchanged(self):
        text = ("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes "
                "start end action log-status\n2 1 eni-1 1.2.3.4 10.0.0.1 5 22 6 1 1 1700000000 1700000060 ACCEPT OK\n"
                "2 1 eni-1 - - - - - - - 1700000000 1700000060 - NODATA\n")
        evs, bad = normalize._run_parser("vpcflow", text, "f")
        self.assertEqual([(e.action, e.ts.timestamp()) for e in evs], [("tcp/22 ACCEPT", 1700000000)])
        self.assertEqual(bad, {})


class UnparsedLinesReported(unittest.TestCase):
    """못 읽은 줄은 파일별 처리 결과와 보고서의 '이렇게 해석했습니다'에 드러난다."""
    def test_load_and_report(self):
        import tempfile
        from logsight.pipeline import run
        good = '203.0.113.5 - - [13/Jan/2026:04:20:10 +0000] "GET / HTTP/1.1" 200 5 "-" "curl"'
        with tempfile.TemporaryDirectory() as d:
            Path(d, "access.log").write_text(f"{good}\nthis is not a log line\n{good}\n")
            Path(d, "vpcflow.log").write_text(VpcFlowCustom.ROW + "\n")
            events, stats = load_paths([Path(d)])
        by = {Path(s["file"]).name: s for s in stats}
        self.assertEqual((by["access.log"]["events"], by["access.log"]["unparsed"]), (2, 1))
        self.assertEqual((by["vpcflow.log"]["events"], by["vpcflow.log"]["unparsed"]), (0, 1))
        res = run(events, {}, file_stats=stats, use_ai=False)
        notes = " ".join(res["assumptions"])
        self.assertIn("access.log: 3줄 중 1줄", notes)
        self.assertIn("머리줄", notes)
        self.assertIn("access.log: 3줄 중 1줄", render(res))

    def test_uploads_report_unparsed(self):
        _, stats = normalize.load_uploads({"vpcflow": ("f.log", (VpcFlowCustom.ROW + "\n").encode())})
        self.assertEqual(stats[0]["unparsed"], 1)

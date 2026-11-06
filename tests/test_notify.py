"""통지(logsight/notify.py) 테스트. 웹훅은 이 PC 안의 임시 HTTP 서버로, 이메일은 SMTP를 흉내 내서 시험한다."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import alert as al  # noqa: E402
from logsight import notify as nt  # noqa: E402

GD_EVENT = json.loads((ROOT / "samples/alerts/guardduty_event.json").read_text(encoding="utf-8"))


class Recorder(BaseHTTPRequestHandler):
    got: list = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Recorder.got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                             "raw": body, "body": json.loads(body)})
        self.send_response(Recorder.status)
        self.end_headers()

    def log_message(self, *a):
        pass


class Notify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Recorder)
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Recorder.got, Recorder.status = [], 200
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"T_SLACK": f"{self.base}/slack", "T_DISCORD": f"{self.base}/discord",
                                                "T_HOOK": f"{self.base}/hook", "T_SECRET": "s3cret",
                                                "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_alert(self, channels):
        (self.d / "notify.json").write_text(json.dumps({"channels": channels}), encoding="utf-8")
        opt = al.Options(logs=[str(ROOT / "samples/demo")], out=str(self.d / "alerts"), use_ai=False,
                         notify=str(self.d / "notify.json"))
        return al.handle(al.parse_event(GD_EVENT), opt)

    def test_all_webhook_channels(self):
        r = self.run_alert([{"type": "slack", "url_env": "T_SLACK"}, {"type": "discord", "url_env": "T_DISCORD"},
                            {"type": "webhook", "url_env": "T_HOOK", "secret_env": "T_SECRET"}])
        self.assertEqual([x["ok"] for x in r["notify_channels"]], [True, True, True])
        by = {g["path"]: g for g in Recorder.got}
        self.assertIn("높음 경보", by["/slack"]["body"]["text"])
        self.assertEqual(by["/discord"]["body"]["allowed_mentions"], {"parse": []})
        hook = by["/hook"]
        self.assertEqual(hook["body"]["alert"]["source"], "guardduty")
        self.assertTrue(hook["body"]["first_actions"])
        ts = hook["headers"]["x-logsight-timestamp"]
        want = hmac.new(b"s3cret", ts.encode() + b"." + hook["raw"], hashlib.sha256).hexdigest()
        self.assertEqual(hook["headers"]["x-logsight-signature"], f"sha256={want}")

    def test_min_severity_disabled_kakao_and_missing_url(self):
        r = self.run_alert([{"type": "slack", "url_env": "T_SLACK", "min_severity": "high"},
                            {"type": "discord", "url_env": "NOT_SET"},
                            {"type": "kakao_alimtalk"},
                            {"type": "webhook", "url_env": "T_HOOK", "enabled": False}])
        res = r["notify_channels"]
        self.assertEqual(len(res), 3)  # enabled=false는 빠짐
        self.assertTrue(res[0]["ok"])  # GuardDuty 샘플은 높음
        self.assertFalse(res[1]["ok"])
        self.assertIn("사업자", res[2]["error"])

    def test_http_error_does_not_break_analysis(self):
        Recorder.status = 400
        r = self.run_alert([{"type": "slack", "url_env": "T_SLACK"}])
        self.assertEqual(r["status"], "done")
        self.assertEqual(r["notify_channels"][0], {"channel": "slack", "ok": False, "status": 400})
        self.assertEqual(len(Recorder.got), 1)  # 4xx는 다시 보내지 않는다

    def test_stages_in_korean(self):
        """관리자가 받는 카드·요약에 공격 단계를 영어 코드 대신 한국어로 쓴다."""
        r = self.run_alert([{"type": "discord", "url_env": "T_DISCORD"}])
        desc = Recorder.got[0]["body"]["embeds"][0]["description"]
        self.assertIn("초기 침투", desc)
        self.assertNotIn("initial-access", desc)
        summary = (Path(r["out"]) / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("초기 침투", summary)
        self.assertNotIn("initial-access", summary)

    def test_slack_mentions_escaped(self):
        msg = nt.test_message()
        msg["title"] = "<!channel> 경보"
        nt.send_slack({"url_env": "T_SLACK"}, msg)
        self.assertNotIn("<!channel>", Recorder.got[0]["body"]["text"])

    def test_email_informational_with_report(self):
        sent = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                self.host = host

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self, context=None):
                pass

            def login(self, u, p):
                sent.append(("login", u, p))

            def send_message(self, m):
                sent.append(("msg", m))

        with mock.patch.dict(os.environ, {"T_USER": "u", "T_PW": "p"}), mock.patch.object(nt.smtplib, "SMTP", FakeSMTP):
            r = self.run_alert([{"type": "email", "smtp_host": "smtp.example.com", "from": "a@example.com",
                                 "to": ["b@example.com"], "user_env": "T_USER", "password_env": "T_PW"}])
        self.assertTrue(r["notify_channels"][0]["ok"])
        self.assertEqual(sent[0], ("login", "u", "p"))
        m = sent[1][1]
        self.assertIn("정보성", m["Subject"])
        body = m.get_body(("plain",)).get_content()
        self.assertIn("광고가 아니며", body)
        self.assertIn("먼저 할 일", body)
        names = [p.get_filename() for p in m.iter_attachments()]
        self.assertEqual(names, ["logsight_report.html"])

    def test_bad_config(self):
        p = self.d / "n.json"
        p.write_text(json.dumps({"channels": [{"type": "sms"}]}), encoding="utf-8")
        with self.assertRaises(ValueError):
            nt.load_config(p)


if __name__ == "__main__":
    unittest.main()

"""관리자 대시보드(알림 → 경보 요약 → 상세 보고서) 테스트.
경보 폴더는 실제 on-alert 처리(alert.handle, AI 끔)로 만들고, 화면 숫자가 report.json 값과 같은지 본다.
실행: python -m unittest tests.test_dashboard -v
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import alert as al  # noqa: E402
from logsight import dashboard as db  # noqa: E402
from logsight import notify as nt  # noqa: E402
from tests.test_app import _load_app  # noqa: E402

GD_EVENT = json.loads((ROOT / "samples/alerts/guardduty_event.json").read_text(encoding="utf-8"))


def _make_alert(out: str) -> Path:
    from logsight import normalize
    saved = dict(normalize.SYSLOG)
    normalize.SYSLOG["year"] = 2026
    try:
        res = al.handle(al.parse_event(GD_EVENT), al.Options(logs=[str(ROOT / "samples/demo")], out=out, use_ai=False))
    finally:
        normalize.SYSLOG.clear()
        normalize.SYSLOG.update(saved)
    return Path(res["out"])


class DashboardData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = _make_alert(cls.tmp.name)
        cls.report = json.loads((cls.dir / "report.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_folder_rejects_bad_names(self):
        self.assertEqual(db.folder(self.tmp.name, self.dir.name), self.dir)
        for bad in ("..", "../etc", "x", self.dir.name + "/..", "20261126_000000_x_deadbeef"):
            self.assertIsNone(db.folder(self.tmp.name, bad), bad)

    def test_list_uses_report_values(self):
        items = db.list_alerts(self.tmp.name)
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it["n_events"], self.report["n_events"])
        self.assertEqual(it["n_incidents"], self.report["n_incidents"])
        self.assertEqual(it["severity"], "high")
        self.assertEqual(db.list_alerts(self.tmp.name, "high"), items)
        self.assertEqual(db.list_alerts(Path(self.tmp.name) / "없음"), [])

    def test_page_numbers_match_report(self):
        html = db.render_alert(db.load(self.dir), "", "", "/r")
        tiles = dict(re.findall(r"<div class=tl>(.*?)</div><div class=tv>(.*?)</div>", html))
        self.assertEqual(tiles["읽은 이벤트"], f"{self.report['n_events']:,}")
        self.assertEqual(tiles["규칙에 걸린 이벤트"], f"{self.report['n_flagged']:,}")
        self.assertEqual(tiles["사건"], f"{self.report['n_incidents']:,}")
        n_attack = sum(1 for i in self.report["incident_index"] if i["verdict"] == "attack")
        self.assertEqual(tiles["공격 의심 사건"], str(n_attack))
        self.assertEqual(tiles["설명 방식"], "규칙")
        for flow in self.report["results"][0]["report"]["attack_flow"][:8]:
            self.assertIn(flow["what"][:30].replace("&", "&amp;"), html)

    def test_missing_values_shown_as_missing(self):
        """run.json이 없는 오래된 폴더: 시간을 지어내지 않고 '기록 없음'."""
        d = db.load(self.dir)
        d["run"] = {}
        html = db.render_alert(d, "", "", "/r")
        tiles = dict(re.findall(r"<div class=tl>(.*?)</div><div class=tv>(.*?)</div>", html))
        self.assertIn("기록 없음", tiles["받은 뒤 보고서까지"])


class DashboardRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = _make_alert(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_local_without_token(self):
        c = _load_app(False, {"LOGSIGHT_ALERTS_DIR": self.tmp.name})
        self.assertIn(self.dir.name, c.get("/alerts").text)
        r = c.get(f"/alerts/{self.dir.name}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/alerts/{self.dir.name}/report", r.text)
        self.assertEqual(c.get(f"/alerts/{self.dir.name}/report").status_code, 200)
        self.assertEqual(c.get("/alerts/nope").status_code, 404)

    def test_remote_without_token_refused(self):
        c = _load_app(False, {"LOGSIGHT_ALERTS_DIR": self.tmp.name}, client=("203.0.113.5", 5000))
        self.assertEqual(c.get("/alerts").status_code, 403)
        self.assertEqual(c.get(f"/alerts/{self.dir.name}").status_code, 403)
        self.assertEqual(c.get("/alerts/sample").status_code, 200)  # 합성 샘플은 공개

    def test_token_login_flow(self):
        c = _load_app(False, {"LOGSIGHT_ALERTS_DIR": self.tmp.name, "LOGSIGHT_TOKEN": "s3cret"},
                      client=("203.0.113.5", 5000))
        path = f"/alerts/{self.dir.name}"
        r = c.get(path, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], f"/login?next={path}")
        self.assertEqual(c.post("/login", data={"token": "wrong", "next": path}).status_code, 401)
        r = c.post("/login", data={"token": "s3cret", "next": path}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], path)
        self.assertEqual(c.get(path).status_code, 200)

    def test_login_next_cannot_leave_dashboard(self):
        c = _load_app(False, {"LOGSIGHT_TOKEN": "s3cret"})
        for bad in ("https://evil.example", "//evil.example", "/analyze"):
            r = c.post("/login", data={"token": "s3cret", "next": bad}, follow_redirects=False)
            self.assertEqual(r.headers["location"], "/alerts", bad)

    def test_demo_hides_disk_alerts(self):
        c = _load_app(True, {"LOGSIGHT_ALERTS_DIR": self.tmp.name})
        self.assertNotIn(self.dir.name, c.get("/alerts").text)
        self.assertEqual(c.get(f"/alerts/{self.dir.name}").status_code, 404)
        r = c.get("/alerts/sample")
        self.assertEqual(r.status_code, 200)
        self.assertIn("합성 샘플", r.text)
        self.assertEqual(c.get("/alerts/sample/report").status_code, 200)


class NotifyLink(unittest.TestCase):
    def test_dashboard_base_from_config_and_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "notify.json"
            p.write_text(json.dumps({"dashboard_url": "https://logs.example.com/", "channels": []}), encoding="utf-8")
            self.assertEqual(nt.dashboard_base(p), "https://logs.example.com")
            p.write_text(json.dumps({"dashboard_url": "javascript:alert(1)", "channels": []}), encoding="utf-8")
            self.assertIsNone(nt.dashboard_base(p))
        os.environ["LOGSIGHT_DASHBOARD_URL"] = "https://env.example.com"
        try:
            self.assertEqual(nt.dashboard_base(None), "https://env.example.com")
        finally:
            del os.environ["LOGSIGHT_DASHBOARD_URL"]

    def test_message_carries_link(self):
        with tempfile.TemporaryDirectory() as d:
            out = _make_alert(d)
            result = json.loads((out / "report.json").read_text(encoding="utf-8"))
            link = nt.dashboard_link("https://logs.example.com", out)
            self.assertEqual(link, f"https://logs.example.com/alerts/{out.name}")
            msg = nt.build(result["alert"], result, out, link=link)
            self.assertIn(f"대시보드: {link}", nt.text(msg))
            self.assertNotIn("보고서: ", nt.text(msg))
            no_link = nt.text(nt.build(result["alert"], result, out))
            self.assertIn("보고서: ", no_link)


if __name__ == "__main__":
    unittest.main()

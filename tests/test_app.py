"""웹앱 라우트 테스트. 공개 데모 모드(LOGSIGHT_DEMO=1)의 차단 규칙과 헬스체크를 고정한다.
실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_app(demo: bool):
    """DEMO 플래그는 import 시점에 정해지므로, 환경변수를 바꿔 app.py를 따로 읽는다."""
    from fastapi.testclient import TestClient  # httpx 필요(CI에서 설치)
    old = os.environ.get("LOGSIGHT_DEMO")
    os.environ["LOGSIGHT_DEMO"] = "1" if demo else "0"
    try:
        spec = importlib.util.spec_from_file_location(f"app_{'demo' if demo else 'full'}", ROOT / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if old is None:
            os.environ.pop("LOGSIGHT_DEMO", None)
        else:
            os.environ["LOGSIGHT_DEMO"] = old
    return TestClient(mod.app)


class HealthTests(unittest.TestCase):
    def test_healthz_ok_in_both_modes(self):
        for demo in (True, False):
            r = _load_app(demo).get("/healthz")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "ok")
            self.assertEqual(r.json()["demo"], demo)


class DemoModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _load_app(demo=True)

    def test_public_pages_work(self):
        for path in ("/", "/web", "/web/demo", "/demo"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_api_docs_hidden(self):
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_uploads_refused(self):
        files = {"access": ("access.log", b"x", "text/plain")}
        self.assertEqual(self.client.post("/web/scan", files=files).status_code, 403)
        self.assertEqual(self.client.post("/api/web/scan", files=files).status_code, 403)

    def test_demo_pages_do_not_call_ai(self):
        # /demo 와 /web/demo 는 use_ai=False 로 돌아야 배포 환경에 API 키가 필요 없다
        from unittest import mock
        with mock.patch("logsight.web.webanalyze._call_claude") as call:
            self.client.get("/web/demo")
            self.client.get("/demo")
            call.assert_not_called()


if __name__ == "__main__":
    unittest.main()

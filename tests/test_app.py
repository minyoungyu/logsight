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


def _load_app(demo: bool, env: dict | None = None, client: tuple[str, int] | None = None):
    """DEMO·TOKEN은 import 시점에 정해지므로, 환경변수를 바꿔 app.py를 따로 읽는다."""
    from fastapi.testclient import TestClient  # httpx 필요(CI에서 설치)
    want = {"LOGSIGHT_DEMO": "1" if demo else "0", "LOGSIGHT_TOKEN": "", **(env or {})}
    old = {k: os.environ.get(k) for k in want}
    os.environ.update(want)
    try:
        spec = importlib.util.spec_from_file_location(f"app_{'demo' if demo else 'full'}", ROOT / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return TestClient(mod.app, client=client) if client else TestClient(mod.app)


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


NGINX = (b'198.51.100.7 - - [02/Nov/2026:01:00:00 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" '
         b'200 512 "-" "curl/8"\n')


class UploadProtectionTests(unittest.TestCase):
    """사양서 NFR-19(TC-WEB-SEC-01~06): 웹 업로드 보호."""

    def _scan(self, c, **kw):
        return c.post("/api/web/scan", files={"access": ("access.log", NGINX, "text/plain")},
                      data={"no_ai": "1"}, **kw)

    def test_local_upload_works_without_token(self):  # TC-WEB-SEC-01
        r = self._scan(_load_app(False))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_remote_upload_refused_without_token(self):  # TC-WEB-SEC-02
        c = _load_app(False, client=("203.0.113.9", 50000))
        self.assertEqual(self._scan(c).status_code, 403)
        self.assertEqual(c.post("/analyze", files={"logs": ("a.log", NGINX)}).status_code, 403)
        self.assertEqual(c.get("/").status_code, 200)  # 보기만 하는 화면은 그대로

    def test_token_required_and_cookie_remembered(self):  # TC-WEB-SEC-03
        c = _load_app(False, env={"LOGSIGHT_TOKEN": "s3cret-token"}, client=("203.0.113.9", 50000))
        self.assertEqual(self._scan(c).status_code, 401)
        self.assertEqual(self._scan(c, headers={"X-LogSight-Token": "wrong"}).status_code, 401)
        self.assertEqual(self._scan(c, headers={"X-LogSight-Token": "s3cret-token"}).status_code, 200)
        c.get("/?token=s3cret-token")  # 한 번 열면 쿠키로 기억
        self.assertEqual(self._scan(c).status_code, 200)

    def test_cross_site_upload_refused(self):  # TC-WEB-SEC-04
        c = _load_app(False)
        self.assertEqual(self._scan(c, headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self._scan(c, headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        self.assertEqual(self._scan(c, headers={"Origin": "http://testserver"}).status_code, 200)

    def test_size_limit_on_every_upload_route(self):  # TC-WEB-SEC-05
        c = _load_app(False, env={"LOGSIGHT_MAX_UPLOAD_MB": "1"})
        big = b"x" * (1024 * 1024 + 10)
        self.assertEqual(c.post("/api/web/scan", files={"access": ("a.log", big)}).status_code, 413)
        self.assertEqual(c.post("/web/scan", files={"access": ("a.log", big)}).status_code, 413)
        self.assertEqual(c.post("/analyze", files={"logs": ("a.log", big)}).status_code, 413)

    def test_gzip_bomb_not_expanded(self):  # TC-WEB-SEC-05
        import gzip
        from logsight.normalize import load_uploads
        old = os.environ.get("LOGSIGHT_MAX_UNZIP_MB")
        os.environ["LOGSIGHT_MAX_UNZIP_MB"] = "1"
        try:
            evs, st = load_uploads({"auto": ("bomb.log.gz", gzip.compress(b"A" * (3 * 1024 * 1024)))})
        finally:
            if old is None:
                os.environ.pop("LOGSIGHT_MAX_UNZIP_MB", None)
            else:
                os.environ["LOGSIGHT_MAX_UNZIP_MB"] = old
        self.assertEqual(evs, [])
        self.assertIn("1MB", st[0]["error"])

    def test_security_headers(self):  # TC-WEB-SEC-06
        r = _load_app(False).get("/demo")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertIn("default-src 'none'", r.headers["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])


if __name__ == "__main__":
    unittest.main()

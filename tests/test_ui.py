"""웹 점검 화면 테스트: 랜딩(데모/일반), 보고서 구성, 이스케이프, 외부 리소스 없음.
실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.web.ui import landing, render  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402


def _sample_result():
    return assess(SiteProfile.load(ROOT / "samples" / "web" / "profile.json"), use_ai=False, top=500)


class LandingTests(unittest.TestCase):
    def test_demo_landing_has_no_upload_inputs(self):
        html = landing(demo=True)
        self.assertNotIn("<input type=file", html)
        self.assertNotIn("action=/web/scan", html)
        self.assertIn("샘플 점검 결과 보기", html)

    def test_normal_landing_has_upload_inputs_for_each_kind(self):
        html = landing(demo=False)
        for name in ("access", "weberror", "auth"):
            self.assertRegex(html, rf"name={name} multiple")
        self.assertIn("action=/web/scan", html)

    def test_landing_has_no_external_resources(self):
        for demo in (True, False):
            html = landing(demo=demo)
            self.assertNotRegex(html, r"<script[^>]+src|<link|@import|https?://")


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _sample_result()
        cls.html = render(cls.result)

    def test_verdict_comes_first(self):
        verdict_at = self.html.index("class='verdict")
        timeline_at = self.html.index("사건 흐름")
        self.assertLess(verdict_at, timeline_at)
        self.assertIn(self.result["overall_verdict_ko"], self.html)

    def test_immediate_actions_shown(self):
        if self.result["simple"]["now"]:
            self.assertIn("지금 할 일", self.html)

    def test_block_rules_have_copy_buttons(self):
        self.assertIn("data-copy=", self.html)
        self.assertIn("deny ", self.html)
        self.assertIn("iptables -I INPUT -s", self.html)

    def test_no_external_resources(self):
        # 로그 안의 URL은 공격자가 보낸 텍스트라서 허용한다. 페이지가 불러오는 것만 막는다.
        self.assertNotRegex(self.html, r"<script[^>]+src|<link|@import|<img[^>]+src=['\"]?https?://")

    def test_user_text_is_escaped(self):
        result = _sample_result()
        result["results"][0]["report"]["summary"] = "<img src=x onerror=alert(1)>"
        result["results"][0]["report"]["unknowns"] = ["<script>bad()</script>"]
        html = render(result)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<script>bad()", html)
        self.assertIn("&lt;img src=x", html)

    def test_empty_result_shows_no_evidence_card(self):
        result = _sample_result()
        result["results"] = []
        result["incident_index"] = []
        result["simple"]["now"] = []
        result["expert"] = {}
        html = render(result)
        self.assertIn("뚜렷한 침해 흔적이 없습니다", html)


if __name__ == "__main__":
    unittest.main()

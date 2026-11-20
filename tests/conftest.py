"""LOGSIGHT_NO_SKIP=1이면 건너뛴 테스트를 실패로 바꾼다(사양서 NFR-21).

moto·httpx가 없으면 일부 테스트가 조용히 건너뛰어진다. 그 상태로 '전부 통과'라고 세면 격리·로그 점검처럼
가짜 AWS가 필요한 요구사항은 실제로는 확인되지 않은 것이다. CI는 이 값을 켜고 돈다.
"""
from __future__ import annotations

import os

import pytest

STRICT = os.environ.get("LOGSIGHT_NO_SKIP") == "1"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if STRICT and rep.skipped and not hasattr(rep, "wasxfail"):
        rep.outcome = "failed"
        reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
        rep.longrepr = f"LOGSIGHT_NO_SKIP=1: 건너뛴 테스트는 통과로 세지 않는다 ({reason})"

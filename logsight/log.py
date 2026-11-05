"""구조화(JSON) 로그. 한 줄에 JSON 객체 하나를 stderr로 쓴다.

  {"ts": "...", "level": "info", "event": "scan_done", "incidents": 3, ...}

운영 도구가 그대로 읽을 수 있게 하고, 사람도 눈으로 볼 수 있게 키 이름을 고정한다.
민감값(IP 등)은 호출하는 쪽에서 넘기지 않는다. 여기서는 형식만 맡는다.
"""
from __future__ import annotations

import json
import sys
import time

LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
_MIN = {"level": 20}


def set_level(name: str) -> None:
    _MIN["level"] = LEVELS.get(name, 20)


def log(level: str, event: str, **fields) -> None:
    if LEVELS.get(level, 20) < _MIN["level"]:
        return
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "event": event}
    rec.update(fields)
    sys.stderr.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")


def info(event: str, **fields) -> None:
    log("info", event, **fields)


def warning(event: str, **fields) -> None:
    log("warning", event, **fields)

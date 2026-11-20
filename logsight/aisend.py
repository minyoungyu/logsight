"""AI로 보내기 전 안내와 보낸 양 기록(사양서 NFR-25, FR-21).

외부 AI(Anthropic API)로 보내는 세 경로(재검토·설명·웹서버 점검)가 보내기 직전에 `announce()`를 부른다.
명령줄에서는 표준 오류로 무엇을 얼마나 어디로 보내는지 한 줄씩 알리고, 보낸 양은 처리 기록(selflog)에 남긴다.
"""
from __future__ import annotations

import json
import sys

DEST = "Anthropic API(api.anthropic.com)"
SENT: list[dict] = []  # 이 프로세스에서 보낸 것(처리 기록에 쓴다)
QUIET = False  # 웹 화면 등 표준 오류를 쓰지 않을 때


def _count_events(obj) -> int:
    if isinstance(obj, dict):
        n = len(obj["events"]) if isinstance(obj.get("events"), list) else 0
        return n + sum(_count_events(v) for k, v in obj.items() if k != "events")
    if isinstance(obj, list):
        return sum(_count_events(v) for v in obj)
    return 0


def announce(kind: str, payload: dict, model: str) -> dict:
    """보낼 내용의 크기를 알리고 기록한다. kind: '재검토' | '설명' | '웹서버 점검'."""
    body = json.dumps(payload, ensure_ascii=False)
    n_inc = len(payload["incidents"]) if isinstance(payload.get("incidents"), list) else 1
    rec = {"kind": kind, "model": model, "incidents": n_inc, "events": _count_events(payload),
           "bytes": len(body.encode("utf-8")), "dest": DEST}
    SENT.append(rec)
    if not QUIET:
        print(f"[AI 전송] {kind}: 사건 {rec['incidents']}개 · 이벤트 {rec['events']}건 · 약 {rec['bytes'] / 1024:.1f}KB"
              f" → {DEST}, 모델 {model}. 비밀번호·토큰·키는 가린 뒤 보냅니다. 보내지 않으려면 --no-ai로 실행하세요.",
              file=sys.stderr)
    return rec


def total() -> dict:
    return {"calls": len(SENT), "bytes": sum(r["bytes"] for r in SENT),
            "models": sorted({r["model"] for r in SENT})}

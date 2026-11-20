"""LogFinder 자신의 처리 기록(사양서 FR-21).

분석·점검·격리 한 번마다 JSON 한 줄을 출력 폴더의 `logsight_audit.jsonl`에 덧붙인다.
나중에 "그때 어떤 파일을 읽고, AI에 무엇을 얼마나 보냈고, 무엇을 판정·실행했나"를 되짚을 수 있게 하는 것이 목적이다.
원본 로그 내용은 적지 않는다(파일 이름·크기·해시만).
"""
from __future__ import annotations

import getpass
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

NAME = "logsight_audit.jsonl"


def file_hash(path: str | Path) -> dict:
    p = Path(path)
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return {"file": str(p), "bytes": p.stat().st_size, "sha256": h.hexdigest()}
    except OSError as exc:
        return {"file": str(p), "error": type(exc).__name__}


def _who() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — 컨테이너 등에서 사용자 이름이 없을 수 있다
        return "?"


def record(out_dir: str | Path, command: str, *, files: list[str] = (), result: dict | None = None,
           actions: list[dict] = (), ai: dict | None = None) -> Path:
    """한 줄을 덧붙이고 기록 파일 경로를 돌려준다."""
    from .aisend import total
    ai = ai if ai is not None else total()
    line = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": __version__,
            "command": command, "by": _who(),
            "inputs": [file_hash(f) for f in files],
            "ai": ai if ai.get("calls") else {"calls": 0},
            "result": result or {}, "actions": list(actions)}
    out = Path(out_dir) / NAME
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
    return out


def summary_of(result: dict) -> dict:
    """분석 결과에서 기록할 것: 이벤트·사건 수와 사건별 판정(원본 내용 없음)."""
    rows = []
    for r in result.get("results", []):
        inc, rep = r["incident"], r.get("report", {})
        rows.append({"id": inc["id"], "verdict": inc.get("verdict") or rep.get("attack_verdict") or rep.get("verdict"),
                     "web_verdict": rep.get("verdict") if rep.get("attack_verdict") else None})
    return {"events": result.get("n_events"), "incidents": result.get("n_incidents"),
            "overall": result.get("overall_verdict"), "verdicts": rows}

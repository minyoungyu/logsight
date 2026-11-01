"""전체 흐름: 읽기 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .analyze import analyze
from .config_audit import audit
from .correlate import build_incidents, group_repeats
from .detect import run_detections
from .normalize import Event, load_paths


def load_env(path: str | Path | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8-sig")) if p.is_file() else {}


def run(events: list[Event], env: dict | None = None, *, file_stats: list[dict] | None = None,
        top: int = 5, use_ai: bool = True, model: str | None = None,
        window_min: int = 30) -> dict:
    t0 = time.time()
    env = env or {}
    findings = run_detections(events, env)
    incidents = build_incidents(events, findings, window_min=window_min)
    groups = group_repeats(incidents)  # 반복 사건은 대표 하나로 접어서 상위 N개를 고른다
    t_detect = time.time() - t0
    results = []
    for inc in groups[:top]:
        checks = audit(inc, env)
        out = analyze(inc, checks, model=model, use_ai=use_ai)
        results.append({"incident": inc, "checks": checks, **out})
    by_source: dict[str, int] = {}
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": file_stats or [],
        "n_events": len(events),
        "events_by_source": by_source,
        "n_flagged": sum(1 for e in events if e.findings),
        "n_findings": len(findings),
        "rule_counts": _rule_counts(findings),
        "n_incidents": len(incidents),
        "n_groups": len(groups),
        "severity_counts": {s: sum(1 for g in groups if g["severity"] == s) for s in ("high", "medium", "low")},
        "incident_index": [{k: i[k] for k in ("id", "start", "end", "severity", "score", "stages",
                                               "src_ips", "n_events", "repeats", "first_seen",
                                               "last_seen")}
                           | {"rules": sorted({f["rule"] for f in i["findings"]})} for i in groups[:50]],
        "results": results,
        "timing": {"detect_correlate_s": round(t_detect, 2),
                   "total_s": round(time.time() - t0, 2)},
        "has_environment": bool(env),
    }


def _rule_counts(findings) -> dict:
    """규칙별 (탐지 수, 표시된 이벤트 수) — 어떤 규칙이 시끄러운지 보는 용도."""
    out: dict[str, list[int]] = {}
    for f in findings:
        c = out.setdefault(f.rule, [0, 0])
        c[0] += 1
        c[1] += len(f.events)
    return {k: {"findings": v[0], "events": v[1]}
            for k, v in sorted(out.items(), key=lambda kv: -kv[1][1])}


def run_paths(paths: list[str], env_path: str | None = None, **kw) -> dict:
    events, stats = load_paths([Path(p) for p in paths])
    if env_path is None:
        # 폴더 안에 environment.json이 있으면 자동으로 쓴다
        for p in paths:
            cand = Path(p) / "environment.json"
            if cand.is_file():
                env_path = str(cand)
                break
    return run(events, load_env(env_path), file_stats=stats, **kw)

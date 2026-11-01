"""전체 흐름: 읽기 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .analyze import analyze, build_payload
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
        window_min: int = 30, preview: bool = False) -> dict:
    """preview=True면 Claude를 부르지 않고, 보낼 내용(마스킹 후)을 결과에 ai_payload로 담는다."""
    t0 = time.time()
    env = env or {}
    enrich(events, env)
    findings = run_detections(events, env)
    incidents = build_incidents(events, findings, window_min=window_min)
    groups = group_repeats(incidents)  # 반복 사건은 대표 하나로 접어서 상위 N개를 고른다
    t_detect = time.time() - t0
    results = []
    for inc in groups[:top]:
        checks = audit(inc, env)
        out = analyze(inc, checks, model=model, use_ai=use_ai and not preview)
        row = {"incident": inc, "checks": checks, **out}
        if preview:
            row["ai_payload"] = build_payload(inc, checks)
        results.append(row)
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
        # 같은 규칙 조합(공격 유형)끼리 센 수: "처음 보는 공격 유형이 몇 가지인가"
        "n_patterns": len({tuple(sorted({f["rule"] for f in g["findings"]})) for g in groups}),
        "severity_counts": {s: sum(1 for g in groups if g["severity"] == s) for s in ("high", "medium", "low")},
        "incident_index": [{k: i[k] for k in ("id", "start", "end", "severity", "score", "stages",
                                               "src_ips", "n_events", "repeats", "first_seen",
                                               "last_seen")}
                           | {"rules": sorted({f["rule"] for f in i["findings"]})} for i in groups[:50]],
        "results": results,
        "timing": {"detect_correlate_s": round(t_detect, 2),
                   "total_s": round(time.time() - t0, 2)},
        "has_environment": bool(env),
        "assumptions": _assumptions(by_source, env),
    }


def _assumptions(by_source: dict, env: dict) -> list[str]:
    """결과 해석에 영향을 주는 가정을 보고서에 그대로 보여 준다."""
    from .normalize import SYSLOG
    out = []
    if by_source.get("sshauth") or by_source.get("hostfw"):
        tz = SYSLOG["tz"].utcoffset(None)
        hours = tz.total_seconds() / 3600
        out.append(f"auth.log·kern.log처럼 연도·시간대가 없는 줄은 "
                   f"{'UTC' if not hours else f'UTC{hours:+g}'} 기준, 연도는 "
                   f"{SYSLOG['year'] or '올해(미래면 작년)'}로 해석했습니다. 다르면 --syslog-tz, --year로 지정하세요.")
    if not env:
        out.append("설정 스냅샷(environment.json)이 없어 방화벽 수정안을 만들지 않았습니다. "
                   "python -m logsight collect environment로 만들 수 있습니다.")
    elif not env.get("trusted_ips"):
        out.append("관리자 IP(trusted_ips)가 비어 있어 수정안의 허용 IP가 자리표시로 나옵니다.")
    if by_source.get("weblog") and by_source.get("alb"):
        out.append("ALB 뒤의 nginx 로그는 출발지가 ALB 내부 IP일 수 있습니다. 실제 사용자 IP는 X-Forwarded-For를 로그 형식에 넣어야 보입니다.")
    return out


def _rule_counts(findings) -> dict:
    """규칙별 (탐지 수, 표시된 이벤트 수) — 어떤 규칙이 시끄러운지 보는 용도."""
    out: dict[str, list[int]] = {}
    for f in findings:
        c = out.setdefault(f.rule, [0, 0])
        c[0] += 1
        c[1] += len(f.events)
    return {k: {"findings": v[0], "events": v[1]}
            for k, v in sorted(out.items(), key=lambda kv: -kv[1][1])}


def enrich(events: list[Event], env: dict) -> None:
    """설정 스냅샷의 인스턴스 목록으로 네트워크·웹 로그의 대상 IP를 인스턴스 ID로 바꿔 적는다.
    사건 묶기 연결고리로는 쓰지 않는다(여러 스캐너가 같은 서버를 두드리면 한 사건으로 뭉치므로).
    보고서·수정안에서 "어느 서버가 대상이었나"를 보여 주는 용도."""
    ip2inst = {}
    for inst in env.get("instances", []):
        for k in ("private_ip", "public_ip"):
            if inst.get(k):
                ip2inst[inst[k]] = inst["instance_id"]
    if not ip2inst:
        return
    for e in events:
        if not e.instance_id and e.dst_ip in ip2inst:
            e.extra["target_instance"] = ip2inst[e.dst_ip]


def run_paths(paths: list[str], env_path: str | None = None, *, since=None, until=None,
              **kw) -> dict:
    events, stats = load_paths([Path(p) for p in paths], since=since, until=until)
    if env_path is None:
        # 폴더 안에 environment.json이 있으면 자동으로 쓴다
        for p in paths:
            cand = Path(p) / "environment.json"
            if cand.is_file():
                env_path = str(cand)
                break
    return run(events, load_env(env_path), file_stats=stats, **kw)

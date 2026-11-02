"""전체 흐름: 읽기 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .analyze import analyze, build_payload
from .config_audit import audit
from .correlate import build_incidents, group_repeats
from .detect import run_detections
from .explain import mark_known, rule_triage
from .normalize import Event, load_paths
from .triage import reorder, triage


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
    n_known = mark_known(events, env)  # 설정의 정상 작업 목록과 맞는 이벤트 표시(지우지 않음)
    findings = run_detections(events, env)
    incidents = build_incidents(events, findings, window_min=window_min)
    groups = group_repeats(incidents)  # 반복 사건은 대표 하나로 접어서 상위 N개를 고른다
    t_detect = time.time() - t0
    # 재검토: 공격으로 보이는 사건을 위로 올린다. 규칙 판정은 항상 만들고(키 없이도, 비교용),
    # Claude 키가 있으면 Claude 판정(점수순 상위 30개)을 쓴다. 실패하면 규칙 판정으로 계속
    rule_tri = rule_triage(groups, events)
    ai_tri = triage(groups, model=model, use_ai=use_ai and not preview, events=events)
    tri = ai_tri if ai_tri and "incidents" in ai_tri else rule_tri
    groups = reorder(groups, tri)
    rule_v = {x["id"]: x for x in rule_tri["incidents"]}
    results = []
    for inc in groups[:top]:
        checks = audit(inc, env)
        out = analyze(inc, checks, model=model, use_ai=use_ai and not preview,
                      verdict=rule_v.get(inc["id"]))
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
                           | {"rules": sorted({f["rule"] for f in i["findings"]})}
                           | ({"ai_verdict": i["ai_verdict"]} if "ai_verdict" in i else {})
                           | ({"verdict": i["verdict"], "verdict_by": i["verdict_by"]} if "verdict" in i else {})
                           for i in groups[:50]],
        "triage": tri,
        "rule_triage": rule_tri,
        "n_known": n_known,
        "explain_mode": _explain_mode(results, tri, ai_tri),
        "results": results,
        "timing": {"detect_correlate_s": round(t_detect, 2),
                   "total_s": round(time.time() - t0, 2)},
        "has_environment": bool(env),
        "assumptions": _assumptions(by_source, env, file_stats or [],
                                    sum(1 for e in events if e.extra.get("behind_proxy"))),
    }


def _explain_mode(results: list[dict], tri: dict, ai_tri: dict | None) -> dict:
    """보고서 맨 위에 'AI를 썼는가'를 분명히 보여 주기 위한 요약."""
    models = sorted({r["meta"]["model"] for r in results if r["meta"].get("mode") == "claude"})
    errors = [r["meta"]["ai_error"] for r in results if r["meta"].get("ai_error")]
    if ai_tri and ai_tri.get("error"):
        errors.append(ai_tri["error"])
    return {"report": "claude" if models else "rules", "models": models,
            "triage": "rules" if tri.get("mode") == "rules" else "claude",
            "triage_model": None if tri.get("mode") == "rules" else (tri.get("meta") or {}).get("model"),
            "ai_errors": errors[:3]}


def _assumptions(by_source: dict, env: dict, file_stats: list[dict] = (), proxied: int = 0) -> list[str]:
    """결과 해석에 영향을 주는 가정을 보고서에 그대로 보여 준다."""
    from .normalize import SYSLOG
    out = []
    bad = [s["file"] for s in file_stats if not s.get("kind")]
    if bad:
        out.append(f"형식을 알 수 없어 건너뛴 파일 {len(bad)}개: {', '.join(map(str, bad[:5]))}"
                   + (" 외" if len(bad) > 5 else "") + ". 파일 이름에 로그 종류(cloudtrail, vpcflow, nginx 등)를 넣으면 판별됩니다.")
    if by_source.get("sshauth") or by_source.get("hostfw"):
        tz = SYSLOG["tz"].utcoffset(None)
        hours = tz.total_seconds() / 3600
        out.append(f"auth.log·kern.log처럼 연도·시간대가 없는 줄은 "
                   f"{'UTC' if not hours else f'UTC{hours:+g}'} 기준, 연도는 "
                   f"{SYSLOG['year'] or '올해(미래면 작년)'}로 해석했습니다. 다르면 시간대·연도 옵션(명령줄은 --syslog-tz, --year)으로 지정하세요.")
    if not env:
        out.append("설정 스냅샷(environment.json)이 없어 방화벽 수정안을 만들지 않았습니다. "
                   "python -m logsight collect environment로 만들 수 있습니다.")
    elif not env.get("trusted_ips"):
        out.append("관리자 IP(trusted_ips)가 비어 있어 수정안의 허용 IP가 자리표시로 나옵니다.")
    if proxied:
        out.append(f"웹서버 로그 {proxied:,}줄은 ALB·프록시 내부 IP에서 왔고 실제 사용자 IP가 없어 내부 IP로 분석했습니다. "
                   "nginx 로그 형식 끝에 \"$http_x_forwarded_for\"를 넣으면(nginx 기본 main 형식) 실제 IP로 분석합니다.")
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
    ip2inst, host2inst = {}, {}
    for inst in env.get("instances", []):
        for k in ("private_ip", "public_ip"):
            if inst.get(k):
                ip2inst[inst[k]] = inst["instance_id"]
        for k in ("name", "private_dns"):  # 서버 로그의 호스트 이름(web1, ip-10-0-1-10.ec2.internal)
            if inst.get(k):
                host2inst[inst[k].split(".")[0].lower()] = inst["instance_id"]
    if not ip2inst and not host2inst:
        return
    for e in events:
        if e.instance_id:
            continue
        inst = ip2inst.get(e.dst_ip) or host2inst.get(str(e.extra.get("host", "")).split(".")[0].lower())
        if inst:
            e.extra["target_instance"] = inst


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

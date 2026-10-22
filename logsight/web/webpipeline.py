"""
웹서버 침해 판단 전체 흐름 + 외부에서 부르는 깔끔한 API.

  로그 파일(프로필) → 파싱 → 탐지 → 웹 루트 파일 점검 → 사건 묶기 → AI/규칙 판정
  → UI가 그대로 쓸 수 있는 JSON(dict)

assess(profile) 하나만 부르면 된다. CLI도, 웹 UI도, 테스트도 모두 이 함수를 쓴다.
판정 로직·데이터 형식은 여기 한 곳에만 있어서, 나중에 UI를 붙여도 백엔드를 다시 안 짜도 된다.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from ..normalize import Event, read_text, mask, parse_sshauth
from ..correlate import build_incidents
from ..detect import RULES
from .weblog import parse_access, parse_weberror, parse_auth
from .webdetect import run_web_detections
from .webscan import scan_webroot
from .webanalyze import analyze_web, rule_verdict, VERDICT_KO
from .webprofile import SiteProfile
from .expert import expert_report
from .layman import layman_card

PARSERS = {
    "access": parse_access,
    "weberror": parse_weberror,
    "auth": parse_auth,
    "sshauth": parse_sshauth,
}

VERDICT_RANK = {"no_evidence": 0, "suspicious": 1, "likely_breached": 2, "breached": 3}


def load_events(profile: SiteProfile) -> tuple[list[Event], list[dict]]:
    events: list[Event] = []
    stats: list[dict] = []
    for kind, files in profile.resolved_logs().items():
        parser = PARSERS.get(kind)
        if not parser:
            stats.append({"file": f"<{kind}>", "kind": kind, "events": 0, "error": "알 수 없는 로그 종류"})
            continue
        for p in files:
            try:
                text = read_text(Path(p))
            except OSError as exc:
                stats.append({"file": str(p), "kind": kind, "events": 0, "error": str(exc)})
                continue
            kw = {"year": profile.year} if kind in ("auth", "sshauth") else {}
            evs = parser(text, name=Path(p).name, **kw)
            events.extend(evs)
            stats.append({"file": str(p), "kind": kind, "events": len(evs)})
    return events, stats


def _within(events: list[Event], profile: SiteProfile) -> list[Event]:
    def _p(s):
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    lo, hi = _p(profile.since), _p(profile.until)
    if not lo and not hi:
        return events
    return [e for e in events if (not lo or e.ts >= lo) and (not hi or e.ts <= hi)]


def assess(profile: SiteProfile, *, top: int = 10, use_ai: bool = True,
           model: str | None = None, window_min: int = 30) -> dict:
    """웹서버 로그·파일을 분석해 침해 여부 판정 결과(dict)를 돌려준다. 이것이 공개 API."""
    t0 = time.time()
    events, stats = load_events(profile)
    events = _within(events, profile)

    # 웹 루트 파일 점검 → 발견 파일을 이벤트로 합친다
    file_findings, file_events = scan_webroot(profile)
    # 발견한 "웹셸 등급" 파일 경로로 들어온 접속 요청만 같은 사건으로 잇는다.
    # (의심 등급 파일은 정상 앱 코드일 수 있어, 그 경로로 링크하면 무관한 방문자까지 엮인다.)
    shell_paths = {e.extra["webshell_path"] for e in file_events
                   if e.extra.get("webshell_path") and "FILE_WEBSHELL" in e.findings}
    if shell_paths:
        for e in events:
            if e.source == "access" and ("/" + e.extra.get("path", "").lstrip("/")) in shell_paths:
                e.extra["webshell_path"] = "/" + e.extra.get("path", "").lstrip("/")
    events.extend(file_events)

    findings = run_web_detections(events, profile) + file_findings
    mask(events)  # 보고서·AI로 나가기 전 민감정보 마스킹
    incidents = build_incidents(events, findings, window_min=window_min)
    t_detect = time.time() - t0

    profile_dict = profile.to_dict()
    results = []
    for inc in incidents[:top]:
        out = analyze_web(inc, profile_dict, model=model, use_ai=use_ai)
        results.append({"incident": inc, **out})

    # 전체 판정 = 사건들 중 가장 심각한 판정
    all_rules = [f for inc in incidents for f in inc["findings"]]
    overall, _ = rule_verdict(all_rules) if all_rules else ("no_evidence", "low")
    for r in results:
        v = r["report"].get("verdict")
        if v and VERDICT_RANK.get(v, 0) > VERDICT_RANK.get(overall, 0):
            overall = v

    by_source: dict[str, int] = {}
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "site": {"name": profile.name, "stack": profile.stack, "webroot": profile.webroot},
        "overall_verdict": overall,
        "overall_verdict_ko": VERDICT_KO.get(overall, overall),
        "files": stats,
        "n_events": len(events),
        "events_by_source": by_source,
        "n_flagged": sum(1 for e in events if e.findings),
        "n_findings": len(findings),
        "rule_counts": _rule_counts(findings),
        "n_incidents": len(incidents),
        "incident_index": [{k: i[k] for k in ("id", "start", "end", "severity", "stages",
                                              "src_ips", "n_events")} for i in incidents[:50]],
        "results": results,
        "timing": {"detect_correlate_s": round(t_detect, 2),
                   "total_s": round(time.time() - t0, 2)},
    }
    # 같은 결과를 두 독자용으로 나눈 뷰: 비숙련자 카드 + 숙련자 상세
    out["simple"] = layman_card(out)
    out["expert"] = expert_report(out, profile_dict)
    return out


def _rule_counts(findings) -> dict:
    out: dict[str, list[int]] = {}
    for f in findings:
        c = out.setdefault(f.rule, [0, 0])
        c[0] += 1
        c[1] += len(f.events)
    return {k: {"findings": v[0], "events": v[1], "title": RULES.get(k, ("", "", k))[2]}
            for k, v in sorted(out.items(), key=lambda kv: -kv[1][1])}

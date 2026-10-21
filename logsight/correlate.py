"""
탐지된(의심) 이벤트를 연결고리(출발지 IP, 인스턴스 ID, IAM 주체, 액세스 키)로 묶어
하나의 '사건(Incident)'으로 만든다. networkx 그래프 기반.

대용량 로그(수십만~수백만 건)에서도 돌 수 있도록 그래프에는 탐지 표시가 붙은 이벤트만
노드로 넣고, 표시가 없는 이벤트는 사건마다 '맥락 집계'(어떤 API가 몇 건)로만 요약한다.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import timedelta

import networkx as nx

from .detect import RULES, STAGE_ORDER, Finding, _is_ip, _is_private
from .normalize import Event, mask_obj

SEV_RANK = {"high": 3, "medium": 2, "low": 1}


WEB_SOURCES = {"access", "weberror", "auth", "sshauth", "alb", "waf", "file"}


def _keys(e: Event):
    # 웹/엣지 로그는 공격자 IP가 연결 축이다. 로컬·사내 IP(127.0.0.1 등)라도 그대로 쓴다
    # (프록시 없는 단독 서버, 로컬 테스트, 사내 침해 모두 이 경로로 묶여야 한다).
    if e.src_ip and _is_ip(e.src_ip) and (e.source in WEB_SOURCES or not _is_private(e.src_ip)):
        yield ("ip", e.src_ip)
    if e.extra.get("webshell_path"):
        yield ("path", e.extra["webshell_path"])  # 웹셸 파일 ↔ 그 경로로의 접근 요청을 잇는다
    if e.instance_id:
        yield ("inst", e.instance_id)
    if e.access_key:
        yield ("key", e.access_key)
    if e.actor and e.source == "cloudtrail" and e.actor.startswith("arn:"):
        yield ("actor", e.actor)


def _split_long(evs: list[Event], max_span: timedelta) -> list[list[Event]]:
    """몇 시간씩 끊임없이 이어지는 활동은 max_span 단위 사건으로 나눈다(보고서 가독성)."""
    chunks, cur = [], []
    for e in evs:
        if cur and e.ts - cur[0].ts > max_span:
            chunks.append(cur)
            cur = []
        cur.append(e)
    return chunks + ([cur] if cur else [])


def build_incidents(events: list[Event], findings: list[Finding],
                    window_min: int = 30, max_events: int = 60,
                    max_span_min: int = 120) -> list[dict]:
    """탐지 이벤트를 사건으로 묶는다. max_events: 사건 하나에 상세로 남길 이벤트 수 상한,
    max_span_min: 사건 하나의 최대 길이(분)."""
    flagged = sorted({id(e): e for f in findings for e in f.events}.values(), key=lambda e: e.ts)
    if not flagged:
        return []
    win = timedelta(minutes=window_min)
    # 연결 요소 계산: 노드가 수백만 개여도 가볍도록 networkx의 UnionFind 사용
    uf = nx.utils.UnionFind(range(len(flagged)))
    idx_by_key: dict[tuple, list[int]] = defaultdict(list)
    for i, e in enumerate(flagged):
        for k in _keys(e):
            idx_by_key[k].append(i)
    for idxs in idx_by_key.values():
        for a, b in zip(idxs, idxs[1:]):
            if flagged[b].ts - flagged[a].ts <= win:
                uf.union(a, b)

    # 맥락 이벤트(표시 없음)를 키로 색인
    ctx_by_key: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if not e.findings:
            for k in _keys(e):
                ctx_by_key[k].append(e)
    ctx_ts: dict[tuple, list] = {}
    for k, lst in ctx_by_key.items():
        lst.sort(key=lambda e: e.ts)
        ctx_ts[k] = [e.ts for e in lst]

    finding_by_event: dict[int, list[Finding]] = defaultdict(list)
    for f in findings:
        for e in f.events:
            finding_by_event[id(e)].append(f)

    incidents = []
    comps = [[flagged[i] for i in sorted(c)] for c in uf.to_sets()]  # flagged는 시간순
    for evs in (ch for c in comps for ch in _split_long(c, timedelta(minutes=max_span_min))):
        fset = {id(f): f for e in evs for f in finding_by_event[id(e)]}
        fl = sorted(fset.values(), key=lambda f: f.events[0].ts)
        start, end = evs[0].ts, evs[-1].ts
        keys = {k for e in evs for k in _keys(e)}
        ctx = []
        seen = {id(e) for e in evs}
        for k in keys:
            lst = ctx_by_key.get(k)
            if not lst:
                continue
            lo = bisect_left(ctx_ts[k], start - win)
            hi = bisect_right(ctx_ts[k], end + win)
            for e in lst[lo:hi]:
                if id(e) not in seen:
                    seen.add(id(e))
                    ctx.append(e)
        sev = max((SEV_RANK[f.severity] for f in fl), default=1)
        stages = sorted({f.stage for f in fl}, key=STAGE_ORDER.index)
        # 상세 이벤트가 너무 많으면 규칙마다 앞·뒤 몇 건만 남기고 나머지는 개수로
        detail = evs
        omitted = 0
        if len(evs) > max_events:
            keep: dict[int, Event] = {}
            per = max(2, max_events // max(1, len(fl)))
            in_comp = {id(x) for x in evs}
            for f in fl:
                fe = [e for e in f.events if id(e) in in_comp]
                for e in fe[: per // 2] + fe[-(per - per // 2):]:
                    keep[id(e)] = e
            detail = sorted(keep.values(), key=lambda e: e.ts)[:max_events]
            omitted = len(evs) - len(detail)
        incidents.append({
            "start": start.isoformat(),
            "end": end.isoformat(),
            "severity": {3: "high", 2: "medium", 1: "low"}[sev],
            "score": sev * 100 + len({f.rule for f in fl}) * 10 + min(len(evs), 9),
            "stages": stages,
            "src_ips": sorted({e.src_ip for e in evs if e.src_ip and _is_ip(e.src_ip)}),
            "instances": sorted({e.instance_id for e in evs if e.instance_id}),
            "actors": sorted({e.actor for e in evs if e.actor}),
            "sources": sorted({e.source for e in evs}),
            "n_events": len(evs),
            "findings": [_finding_in(f, evs) for f in fl],
            "events": [_compact(e) for e in detail],
            "omitted_events": omitted,
            "context": {
                "n_events": len(ctx),
                "top_actions": mask_obj(Counter(e.action for e in ctx).most_common(10)),
                "sources": dict(Counter(e.source for e in ctx)),
            },
        })
    incidents.sort(key=lambda c: (-c["score"], c["start"]))
    for n, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{n:03d}"
    return incidents


def _finding_in(f: Finding, evs: list[Event]) -> dict:
    """사건(나뉜 조각) 안에 든 이벤트만 기준으로 Finding을 요약한다."""
    ids = {id(e) for e in evs}
    mine = [e for e in f.events if id(e) in ids] or f.events
    d = f.to_dict()
    d.update(first=mine[0].ts.isoformat(), last=mine[-1].ts.isoformat(), n_events=len(mine),
             evidence=[e.raw_ref for e in mine[:20]])
    return d


def _compact(e: Event) -> dict:
    """AI·보고서용 축약 이벤트(원본 전체 대신 판단에 필요한 필드만)."""
    d = {"ref": e.raw_ref, "ts": e.ts.isoformat(), "source": e.source, "action": e.action,
         "outcome": e.outcome, "src_ip": e.src_ip, "rules": list(e.findings)}
    for k in ("dst_ip", "dst_port", "actor", "instance_id", "access_key"):
        v = getattr(e, k)
        if v is not None:
            d[k] = v
    for k in ("errorCode", "params", "counted_rules", "labels", "ua", "userAgent", "awsRegion"):
        v = e.extra.get(k)
        if v:
            d[k] = v
    return mask_obj(d)  # AI·보고서로 나가는 것만 마스킹(대용량에서 전체 마스킹 비용 절약)


def summarize_rules() -> dict:
    return {k: {"technique": v[0], "stage": v[1], "title": v[2], "severity": v[3]}
            for k, v in RULES.items()}

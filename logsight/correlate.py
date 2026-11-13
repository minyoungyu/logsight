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

from .detect import (APP_SOURCES, NET_SOURCES, RULES, STAGE_ORDER, Finding, _is_ip, _is_private,
                     anchored_private_ips, shared_private_ips)
from .normalize import Event, mask_obj

SEV_RANK = {"high": 3, "medium": 2, "low": 1}


WEB_SOURCES = {"access", "weberror", "auth", "sshauth", "alb", "waf", "file"}


def _key_policy(events: list[Event], findings: list[Finding], env: dict | None):
    """사설(사내) IP를 연결고리로 쓸지 정하는 기준을 만든다.

    - 공인 IP: 어느 로그든 연결고리.
    - 사설 IP, 웹·엣지·인증 로그(nginx·Apache 포함): 연결고리. 사내에서 시작된 공격도 엮여야 한다.
      단 여러 사용자가 함께 쓰는 주소(로드밸런서·프록시·NAT로 보이는 것, shared_private_ips)는 뺀다.
      빼지 않으면 XFF 없는 로드밸런서 뒤 웹서버에서 모든 사용자의 의심 행동이 한 사건으로 뭉친다.
    - 사설 IP, 네트워크 로그(VPC Flow·서버 방화벽): 웹·서버 로그에서 의심 행동이 잡힌 IP일 때만.
      사내 통신(10.x ↔ 10.x)을 모두 이으면 무관한 활동이 다 이어지기 때문이다.
    - 그 밖(CloudTrail의 VPC 엔드포인트 주소 등)의 사설 IP: 연결고리 아님.
    반환: (키 함수, 공유 주소 {IP: 이유})"""
    shared = shared_private_ips(events, env)
    anchors = anchored_private_ips(findings, shared)

    def keys(e: Event):
        ip = e.src_ip
        if ip and _is_ip(ip):
            if not _is_private(ip):
                yield ("ip", ip)
            elif ip not in shared and (e.source in APP_SOURCES or e.source in WEB_SOURCES
                                       or (e.source in NET_SOURCES and ip in anchors)):
                yield ("ip", ip)
        yield from _other_keys(e)
    return keys, shared


def _other_keys(e: Event):
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
                    max_span_min: int = 120, env: dict | None = None) -> list[dict]:
    """탐지 이벤트를 사건으로 묶는다. max_events: 사건 하나에 상세로 남길 이벤트 수 상한,
    max_span_min: 사건 하나의 최대 길이(분). env: 설정(shared_ips로 공유 사설 주소를 지정할 수 있음)."""
    keys_of, _ = _key_policy(events, findings, env)
    flagged = sorted({id(e): e for f in findings for e in f.events}.values(), key=lambda e: e.ts)
    if not flagged:
        return []
    win = timedelta(minutes=window_min)
    # 연결 요소 계산: 노드가 수백만 개여도 가볍도록 networkx의 UnionFind 사용
    uf = nx.utils.UnionFind(range(len(flagged)))
    idx_by_key: dict[tuple, list[int]] = defaultdict(list)
    for i, e in enumerate(flagged):
        for k in keys_of(e):
            idx_by_key[k].append(i)
    for idxs in idx_by_key.values():
        for a, b in zip(idxs, idxs[1:]):
            if flagged[b].ts - flagged[a].ts <= win:
                uf.union(a, b)

    # 맥락 이벤트(표시 없음)를 키로 색인
    ctx_by_key: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if not e.findings:
            for k in keys_of(e):
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
        keys = {k for e in evs for k in keys_of(e)}
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
            "score": _score(sev, stages, fl, evs),
            "stages": stages,
            "src_ips": sorted({e.src_ip for e in evs if e.src_ip and _is_ip(e.src_ip)}),
            "instances": sorted({e.instance_id for e in evs if e.instance_id}
                                | {e.extra["target_instance"] for e in evs if e.extra.get("target_instance")}),
            "actors": sorted({e.actor for e in evs if e.actor}),
            "sources": sorted({e.source for e in evs}),
            "n_events": len(evs),
            # 정상 작업 목록(설정의 known_activity)과 맞는 이벤트 수. 상세 이벤트가 잘려도 전체 기준
            "n_known": sum(1 for e in evs if e.extra.get("known")),
            "known_labels": sorted({e.extra["known"] for e in evs if e.extra.get("known")}),
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


_OK = {"success", "accept", "allow", "count", "detected"}


def _score(sev: int, stages: list[str], fl: list[Finding], evs: list[Event]) -> int:
    """우선순위 점수. 심각도가 가장 크고, 그다음 여러 단계로 이어졌는지(공격 흐름),
    성공한 행위가 있는지를 본다. 전부 실패(거부)로 끝난 시도는 내린다."""
    score = sev * 100 + len(stages) * 15 + len({f.rule for f in fl}) * 10 + min(len(evs), 9)
    if any(e.outcome in _OK for e in evs):
        score += 20
    else:
        score -= 30
    return score


def _signature(inc: dict) -> tuple:
    """같은 주체가 같은 규칙 조합을 반복하면 같은 서명."""
    who = tuple(inc["src_ips"][:3]) or tuple(inc["instances"][:2]) or tuple(inc["actors"][:2])
    return (tuple(sorted({f["rule"] for f in inc["findings"]})), who)


def group_repeats(incidents: list[dict]) -> list[dict]:
    """반복 사건을 묶는다. 각 묶음에서 점수가 가장 높은(같으면 최근) 사건을 대표로 남기고
    repeats(반복 횟수), first_seen/last_seen, repeat_ids를 붙인다. 반환: 대표 사건 목록(점수순).
    원래 사건 목록은 그대로 둔다(보고서·근거 추적용)."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for inc in incidents:
        groups[_signature(inc)].append(inc)
    reps = []
    for members in groups.values():
        rep = max(members, key=lambda c: (c["score"], c["start"]))
        rep["repeats"] = len(members)
        rep["first_seen"] = min(c["start"] for c in members)
        rep["last_seen"] = max(c["end"] for c in members)
        rep["repeat_ids"] = [c["id"] for c in members if c is not rep][:20]
        reps.append(rep)
    # 한 번만 일어난 사건과 반복 사건을 같은 기준으로 정렬하되, 반복은 정찰 소음일 가능성이 있어
    # 점수가 같으면 처음 보는 쪽을 앞에 둔다
    reps.sort(key=lambda c: (-c["score"], c["repeats"], c["start"]))
    return reps


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
         "outcome": e.outcome, "status": e.status, "disposition": e.disposition,
         "src_ip": e.src_ip, "rules": list(e.findings)}
    for k in ("dst_ip", "dst_port", "actor", "instance_id", "access_key"):
        v = getattr(e, k)
        if v is not None:
            d[k] = v
    for k in ("errorCode", "params", "counted_rules", "labels", "ua", "userAgent", "awsRegion",
              "http_status", "http_host", "host", "proxy_ip", "target_instance",
              "gd_type", "gd_title", "gd_severity", "gd_alias", "gd_count", "gd_last_seen", "known"):
        v = e.extra.get(k)
        if v:
            d[k] = v
    return mask_obj(d)  # AI·보고서로 나가는 것만 마스킹(대용량에서 전체 마스킹 비용 절약)


def summarize_rules() -> dict:
    return {k: {"technique": v[0], "stage": v[1], "title": v[2], "severity": v[3]}
            for k, v in RULES.items()}

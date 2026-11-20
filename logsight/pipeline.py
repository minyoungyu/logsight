"""전체 흐름: 읽기 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석."""
from __future__ import annotations

import json
from collections import defaultdict
import time
from pathlib import Path

from .analyze import analyze, build_payload
from .config_audit import audit
from .correlate import build_incidents, group_repeats
from .detect import run_detections
from .explain import mark_known, rule_triage
from .netaddr import set_vpc_cidrs
from .normalize import Event, load_paths
from .guard import hold
from .triage import reorder, triage


def load_env(path: str | Path | None) -> dict:
    """environment.json을 읽는다. 깨진 파일 때문에 분석 전체가 멈추지 않게, 읽지 못하면 빈 설정으로 두고
    이유를 "_error"에 남긴다(보고서의 '가정'에 그대로 보여 준다)."""
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        env = json.loads(p.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {"_error": f"{p.name}을 JSON으로 읽지 못했습니다({exc})"}
    if not isinstance(env, dict):
        return {"_error": f"{p.name}의 최상위가 객체({{...}})가 아니라 {type(env).__name__}입니다"}
    return env


def run(events: list[Event], env: dict | None = None, *, file_stats: list[dict] | None = None,
        top: int = 5, use_ai: bool = True, model: str | None = None,
        window_min: int = 30, preview: bool = False) -> dict:
    """preview=True면 Claude를 부르지 않고, 보낼 내용(마스킹 후)을 결과에 ai_payload로 담는다."""
    t0 = time.time()
    env = env or {}
    set_vpc_cidrs(env)  # 고객 VPC 대역도 사내로 본다(모든 모듈이 같은 기준)
    enrich(events, env)
    n_known = mark_known(events, env)  # 설정의 정상 작업 목록과 맞는 이벤트 표시(지우지 않음)
    findings = run_detections(events, env)
    team_info = _team(events, env)
    incidents = build_incidents(events, findings, window_min=window_min)
    groups = group_repeats(incidents)  # 반복 사건은 대표 하나로 접어서 상위 N개를 고른다
    t_detect = time.time() - t0
    # 재검토: 공격으로 보이는 사건을 위로 올린다. 규칙 판정은 항상 만들고(키 없이도, 비교용),
    # Claude 키가 있으면 Claude 판정(점수순 상위 30개)을 쓴다. 실패하면 규칙 판정으로 계속
    rule_tri = rule_triage(groups, events)
    ai_tri = triage(groups, model=model, use_ai=use_ai and not preview, events=events)
    tri = ai_tri if ai_tri and "incidents" in ai_tri else rule_tri
    if tri is ai_tri:
        tri["guard"] = hold(groups, tri, rule_tri)  # AI가 규칙의 공격 판정을 낮춘 것을 표시·되돌림
    groups = reorder(groups, tri)
    rule_v = {x["id"]: x for x in rule_tri["incidents"]}
    results, audit_errors = [], []
    for inc in groups[:top]:
        try:
            checks = audit(inc, env)
        except Exception as exc:  # noqa: BLE001 — 설정 파일 하나가 이상해도 분석은 끝까지 간다
            checks = []
            audit_errors.append(f"{inc['id']}: {type(exc).__name__}: {exc}"[:200])
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
                           | {k: i[k] for k in ("contested", "ai_said", "injection") if i.get(k)}
                           for i in groups[:50]],
        "triage": tri,
        "rule_triage": rule_tri,
        "n_known": n_known,
        "explain_mode": _explain_mode(results, tri, ai_tri),
        "results": results,
        "timing": {"detect_correlate_s": round(t_detect, 2),
                   "total_s": round(time.time() - t0, 2)},
        "has_environment": bool(env) and not env.get("_error"),
        "team": team_info,
        "excluded_activity": excluded_summary(events),
        "assumptions": _assumptions(by_source, env, file_stats or [],
                                    sum(1 for e in events if e.extra.get("behind_proxy")))
        + _ambiguous_note(events)
        + [f"설정 점검 중 오류가 나 그 사건의 수정안을 만들지 못했습니다: {m}" for m in audit_errors[:3]],
    }


def _ambiguous_note(events: list[Event]) -> list[str]:
    n = sum(1 for e in events if e.extra.get("target_ambiguous"))
    if not n:
        return []
    return [f"네트워크 기록 {n:,}건은 같은 IP를 쓰는 서버가 여러 VPC에 있어 대상 서버를 정하지 못했습니다. "
            "python -m logsight collect environment로 네트워크 인터페이스(ENI)까지 수집하면 정확히 찾습니다."]


def excluded_summary(events: list[Event]) -> list[dict]:
    """판정에서 뺀 활동(정상 작업 목록·우리 팀·trusted_ips)을 이름별로 센다(사양서 FR-32).
    뺀 이벤트는 지우지 않으므로 사건 묶기와 흐름 그림에는 그대로 남는다."""
    by: dict[str, dict] = {}
    for e in events:
        lab = e.extra.get("known")
        if not lab:
            continue
        d = by.setdefault(str(lab), {"label": str(lab), "n": 0, "who": set()})
        d["n"] += 1
        w = (e.actor or e.src_ip or "").split("/")[-1]
        if w and len(d["who"]) < 6:
            d["who"].add(w)
    return [{"label": d["label"], "n": d["n"], "who": sorted(d["who"])}
            for d in sorted(by.values(), key=lambda d: -d["n"])]


def _team(events: list[Event], env: dict) -> dict:
    """우리 팀 후보(아직 확인 안 된 것만)와 확인된 목록. 후보는 판정에 쓰지 않는다(확인 전에는 제안만)."""
    from .team import LABEL, excluded, propose
    confirmed = sorted({a for ent in env.get("known_activity", []) if ent.get("label") == LABEL
                        for a in ent.get("actors", [])})
    known_actors = {e.actor for e in events if e.extra.get("known")}
    props = [p for p in propose(events, env) if p["actor"] not in known_actors]
    return {"proposed": props, "confirmed": confirmed, "excluded": excluded(events)}


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
    csvs = [s["file"] for s in file_stats if s.get("kind") == "cloudtrail_csv"]
    if csvs:
        out.append("콘솔에서 내려받은 CloudTrail 이벤트 기록(CSV)을 읽었습니다. 이 형식에는 역할 세션 ARN·요청 파라미터가 "
                   "빠져 있어 '서버 역할 키가 밖에서 쓰임' 같은 규칙은 걸리지 않습니다. 리전마다 따로 내려받아야 하고 "
                   "IAM·STS 같은 전역 이벤트는 us-east-1에 있습니다. 가능하면 트레일의 JSON 로그를 쓰세요.")
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
    if env.get("_error"):
        out.append(f"설정 스냅샷을 쓰지 못해 방화벽 수정안을 만들지 않았습니다: {env['_error']}. "
                   "python -m logsight collect environment로 다시 만들 수 있습니다.")
    elif not env:
        out.append("설정 스냅샷(environment.json)이 없어 방화벽 수정안을 만들지 않았습니다. "
                   "python -m logsight collect environment로 만들 수 있습니다.")
    elif not env.get("trusted_ips"):
        out.append("관리자 IP(trusted_ips)가 비어 있어 수정안의 허용 IP가 자리표시로 나옵니다.")
    if env and not env.get("_error") and len(env.get("network_acls", [])) > 1 and not env.get("subnets"):
        out.append("설정 스냅샷에 서브넷·VPC 정보가 없어 서버가 퍼블릭·프라이빗 서브넷 중 어디 있는지 구분하지 못했고, "
                   "VPC끼리 같은 사설 대역을 쓰면 대상 서버를 고르지 못할 수 있습니다. "
                   "python -m logsight collect environment로 다시 만들면 서브넷·라우팅·네트워크 인터페이스까지 담깁니다.")
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
    """설정 스냅샷으로 네트워크·웹 로그의 대상(그리고 출발지)을 서버로 바꿔 적는다.
    - target_instance: 이 이벤트가 향한 우리 서버(EC2 인스턴스 ID, EC2가 아니면 ENI ID: RDS·ALB·Lambda 등)
    - src_instance: 출발지가 우리 서버(침해된 서버에서 다른 서브넷으로 넘어가는 내부 확산을 엮는 데 쓴다)
    - target_ambiguous: 같은 IP를 쓰는 서버가 여러 VPC에 있어 고르지 못함(VPC마다 10.0.0.0/16을 쓰는 조직)

    VPC Flow 로그의 interface-id(ENI)를 먼저 본다. ENI는 VPC가 하나라 IP가 겹쳐도 서버를 정확히 고를 수 있다.
    대상 서버는 사건 묶기 연결고리로 쓰지 않는다(여러 스캐너가 같은 서버를 두드리면 한 사건으로 뭉치므로).
    보고서·수정안에서 "어느 서버가 대상이었나"를 보여 주는 용도."""
    by_ip: dict[str, list[tuple[str, str | None]]] = {}
    host2inst: dict[str, str] = {}
    enis: dict[str, dict] = {}

    def add(ip, rid, vpc):
        if ip and (rid, vpc) not in by_ip.setdefault(ip, []):
            by_ip[ip].append((rid, vpc))

    for inst in env.get("instances", []):
        for k in ("private_ip", "public_ip"):
            add(inst.get(k), inst["instance_id"], inst.get("vpc_id"))
        for k in ("name", "private_dns"):  # 서버 로그의 호스트 이름(web1, ip-10-0-1-10.ec2.internal)
            if inst.get(k):
                host2inst[inst[k].split(".")[0].lower()] = inst["instance_id"]
    for n in env.get("network_interfaces", []):
        rid = n.get("instance_id") or n.get("eni_id")
        if not rid:
            continue
        enis[n.get("eni_id")] = n
        for ip in list(n.get("private_ips") or []) + [n.get("public_ip")]:
            add(ip, rid, n.get("vpc_id"))
    if not by_ip and not host2inst:
        return

    memo: dict[tuple, tuple] = {}

    def resolve(ip, vpc):
        """IP → (서버, 고르지 못한 후보 목록)"""
        k = (ip, vpc)
        if k not in memo:
            memo[k] = _resolve(ip, vpc)
        return memo[k]

    def _resolve(ip, vpc):
        cands = by_ip.get(ip) or []
        if vpc:
            same = [c for c in cands if c[1] in (vpc, None)]
            cands = same or cands
        ids = sorted({c[0] for c in cands})
        if len(ids) == 1:
            return ids[0], None
        return None, (ids or None)

    for e in events:
        eni = enis.get(e.extra.get("interface")) if e.extra.get("interface") else None
        vpc = eni.get("vpc_id") if eni else None
        if eni and e.src_ip in (eni.get("private_ips") or []):
            src = eni.get("instance_id") or eni.get("eni_id")
        else:
            src = resolve(e.src_ip, vpc)[0] if e.src_ip else None
        if src:
            e.extra["src_instance"] = src
        if e.instance_id:
            continue
        if eni and e.dst_ip in (eni.get("private_ips") or []):
            inst, amb = eni.get("instance_id") or eni.get("eni_id"), None
        else:
            inst, amb = resolve(e.dst_ip, vpc) if e.dst_ip else (None, None)
        inst = inst or host2inst.get(str(e.extra.get("host", "")).split(".")[0].lower())
        if inst:
            e.extra["target_instance"] = inst
        elif amb and len(amb) > 1:
            e.extra["target_ambiguous"] = amb[:5]
    _infer_web_targets(events)


# 서버 한 대의 로그인 웹서버 로그만. ALB·WAF 로그는 여러 서버 앞에 있어 서버 하나로 정하지 않는다
WEB_LOGS = ("weblog", "access")
WEB_PORTS = (80, 443, 8080, 8443)


def _infer_web_targets(events: list[Event]) -> None:
    """웹 로그(nginx·Apache)에는 어느 서버의 로그인지 적혀 있지 않다. 같은 출발지 IP의 VPC Flow 기록이
    우리 서버 한 대의 웹 포트로만 갔으면 그 서버를 대상으로 적는다(target_inferred). 여러 대면 정하지 않는다."""
    web_to: dict[str, set] = defaultdict(set)
    for e in events:
        t = e.extra.get("target_instance")
        if t and e.source in ("vpcflow", "hostfw") and e.dst_port in WEB_PORTS and e.src_ip:
            web_to[e.src_ip].add(t)
    if not web_to:
        return
    for e in events:
        if e.source in WEB_LOGS and not e.instance_id and not e.extra.get("target_instance"):
            t = web_to.get(e.src_ip)
            if t and len(t) == 1:
                e.extra["target_instance"] = next(iter(t))
                e.extra["target_inferred"] = "같은 IP의 VPC Flow 기록"


def run_paths(paths: list[str], env_path: str | None = None, *, since=None, until=None,
              team_path: str | None = None, **kw) -> dict:
    events, stats = load_paths([Path(p) for p in paths], since=since, until=until)
    if env_path is None:
        # 폴더 안에 environment.json이 있으면 자동으로 쓴다
        for p in paths:
            cand = Path(p) / "environment.json"
            if cand.is_file():
                env_path = str(cand)
                break
    return run(events, with_team(load_env(env_path), team_path), file_stats=stats, **kw)


def with_team(env: dict, team_path: str | None) -> dict:
    """확인된 팀 목록(logsight team --confirm으로 만든 파일)을 설정에 더한다."""
    if not team_path:
        return env
    from .team import load, merge
    return merge(env, load(team_path))

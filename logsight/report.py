"""분석 결과(dict)를 한 파일짜리 HTML 보고서로 만든다(외부 리소스 없음, 오프라인 시연 가능)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from html import escape

from .analyze import STAGE_KO
from .detect import RULES

SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
PRI_KO = {"now": "즉시", "soon": "이번 주", "later": "여유 있을 때"}
SRC_KO = {"cloudtrail": "CloudTrail", "vpcflow": "VPC Flow", "waf": "WAF", "alb": "ALB",
          "sshauth": "SSH 로그", "hostfw": "서버 방화벽", "weblog": "웹서버 로그", "guardduty": "GuardDuty"}

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;--accent:#2457c5;
--high:#c0362c;--medium:#b7791f;--low:#3b7d4f;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#ececec;--muted:#a0a0a6;
--line:#333338;--accent:#7aa2ff;--high:#ff6b5e;--medium:#e3a94a;--low:#6cc287;--code:#26262a}}
a{color:var(--accent)}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px}h3{font-size:16px;margin:0 0 6px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat b{display:block;font-size:22px}.sev{display:inline-block;padding:1px 8px;border-radius:99px;
font-size:12px;font-weight:600;color:#fff}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}
.sev.low{background:var(--low)}.chip{display:inline-block;border:1px solid var(--line);border-radius:99px;
padding:0 8px;font-size:12px;margin:2px 4px 2px 0}ol.flow{list-style:none;padding:0;margin:0;
border-left:2px solid var(--line)}ol.flow li{position:relative;padding:4px 0 12px 18px}
ol.flow li:before{content:"";position:absolute;left:-7px;top:10px;width:12px;height:12px;border-radius:50%;
background:var(--accent)}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--code);padding:10px;border-radius:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
a.ref{color:var(--accent);text-decoration:none;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{border-bottom:1px solid var(--line);
padding:6px;text-align:left;vertical-align:top}tr:target{background:rgba(122,162,255,.18)}
.tablewrap{overflow-x:auto}.warn{color:var(--high)}.ok{color:var(--low)}details summary{cursor:pointer}
.refs{margin-top:4px;line-height:1.9}.refs a.ref{display:inline-block}details.more{display:inline}
details.more[open]{display:block}details.more summary{display:inline;color:var(--muted);font-size:12.5px}
.meta{font-size:14px}.meta>div{display:flex;gap:10px}.meta .muted{flex:0 0 84px}
.card,ol.flow li{overflow-wrap:anywhere}.why{margin:6px 0 2px}.note{border-left:4px solid var(--medium)}.note ul{margin:6px 0 0}
ol.todo{margin:0;padding-left:20px}ol.todo li{margin:4px 0}.pri{display:inline-block;font-size:12px;
font-weight:600;padding:0 7px;border-radius:4px;border:1px solid currentColor}.pri.now{color:var(--high)}
.pri.soon{color:var(--medium)}.pri.later{color:var(--muted)}details.evidence{margin:14px 0}
details.evidence>summary{font-size:16px;padding:4px 0}table.ev{table-layout:fixed;min-width:760px}
table.ev th:nth-child(1){width:14%}table.ev th:nth-child(2){width:19%}table.ev th:nth-child(3){width:9%}
table.ev th:nth-child(4){width:21%}table.ev th:nth-child(5){width:8%}table.ev th:nth-child(6){width:16%}
td.act,td code{word-break:break-all;overflow-wrap:anywhere}td.nw{white-space:nowrap}
"""


REF_SHOW = 6
STATUS_KO = {"blocked": "차단", "allowed": "허용", "detected": "탐지"}
RESULT_KO = {"success": "성공", "failure": "실패"}
KST = timezone(timedelta(hours=9))


def _refs(refs: list[str], inc_id: str) -> str:
    """근거 링크. 많으면 앞의 몇 개만 보이고 나머지는 접는다."""
    def a(r):
        return f'<a class="ref" href="#{escape(inc_id)}-{escape(r)}">{escape(r)}</a>'
    if not refs:
        return ""
    head = "".join(a(r) for r in refs[:REF_SHOW])
    if len(refs) > REF_SHOW:
        head += (f"<details class=more><summary>외 {len(refs) - REF_SHOW}건</summary>"
                 + "".join(a(r) for r in refs[REF_SHOW:]) + "</details>")
    return f"<div class=refs><span class=muted>근거</span> {head}</div>"


def _sev(s: str) -> str:
    return f'<span class="sev {escape(s)}">{SEV_KO.get(s, s)}</span>'


def _dt(iso: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _when(start: str, end: str | None = None) -> str:
    """'2026-10-30 01:20~01:52 UTC (한국 10:20~10:52)' 형태."""
    a, b = _dt(start), _dt(end) if end else None
    if not a:
        return escape(str(start)[:19])
    def rng(tz, fmt_a):
        x = a.astimezone(tz)
        txt = x.strftime(fmt_a)
        if b:
            y = b.astimezone(tz)
            txt += "~" + y.strftime("%H:%M" if y.date() == x.date() else "%m-%d %H:%M")
        return txt
    return f"{rng(timezone.utc, '%Y-%m-%d %H:%M')} UTC (한국 {rng(KST, '%m-%d %H:%M')})"


def _result_ko(e: dict) -> str:
    """로그마다 다른 결과 표기(ACCEPT/REJECT, ALLOW/BLOCK/COUNT, Success/Failure, 404)를 한국어로 맞춘다."""
    ko = STATUS_KO.get(e.get("disposition")) or RESULT_KO.get(e.get("status")) or ""
    raw = str(e.get("outcome") or "")
    if e.get("http_status"):
        raw = str(e["http_status"])  # 웹 로그는 HTTP 상태 코드가 가장 알아보기 쉽다
    cls = {"차단": "ok", "실패": "muted", "성공": "warn", "허용": "warn"}.get(ko, "")
    plain = {"success", "failure", "detected", "accept", "reject", "allow", "block"}
    show_raw = raw and raw.lower() not in plain  # COUNT, 404처럼 뜻을 더해 줄 때만 원래 값을 덧붙인다
    return (f"<span class='{cls}'>{ko or escape(raw) or '-'}</span>"
            + (f"<br><span class=muted>{escape(raw)}</span>" if ko and show_raw else ""))


def _rule_ko(rule: str) -> str:
    name = RULES.get(rule, ("", "", rule))[2]
    return f"<span title='{escape(rule)}'>{escape(name)}</span>"


def _todo(results: list[dict]) -> list[tuple[dict, str]]:
    """사건 전체에서 우선순위가 높은 수정안을 모아 '먼저 할 일'로 보여 준다."""
    order = {"now": 0, "soon": 1, "later": 2}
    seen, out = set(), []
    for r in results:
        for fc in r["report"].get("firewall_changes", []):
            k = (fc["check_id"], fc["resource"])
            if k not in seen:
                seen.add(k)
                out.append((fc, r["incident"]["id"]))
    out.sort(key=lambda x: order.get(x[0]["priority"], 3))
    return out


def render(result: dict, title: str = "LogSight 분석 보고서") -> str:
    h = [f"<!doctype html><html lang=ko><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}</style><main>"]
    h.append(f"<h1>{escape(title)}</h1><div class=muted>생성 {escape(result['generated_at'])} · "
             f"원본 로그 {len(result['files'])}개 파일</div>")

    sc = result.get("severity_counts") or {}
    n_groups = result.get("n_groups", result["n_incidents"])
    h.append("<div class='grid' style='margin-top:14px'>")
    for label, val, cls in (("검토할 사건", f"{n_groups:,}건", ""),
                            ("심각도 높음", f"{sc.get('high', 0):,}건", "warn" if sc.get("high") else ""),
                            ("중간 · 낮음", f"{sc.get('medium', 0):,} · {sc.get('low', 0):,}", ""),
                            ("읽은 이벤트", f"{result['n_events']:,}", "")):
        h.append(f"<div class='card stat'><span class=muted>{label}</span><b class='{cls}'>{val}</b></div>")
    h.append("</div>")
    srcs = ", ".join(f"{SRC_KO.get(k, k)} {v:,}" for k, v in sorted(result["events_by_source"].items()))
    rep_note = (f", 같은 유형 반복을 묶어 {n_groups:,}건" if n_groups != result["n_incidents"] else "")
    h.append(f"<div class=muted>로그 종류별 {escape(srcs) or '없음'}. 이벤트 {result['n_events']:,}건 중 "
             f"{result['n_flagged']:,}건이 규칙에 걸렸고, 탐지 {result['n_findings']:,}건을 "
             f"사건 {result['n_incidents']:,}건으로 엮었습니다{rep_note}. 처리 {result['timing']['total_s']}초.</div>")

    todo = _todo(result["results"])
    if todo:
        h.append("<h2>먼저 할 일</h2><div class=card><ol class=todo>")
        for fc, iid in todo[:5]:
            h.append(f"<li><span class='pri {escape(fc['priority'])}'>{PRI_KO.get(fc['priority'], fc['priority'])}"
                     f"</span> {escape(fc['change'])} <span class=muted>({escape(fc['resource'])}, "
                     f"<a href='#{escape(iid)}'>{escape(iid)}</a>)</span></li>")
        h.append("</ol><div class=muted>수정안은 자동 적용되지 않습니다. 사건별 설명에서 적용 명령과 "
                 "되돌리기 명령을 확인한 뒤 직접 적용하세요.</div></div>")
    if result.get("assumptions"):
        h.append("<div class='card note'><b>이렇게 해석했습니다</b><ul>" +
                 "".join(f"<li>{escape(a)}</li>" for a in result["assumptions"]) + "</ul></div>")
    if not result["results"]:
        h.append("<div class=card>탐지된 사건이 없습니다.</div>")

    for r in result["results"]:
        inc, rep, meta = r["incident"], r["report"], r["meta"]
        iid = inc["id"]
        repeat = (f" <span class=chip>같은 유형 {inc['repeats']}회 반복</span>"
                  if inc.get("repeats", 1) > 1 else "")
        h.append(f"<h2 id='{escape(iid)}'>{escape(iid)} {_sev(rep.get('severity', inc['severity']))}{repeat}</h2>")
        h.append("<div class=card>")
        h.append(f"<p style='margin-top:0'>{escape(rep.get('summary', ''))}</p>")
        logs = ", ".join(SRC_KO.get(s, s) for s in sorted({e["source"] for e in inc["events"]}))
        h.append("<div class=meta>"
                 f"<div><span class=muted>단계</span> " + " → ".join(
                     escape(STAGE_KO.get(s, s)) for s in inc["stages"]) + "</div>"
                 f"<div><span class=muted>기간</span> {_when(inc['start'], inc['end'])}</div>"
                 f"<div><span class=muted>출발지</span> {escape(', '.join(inc['src_ips'][:5]) or '-')}"
                 + (f" 외 {len(inc['src_ips']) - 5}개" if len(inc["src_ips"]) > 5 else "") + "</div>"
                 + (f"<div><span class=muted>관련 서버</span> {escape(', '.join(inc['instances'][:5]))}</div>"
                    if inc.get("instances") else "")
                 + f"<div><span class=muted>함께 본 로그</span> {escape(logs)}</div></div>")
        mode = "Claude " + escape(meta.get("model") or "") if meta["mode"] == "claude" else "규칙 기반(AI 키 없음)"
        v = meta["validation"]
        vtxt = ("<span class=ok>근거 검증 통과</span>" if v["passed"] else
                f"<span class=warn>근거 검증: 잘못된 근거 {v['evidence_invalid']}건, "
                f"근거 없는 단계 {v['steps_without_evidence']}건</span>")
        h.append(f"<div class=muted style='margin-top:6px'>분석: {mode} · 확신도 "
                 f"{SEV_KO.get(rep.get('confidence'), '-')} · {vtxt}</div>")
        if meta.get("ai_error"):
            h.append(f"<div class=warn>AI 호출 실패로 규칙 기반 결과를 표시: {escape(meta['ai_error'])}</div>")
        h.append("</div>")

        h.append("<h3>공격 흐름</h3><div class=card><ol class=flow>")
        for st in rep.get("attack_flow", []):
            tech = st.get("technique", "")
            h.append(f"<li><b>{escape(STAGE_KO.get(st['stage'], st['stage']))}</b> "
                     + (f"<span class=chip>{escape(tech)}</span>" if tech else "")
                     + (f"<span class=muted>{_when(st['time'])}</span>" if st.get("time") else "")
                     + f"<br>{escape(st['what'])}{_refs(st.get('evidence', []), iid)}"
                     + (f"<div class=warn>확인 안 된 근거: {escape(', '.join(st['unverified_evidence']))}</div>"
                        if st.get("unverified_evidence") else "") + "</li>")
        h.append("</ol></div>")

        if rep.get("root_causes") or r["checks"] or rep.get("firewall_changes"):
            h.append("<h3>원인과 수정안 <span class=muted style='font-weight:400'>"
                     "(자동 적용하지 않음, 검토 후 직접 적용)</span></h3>")
        causes = {rc["setting"]: rc for rc in rep.get("root_causes", [])}
        by_id = {c["id"] + c["resource"]: c for c in r["checks"]}
        for fc in rep.get("firewall_changes", []):
            c = by_id.get(fc["check_id"] + fc["resource"]) or next(
                (x for x in r["checks"] if x["id"] == fc["check_id"]), None)
            rc = causes.pop(fc["change"], None) or (causes.pop(c["title"], None) if c else None)
            h.append(f"<div class=card><span class='pri {escape(fc['priority'])}'>"
                     f"{PRI_KO.get(fc['priority'], fc['priority'])}</span> <b>{escape(fc['change'])}</b>"
                     f"<div class=muted>{escape(fc['target'])} · {escape(fc['resource'])}</div>")
            if rc:  # 원인 설명을 같은 카드에 붙여 '왜 → 무엇을 바꾸나'를 한곳에서 본다
                h.append(f"<div class=why>{escape(rc['why'])}</div>{_refs(rc.get('evidence', []), iid)}")
            if c:
                h.append("<details><summary>현재 설정과 제안, 적용·되돌리기 명령 보기</summary>"
                         f"<pre>현재: {escape(json.dumps(c['current'], ensure_ascii=False, indent=1))}\n"
                         f"제안: {escape(json.dumps(c['proposed'], ensure_ascii=False, indent=1))}</pre>"
                         f"<div class=muted>적용</div><pre>{escape(chr(10).join(c['cli']))}</pre>"
                         + (f"<div class=muted>되돌리기</div><pre>{escape(chr(10).join(c['rollback']))}</pre>"
                            if c.get("rollback") else "") +
                         f"<div class=muted>주의: {escape(c['caution'])}</div></details>")
            h.append("</div>")
        if causes:  # 수정안과 짝이 없는 원인(AI가 따로 찾은 것 등)
            h.append("<div class=card><b>그 밖에 원인으로 보이는 것</b><ul>")
            for rc in causes.values():
                h.append(f"<li><b>{escape(rc['setting'])}</b>: {escape(rc['why'])}"
                         f"{_refs(rc.get('evidence', []), iid)}</li>")
            h.append("</ul></div>")
        if rep.get("unknowns"):
            h.append("<h3>로그만으로 확인할 수 없는 것</h3><div class=card><ul>" +
                     "".join(f"<li>{escape(u)}</li>" for u in rep["unknowns"]) + "</ul></div>")

        h.append(f"<details class=evidence><summary><b>근거 이벤트 {len(inc['events'])}건</b>"
                 + (f" <span class=muted>(비슷한 {inc['omitted_events']}건 생략)</span>" if inc["omitted_events"] else "")
                 + "</summary><div class='card tablewrap'><table class=ev><tr><th>근거</th><th>시각(UTC)</th>"
                 "<th>로그</th><th>행위</th><th>결과</th><th>출발지 → 대상</th><th>탐지 규칙</th></tr>")
        for e in inc["events"]:
            dst = e.get("target_instance") or e.get("instance_id") or e.get("dst_ip") or ""
            if e.get("dst_port"):
                dst = f"{dst}:{e['dst_port']}" if dst else f"포트 {e['dst_port']}"
            h.append(f"<tr id='{escape(iid)}-{escape(e['ref'])}'><td><code>{escape(e['ref'])}</code></td>"
                     f"<td class=nw>{escape(e['ts'][:19].replace('T', ' '))}</td>"
                     f"<td>{escape(SRC_KO.get(e['source'], e['source']))}</td>"
                     f"<td class=act>{escape(str(e.get('action') or ''))}"
                     + (f"<br><span class=muted>{escape(str(e['errorCode']))}</span>" if e.get("errorCode") else "")
                     + f"</td><td>{_result_ko(e)}</td>"
                     f"<td class=act>{escape(str(e.get('src_ip') or e.get('actor') or ''))}"
                     + (f" → {escape(str(dst))}" if dst else "") + "</td>"
                     "<td>" + "<br>".join(_rule_ko(x) for x in e.get("rules", [])) + "</td></tr>")
        h.append("</table></div></details>")

    if len(result["incident_index"]) > len(result["results"]):
        rest = result["incident_index"][len(result["results"]):]
        h.append(f"<h2>나머지 사건 {len(rest):,}건</h2><div class='card tablewrap'><table>"
                 "<tr><th>ID</th><th>심각도</th><th>시작(UTC)</th><th>단계</th><th>출발지</th><th>이벤트</th>"
                 "<th>반복</th></tr>")
        for i in rest:
            rp = i.get("repeats", 1)
            rep_txt = f"{rp}회 ({escape(str(i.get('first_seen', ''))[:10])}부터)" if rp > 1 else ""
            h.append(f"<tr><td>{escape(i['id'])}</td><td>{_sev(i['severity'])}</td>"
                     f"<td class=nw>{escape(i['start'][:16].replace('T', ' '))}</td>"
                     f"<td>{escape(' → '.join(STAGE_KO.get(s, s) for s in i['stages']))}</td>"
                     f"<td class=act>{escape(', '.join(i['src_ips'][:3]))}</td><td>{i['n_events']}</td>"
                     f"<td>{rep_txt}</td></tr>")
        h.append("</table></div>")
    h.append("<p class=muted>LogSight · 판단마다 근거 로그 위치(파일:줄)를 붙였습니다. "
             "수정안은 자동 적용되지 않습니다.</p></main></html>")
    return "".join(h)

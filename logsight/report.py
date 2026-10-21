"""분석 결과(dict)를 한 파일짜리 HTML 보고서로 만든다(외부 리소스 없음, 오프라인 시연 가능)."""
from __future__ import annotations

import json
from html import escape

from .analyze import STAGE_KO

SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
PRI_KO = {"now": "즉시", "soon": "이번 주", "later": "여유 있을 때"}

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;--accent:#2457c5;
--high:#c0362c;--medium:#b7791f;--low:#3b7d4f;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#ececec;--muted:#a0a0a6;
--line:#333338;--accent:#7aa2ff;--high:#ff6b5e;--medium:#e3a94a;--low:#6cc287;--code:#26262a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
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
"""


def _refs(refs: list[str], inc_id: str) -> str:
    return "".join(f'<a class="ref" href="#{escape(inc_id)}-{escape(r)}">{escape(r)}</a>' for r in refs)


def _sev(s: str) -> str:
    return f'<span class="sev {escape(s)}">{SEV_KO.get(s, s)}</span>'


def render(result: dict, title: str = "LogSight 분석 보고서") -> str:
    h = [f"<!doctype html><html lang=ko><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}</style><main>"]
    h.append(f"<h1>{escape(title)}</h1><div class=muted>생성 {escape(result['generated_at'])} · "
             f"원본 로그 {len(result['files'])}개 파일</div>")
    srcs = ", ".join(f"{k} {v:,}" for k, v in sorted(result["events_by_source"].items()))
    h.append("<div class='grid' style='margin-top:14px'>")
    for label, val in (("읽은 이벤트", f"{result['n_events']:,}"),
                       ("의심 표시 이벤트", f"{result['n_flagged']:,}"),
                       ("탐지 결과", f"{result['n_findings']:,}"),
                       ("사건", f"{result['n_incidents']:,}"),
                       ("처리 시간", f"{result['timing']['total_s']}초")):
        h.append(f"<div class='card stat'><span class=muted>{label}</span><b>{val}</b></div>")
    h.append(f"</div><div class=muted>로그 종류별: {escape(srcs) or '없음'}</div>")
    if not result["results"]:
        h.append("<div class=card>탐지된 사건이 없습니다.</div>")

    for r in result["results"]:
        inc, rep, meta = r["incident"], r["report"], r["meta"]
        iid = inc["id"]
        h.append(f"<h2 id='{escape(iid)}'>{escape(iid)} {_sev(rep.get('severity', inc['severity']))}</h2>")
        h.append("<div class=card>")
        h.append(f"<p style='margin-top:0'>{escape(rep.get('summary', ''))}</p>")
        h.append("<div class=muted>" + " ".join(
            f"<span class=chip>{escape(STAGE_KO.get(s, s))}</span>" for s in inc["stages"]) +
            f" · 기간 {escape(inc['start'][:19])} ~ {escape(inc['end'][11:19])} UTC"
            f" · 출발지 {escape(', '.join(inc['src_ips'][:5]) or '-')}</div>")
        mode = "Claude " + escape(meta.get("model") or "") if meta["mode"] == "claude" else "규칙 기반(키 없음)"
        v = meta["validation"]
        vtxt = ("<span class=ok>근거 검증 통과</span>" if v["passed"] else
                f"<span class=warn>근거 검증: 잘못된 근거 {v['evidence_invalid']}건, "
                f"근거 없는 단계 {v['steps_without_evidence']}건</span>")
        compress = ""
        if inc["n_events"] + inc["context"]["n_events"]:
            compress = (f" · AI 입력 {meta['payload_chars']:,}자"
                        f"(상세 이벤트 {len(inc['events'])}건 + 맥락 {inc['context']['n_events']:,}건 집계)")
        h.append(f"<div class=muted>분석: {mode} · 확신도 {SEV_KO.get(rep.get('confidence'), '-')}"
                 f" · {vtxt}{compress}</div>")
        if meta.get("ai_error"):
            h.append(f"<div class=warn>AI 호출 실패로 규칙 기반 결과를 표시: {escape(meta['ai_error'])}</div>")
        h.append("</div>")

        h.append("<h3>공격 흐름</h3><div class=card><ol class=flow>")
        for st in rep.get("attack_flow", []):
            h.append(f"<li><b>{escape(STAGE_KO.get(st['stage'], st['stage']))}</b> "
                     f"<span class=chip>{escape(st.get('technique', ''))}</span>"
                     f"<span class=muted>{escape(str(st.get('time', ''))[:19])}</span><br>"
                     f"{escape(st['what'])}<br>{_refs(st.get('evidence', []), iid)}"
                     + (f"<div class=warn>확인 안 된 근거: {escape(', '.join(st['unverified_evidence']))}</div>"
                        if st.get("unverified_evidence") else "") + "</li>")
        h.append("</ol></div>")

        if rep.get("root_causes"):
            h.append("<h3>원인으로 보이는 설정</h3>")
            for rc in rep["root_causes"]:
                h.append(f"<div class=card><b>{escape(rc['setting'])}</b><br>{escape(rc['why'])}"
                         f"<br>{_refs(rc.get('evidence', []), iid)}</div>")

        if r["checks"] or rep.get("firewall_changes"):
            h.append("<h3>방화벽·권한 수정안 <span class=muted style='font-weight:400'>"
                     "(자동 적용하지 않음 — 검토 후 직접 적용)</span></h3>")
            by_id = {c["id"] + c["resource"]: c for c in r["checks"]}
            for fc in rep.get("firewall_changes", []):
                c = by_id.get(fc["check_id"] + fc["resource"]) or next(
                    (x for x in r["checks"] if x["id"] == fc["check_id"]), None)
                h.append(f"<div class=card><b>[{PRI_KO.get(fc['priority'], fc['priority'])}] "
                         f"{escape(fc['change'])}</b><div class=muted>{escape(fc['target'])} · "
                         f"{escape(fc['resource'])}</div>")
                if c:
                    h.append("<details><summary>현재 → 제안, 적용 명령</summary>"
                             f"<pre>현재: {escape(json.dumps(c['current'], ensure_ascii=False, indent=1))}\n"
                             f"제안: {escape(json.dumps(c['proposed'], ensure_ascii=False, indent=1))}</pre>"
                             f"<pre>{escape(chr(10).join(c['cli']))}</pre>"
                             f"<div class=muted>주의: {escape(c['caution'])}</div></details>")
                h.append("</div>")
        if rep.get("unknowns"):
            h.append("<h3>로그만으로 확인할 수 없는 것</h3><div class=card><ul>" +
                     "".join(f"<li>{escape(u)}</li>" for u in rep["unknowns"]) + "</ul></div>")

        h.append(f"<h3>근거 이벤트 ({len(inc['events'])}건"
                 + (f", {inc['omitted_events']}건 생략" if inc["omitted_events"] else "")
                 + ")</h3><div class='card tablewrap'><table><tr><th>근거</th><th>시각(UTC)</th>"
                 "<th>로그</th><th>행위</th><th>결과</th><th>출발지</th><th>탐지 규칙</th></tr>")
        for e in inc["events"]:
            h.append(f"<tr id='{escape(iid)}-{escape(e['ref'])}'><td><code>{escape(e['ref'])}</code></td>"
                     f"<td>{escape(e['ts'][:19])}</td><td>{escape(e['source'])}</td>"
                     f"<td>{escape(str(e.get('action') or ''))}"
                     + (f"<br><span class=muted>{escape(str(e['errorCode']))}</span>" if e.get("errorCode") else "")
                     + f"</td><td>{escape(str(e.get('outcome') or ''))}</td>"
                     f"<td>{escape(str(e.get('src_ip') or ''))}</td>"
                     f"<td>{escape(', '.join(e.get('rules', [])))}</td></tr>")
        h.append("</table></div>")

    if result["n_incidents"] > len(result["results"]):
        h.append(f"<h2>나머지 사건 목록</h2><div class='card tablewrap'><table>"
                 "<tr><th>ID</th><th>심각도</th><th>시작</th><th>단계</th><th>출발지</th><th>이벤트</th></tr>")
        for i in result["incident_index"][len(result["results"]):]:
            h.append(f"<tr><td>{escape(i['id'])}</td><td>{_sev(i['severity'])}</td>"
                     f"<td>{escape(i['start'][:19])}</td>"
                     f"<td>{escape(' → '.join(STAGE_KO.get(s, s) for s in i['stages']))}</td>"
                     f"<td>{escape(', '.join(i['src_ips'][:3]))}</td><td>{i['n_events']}</td></tr>")
        h.append("</table></div>")
    h.append("<p class=muted>LogSight · 판단마다 근거 로그 위치(파일:줄)를 붙였습니다. "
             "수정안은 자동 적용되지 않습니다.</p></main></html>")
    return "".join(h)

"""assess() 결과(dict)를 한 파일짜리 HTML 보고서로 만든다(외부 리소스 없음, 오프라인 가능)."""
from __future__ import annotations

from html import escape

from ..analyze import STAGE_KO
from ..report import CSS as REPORT_CSS, SEV_KO
from .webanalyze import VERDICT_KO

VERDICT_CLASS = {"breached": "high", "likely_breached": "high",
                 "suspicious": "medium", "no_evidence": "low"}
PRI_KO = {"now": "지금 바로", "soon": "이번 주", "later": "여유 있을 때"}
TARGET_KO = {"file": "파일", "app": "앱 코드", "server": "서버 설정", "waf": "WAF",
             "account": "계정", "network": "네트워크", "patch": "패치", "other": "기타"}

# 보고서 모양은 AWS 보고서(report.py)와 같은 사고 보고서형을 쓴다.
CSS = REPORT_CSS + """
.shell.one{grid-template-columns:1fr!important;max-width:1000px}
.verdictbox{border:1.5px solid var(--rule);padding:12px 16px;margin:16px 0 6px}
.verdictbox b{display:block;font-family:var(--serif);font-size:22px;font-weight:900}
.verdictbox.high{border-color:var(--high)}.verdictbox.high b{color:var(--high)}
.verdictbox.medium{border-color:var(--medium)}.verdictbox.medium b{color:var(--medium)}
.prio{font-weight:700;white-space:nowrap}.prio.now{color:var(--high)}.prio.soon{color:var(--medium)}.prio.later{color:var(--muted)}
"""


def _sev(s: str) -> str:
    return f'<span class="sev {escape(s)}">심각도 {SEV_KO.get(s, s)}</span>'


def _refs(refs, inc_id: str) -> str:
    return "".join(f'<a class="ref" href="#{escape(inc_id)}-{escape(r)}">{escape(r)}</a>' for r in refs)


def render(result: dict, title: str = "LogFinder 웹서버 침해 점검 보고서") -> str:
    site = result.get("site", {})
    v = result["overall_verdict"]
    vcls = VERDICT_CLASS.get(v, "low")
    gen = str(result.get("generated_at", ""))
    doc_no = "LS-W-" + "".join(ch for ch in gen[:16] if ch.isdigit())[:12]
    srcs = ", ".join(f"{k} {n:,}" for k, n in sorted(result["events_by_source"].items()))
    target = escape(site.get("name") or "웹서버") + (f" · {escape(site.get('stack'))}" if site.get("stack") else "")
    h = [f"<!doctype html><html lang=ko><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}</style><div class='shell one'><main>"
         f"<header class=top><div class=brand><span><b>LogFinder</b> 웹서버 침해 점검 보고서 · 문서번호 "
         f"<code>{doc_no}</code></span><span class=cls>내부 검토용</span></div><h1>{escape(title)}</h1>"
         f"<div class=metaline><span>점검 대상</span><span>{target}</span>"
         f"<span>읽은 로그</span><span>이벤트 {result['n_events']:,}건 ({escape(srcs) or '없음'})</span>"
         f"<span>작성 일시</span><span><code>{escape(gen)}</code> · 처리 {result['timing']['total_s']}초</span></div></header>"]
    h.append(f"<h2>판정</h2><div class='verdictbox {vcls}'><b>{escape(VERDICT_KO.get(v, v))}</b>"
             f"<div class=small>탐지 {result['n_findings']:,}건 · 사건 {result['n_incidents']:,}건 · "
             f"읽은 이벤트 {result['n_events']:,}건</div></div>")
    h.append("<div class=kpis>")
    for label, val in (("읽은 이벤트", f"{result['n_events']:,}"),
                       ("의심 표시", f"{result['n_flagged']:,}"),
                       ("탐지 결과", f"{result['n_findings']:,}"),
                       ("사건", f"{result['n_incidents']:,}")):
        h.append(f"<div class=kpi><span>{label}</span><b>{val}</b></div>")
    h.append("</div>")

    if not result["results"]:
        h.append("<div class=card>탐지된 사건이 없습니다. 분석한 로그 범위에서는 뚜렷한 공격 흔적을 "
                 "찾지 못했습니다. (로그 보관 기간이 짧으면 이미 지워졌을 수 있습니다.)</div>")

    if result["results"]:
        h.append(f"<h2>사건 {len(result['results'])}건 자세히</h2>")
    for r in result["results"]:
        inc, rep, meta = r["incident"], r["report"], r["meta"]
        iv = rep.get("verdict", "suspicious")
        h.append(f"<article class='inc' id={escape(inc['id'])}><div class=head><div class=row>"
                 f"<span class=id>{escape(inc['id'])}</span><span class='vd {'attack' if iv in ('breached', 'likely_breached') else 'risky_not_attack'}'>"
                 f"{escape(VERDICT_KO.get(iv, iv))}</span>{_sev(rep.get('severity', inc['severity']))}</div></div>")
        val = meta.get("validation", {})
        badge = ("<span class=ok>근거검증 통과</span>" if val.get("passed")
                 else f"<span class=warn>근거검증: 무효 {val.get('evidence_invalid', 0)}건, "
                      f"근거없는 단계 {val.get('steps_without_evidence', 0)}건</span>")
        h.append(f"<div class=analysis>분석 {escape(meta.get('mode', '-'))}"
                 + (f"({escape(meta.get('model'))})" if meta.get("model") else "") + f" · {badge} · "
                 f"출발지 {escape(', '.join(inc['src_ips'][:4]) or '-')}</div>")
        h.append(f"<p class=summary>{escape(rep.get('summary', ''))}</p>")

        if rep.get("attack_flow"):
            h.append("<h3>공격 흐름</h3><ol class=flow>")
            for step in rep["attack_flow"]:
                h.append(f"<li><div class=flowhead><b>{escape(STAGE_KO.get(step['stage'], step['stage']))}</b>"
                         f"<span class=tech>{escape(step.get('technique', ''))}</span>"
                         f"<span class=muted>{escape(step.get('time', '')[:19])}</span></div>"
                         f"<div class=what>{escape(step.get('what', ''))}</div>"
                         f"<div class=refs>{_refs(step.get('evidence', []), inc['id'])}</div></li>")
            h.append("</ol>")

        if rep.get("remediation"):
            h.append("<h3>조치안</h3><div class=tablewrap><table>"
                     "<tr><th>우선순위</th><th>대상</th><th>조치</th><th>설명</th><th>근거</th></tr>")
            order = {"now": 0, "soon": 1, "later": 2}
            for c in sorted(rep["remediation"], key=lambda x: order.get(x.get("priority"), 3)):
                pr = c.get("priority", "later")
                h.append(f"<tr><td class='prio {escape(pr)}'>{escape(PRI_KO.get(pr, pr))}</td>"
                         f"<td>{escape(TARGET_KO.get(c.get('target'), c.get('target', '')))}</td>"
                         f"<td>{escape(c.get('action', ''))}</td><td>{escape(c.get('detail', ''))}</td>"
                         f"<td>{_refs(c.get('evidence', []), inc['id'])}</td></tr>")
            h.append("</table></div>")

        if rep.get("unknowns"):
            h.append("<h3>확인이 필요한 점</h3><ul>"
                     + "".join(f"<li>{escape(u)}</li>" for u in rep["unknowns"]) + "</ul>")

        # 근거 로그(이벤트) 표 — ref 링크가 가리키는 대상
        h.append("<details class=evidence><summary>근거 로그 보기 ("
                 f"{len(inc['events'])}건" + (f", {inc['omitted_events']}건 생략" if inc.get("omitted_events") else "")
                 + ")</summary><div class=tablewrap><table>"
                 "<tr><th>ref</th><th>시각</th><th>출발지</th><th>동작</th><th>결과</th><th>규칙</th></tr>")
        for e in inc["events"]:
            h.append(f"<tr id='{escape(inc['id'])}-{escape(e['ref'])}'><td><code>{escape(e['ref'])}</code></td>"
                     f"<td>{escape(e.get('ts', '')[:19])}</td><td>{escape(str(e.get('src_ip') or '-'))}</td>"
                     f"<td>{escape(str(e.get('action') or '')[:80])}</td>"
                     f"<td>{escape(str(e.get('outcome') or ''))}</td>"
                     f"<td>{escape(', '.join(e.get('rules', [])))}</td></tr>")
        h.append("</table></div></details></article>")

    h.append("<h2>탐지 규칙별 집계</h2><div class=tablewrap><table>"
             "<tr><th>규칙</th><th>설명</th><th>탐지</th><th>이벤트</th></tr>")
    for rid, c in result["rule_counts"].items():
        h.append(f"<tr><td><code>{escape(rid)}</code></td><td>{escape(c.get('title', ''))}</td>"
                 f"<td>{c['findings']}</td><td>{c['events']}</td></tr>")
    h.append("</table></div>")
    h.append("<div class=sign><div>분석 · LogFinder (자동 생성)</div><div>검토자</div><div>승인</div></div>"
             "<p class='small muted' style='margin-top:18px'>이 보고서는 쌓여 있는 로그와 파일만 보고 자동으로 "
             "판단한 결과입니다. 조치(파일 삭제·계정 잠금 등)는 사람이 확인한 뒤 직접 적용하세요. "
             "웹 로그는 보통 요청 본문을 남기지 않아, 로그만으로 공격 성공을 단정하기 어려운 경우가 있습니다.</p>")
    h.append(f"<footer><span>LogFinder · {doc_no}</span><span>근거 로그 위치를 판단마다 붙였습니다.</span></footer>"
             "</main></div></html>")
    return "".join(h)

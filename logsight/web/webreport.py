"""assess() 결과(dict)를 한 파일짜리 HTML 보고서로 만든다(외부 리소스 없음, 오프라인 가능)."""
from __future__ import annotations

from html import escape

from ..analyze import STAGE_KO
from ..report import SEV_KO
from .webanalyze import VERDICT_KO

VERDICT_CLASS = {"breached": "high", "likely_breached": "high",
                 "suspicious": "medium", "no_evidence": "low"}
PRI_KO = {"now": "지금 바로", "soon": "이번 주", "later": "여유 있을 때"}
TARGET_KO = {"file": "파일", "app": "앱 코드", "server": "서버 설정", "waf": "WAF",
             "account": "계정", "network": "네트워크", "patch": "패치", "other": "기타"}

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
padding:16px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.stat b{display:block;font-size:22px}.sev{display:inline-block;padding:1px 8px;border-radius:99px;
font-size:12px;font-weight:600;color:#fff}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}
.sev.low{background:var(--low)}.chip{display:inline-block;border:1px solid var(--line);border-radius:99px;
padding:0 8px;font-size:12px;margin:2px 4px 2px 0}
.verdict{border-radius:12px;padding:18px 20px;margin:14px 0;color:#fff}
.verdict.high{background:linear-gradient(90deg,#c0362c,#9e2a22)}
.verdict.medium{background:linear-gradient(90deg,#b7791f,#946017)}
.verdict.low{background:linear-gradient(90deg,#3b7d4f,#2f6640)}
.verdict b{font-size:22px;display:block}
ol.flow{list-style:none;padding:0;margin:0;border-left:2px solid var(--line)}
ol.flow li{position:relative;padding:4px 0 12px 18px}
ol.flow li:before{content:"";position:absolute;left:-7px;top:10px;width:12px;height:12px;border-radius:50%;
background:var(--accent)}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--code);padding:10px;border-radius:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
a.ref{color:var(--accent);text-decoration:none;font-family:ui-monospace,Menlo,monospace;font-size:12px;margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{border-bottom:1px solid var(--line);
padding:6px;text-align:left;vertical-align:top}tr:target{background:rgba(122,162,255,.18)}
.tablewrap{overflow-x:auto}.warn{color:var(--high)}.ok{color:var(--low)}details summary{cursor:pointer}
.prio{font-weight:600}.prio.now{color:var(--high)}.prio.soon{color:var(--medium)}.prio.later{color:var(--muted)}
"""


def _sev(s: str) -> str:
    return f'<span class="sev {escape(VERDICT_CLASS.get(s, s))}">{SEV_KO.get(s, s)}</span>'


def _refs(refs, inc_id: str) -> str:
    return "".join(f'<a class="ref" href="#{escape(inc_id)}-{escape(r)}">{escape(r)}</a>' for r in refs)


def render(result: dict, title: str = "LogSight 웹서버 침해 점검 보고서") -> str:
    site = result.get("site", {})
    v = result["overall_verdict"]
    vcls = VERDICT_CLASS.get(v, "low")
    h = [f"<!doctype html><html lang=ko><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}</style><main>"]
    h.append(f"<h1>{escape(title)}</h1>"
             f"<div class=muted>생성 {escape(result['generated_at'])} · 대상 "
             f"{escape(site.get('name') or '웹서버')}"
             + (f" · {escape(site.get('stack'))}" if site.get("stack") else "") + "</div>")

    h.append(f"<div class='verdict {vcls}'><b>판정: {escape(VERDICT_KO.get(v, v))}</b>"
             f"<div>탐지 {result['n_findings']:,}건 · 사건 {result['n_incidents']:,}건 · "
             f"읽은 이벤트 {result['n_events']:,}건</div></div>")

    srcs = ", ".join(f"{k} {n:,}" for k, n in sorted(result["events_by_source"].items()))
    h.append("<div class='grid' style='margin-top:14px'>")
    for label, val in (("읽은 이벤트", f"{result['n_events']:,}"),
                       ("의심 표시", f"{result['n_flagged']:,}"),
                       ("탐지 결과", f"{result['n_findings']:,}"),
                       ("사건", f"{result['n_incidents']:,}"),
                       ("처리 시간", f"{result['timing']['total_s']}초")):
        h.append(f"<div class='card stat'><span class=muted>{label}</span><b>{val}</b></div>")
    h.append(f"</div><div class=muted>로그 종류별: {escape(srcs) or '없음'}</div>")

    if not result["results"]:
        h.append("<div class=card>탐지된 사건이 없습니다. 분석한 로그 범위에서는 뚜렷한 공격 흔적을 "
                 "찾지 못했습니다. (로그 보관 기간이 짧으면 이미 지워졌을 수 있습니다.)</div>")

    for r in result["results"]:
        inc, rep, meta = r["incident"], r["report"], r["meta"]
        iv = rep.get("verdict", "suspicious")
        h.append(f"<h2 id={escape(inc['id'])}>{escape(inc['id'])} · {escape(VERDICT_KO.get(iv, iv))} "
                 f"{_sev(rep.get('severity', inc['severity']))}</h2>")
        val = meta.get("validation", {})
        badge = ("<span class=ok>근거검증 통과</span>" if val.get("passed")
                 else f"<span class=warn>근거검증: 무효 {val.get('evidence_invalid', 0)}건, "
                      f"근거없는 단계 {val.get('steps_without_evidence', 0)}건</span>")
        h.append(f"<div class=muted>분석 {escape(meta.get('mode', '-'))}"
                 + (f"({escape(meta.get('model'))})" if meta.get("model") else "") + f" · {badge} · "
                 f"출발지 {escape(', '.join(inc['src_ips'][:4]) or '-')}</div>")
        h.append(f"<div class=card>{escape(rep.get('summary', ''))}</div>")

        if rep.get("attack_flow"):
            h.append("<h3>공격 흐름</h3><ol class=flow>")
            for step in rep["attack_flow"]:
                h.append(f"<li><b>{escape(STAGE_KO.get(step['stage'], step['stage']))}</b> "
                         f"<span class=muted>{escape(step.get('technique', ''))} · "
                         f"{escape(step.get('time', '')[:19])}</span><br>{escape(step.get('what', ''))}"
                         f"<br>{_refs(step.get('evidence', []), inc['id'])}</li>")
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
        h.append("<details><summary>근거 로그 보기 ("
                 f"{len(inc['events'])}건" + (f", {inc['omitted_events']}건 생략" if inc.get("omitted_events") else "")
                 + ")</summary><div class=tablewrap><table>"
                 "<tr><th>ref</th><th>시각</th><th>출발지</th><th>동작</th><th>결과</th><th>규칙</th></tr>")
        for e in inc["events"]:
            h.append(f"<tr id='{escape(inc['id'])}-{escape(e['ref'])}'><td><code>{escape(e['ref'])}</code></td>"
                     f"<td>{escape(e.get('ts', '')[:19])}</td><td>{escape(str(e.get('src_ip') or '-'))}</td>"
                     f"<td>{escape(str(e.get('action') or '')[:80])}</td>"
                     f"<td>{escape(str(e.get('outcome') or ''))}</td>"
                     f"<td>{escape(', '.join(e.get('rules', [])))}</td></tr>")
        h.append("</table></div></details>")

    h.append("<h2>탐지 규칙별 집계</h2><div class=tablewrap><table>"
             "<tr><th>규칙</th><th>설명</th><th>탐지</th><th>이벤트</th></tr>")
    for rid, c in result["rule_counts"].items():
        h.append(f"<tr><td><code>{escape(rid)}</code></td><td>{escape(c.get('title', ''))}</td>"
                 f"<td>{c['findings']}</td><td>{c['events']}</td></tr>")
    h.append("</table></div>")
    h.append("<p class=muted style='margin-top:30px'>이 보고서는 쌓여 있는 로그와 파일만 보고 자동으로 "
             "판단한 결과입니다. 조치(파일 삭제·계정 잠금 등)는 사람이 확인한 뒤 직접 적용하세요. "
             "웹 로그는 보통 요청 본문을 남기지 않아, 로그만으로 공격 성공을 단정하기 어려운 경우가 있습니다.</p>")
    h.append("</main></html>")
    return "".join(h)

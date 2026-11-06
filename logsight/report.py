"""분석 결과(dict)를 한 파일짜리 HTML 보고서로 만든다(외부 리소스 없음, 오프라인 시연 가능)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from html import escape

from .analyze import STAGE_KO
from .detect import RULES
from .graph import GRAPH_CSS, figure

SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
PRI_KO = {"now": "즉시", "soon": "이번 주", "later": "여유 있을 때"}
SRC_KO = {"cloudtrail": "CloudTrail", "vpcflow": "VPC Flow", "waf": "WAF", "alb": "ALB",
          "sshauth": "SSH 로그", "hostfw": "서버 방화벽", "weblog": "웹서버 로그", "guardduty": "GuardDuty"}

CSS = """:root{--paper:#fbfaf7;--desk:#e8e6e1;--card:#fbfaf7;--fg:#1a1a1a;--muted:#5a5852;--faint:#737067;
--line:#d4d1c9;--rule:#1a1a1a;--soft:#f1efe9;--accent:#1f3a5f;--accent-soft:#e6ebf1;
--high:#a4161a;--high-soft:#f6e6e4;--medium:#8a5a00;--medium-soft:#f5ecd9;--low:#2d5f3a;--low-soft:#e5eee6;
--gray:#6b6860;--gray-soft:#ecebe6;--code:#f1efe9;--shadow:none;
--serif:"Noto Serif KR","Nanum Myeongjo","AppleMyungjo","Batang","바탕",serif;
--sans:"IBM Plex Sans KR","Pretendard","Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif;
--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--desk);color:var(--fg);
font:14.5px/1.75 var(--sans);-webkit-font-smoothing:antialiased}a{color:var(--accent)}
.shell{max-width:1180px;margin:0 auto;padding:28px 16px 48px;display:grid;grid-template-columns:1fr;gap:28px}
@media (min-width:1080px){.shell{grid-template-columns:200px minmax(0,1fr)}}
.shell>main{min-width:0;background:var(--paper);border:1px solid #d2cfc7;padding:0 56px 40px;counter-reset:sec}
@media (max-width:700px){.shell>main{padding:0 18px 32px}}
header.top{padding:40px 0 0}
.brand{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:12px;color:var(--muted);
border-top:3px solid var(--rule);border-bottom:1px solid var(--rule);padding:8px 0}
.brand b{color:var(--fg)}.brand .cls{border:1.5px solid var(--high);color:var(--high);font-weight:700;padding:0 8px;letter-spacing:.12em;font-size:11px;white-space:nowrap}
h1{font-family:var(--serif);font-weight:900;font-size:28px;line-height:1.35;margin:26px 0 4px;letter-spacing:-.02em}
h2{font-family:var(--serif);font-weight:700;font-size:18.5px;margin:40px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--rule);
scroll-margin-top:16px;counter-increment:sec;display:flex;gap:14px;align-items:baseline}
h2:before{content:counter(sec);font-family:var(--mono);font-size:13px;color:var(--high);font-weight:600}
h3{font-size:14px;margin:24px 0 8px;font-weight:700}
.muted{color:var(--muted)}.faint{color:var(--faint)}.small{font-size:12.5px}
.card{background:transparent;border:0;border-top:1px solid var(--line);padding:12px 0;margin:10px 0}
h2+.card:not(.modecard){border-top:0;padding-top:0}
.pill{display:inline-block;border:1px solid currentColor;padding:0 7px;font-size:11.5px;font-weight:700;letter-spacing:.04em}
.pill.rules{color:var(--accent)}.pill.ai{color:var(--medium)}
.metaline{display:grid;grid-template-columns:110px 1fr;font-size:12.5px;margin:16px 0 8px;border-bottom:1px solid var(--line)}
.metaline>span{border-top:1px solid var(--line);padding:5px 0}.metaline>span:nth-child(odd){color:var(--muted)}
.metaline .pill{margin:3px 0}
nav.toc{display:none}
@media (min-width:1080px){nav.toc{display:block;position:sticky;top:16px;align-self:start;max-height:calc(100vh - 32px);
overflow:auto;padding-top:36px;font-size:13px;counter-reset:toc}}
nav.toc .h{font-size:11.5px;font-weight:700;color:var(--muted);margin:16px 0 4px;padding-bottom:4px;border-bottom:1px solid var(--rule)}
nav.toc a{display:flex;gap:8px;align-items:baseline;padding:4px 0;color:var(--fg);text-decoration:none;border-bottom:1px solid var(--line)}
nav.toc a:hover{color:var(--high)}nav.toc .sub{color:var(--faint);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:170px}
nav.toc b{font-family:var(--mono);font-weight:500;font-size:12px}
.dot{flex:0 0 7px;width:7px;height:7px;background:var(--gray);display:inline-block}
.dot.attack{background:var(--high)}.dot.risky_not_attack{background:var(--medium)}.dot.benign_activity{background:var(--low)}
.card.modecard{display:block;border:1px solid var(--rule);padding:10px 14px;margin:6px 0 18px;font-size:13px}
.modecard .ico{display:none}.modecard b{display:block;font-size:13px;margin-bottom:2px}
.modecard.ai{border-color:var(--medium)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);margin:14px 0 6px}
.kpi{padding:10px 14px;border-left:1px solid var(--line)}.kpi:first-child{border-left:0;padding-left:0}
.kpi span{font-size:12px;color:var(--muted);display:block}.kpi b{display:block;font-family:var(--serif);font-size:28px;font-weight:700;line-height:1.25;
font-variant-numeric:tabular-nums}.kpi b.warn{color:var(--high)}
.vbar{display:flex;height:8px;overflow:hidden;background:var(--soft);margin:10px 0 8px}
.vbar i{display:block;height:100%}.vbar .attack{background:var(--high)}.vbar .risky_not_attack{background:var(--medium)}
.vbar .unclear{background:var(--gray)}.vbar .benign_activity{background:var(--low)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12.5px;color:var(--muted)}.legend span{display:inline-flex;gap:6px;align-items:center}
.vd{display:inline-block;border:1.5px solid var(--gray);color:var(--gray);padding:0 7px;font-size:12px;font-weight:700;white-space:nowrap;letter-spacing:.03em}
.vd.attack{border-color:var(--high);color:var(--high)}.vd.risky_not_attack{border-color:var(--medium);color:var(--medium)}
.vd.benign_activity{border-color:var(--low);color:var(--low)}
.sev{display:inline-block;font-size:12px;font-weight:600;color:var(--muted);white-space:nowrap}
.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}
.chip{display:inline-block;border:1px solid var(--line);padding:0 7px;font-size:11.5px;color:var(--muted);white-space:nowrap}
ol.todo{list-style:none;margin:0;padding:0;counter-reset:t}
ol.todo li{counter-increment:t;display:grid;grid-template-columns:28px 1fr;gap:4px 8px;padding:9px 0;border-bottom:1px solid var(--line)}
ol.todo li:before{content:counter(t);font-family:var(--mono);font-size:12.5px;color:var(--muted);padding-top:1px}
.pri{display:inline-block;font-size:12px;font-weight:700;margin-right:8px;color:var(--gray)}
.pri.now{color:var(--high)}.pri.soon{color:var(--medium)}.pri:before{content:"["}.pri:after{content:"]"}
.note{border:1px solid var(--line);border-left:3px solid var(--rule);padding:10px 14px}.note ul,.card ul{margin:6px 0 0;padding-left:20px}.card li{margin:3px 0}
.gantt{display:grid;grid-template-columns:110px 1fr 64px;gap:6px 10px;align-items:center;font-size:12.5px;margin-top:6px}
.gantt .track{position:relative;height:12px;background:var(--soft);border-bottom:1px solid var(--line)}
.gantt .bar{position:absolute;top:2px;bottom:2px;background:var(--accent);min-width:3px}
.gantt .bar.missing{display:none}.gantt .n{text-align:right;color:var(--muted);font-family:var(--mono);font-size:12px}
.gantt .miss{color:var(--faint)}.gantt .mk{position:absolute;top:0;bottom:0;min-width:3px}
.gantt .mk.attack{background:var(--high)}.gantt .mk.risky_not_attack{background:var(--medium)}
.gantt .mk.unclear{background:var(--gray)}.gantt .mk.benign_activity{background:var(--low)}
.axis{display:flex;justify-content:space-between;font-size:11.5px;color:var(--faint);grid-column:2;font-family:var(--mono)}
.cantell{margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.gdnote{margin:0 0 12px;padding:8px 12px;border-left:3px solid var(--rule);background:var(--soft)}
article.inc{margin:22px 0 36px;scroll-margin-top:16px}
article.inc>.head{padding:10px 0 4px;border-top:3px solid var(--rule)}
.head .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.head .id{font-family:var(--serif);font-size:20px;font-weight:900;margin-right:6px}
.head .when{font-size:12.5px;color:var(--muted);margin-top:2px;font-family:var(--mono)}
.summary{font-family:var(--serif);font-size:16px;line-height:1.85;margin:12px 0 6px;padding-left:16px;border-left:3px solid var(--high)}
article.inc:not(.attack) .summary{border-left-color:var(--rule)}
.body{padding:2px 0 8px}
.reason{border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:8px 0;font-size:13.5px;margin:10px 0}
.reason b{font-size:12px;color:var(--muted);display:block}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:0;font-size:13px;margin:12px 0;border-top:1px solid var(--line)}
.facts div{padding:6px 12px 6px 0;border-bottom:1px solid var(--line)}.facts div span{display:block;font-size:11.5px;color:var(--faint)}
.stepper{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center;margin:10px 0 2px;font-size:12.5px}
.stepper span{font-weight:600}.stepper i{color:var(--faint);font-style:normal}
.analysis{font-size:12px;color:var(--muted);margin-top:8px}.ok{color:var(--low)}.warn{color:var(--high)}
ol.flow{list-style:none;padding:0;margin:4px 0 0;border-top:1px solid var(--rule);counter-reset:f}
ol.flow li{display:grid;grid-template-columns:34px 1fr;padding:8px 0;border-bottom:1px solid var(--line);counter-increment:f}
ol.flow li:before{content:counter(f, decimal-leading-zero);font-family:var(--mono);font-size:12px;color:var(--faint);grid-row:span 3;padding-top:2px}
.flowhead{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline;font-size:12.5px}.flowhead b{font-size:13.5px}
.flowhead .muted{font-family:var(--mono);font-size:11.5px}
.tech{font-family:var(--mono);font-size:11px;color:var(--muted)}
.what{margin-top:1px}
code,pre{font-family:var(--mono);font-size:12px}
pre{background:var(--code);border-left:2px solid var(--rule);padding:8px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0}
a.ref{color:var(--high);text-decoration:none;font-family:var(--mono);font-size:11px;margin:0 8px 0 0;display:inline-block}
a.ref:before{content:"↳ "}a.ref:hover{text-decoration:underline}
.refs{margin-top:2px;line-height:1.7}.refs>.muted{font-size:11.5px;margin-right:6px}
details.more{display:inline}details.more[open]{display:block}details.more summary{display:inline;color:var(--muted);font-size:12px;cursor:pointer}
.fix{border-top:1px solid var(--line);padding:10px 0;margin:0}
.fix .t{font-weight:700}.fix .res{font-size:12px;color:var(--muted);margin-top:1px;font-family:var(--mono);overflow-wrap:anywhere}
.why{margin:6px 0 2px;font-size:13.5px}details summary{cursor:pointer;color:var(--accent);font-size:13px;margin-top:6px}
details.evidence{margin:14px 0 0;border-top:1px solid var(--rule);padding-top:8px}
details.evidence>summary{font-size:13.5px;color:var(--fg);font-weight:700}
.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12.5px}
td,th{border-bottom:1px solid var(--line);padding:6px 8px 6px 0;text-align:left;vertical-align:top}
th{font-size:11.5px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--rule)}tr:target{background:var(--high-soft)}
table.ev{table-layout:fixed;min-width:760px}table.ev th:nth-child(1){width:14%}table.ev th:nth-child(2){width:17%}
table.ev th:nth-child(3){width:10%}table.ev th:nth-child(4){width:21%}table.ev th:nth-child(5){width:8%}
table.ev th:nth-child(6){width:16%}td.act,td code{word-break:break-all;overflow-wrap:anywhere}td.nw{white-space:nowrap;font-family:var(--mono);font-size:12px}
.card,ol.flow li,.summary{overflow-wrap:anywhere}
.sign{display:grid;grid-template-columns:repeat(3,1fr);margin-top:40px;border-top:1px solid var(--rule);font-size:12px;color:var(--muted)}
.sign div{padding:6px 10px 34px;border-left:1px solid var(--line)}.sign div:first-child{border-left:0;padding-left:0}
footer{color:var(--faint);font-size:11.5px;margin-top:18px;border-top:1px solid var(--line);padding-top:6px;display:flex;justify-content:space-between;gap:12px}
@media print{body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}nav.toc{display:none}.shell{display:block;padding:0}.shell>main{border:0;padding:0;background:#fff}
details{display:block}details>summary{display:none}article.inc+article.inc{break-before:page}h2,h3{break-after:avoid}.gantt,.kpis,.fix,ol.flow li{break-inside:avoid}}
.flowgraph .node rect,.flowgraph rect.lab{rx:3px;ry:3px}
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
    return f'<span class="sev {escape(s)}">심각도 {SEV_KO.get(s, s)}</span>'


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
        if b and b != a:
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


VERDICT_KO = {"attack": "공격 의심", "risky_not_attack": "공격 아님·위험 설정",
              "unclear": "판단 불가", "benign_activity": "정상 활동"}
VERDICT_ORDER = ["attack", "risky_not_attack", "unclear", "benign_activity"]


def _verdict(v: str | None, by: str | None = None) -> str:
    if not v:
        return ""
    who = {"rules": "규칙 판정", "claude": "Claude 판정"}.get(by or "", "")
    return (f"<span class='vd {escape(v)}'>{VERDICT_KO.get(v, escape(v))}</span>"
            + (f"<span class=faint style='font-size:12px'>{who}</span>" if who else ""))


def _explain_mode(result: dict) -> dict:
    """예전 결과 파일에는 explain_mode가 없으므로 사건별 meta에서 다시 만든다."""
    if result.get("explain_mode"):
        return result["explain_mode"]
    models = sorted({r["meta"].get("model") for r in result.get("results", [])
                     if r["meta"].get("mode") == "claude"})
    tri = result.get("triage") or {}
    tri_ai = tri.get("mode") != "rules" and "incidents" in tri
    return {"report": "claude" if models else "rules", "models": models,
            "triage": "claude" if tri_ai else "rules",
            "triage_model": (tri.get("meta") or {}).get("model") if tri_ai else None, "ai_errors": []}


def _uses_ai(m: dict) -> bool:
    return m["report"] == "claude" or m["triage"] == "claude"


def _mode_card(result: dict) -> str:
    """AI를 썼는지, 로그가 밖으로 나갔는지 분명히 적는다."""
    m = _explain_mode(result)
    if not _uses_ai(m):
        txt = ("<b>설명 방식: 규칙 기반 · AI 사용 안 함</b><div class=small>사건 판정과 설명 문장을 프로그램 안의 규칙과 "
               "문장 틀로 만들었습니다. 로그는 이 컴퓨터 밖으로 나가지 않았고, 같은 로그를 넣으면 항상 같은 "
               "결과가 나옵니다. 규칙에 없는 상황은 설명하지 못하므로 '판단 불가' 사건은 사람이 확인하세요.</div>")
        cls, ico = "modecard", "규칙"
    else:
        parts, labels = [], []
        if m["triage"] == "claude":
            parts.append("사건 판정(공격·정상 구분, 순서)")
            if m.get("triage_model"):
                labels.append(f"판정 {m['triage_model']}")
        if m["report"] == "claude":
            parts.append("사건 설명")
            if m.get("models"):
                labels.append("설명 " + ", ".join(m["models"]))
        models = " · ".join(labels) or "Claude"
        txt = (f"<b>설명 방식: Claude 사용 ({escape(models)})</b><div class=small>{' · '.join(parts)}에 Claude를 썼습니다. "
               "원본 로그가 아니라 사건별 축약본을 액세스 키 등을 가린 뒤 보냈고, Claude가 든 근거(파일:줄)는 "
               "코드로 다시 검사했습니다. 탐지·원인 설정·수정 명령은 AI가 아니라 코드가 만듭니다.</div>")
        cls, ico = "modecard ai", "AI"
    if m.get("ai_errors"):
        txt += ("<div class='warn small'>AI 호출이 실패한 부분은 규칙 기반 결과로 대신했습니다: "
                + escape(m["ai_errors"][0][:160]) + "</div>")
    return f"<div class='card {cls}'><div class=ico>{ico}</div><div>{txt}</div></div>"


def _hm(d: datetime) -> str:
    return f"{d.astimezone(timezone.utc):%m-%d %H:%M} UTC · 한국 {d.astimezone(KST):%H:%M}"


def _team_card(result: dict) -> str:
    """우리 팀 후보를 보여 주고 확인을 받는다. 확인 전에는 판정에 쓰지 않는다."""
    t = result.get("team") or {}
    props, conf = t.get("proposed") or [], t.get("confirmed") or []
    if not props and not conf:
        return ""
    rows = "".join(f"<li><b>{escape(p['name'])}</b> · {escape(', '.join(p['reasons']))} "
                   f"<span class=muted>(이벤트 {p['n_events']:,}건)</span></li>" for p in props)
    out = ["<div class='card note small'><b>우리 팀으로 보이는 계정</b>"]
    if props:
        names = " ".join(escape(p["name"]) for p in props)
        out.append(f"<ul>{rows}</ul><div>우리 팀이 맞으면 한 번 확인해 주세요. 확인한 계정의 작업은 다음 분석부터 공격 판정에서 뺍니다: "
                   f"<code>python -m logsight team &lt;로그&gt; --confirm {names}</code><br>"
                   "모르는 계정은 넣지 마세요. 비밀번호를 훔친 공격자도 콘솔로 들어옵니다. 확인 전에는 판정을 바꾸지 않았습니다.</div>")
    if conf:
        out.append(f"<div>확인된 우리 팀: {escape(', '.join(conf))}. 이 계정들의 작업은 공격 판정에서 뺐습니다"
                   "(키 유출에서 흔한 모습이 보이면 그래도 공격으로 봅니다).</div>")
    out.append("</div>")
    return "".join(out)


def _coverage_card(result: dict) -> str:
    """로그로 볼 수 있는 범위: 로그 종류별 기간을 막대로, 빠진 로그와 알 수 없는 것을 문장으로."""
    from .explain import _periods
    rt = result.get("rule_triage") or {}
    cov = rt.get("coverage") or {}
    srcs = cov.get("sources") or {}
    if not srcs:
        return ""
    idx = result.get("incident_index", [])
    h = ["<h2 id=coverage>로그로 볼 수 있는 범위</h2><div class=card>"]
    from .explain import guardduty_note
    gd = guardduty_note(cov)
    if gd:
        h.append(f"<div class='small gdnote'>{escape(gd)}</div>")
    periods = _periods(srcs)
    for n, p in enumerate(periods):
        a, b = p["first"], p["last"]
        span = max((b - a).total_seconds(), 60.0)

        def pos(t):
            return max(0.0, min(100.0, (t - a).total_seconds() / span * 100))
        if len(periods) > 1:
            h.append(f"<div class='small muted' style='margin-top:{14 if n else 0}px'><b>기간 {n + 1}</b></div>")
        h.append("<div class=gantt>")
        for k in sorted(p["sources"], key=lambda k: srcs[k]["first"]):
            v = srcs[k]
            x0, x1 = pos(_dt(v["first"])), pos(_dt(v["last"]))
            h.append(f"<div>{escape(SRC_KO.get(k, k))}</div><div class=track title='{escape(_when(v['first'], v['last']))}'>"
                     f"<div class=bar style='left:{x0:.2f}%;width:{max(x1 - x0, 0.6):.2f}%'></div></div>"
                     f"<div class=n>{v['n_events']:,}건</div>")
        marks = []
        for i in idx[:50]:
            s0, s1 = _dt(i["start"]), _dt(i["end"])
            if s0 and a <= s0 <= b:
                v = i.get("verdict") or i.get("ai_verdict") or "unclear"
                marks.append(f"<a href='#{escape(i['id'])}' class='mk {escape(v)}' title='{escape(i['id'])} "
                             f"{escape(VERDICT_KO.get(v, v))}' style='left:{pos(s0):.2f}%;"
                             f"width:{max(pos(s1) - pos(s0), 0.5):.2f}%'></a>")
        if marks:
            h.append("<div><b>사건</b></div><div class=track>" + "".join(marks) + "</div><div class=n></div>")
        h.append(f"<div class=axis><span>{_hm(a)}</span><span>{_hm(b)}</span></div></div>")
    miss = cov.get("missing_sources", [])
    if miss:
        h.append("<div class='small' style='margin-top:10px'><span class=muted>없는 로그</span> "
                 + " ".join(f"<span class=chip>{escape(SRC_KO.get(k, k))}</span>" for k in miss) + "</div>")
    notes = list(rt.get("cannot_tell") or [])
    tri = result.get("triage") or {}
    ai_notes = tri.get("cannot_tell") if tri.get("mode") != "rules" else None
    if notes or ai_notes:
        h.append("<div class=cantell>")
        if notes:
            h.append("<b>그래서 이 로그로는 알 수 없는 것</b><ul>" + "".join(f"<li>{escape(n)}</li>" for n in notes) + "</ul>")
        if ai_notes:
            h.append("<b style='display:block;margin-top:10px'>Claude가 덧붙인 것</b><ul>" + "".join(
                f"<li>{escape(n if isinstance(n, str) else n.get('what', str(n)))}</li>" for n in ai_notes) + "</ul>")
        h.append("</div>")
    h.append("<div class='small faint' style='margin-top:8px'>'기록이 없음'은 '일어나지 않음'이 아닙니다. 빠진 로그는 "
             "<code>python -m logsight check</code>로 켜는 방법과 비용을 볼 수 있습니다.</div></div>")
    return "".join(h)


def _campaign_card(result: dict) -> str:
    """같은 공격으로 묶인 사건들. 상세 사건에 들어 있으면 하나의 흐름 그림으로 합쳐 그린다."""
    tri = result.get("triage") or {}
    camps = [c for c in tri.get("campaigns", []) if len(c.get("incident_ids", [])) > 1]
    if not camps:
        return ""
    who = "Claude가" if tri.get("mode") != "rules" else "규칙으로"
    by_id = {r["incident"]["id"]: r["incident"] for r in result["results"]}
    h = [f"<h2 id=campaign>같은 공격으로 보이는 사건</h2><div class=card><div class='small muted'>{who} 연결했습니다.</div><ul>"]
    for c in camps[:3]:
        links = " · ".join(f"<a href='#{escape(i)}'>{escape(i)}</a>" for i in c["incident_ids"])
        h.append(f"<li><b>{links}</b> <span class=muted>{escape(c.get('link_reason', ''))}</span></li>")
    h.append("</ul>")
    incs = [by_id[i] for i in camps[0]["incident_ids"] if i in by_id]
    if len(incs) > 1:
        fig = figure(sorted(incs, key=lambda i: i["start"]))
        if fig:
            h.append("<h3 style='margin-top:14px'>합친 공격 흐름 그림 (" + ", ".join(escape(i["id"]) for i in incs) + ")</h3>" + fig)
    h.append("</div>")
    return "".join(h)


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


def _incident(r: dict, verdicts: dict) -> str:
    inc, rep, meta = r["incident"], r["report"], r["meta"]
    iid = inc["id"]
    v = inc.get("verdict") or inc.get("ai_verdict") or rep.get("verdict") or "unclear"
    h = [f"<article class='inc {escape(v)}' id='{escape(iid)}'><div class=head><div class=row>"
         f"<span class=id>{escape(iid)}</span>{_verdict(v, inc.get('verdict_by'))}"
         f"{_sev(rep.get('severity', inc['severity']))}"]
    if inc.get("injection"):
        h.append("<span class=chip title='User-Agent·요청 주소 등에 AI 판정을 바꾸려는 문장이 있음'>"
                 "로그에 AI를 속이려는 문장</span>")
    if inc.get("contested"):
        c = inc["contested"]
        h.append(f"<span class=chip title='사람이 근거 로그를 보고 정하세요'>규칙은 {VERDICT_KO['attack']}, "
                 f"AI는 {escape(VERDICT_KO.get(c['ai'], c['ai']))} · 확인 필요</span>")
    if inc.get("ai_said"):
        h.append(f"<span class=chip>AI 판정({escape(VERDICT_KO.get(inc['ai_said'], inc['ai_said']))}) 따르지 않음</span>")
    if inc.get("repeats", 1) > 1:
        h.append(f"<span class=chip>같은 유형 {inc['repeats']}회 반복</span>")
    if inc.get("n_known"):
        h.append(f"<span class=chip>정상 작업 목록 일치 {inc['n_known']:,}건</span>")
    h.append(f"</div><div class=when>{_when(inc['start'], inc['end'])}</div>")
    h.append(f"<p class=summary>{escape(rep.get('summary', ''))}</p></div><div class=body>")
    vr = verdicts.get(iid)
    if vr and vr.get("reason") and vr["reason"] not in rep.get("summary", ""):
        h.append(f"<div class=reason><b>판정 이유</b>{escape(vr['reason'])}</div>")
    if inc["stages"]:
        h.append("<div class=stepper>" + "<i>→</i>".join(
            f"<span>{escape(STAGE_KO.get(s, s))}</span>" for s in inc["stages"]) + "</div>")
    logs = ", ".join(SRC_KO.get(s, s) for s in sorted({e["source"] for e in inc["events"]}))
    src = ", ".join(inc["src_ips"][:5]) + (f" 외 {len(inc['src_ips']) - 5}개" if len(inc["src_ips"]) > 5 else "")
    h.append("<div class=facts>"
             f"<div><span>출발지</span>{escape(src or '-')}</div>"
             + (f"<div><span>관련 서버</span>{escape(', '.join(inc['instances'][:5]))}</div>" if inc.get("instances") else "")
             + f"<div><span>함께 본 로그</span>{escape(logs)}</div>"
             f"<div><span>이벤트</span>{inc['n_events']:,}건</div></div>")
    mode = "Claude " + escape(meta.get("model") or "") if meta["mode"] == "claude" else "규칙 기반(AI 사용 안 함)"
    val = meta["validation"]
    vtxt = ("<span class=ok>근거 검증 통과</span>" if val["passed"] else
            f"<span class=warn>근거 검증: 잘못된 근거 {val['evidence_invalid']}건, "
            f"근거 없는 단계 {val['steps_without_evidence']}건</span>")
    h.append(f"<div class=analysis>설명: {mode} · 확신도 {SEV_KO.get(rep.get('confidence'), '-')} · {vtxt}</div>")
    if meta.get("ai_error"):
        h.append(f"<div class='warn small'>AI 호출 실패로 규칙 기반 결과를 표시: {escape(meta['ai_error'])}</div>")

    fig = figure([inc])
    if fig:
        h.append("<h3>공격 흐름 그림</h3>" + fig)
    h.append("<h3>단계별 설명</h3><ol class=flow>")
    for st in rep.get("attack_flow", []):
        tech = st.get("technique", "")
        h.append(f"<li><div class=flowhead><b>{escape(STAGE_KO.get(st['stage'], st['stage']))}</b>"
                 + (f"<span class=tech>{escape(tech)}</span>" if tech else "")
                 + (f"<span class=muted>{_when(st['time'])}</span>" if st.get("time") else "")
                 + f"</div><div class=what>{escape(st['what'])}</div>{_refs(st.get('evidence', []), iid)}"
                 + (f"<div class='warn small'>확인 안 된 근거: {escape(', '.join(st['unverified_evidence']))}</div>"
                    if st.get("unverified_evidence") else "") + "</li>")
    h.append("</ol>")

    if rep.get("root_causes") or r["checks"] or rep.get("firewall_changes"):
        h.append("<h3>원인과 수정안 <span class=faint style='font-weight:400'>· 자동 적용하지 않음, 검토 후 직접 적용</span></h3>")
    causes = {rc["setting"]: rc for rc in rep.get("root_causes", [])}
    by_id = {c["id"] + c["resource"]: c for c in r["checks"]}
    for fc in rep.get("firewall_changes", []):
        c = by_id.get(fc["check_id"] + fc["resource"]) or next(
            (x for x in r["checks"] if x["id"] == fc["check_id"]), None)
        rc = causes.pop(fc["change"], None) or (causes.pop(c["title"], None) if c else None)
        h.append(f"<div class=fix><div class=t><span class='pri {escape(fc['priority'])}'>"
                 f"{PRI_KO.get(fc['priority'], fc['priority'])}</span>{escape(fc['change'])}</div>"
                 f"<div class=res>{escape(fc['target'])} · {escape(fc['resource'])}</div>")
        if fc["check_id"] == "NEW":  # AI가 코드 점검 밖에서 새로 제안한 것: 실행 명령이 없는 '검증 안 된 제안'
            h.append("<div class='muted small'>AI 제안 · 코드가 만든 적용 명령이 아님(직접 확인 후 적용)</div>")
        if rc:  # 원인 설명을 같은 카드에 붙여 '왜 → 무엇을 바꾸나'를 한곳에서 본다
            h.append(f"<div class=why>{escape(rc['why'])}</div>{_refs(rc.get('evidence', []), iid)}")
        if c:
            h.append("<details><summary>현재 설정과 제안, 적용·되돌리기 명령 보기</summary>"
                     f"<pre>현재: {escape(json.dumps(c['current'], ensure_ascii=False, indent=1))}\n"
                     f"제안: {escape(json.dumps(c['proposed'], ensure_ascii=False, indent=1))}</pre>"
                     f"<div class='muted small'>적용</div><pre>{escape(chr(10).join(c['cli']))}</pre>"
                     + (f"<div class='muted small'>되돌리기</div><pre>{escape(chr(10).join(c['rollback']))}</pre>"
                        if c.get("rollback") else "") +
                     f"<div class='muted small'>주의: {escape(c['caution'])}</div></details>")
        h.append("</div>")
    if causes:  # 수정안과 짝이 없는 원인(AI가 따로 찾은 것 등)
        h.append("<div class=fix><b>그 밖에 원인으로 보이는 것</b><ul>")
        for rc in causes.values():
            h.append(f"<li><b>{escape(rc['setting'])}</b>: {escape(rc['why'])}{_refs(rc.get('evidence', []), iid)}</li>")
        h.append("</ul></div>")
    if rep.get("unknowns"):
        h.append("<h3>로그만으로 확인할 수 없는 것</h3><ul class=small>" +
                 "".join(f"<li>{escape(u)}</li>" for u in rep["unknowns"]) + "</ul>")

    h.append(f"<details class=evidence><summary>근거 이벤트 {len(inc['events'])}건"
             + (f" <span class='muted small'>(비슷한 {inc['omitted_events']}건 생략)</span>" if inc["omitted_events"] else "")
             + "</summary><div class=tablewrap><table class=ev><tr><th>근거</th><th>시각(UTC)</th>"
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
                 + (f"<br><span class=chip>{escape(str(e['known']))}</span>" if e.get("known") else "")
                 + f"</td><td>{_result_ko(e)}</td>"
                 f"<td class=act>{escape(str(e.get('src_ip') or e.get('actor') or ''))}"
                 + (f" → {escape(str(dst))}" if dst else "") + "</td>"
                 "<td>" + "<br>".join(_rule_ko(x) for x in e.get("rules", [])) + "</td></tr>")
    h.append("</table></div></details></div></article>")
    return "".join(h)


def render(result: dict, title: str = "LogFinder 분석 보고서") -> str:
    mode = _explain_mode(result)
    tri = result.get("triage") or {}
    verdicts = {x["id"]: x for x in tri.get("incidents", [])}
    idx = result.get("incident_index", [])
    n_groups = result.get("n_groups", result["n_incidents"])
    vcount = {v: 0 for v in VERDICT_ORDER}
    for x in tri.get("incidents", []):
        vcount[x["verdict"]] = vcount.get(x["verdict"], 0) + 1
    todo = _todo(result["results"])

    h = [f"<!doctype html><html lang=ko><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}{GRAPH_CSS}</style>"]
    pill = ("<span class='pill ai'>Claude 사용</span>" if _uses_ai(mode)
            else "<span class='pill rules'>AI 사용 안 함</span>")
    gen = _dt(result["generated_at"])
    doc_no = f"LS-{gen:%Y%m%d-%H%M}" if gen else "LS"
    srcs = ", ".join(f"{SRC_KO.get(k, k)} {v:,}" for k, v in sorted(result["events_by_source"].items(),
                                                                     key=lambda kv: -kv[1]))
    header = (f"<header class=top><div class=brand><span><b>LogFinder</b> 침해사고 초동 분석 보고서 · 문서번호 "
              f"<code>{doc_no}</code></span><span class=cls>내부 검토용</span></div><h1>{escape(title)}</h1>"
              f"<div class=metaline><span>분석 방식</span><span>{pill}</span>"
              f"<span>분석 대상</span><span>원본 로그 {len(result['files'])}개 파일 · 이벤트 {result['n_events']:,}건"
              f"{' (' + escape(srcs) + ')' if srcs else ''}</span>"
              f"<span>작성 일시</span><span><code>{escape(result['generated_at'])}</code> · 처리 {result['timing']['total_s']}초</span>"
              "</div></header>")

    # 왼쪽 목차
    nav = ["<nav class=toc><div class=h>목차</div><a href='#summary'>요약</a>"]
    if todo:
        nav.append("<a href='#todo'>먼저 할 일</a>")
    if (result.get("rule_triage") or {}).get("coverage", {}).get("sources"):
        nav.append("<a href='#coverage'>로그 범위</a>")
    if result["results"]:
        nav.append("<div class=h>사건</div>")
        for r in result["results"]:
            inc = r["incident"]
            v = inc.get("verdict") or inc.get("ai_verdict") or r["report"].get("verdict") or "unclear"
            first = (inc["findings"][0]["title"] if inc["findings"] else "")
            nav.append(f"<a href='#{escape(inc['id'])}'><span class='dot {escape(v)}'></span>"
                       f"<span><b>{escape(inc['id'])}</b><div class=sub>{escape(first)}</div></span></a>")
    if len(idx) > len(result["results"]):
        nav.append("<a href='#rest'>나머지 사건</a>")
    if any(len(c.get("incident_ids", [])) > 1 for c in tri.get("campaigns", [])):
        nav.insert(1 + bool(todo) + 1, "<a href='#campaign'>같은 공격 묶음</a>")
    nav.append("</nav>")
    h.append("<div class=shell>" + "".join(nav) + "<main>" + header)

    # 요약
    h.append("<section id=summary><h2>요약</h2>" + _mode_card(result))
    sc = result.get("severity_counts") or {}
    h.append("<div class=kpis>")
    for label, val, cls in (("검토할 사건", f"{n_groups:,}건", ""),
                            ("공격 의심", f"{vcount.get('attack', 0):,}건", "warn" if vcount.get("attack") else ""),
                            ("심각도 높음", f"{sc.get('high', 0):,}건", ""),
                            ("읽은 이벤트", f"{result['n_events']:,}", "")):
        h.append(f"<div class=kpi><span>{label}</span><b class='{cls}'>{val}</b></div>")
    h.append("</div>")
    total = sum(vcount.values())
    if total:
        h.append("<div class=card><div class=small><b>사건 판정</b> <span class=muted>"
                 f"({'Claude' if mode['triage'] == 'claude' else '규칙'} 판정, 공격 의심부터 보여 줍니다)</span></div><div class=vbar>"
                 + "".join(f"<i class='{v}' style='width:{vcount[v] / total * 100:.2f}%'></i>" for v in VERDICT_ORDER if vcount.get(v))
                 + "</div><div class=legend>"
                 + "".join(f"<span><i class='dot {v}'></i>{VERDICT_KO[v]} {vcount[v]}</span>" for v in VERDICT_ORDER if vcount.get(v))
                 + "</div></div>")
    srcs = ", ".join(f"{SRC_KO.get(k, k)} {v:,}" for k, v in sorted(result["events_by_source"].items()))
    rep_note = (f", 같은 유형 반복을 묶어 {n_groups:,}건" if n_groups != result["n_incidents"] else "")
    h.append(f"<div class='small muted'>로그 종류별 {escape(srcs) or '없음'}. 이벤트 {result['n_events']:,}건 중 "
             f"{result['n_flagged']:,}건이 규칙에 걸렸고, 탐지 {result['n_findings']:,}건을 "
             f"사건 {result['n_incidents']:,}건으로 엮었습니다{rep_note}.</div></section>")

    if todo:
        h.append("<h2 id=todo>먼저 할 일</h2><div class=card><ol class=todo>")
        for fc, iid in todo[:5]:
            h.append(f"<li><div><span class='pri {escape(fc['priority'])}'>{PRI_KO.get(fc['priority'], fc['priority'])}"
                     f"</span>{escape(fc['change'])}<div class='small muted'>{escape(fc['resource'])} · "
                     f"<a href='#{escape(iid)}'>{escape(iid)}</a></div></div></li>")
        h.append("</ol><div class='small faint' style='margin-top:8px'>수정안은 자동 적용되지 않습니다. 사건별 설명에서 적용 명령과 "
                 "되돌리기 명령을 확인한 뒤 직접 적용하세요.</div></div>")
    if result.get("assumptions"):
        h.append("<div class='card note small'><b>이렇게 해석했습니다</b><ul>" +
                 "".join(f"<li>{escape(a)}</li>" for a in result["assumptions"]) + "</ul></div>")
    h.append(_team_card(result))
    h.append(_coverage_card(result))

    h.append(f"<h2>사건 {len(result['results'])}건 자세히</h2>" if result["results"] else "")
    if not result["results"]:
        h.append("<div class=card>탐지된 사건이 없습니다.</div>")
    else:
        h.append(_campaign_card(result))
    for r in result["results"]:
        h.append(_incident(r, verdicts))

    if len(idx) > len(result["results"]):
        rest = idx[len(result["results"]):]
        h.append(f"<h2 id=rest>나머지 사건 {len(rest):,}건</h2><div class='card tablewrap'><table>"
                 "<tr><th>ID</th><th>판정</th><th>심각도</th><th>시작(UTC)</th><th>단계</th><th>출발지</th><th>이벤트</th>"
                 "<th>반복</th></tr>")
        for i in rest:
            rp = i.get("repeats", 1)
            rep_txt = f"{rp}회 ({escape(str(i.get('first_seen', ''))[:10])}부터)" if rp > 1 else ""
            h.append(f"<tr><td>{escape(i['id'])}</td>"
                     f"<td>{_verdict(i.get('verdict') or i.get('ai_verdict'))}</td><td>{_sev(i['severity'])}</td>"
                     f"<td class=nw>{escape(i['start'][:16].replace('T', ' '))}</td>"
                     f"<td>{escape(' → '.join(STAGE_KO.get(s, s) for s in i['stages']))}</td>"
                     f"<td class=act>{escape(', '.join(i['src_ips'][:3]))}</td><td>{i['n_events']}</td>"
                     f"<td>{rep_txt}</td></tr>")
        h.append("</table></div>")
    h.append("<div class=sign><div>분석 · LogFinder (자동 생성)</div><div>검토자</div><div>승인</div></div>"
             f"<footer><span>LogFinder · {doc_no}</span><span>판단마다 근거 로그 위치(파일:줄)를 붙였습니다. "
             "수정안은 자동 적용되지 않습니다.</span></footer></main></div></html>")
    return "".join(h)

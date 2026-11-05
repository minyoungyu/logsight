"""웹 점검 화면: 첫 화면(랜딩)과 보고서 HTML. 외부 리소스 없이 한 파일로 나온다.

설계 방향
- 판정이 맨 위에 온다. 읽는 사람이 먼저 알고 싶은 것은 "뚫렸나"와 "지금 뭘 하나"다.
- 숙련자 정보(IOC, ATT&CK, 차단 규칙)는 아래쪽에 접어 두고, 복사 버튼으로 바로 옮기게 한다.
- 색은 판정 세 단계(위험·주의·정상)에만 쓴다. 나머지는 종이 같은 바탕과 잉크색 글자다.
- 데모 모드에서는 업로드 칸을 숨기고 샘플 결과로 바로 보내는 문구만 보여 준다.
"""
from __future__ import annotations

from html import escape

from ..analyze import STAGE_KO
from ..report import SEV_KO
from .webanalyze import VERDICT_KO

TONE = {"breached": "danger", "likely_breached": "danger", "suspicious": "warn", "no_evidence": "ok"}
PRI_KO = {"now": "지금 바로", "soon": "이번 주", "later": "여유 있을 때"}
TARGET_KO = {"file": "파일", "app": "앱 코드", "server": "서버 설정", "waf": "WAF",
             "account": "계정", "network": "네트워크", "patch": "패치", "other": "기타"}
DEMO_NOTE = "데모 서버는 로그 업로드를 받지 않습니다. 샘플 결과로 화면과 판정 방식을 확인하세요."

STYLE = """
:root{--paper:#f6f4ef;--surface:#ffffff;--ink:#1c1d21;--ink-2:#4a4d55;--ink-3:#6f7380;
--line:#dcd9d0;--line-2:#ebe9e2;--accent:#0f5f58;--accent-ink:#ffffff;--code:#f0efea;
--danger:#a8281e;--danger-bg:#fbeceb;--warn:#8a5a00;--warn-bg:#fdf3dc;--ok:#1f6b3a;--ok-bg:#e8f4ec;
--focus:#0f5f58;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#121316;--surface:#1a1c21;
--ink:#ececea;--ink-2:#b9bcc4;--ink-3:#8d919c;--line:#2e3138;--line-2:#24262c;--accent:#5fd0c4;
--accent-ink:#0b1f1d;--code:#202228;--danger:#ff8a80;--danger-bg:#3a1d1b;--warn:#f0c26a;--warn-bg:#3a2f16;
--ok:#7fd49a;--ok-bg:#1a3223;--focus:#5fd0c4;color-scheme:dark}}
:root[data-theme="dark"]{--paper:#121316;--surface:#1a1c21;--ink:#ececea;--ink-2:#b9bcc4;--ink-3:#8d919c;
--line:#2e3138;--line-2:#24262c;--accent:#5fd0c4;--accent-ink:#0b1f1d;--code:#202228;--danger:#ff8a80;
--danger-bg:#3a1d1b;--warn:#f0c26a;--warn-bg:#3a2f16;--ok:#7fd49a;--ok-bg:#1a3223;--focus:#5fd0c4;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.65 "Apple SD Gothic Neo","Malgun Gothic",
"Noto Sans KR",-apple-system,"Segoe UI",sans-serif;padding-left:max(16px,env(safe-area-inset-left,0px));
padding-right:max(16px,env(safe-area-inset-right,0px));padding-block:0 56px;-webkit-text-size-adjust:100%}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.wrap{max-width:960px;margin:0 auto}
header.top{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 0;
border-bottom:1px solid var(--line-2);flex-wrap:wrap}
.brand{font-weight:700;letter-spacing:-.01em;text-decoration:none;color:var(--ink)}
.brand small{font-weight:500;color:var(--ink-3);margin-left:8px}
nav.top a{color:var(--ink-2);text-decoration:none;margin-left:16px;font-size:14px}
nav.top a:hover{color:var(--ink)}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);margin:0 0 8px}
h1{font-size:clamp(26px,4.2vw,36px);line-height:1.2;letter-spacing:-.02em;margin:0 0 12px;text-wrap:balance}
h2{font-size:18px;margin:0 0 12px;letter-spacing:-.01em}
h3{font-size:15px;margin:18px 0 8px}
p{margin:0 0 12px;max-width:68ch}
.lede{font-size:17px;color:var(--ink-2)}
.muted{color:var(--ink-3)}
.small{font-size:13px}
.hero{padding:56px 0 28px}
.btns{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}
.btn{display:inline-flex;align-items:center;min-height:44px;padding:0 18px;border-radius:8px;border:1px solid var(--line);
background:var(--surface);color:var(--ink);font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.ghost{background:transparent}
.steps{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin:28px 0 8px;padding:0;list-style:none}
.steps li{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}
.steps b{display:block;margin-bottom:4px}
.step-no{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;background:var(--line-2);
font-size:13px;font-weight:700;margin-bottom:8px}
section.block{margin:40px 0 0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px}
.drops{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin:14px 0}
.drop{position:relative;display:block;border:1.5px dashed var(--line);border-radius:10px;padding:16px;
background:var(--paper);cursor:pointer;min-width:0}
.drop:hover{border-color:var(--ink-3)}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop b{display:block}
.drop .hint{font-size:13px;color:var(--ink-3);display:block;margin-top:4px;word-break:break-word}
.drop:focus-within{outline:2px solid var(--focus);outline-offset:2px}
.check{display:flex;gap:8px;align-items:center;margin:8px 0 4px;font-size:14px;color:var(--ink-2)}
.privacy{font-size:13px;color:var(--ink-3);margin-top:12px}
.notice{background:var(--warn-bg);color:var(--warn);border-radius:10px;padding:12px 14px;margin:0 0 16px;font-size:14px}
.verdict{border-radius:14px;padding:22px;border:1px solid var(--line);background:var(--surface);position:relative;
overflow:hidden}
.verdict:before{content:"";position:absolute;left:0;top:0;bottom:0;width:6px;background:var(--ink-3)}
.verdict.danger:before{background:var(--danger)}.verdict.warn:before{background:var(--warn)}
.verdict.ok:before{background:var(--ok)}
.verdict .word{font-size:clamp(24px,4vw,32px);font-weight:800;letter-spacing:-.02em;line-height:1.15}
.verdict.danger .word{color:var(--danger)}.verdict.warn .word{color:var(--warn)}.verdict.ok .word{color:var(--ok)}
.verdict .headline{font-size:17px;margin:8px 0 0;color:var(--ink-2)}
.figures{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:18px}
.fig{background:var(--paper);border-radius:8px;padding:10px 12px}
.fig b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
.fig span{font-size:12px;color:var(--ink-3)}
ol.actions{list-style:none;counter-reset:a;padding:0;margin:18px 0 0;display:grid;gap:10px}
ol.actions li{counter-increment:a;display:grid;grid-template-columns:auto 1fr;gap:12px;padding:12px 14px;
background:var(--paper);border-radius:10px}
ol.actions li:before{content:counter(a);display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;
background:var(--ink);color:var(--paper);font-size:13px;font-weight:700}
ol.actions .tag{font-size:12px;font-weight:700;color:var(--danger)}
ol.actions .tag.soon{color:var(--warn)}ol.actions .tag.later{color:var(--ink-3)}
ol.actions .what{font-weight:600}ol.actions .why{font-size:14px;color:var(--ink-2)}
.chip{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:0 9px;font-size:12px;margin:2px 4px 2px 0;
color:var(--ink-2);background:var(--surface)}
.sev{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700}
.sev.high{background:var(--danger-bg);color:var(--danger)}.sev.medium{background:var(--warn-bg);color:var(--warn)}
.sev.low{background:var(--ok-bg);color:var(--ok)}
.timeline{list-style:none;margin:0;padding:0 0 0 22px;border-left:2px solid var(--line)}
.timeline>li{position:relative;margin:0 0 18px;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px}
.timeline>li:before{content:"";position:absolute;left:-30px;top:20px;width:12px;height:12px;border-radius:50%;
background:var(--surface);border:2px solid var(--accent)}
.inc-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between}
.inc-head h3{margin:0;font-size:16px}
.meta{font-size:13px;color:var(--ink-3);margin:6px 0 10px}
.flow{list-style:none;padding:0;margin:8px 0 0}
.flow li{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:10px 0;border-top:1px solid var(--line-2)}
.flow time{font-size:13px;color:var(--ink-3);font-variant-numeric:tabular-nums;white-space:nowrap}
.flow .stage{font-weight:600}
.flow .what{font-size:14px;color:var(--ink-2);grid-column:2}
.flow .refs{grid-column:2}
a.ref{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;margin-right:8px;word-break:break-all}
details{margin-top:12px}
details>summary{cursor:pointer;color:var(--accent);font-weight:600;min-height:36px;display:flex;align-items:center}
.table-wrap{overflow-x:auto;margin-top:8px;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line-2)}
th{font-size:12px;color:var(--ink-3);font-weight:600;letter-spacing:.02em;text-transform:uppercase}
td code{word-break:break-all}
tr:target td{background:var(--code)}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
code{background:var(--code);padding:1px 5px;border-radius:5px}
.rules{display:grid;gap:14px;margin-top:10px}
.rule-block{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.rule-block header{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:8px 12px;
background:var(--paper);font-size:13px;font-weight:600;flex-wrap:wrap}
.copy{min-height:36px;padding:0 12px;border-radius:8px;border:1px solid var(--line);background:var(--surface);
color:var(--ink);font:inherit;font-size:13px;cursor:pointer}
.copy:hover{border-color:var(--ink-3)}
pre{margin:0;padding:12px;background:var(--code);overflow-x:auto;white-space:pre}
.tone-note{font-size:13px;color:var(--ink-3);margin:8px 0 0}
.chips-row{margin-top:6px}
.empty{text-align:center;padding:36px 16px}
footer.foot{margin-top:48px;padding-top:18px;border-top:1px solid var(--line-2);font-size:13px;color:var(--ink-3)}
@media (max-width:560px){
  .hero{padding-top:36px}
  .flow li{grid-template-columns:1fr}
  .flow .what,.flow .refs{grid-column:1}
  .timeline{padding-left:16px}
  .timeline>li:before{left:-23px}
  nav.top a{margin-left:12px}
}
@media (prefers-reduced-motion:no-preference){.btn,.drop{transition:border-color .15s,background .15s}}
"""

SCRIPT = """
document.addEventListener('click', function (ev) {
  var btn = ev.target.closest && ev.target.closest('[data-copy]');
  if (!btn) return;
  var text = btn.getAttribute('data-copy') || '';
  var done = function (msg) { btn.textContent = msg; setTimeout(function () { btn.textContent = '복사'; }, 1600); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { done('복사됨'); },
      function () { done('선택해서 복사'); });
  } else { done('선택해서 복사'); }
});
document.addEventListener('change', function (ev) {
  var input = ev.target;
  if (!input || !input.matches || !input.matches('input[type=file][data-out]')) return;
  var out = document.getElementById(input.getAttribute('data-out'));
  if (!out) return;
  var names = Array.prototype.map.call(input.files, function (f) { return f.name; });
  out.textContent = names.length ? names.join(', ') : '선택한 파일 없음';
});
"""


def _page(title: str, body: str, description: str = "") -> str:
    desc = f"<meta name=description content='{escape(description, quote=True)}'>" if description else ""
    return ("<!doctype html><html lang=ko><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{escape(title)}</title>{desc}<style>{STYLE}</style>"
            f"<div class=wrap>{body}</div><script>{SCRIPT}</script></html>")


def _top() -> str:
    return ("<header class=top><a class=brand href='/'>LogSight<small>웹서버 침해 점검</small></a>"
            "<nav class=top><a href='/web/demo'>샘플 결과</a><a href='/web'>점검하기</a></nav></header>")


def _drop(name: str, label: str, hint: str) -> str:
    out = f"out-{name}"
    return (f"<label class=drop><b>{escape(label)}</b>"
            f"<span class=hint id='{out}'>{escape(hint)}</span>"
            f"<input type=file name={name} multiple data-out='{out}'></label>")


def landing(demo: bool = False) -> str:
    """첫 화면. 데모면 업로드 칸 없이 샘플로 보내고, 아니면 로그 업로드 칸을 보여 준다."""
    if demo:
        form = (f"<div class=notice>{escape(DEMO_NOTE)}</div>"
                "<div class=btns><a class='btn primary' href='/web/demo'>샘플 점검 결과 보기</a></div>")
    else:
        form = ("<form class=panel action=/web/scan method=post enctype=multipart/form-data>"
                "<h2>로그 올리기</h2>"
                "<p class=muted>가진 로그만 올리면 됩니다. 비워 둔 칸은 건너뜁니다. .gz 파일도 됩니다.</p>"
                "<div class=drops>"
                + _drop("access", "접속 로그", "nginx 또는 Apache의 access.log")
                + _drop("weberror", "오류 로그", "error.log (선택)")
                + _drop("auth", "인증 로그", "auth.log 또는 secure (선택)")
                + "</div>"
                "<label class=check><input type=checkbox name=no_ai value=1> AI 호출 없이 규칙으로만 판정</label>"
                "<div class=btns><button class='btn primary' type=submit>점검 시작</button>"
                "<a class='btn ghost' href='/web/demo'>샘플 결과 먼저 보기</a></div>"
                "<p class=privacy>분석에만 쓰고 저장하지 않습니다. 분석이 끝나면 임시 파일도 지웁니다.</p>"
                "</form>")
    body = (_top()
            + "<section class=hero><p class=eyebrow>서버 로그 기반 침해 판단</p>"
              "<h1>웹서버, 이미 뚫렸나요?</h1>"
              "<p class=lede>접속 로그와 인증 로그를 읽어 공격이 성공했는지 판정하고, "
              "공격 흐름과 지금 해야 할 일을 보여 줍니다.</p></section>"
            + "<section class=block><ol class=steps>"
              "<li><span class=step-no>1</span><b>로그 올리기</b>접속 로그, 오류 로그, 인증 로그를 올립니다.</li>"
              "<li><span class=step-no>2</span><b>판정 받기</b>뚫렸는지, 어디까지 들어왔는지 한 장에 보여 줍니다.</li>"
              "<li><span class=step-no>3</span><b>조치하기</b>지금 할 일 순서와 차단 규칙을 복사해 씁니다.</li>"
              "</ol></section>"
            + f"<section class=block>{form}</section>"
            + "<footer class=foot>판정은 로그에 남은 흔적을 규칙으로 읽은 결과입니다. 최종 판단과 조치는 사람이 확인하세요.</footer>")
    return _page("웹서버, 이미 뚫렸나요? · LogSight", body,
                 "접속 로그와 인증 로그로 웹서버 침해 여부를 판정합니다.")


def _sev(s: str) -> str:
    return f"<span class='sev {escape(s)}'>{escape(SEV_KO.get(s, s))}</span>"


def _refs(refs, inc_id: str) -> str:
    return "".join(f'<a class=ref href="#{escape(inc_id)}-{escape(r)}">{escape(r)}</a>' for r in refs)


def _verdict(result: dict) -> str:
    v = result["overall_verdict"]
    simple = result.get("simple", {})
    headline = simple.get("headline", "")
    period = simple.get("period", "")
    figs = [(f"{result['n_events']:,}", "읽은 이벤트"), (f"{result['n_flagged']:,}", "의심 이벤트"),
            (f"{result['n_findings']:,}", "탐지 결과"), (f"{result['n_incidents']:,}", "사건")]
    fig_html = "".join(f"<div class=fig><b>{n}</b><span>{l}</span></div>" for n, l in figs)
    now = simple.get("now", [])
    actions = ""
    if now:
        rows = []
        for a in now:
            tag = {"지금": "now", "곧": "soon"}.get(a["priority"], "later")
            rows.append(f"<li><div><span class='tag {tag}'>{escape(a['priority'])}</span> "
                        f"<div class=what>{escape(a['action'])}</div>"
                        f"<div class=why>{escape(a['detail'])}</div></div></li>")
        actions = "<h3>지금 할 일</h3><ol class=actions>" + "".join(rows) + "</ol>"
    return (f"<section class=block><div class='verdict {TONE.get(v, 'ok')}'>"
            f"<p class=eyebrow style='margin:0 0 6px'>판정</p>"
            f"<div class=word>{escape(VERDICT_KO.get(v, v))}</div>"
            f"<p class=headline>{escape(headline)}</p>"
            + (f"<p class=meta style='margin-top:10px' >기간 {escape(period)}</p>" if period else "")
            + f"<div class=figures>{fig_html}</div>{actions}</div></section>")


def _incident(r: dict) -> str:
    inc, rep, meta = r["incident"], r["report"], r["meta"]
    iv = rep.get("verdict", "suspicious")
    val = meta.get("validation", {})
    check = ("근거 검증 통과" if val.get("passed")
             else f"근거 검증: 무효 {val.get('evidence_invalid', 0)}건, "
                  f"근거 없는 단계 {val.get('steps_without_evidence', 0)}건")
    stages = " ".join(f"<span class=chip>{escape(STAGE_KO.get(s, s))}</span>" for s in inc.get("stages", []))
    ips = ", ".join(inc.get("src_ips", [])[:4]) or "-"
    head = (f"<div class=inc-head><h3 id='{escape(inc['id'])}'>{escape(inc['id'])} · "
            f"{escape(VERDICT_KO.get(iv, iv))}</h3>"
            f"<div>{_sev(rep.get('severity', inc['severity']))}</div></div>")
    flow = ""
    if rep.get("attack_flow"):
        items = []
        for step in rep["attack_flow"]:
            items.append(f"<li><time>{escape(step.get('time', '')[11:19])}</time>"
                         f"<div><span class=stage>{escape(STAGE_KO.get(step['stage'], step['stage']))}</span> "
                         f"<span class=muted>{escape(step.get('technique', ''))}</span></div>"
                         f"<div class=what>{escape(step.get('what', ''))}</div>"
                         f"<div class=refs>{_refs(step.get('evidence', []), inc['id'])}</div></li>")
        flow = "<h3>공격 흐름</h3><ol class=flow>" + "".join(items) + "</ol>"
    summary = f"<p>{escape(rep.get('summary', ''))}</p>"
    unknowns = ""
    if rep.get("unknowns"):
        unknowns = ("<details><summary>확인이 필요한 점</summary><ul>"
                    + "".join(f"<li>{escape(u)}</li>" for u in rep["unknowns"]) + "</ul></details>")
    events = inc.get("events", [])
    more = f", {inc['omitted_events']}건 생략" if inc.get("omitted_events") else ""
    rows = "".join(
        f"<tr id='{escape(inc['id'])}-{escape(e['ref'])}'><td><code>{escape(e['ref'])}</code></td>"
        f"<td>{escape(e.get('ts', '')[:19])}</td><td>{escape(str(e.get('src_ip') or '-'))}</td>"
        f"<td>{escape(str(e.get('action') or '')[:90])}</td><td>{escape(str(e.get('outcome') or ''))}</td>"
        f"<td>{escape(', '.join(e.get('rules', [])))}</td></tr>" for e in events)
    evidence = (f"<details><summary>근거 로그 {len(events)}건{escape(more)}</summary><div class=table-wrap><table>"
                "<tr><th>근거 위치</th><th>시각</th><th>출발지</th><th>요청</th><th>결과</th><th>규칙</th></tr>"
                f"{rows}</table></div></details>")
    meta_line = (f"<p class=meta>출발지 {escape(ips)} · 분석 {escape(meta.get('mode', '-'))} · {escape(check)}</p>")
    return (f"<li>{head}{meta_line}<div class=chips-row>{stages}</div>{summary}{flow}{unknowns}{evidence}</li>")


def _timeline(result: dict) -> str:
    if not result["results"]:
        return ("<section class=block><div class='panel empty'><h2>뚜렷한 침해 흔적이 없습니다</h2>"
                "<p class=muted style='margin:0 auto'>분석한 로그 범위에서는 공격 흔적을 찾지 못했습니다. "
                "로그 보관 기간이 짧으면 이미 지워졌을 수 있습니다.</p></div></section>")
    items = "".join(_incident(r) for r in result["results"])
    return f"<section class=block><h2>사건 흐름</h2><ol class=timeline>{items}</ol></section>"


def _expert(result: dict) -> str:
    ex = result.get("expert") or {}
    if not ex:
        return ""
    iocs = ex.get("iocs", {})
    ip_html = ", ".join(escape(ip) for ip in iocs.get("ips", [])) or "없음"
    ua_html = "<br>".join(escape(u) for u in iocs.get("user_agents", [])[:10]) or "없음"
    path_html = "<br>".join(f"<code>{escape(p)}</code>" for p in iocs.get("paths", [])[:10]) or "없음"
    mitre = "".join(f"<tr><td><code>{escape(m['technique'])}</code></td><td>{escape(m['title'])}</td>"
                    f"<td>{escape(STAGE_KO.get(m['stage'], m['stage']))}</td></tr>" for m in ex.get("mitre", []))
    blocks = []
    labels = {"nginx": "nginx 차단 (server 또는 http 블록 안에 넣기)", "iptables": "iptables",
              "ufw": "ufw", "nginx_path": "nginx 웹셸 경로 차단 (location 블록)"}
    for key in ("nginx", "iptables", "ufw", "nginx_path"):
        lines = ex.get("block_rules", {}).get(key, [])
        if not lines:
            continue
        text = "\n".join(lines)
        blocks.append(f"<div class=rule-block><header><span>{escape(labels[key])}</span>"
                      f"<button class=copy type=button data-copy='{escape(text, quote=True)}'>복사</button></header>"
                      f"<pre>{escape(text)}</pre></div>")
    rules_html = ("".join(blocks) if blocks else "<p class=muted>자동으로 만든 차단 규칙이 없습니다.</p>")
    note = escape(ex.get("block_rules_note", ""))
    return ("<section class=block><h2>숙련자 상세</h2>"
            "<div class=panel>"
            "<h3>IOC</h3><div class=table-wrap><table><tr><th>구분</th><th>값</th></tr>"
            f"<tr><td>출발지 IP</td><td>{ip_html}</td></tr>"
            f"<tr><td>User-Agent</td><td>{ua_html}</td></tr>"
            f"<tr><td>공격 경로</td><td>{path_html}</td></tr></table></div>"
            + (f"<h3>ATT&amp;CK 매핑</h3><div class=table-wrap><table><tr><th>기법</th><th>설명</th><th>단계</th></tr>"
               f"{mitre}</table></div>" if mitre else "")
            + f"<h3>차단 규칙</h3><p class=tone-note>{note}</p><div class=rules>{rules_html}</div>"
            "</div></section>")


def _remediation(result: dict) -> str:
    rows = []
    seen = set()
    order = {"now": 0, "soon": 1, "later": 2}
    for r in result["results"]:
        inc = r["incident"]
        for c in sorted(r["report"].get("remediation", []), key=lambda x: order.get(x.get("priority"), 3)):
            key = (c.get("action"), c.get("detail"))
            if key in seen:
                continue
            seen.add(key)
            pr = c.get("priority", "later")
            rows.append(f"<tr><td class='small'>{escape(PRI_KO.get(pr, pr))}</td>"
                        f"<td>{escape(TARGET_KO.get(c.get('target'), c.get('target', '')))}</td>"
                        f"<td>{escape(c.get('action', ''))}</td><td>{escape(c.get('detail', ''))}</td>"
                        f"<td>{_refs(c.get('evidence', []), inc['id'])}</td></tr>")
    if not rows:
        return ""
    return ("<section class=block><h2>조치안 전체</h2><div class='panel'><div class=table-wrap><table>"
            "<tr><th>우선순위</th><th>대상</th><th>조치</th><th>설명</th><th>근거</th></tr>"
            + "".join(rows) + "</table></div></div></section>")


def _rules_table(result: dict) -> str:
    rows = "".join(f"<tr><td><code>{escape(rid)}</code></td><td>{escape(c.get('title', ''))}</td>"
                   f"<td>{c['findings']}</td><td>{c['events']}</td></tr>"
                   for rid, c in result["rule_counts"].items())
    return ("<section class=block><details><summary>탐지 규칙별 집계</summary><div class=table-wrap><table>"
            "<tr><th>규칙</th><th>설명</th><th>탐지</th><th>이벤트</th></tr>" + rows
            + "</table></div></details></section>")


def render(result: dict, title: str = "LogSight 웹서버 침해 점검 보고서") -> str:
    """assess() 결과를 보고서 HTML로 만든다. 외부 리소스 없이 열린다."""
    site = result.get("site", {})
    subtitle = " · ".join(x for x in (site.get("name") or "웹서버", site.get("stack") or "") if x)
    head = (f"<section class=hero style='padding-bottom:0'><p class=eyebrow>{escape(subtitle)}</p>"
            f"<h1>{escape(title)}</h1><p class=meta>생성 {escape(result['generated_at'])} · "
            f"원본 로그 {len(result.get('files', []))}개 파일</p></section>")
    body = (_top() + head + _verdict(result) + _timeline(result) + _expert(result)
            + _remediation(result) + _rules_table(result)
            + "<footer class=foot>이 보고서는 쌓인 로그와 파일만 보고 자동으로 판단한 결과입니다. "
              "조치(파일 삭제, 계정 잠금, 차단 적용)는 사람이 확인한 뒤 직접 하세요. "
              "웹 로그는 보통 요청 본문을 남기지 않아 공격 성공을 로그만으로 단정하기 어려운 경우가 있습니다.</footer>")
    return _page(title, body, "LogSight 웹서버 침해 점검 결과")

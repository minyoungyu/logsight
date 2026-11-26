"""
관리자 대시보드: 알림(디스코드·슬랙·이메일)의 링크를 누르면 열리는 화면.

    알림 → /alerts/<경보 폴더>  (한눈 요약: 등급·숫자·공격 흐름·먼저 할 일)
         → /alerts/<경보 폴더>/report  (기존 상세 보고서 report.html)
    /alerts  (지금까지 받은 경보 목록)

데이터는 `logsight watch`·`on-alert`가 경보마다 만드는 폴더(reports/alerts/<id>/)의 report.json·run.json·alert.json
에서만 읽는다. 화면의 숫자는 모두 이 파일에 있는 값이며, 없는 값은 지어내지 않고 '기록 없음'으로 보인다.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from . import PRODUCT_NAME
from .analyze import STAGE_KO
from .report import VERDICT_KO, _explain_mode, _uses_ai

# alert.handle()이 만드는 폴더 이름: 20261104_142606_guardduty_2019c894
FOLDER_RE = re.compile(r"^\d{8}_\d{6}_[a-z]+_[0-9a-f]{8}$")
SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}
SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
SOURCE_KO = {"guardduty": "GuardDuty", "cloudwatch": "CloudWatch 경보", "cloudtrail": "위험 API 호출",
             "securityhub": "Security Hub", "unknown": "기타"}
KST = timezone(timedelta(hours=9))
NONE = "<span class=dim>기록 없음</span>"


def folder(root: str | Path, name: str) -> Path | None:
    """이름이 경보 폴더 형식이고 root 바로 아래에 있으며 report.json이 있으면 그 경로. 아니면 None(경로 조작 차단)."""
    if not FOLDER_RE.match(name or ""):
        return None
    p = Path(root) / name
    return p if (p / "report.json").is_file() else None


def _read(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def load(path: Path) -> dict:
    """경보 폴더 하나를 읽는다. report: 분석 결과, run: 처리 기록, alert: 받은 경보."""
    report = _read(path / "report.json")
    run = _read(path / "run.json")
    alert = report.get("alert") or run.get("alert") or _read(path / "alert.json")
    return {"id": path.name, "report": report, "run": run, "alert": alert or {}}


def list_alerts(root: str | Path, min_severity: str = "low") -> list[dict]:
    """경보 폴더 목록(최근 것 먼저). 목록 줄에 필요한 값만 뽑는다."""
    rootp = Path(root)
    if not rootp.is_dir():
        return []
    out = []
    for p in sorted(rootp.iterdir(), reverse=True):  # 폴더 이름이 수신 시각으로 시작한다
        if not p.is_dir() or not folder(rootp, p.name):
            continue
        d = load(p)
        a, r = d["alert"], d["report"]
        if SEV_ORDER.get(a.get("severity"), 0) < SEV_ORDER.get(min_severity, 0):
            continue
        verdicts = [i.get("verdict") for i in r.get("incident_index", []) if i.get("verdict")]
        out.append({"id": p.name, "severity": a.get("severity"), "title": a.get("title", ""),
                    "source": a.get("source"), "time": a.get("time"), "received": d["run"].get("received"),
                    "n_events": r.get("n_events"), "n_incidents": r.get("n_incidents"),
                    "n_attack": verdicts.count("attack") if verdicts else None,
                    "ai": _uses_ai(_explain_mode(r)) if r else None})
    return out


# ------------------------------------------------------------------ 표시 도우미
def _num(v) -> str:
    return f"{v:,}" if isinstance(v, (int, float)) and not isinstance(v, bool) else NONE


def _when(iso: str | None, with_utc: bool = True) -> str:
    """UTC ISO → '11-04 23:26 (한국)' + UTC. 못 읽으면 '기록 없음'."""
    if not iso:
        return NONE
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return escape(str(iso))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    k = d.astimezone(KST).strftime("%Y-%m-%d %H:%M")
    u = d.astimezone(timezone.utc).strftime("%H:%M")
    return f"{k} <span class=dim>한국{f' · {u} UTC' if with_utc else ''}</span>"


def _sev(s: str | None) -> str:
    # 색만으로 구분하지 않게 글자도 함께 쓴다
    return f"<span class='sev {escape(s or '')}'>{SEV_KO.get(s or '', escape(s or '-'))}</span>"


def _tile(label: str, value: str, note: str = "") -> str:
    return (f"<div class=tile><div class=tl>{escape(label)}</div><div class=tv>{value}</div>"
            + (f"<div class=tn>{note}</div>" if note else "") + "</div>")


CSS = """
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 40px}
h1{font-size:19px;font-weight:600;margin:18px 0 6px;line-height:1.4}
h2{font-size:12px;font-weight:600;color:var(--dim);letter-spacing:.06em;margin:26px 0 8px;text-transform:uppercase}
.meta{color:var(--sub);font-size:12.5px;display:flex;gap:16px;flex-wrap:wrap}
.sev{white-space:nowrap;display:inline-block;font:600 11px var(--mono);padding:2px 8px;border:1px solid var(--dim);color:var(--fg)}
.sev.high{border-color:var(--red);color:var(--red)}.sev.medium{border-color:var(--amb);color:var(--amb)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--ln);
border:1px solid var(--ln);margin-top:14px}
.tile{background:var(--p1);padding:12px 14px}.tl{font-size:11.5px;color:var(--sub)}
.tv{font:600 22px/1.3 var(--mono);margin-top:4px}.tn{font-size:11.5px;color:var(--dim)}
.cols{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:24px}
@media (max-width:900px){.cols{grid-template-columns:1fr}}
.inc{border:1px solid var(--ln);background:var(--p1);margin-bottom:12px}
.inc>.hd{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--ln)}
.inc>.hd b{font-family:var(--mono)}.inc .sum{padding:10px 14px;color:var(--fg)}
.stages{display:flex;flex-wrap:wrap;gap:4px;align-items:center;padding:0 14px 10px;font-size:12px}
.stages span{border:1px solid var(--ln);padding:1px 8px;background:var(--p2)}.stages i{color:var(--dim);font-style:normal}
ol.flow{list-style:none;margin:0;padding:0 14px 12px}
ol.flow li{display:grid;grid-template-columns:118px 1fr;gap:10px;padding:6px 0;border-top:1px dashed var(--ln);font-size:12.5px}
ol.flow .t{font-family:var(--mono);color:var(--sub);font-size:11.5px}ol.flow .st{color:var(--cy);font-size:11.5px}
.vd{font-size:12px;padding:1px 8px;border:1px solid var(--ln)}.vd.attack{border-color:var(--red);color:var(--red)}
.act{border:1px solid var(--ln);background:var(--p1);padding:10px 14px;margin-bottom:8px}
.act .r{font-size:11.5px;color:var(--dim);font-family:var(--mono)}
.bars{border:1px solid var(--ln);background:var(--p1);padding:10px 14px}
.bars .b{display:grid;grid-template-columns:110px 1fr 54px;gap:8px;align-items:center;font-size:12px;padding:3px 0}
.bars .b>div{height:10px;background:var(--p2)}.bars .b>div>i{display:block;height:10px;background:var(--cy);border-radius:0 4px 4px 0}
.bars .b span:last-child{text-align:right;font-family:var(--mono)}
.btn{display:inline-block;margin-top:14px;padding:9px 18px;font:600 13px var(--mono);border:1px solid var(--red);
background:var(--red);color:#111;text-decoration:none}.btn:hover{background:transparent;color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:10px}
th{white-space:nowrap;text-align:left;font-weight:500;color:var(--dim);font-size:11.5px;border-bottom:1px solid var(--ln);padding:6px 8px}
td{border-bottom:1px solid var(--ln);padding:8px;vertical-align:top}tr.go:hover td{background:var(--p2)}
td.n,td.w{white-space:nowrap}td.n{font-family:var(--mono);text-align:right}
.src{font-size:11.5px;color:var(--dim);margin-top:28px;border-top:1px solid var(--ln);padding-top:10px}
.flt a{margin-right:10px;font-size:12px}.flt a.on{color:var(--fg);font-weight:600;text-decoration:none}
.empty{border:1px dashed var(--ln);padding:18px;color:var(--sub);margin-top:14px}
"""


def _page(css: str, bar: str, title: str, body: str) -> str:
    return (f"<!doctype html><html lang=ko><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{escape(title)} · {PRODUCT_NAME}</title><style>{css}{CSS}</style>{bar}<div class=wrap>{body}</div></html>")


# ------------------------------------------------------------------ 경보 목록
def render_index(items: list[dict], css: str, bar: str, min_severity: str = "low", sample: bool = False) -> str:
    flt = "".join(f"<a href='/alerts?min={k}' class='{'on' if k == min_severity else ''}'>{v}</a>"
                  for k, v in (("low", "전체"), ("medium", "중간 이상"), ("high", "높음만")))
    rows = []
    for it in items:
        ai = {True: "AI", False: "규칙", None: NONE}[it["ai"]]
        rows.append(f"<tr class=go><td>{_sev(it['severity'])}</td>"
                    f"<td><a href='/alerts/{it['id']}'>{escape(it['title'][:140])}</a><div class=dim>"
                    f"{escape(SOURCE_KO.get(it['source'] or '', it['source'] or '-'))}</div></td>"
                    f"<td class=w>{_when(it['received'], False)}</td><td class=n>{_num(it['n_events'])}</td>"
                    f"<td class=n>{_num(it['n_incidents'])}</td><td class=n>{_num(it['n_attack'])}</td><td class=w>{ai}</td></tr>")
    table = ("<table><tr><th>등급</th><th>경보</th><th>받은 시각</th><th style='text-align:right'>이벤트</th>"
             "<th style='text-align:right'>사건</th><th style='text-align:right'>공격 의심</th><th>설명</th></tr>"
             + "".join(rows) + "</table>") if rows else (
        "<div class=empty>아직 받은 경보가 없습니다. <span class=m>python -m logsight watch ... --out reports/alerts</span>로 "
        "경보를 받으면 여기에 쌓입니다. 시험: <span class=m>python -m logsight on-alert samples/alerts/guardduty_event.json "
        "--logs samples/demo --no-ai</span></div>")
    sample_link = ("<p class=sub>합성 데이터로 만든 <a href='/alerts/sample'>샘플 경보 화면</a>도 볼 수 있습니다.</p>"
                   if sample else "")
    body = (f"<h1>받은 경보</h1><div class='meta flt'>{flt}<span>{len(items)}건</span></div>{table}{sample_link}"
            "<div class=src>숫자는 경보 폴더마다 있는 report.json(이벤트·사건·판정)과 run.json(받은 시각)에서 그대로 읽습니다.</div>")
    return _page(css, bar, "받은 경보", body)


# ------------------------------------------------------------------ 경보 하나
def _incident(row: dict, verdicts: dict) -> str:
    inc, rep = row.get("incident", {}), row.get("report", {})
    iid = inc.get("id", "")
    v = verdicts.get(iid, {})
    vd = v.get("verdict") or rep.get("verdict")
    by = {"rules": "규칙 판정", "claude": "Claude 판정"}.get(v.get("verdict_by") or "", "")
    stages = "<i>→</i>".join(f"<span>{escape(STAGE_KO.get(s, s))}</span>" for s in inc.get("stages", []))
    flow = "".join(
        f"<li><span class=t>{_when(f.get('time'), False) if f.get('time') else NONE}</span><span>"
        f"<span class=st>{escape(STAGE_KO.get(f.get('stage', ''), f.get('stage', '')))}"
        f"{' · ' + escape(f['technique']) if f.get('technique') else ''}</span><br>{escape(f.get('what', ''))}</span></li>"
        for f in rep.get("attack_flow", [])[:8])
    more = len(rep.get("attack_flow", [])) - 8
    ips = ", ".join(inc.get("src_ips", [])[:3])
    return (f"<div class=inc><div class=hd><b>{escape(iid)}</b>{_sev(inc.get('severity'))}"
            + (f"<span class='vd {escape(vd)}'>{escape(VERDICT_KO.get(vd, vd))}</span>" if vd else "")
            + (f"<span class=dim>{by}</span>" if by else "")
            + f"<span class=dim>이벤트 {_num(inc.get('n_events'))}건"
            + (f" · 출발지 {escape(ips)}" if ips else "") + "</span></div>"
            + (f"<div class=sum>{escape(rep['summary'])}</div>" if rep.get("summary") else "")
            + (f"<div class=stages>{stages}</div>" if stages else "")
            + (f"<ol class=flow>{flow}</ol>" if flow else "")
            + (f"<div class='dim' style='padding:0 14px 10px;font-size:12px'>공격 흐름 {more}단계 더: 상세 보고서</div>"
               if more > 0 else "") + "</div>")


def render_alert(d: dict, css: str, bar: str, report_href: str, note: str = "") -> str:
    a, r, run = d["alert"], d["report"], d["run"]
    mode = _explain_mode(r) if r else {"report": "rules", "triage": "rules"}
    verdicts = {i.get("id"): i for i in r.get("incident_index", [])}
    n_attack = sum(1 for i in r.get("incident_index", []) if i.get("verdict") == "attack")
    sc = r.get("severity_counts") or {}
    took = run.get("received_to_report_s")
    tiles = "".join([
        _tile("읽은 이벤트", _num(r.get("n_events"))),
        _tile("규칙에 걸린 이벤트", _num(r.get("n_flagged"))),
        _tile("사건", _num(r.get("n_incidents")),
              " · ".join(f"{SEV_KO[k]} {sc[k]}" for k in ("high", "medium", "low") if isinstance(sc.get(k), int))),
        _tile("공격 의심 사건", _num(n_attack) if r.get("incident_index") is not None else NONE),
        _tile("받은 뒤 보고서까지", f"{took:,}초" if isinstance(took, (int, float)) else NONE,
              "분석 서버가 경보를 받은 시각 기준"),
        _tile("설명 방식", "Claude" if _uses_ai(mode) else "규칙", "AI를 쓰지 않음" if not _uses_ai(mode) else ""),
    ])
    rows = r.get("results", [])
    incs = "".join(_incident(x, verdicts) for x in rows) or "<div class=empty>묶인 사건이 없습니다.</div>"
    hidden = (r.get("n_incidents") or 0) - len(rows)
    if hidden > 0:
        incs += f"<p class=sub>설명을 쓴 상위 {len(rows)}개만 보입니다. 나머지 {hidden}개는 상세 보고서의 사건 목록에 있습니다.</p>"
    acts, seen = [], set()
    for x in rows:
        for c in x.get("checks", []):
            t = c.get("title")
            if t and t not in seen:
                seen.add(t)
                acts.append(f"<div class=act>{_sev(c.get('severity'))} {escape(t)}<div class=r>"
                            f"{escape(c.get('resource', ''))} · 수정·되돌리기 명령은 상세 보고서</div></div>")
    acts_html = "".join(acts[:6]) or "<div class=empty>설정 점검 결과가 없습니다(environment.json 없이 분석했을 수 있습니다).</div>"
    src = r.get("events_by_source") or {}
    mx = max(src.values(), default=0) or 1
    bars = "".join(f"<div class=b title='{escape(k)}: {v:,}건'><span>{escape(k)}</span><div><i style='width:{v / mx * 100:.1f}%'></i></div>"
                   f"<span>{v:,}</span></div>" for k, v in sorted(src.items(), key=lambda kv: -kv[1]) if isinstance(v, int))
    chans = run.get("notify_channels") or []
    sent = "".join(f"<div class=b><span>{escape(str(c.get('channel')))}</span><span>"
                   + ("보냄" if c.get("ok") else ("건너뜀: " + escape(str(c.get("skipped"))) if c.get("skipped")
                                                 else "실패: " + escape(str(c.get("error") or c.get("status") or ""))))
                   + "</span></div>" for c in chans)
    meta = (f"<div class=meta>{_sev(a.get('severity'))}<span>{escape(SOURCE_KO.get(a.get('source', ''), a.get('source', '-')))}</span>"
            f"<span>경보 시각 {_when(a.get('time'))}</span><span>받은 시각 {_when(run.get('received'))}</span>"
            f"<span>계정 {escape(a.get('account') or '-')} {escape(a.get('region') or '')}</span></div>")
    win = run.get("window") or []
    body = (
        "<p class=sub style='margin:14px 0 0'><a href='/alerts'>← 받은 경보</a></p>"
        + (f"<div class=demo style='margin-top:10px;border:1px solid var(--ln)'>{note}</div>" if note else "")
        + f"<h1>{escape(a.get('title') or '경보')}</h1>{meta}<div class=tiles>{tiles}</div>"
        + f"<a class=btn href='{escape(report_href)}'>상세 보고서 열기 →</a>"
        + f"<div class=cols><div><h2>사건과 공격 흐름</h2>{incs}</div><div>"
        + f"<h2>먼저 고칠 설정</h2>{acts_html}"
        + (f"<h2>로그 종류별 이벤트</h2><div class=bars>{bars}</div>" if bars else "")
        + (f"<h2>알림 보낸 곳</h2><div class=bars>{sent}</div>" if sent else "")
        + "</div></div>"
        + "<div class=src>이 화면의 숫자와 문장은 모두 이 경보 폴더의 report.json(분석 결과)·run.json(처리 기록)에서 그대로 읽었습니다."
        + (f" 분석 기간 {escape(win[0])} ~ {escape(win[1])}." if len(win) == 2 else "")
        + " 수정 명령은 자동으로 적용되지 않습니다.</div>")
    return _page(css, bar, a.get("title") or "경보", body)

"""같은 사건을 여러 설명 방식(규칙만 / 규칙+정상 작업 목록 / Claude)으로 나란히 보여 주는 비교 화면.

입력은 이미 만들어진 결과 파일이다. 이 스크립트는 AI를 부르지 않는다.
- 공방전 채점 결과(scripts/ctf/eval_gongbang.py 출력): 키 rule_triage 또는 ai_triage
- 분석 결과(report.json): 키 rule_triage 또는 triage

예)
  python scripts/compare_modes.py \\
    --col "규칙만=reports/ctf/gongbang_rules_v3.json:rule_triage" \\
    --col "규칙+정상 작업 목록=reports/ctf/gongbang_rules_v3_known.json:rule_triage" \\
    --col "Claude=reports/ctf/gongbang_ai_v2.json:ai_triage" \\
    --title "공방전 로그: 규칙 vs Claude" --out reports/ctf/compare.html

채점 결과 파일에는 정답(블루팀 보고서 기준)이 있어 맞음·틀림과 첫 공격 사건 순위를 함께 보여 준다.
"""
from __future__ import annotations

import argparse
import json
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import RULES  # noqa: E402
from logsight.report import CSS as REPORT_CSS  # noqa: E402

VKO = {"attack": "공격 의심", "risky_not_attack": "공격 아님·위험 설정",
       "unclear": "판단 불가", "benign_activity": "정상 활동"}
RANK = {"attack": 0, "risky_not_attack": 1, "unclear": 2, "benign_activity": 3}

CSS = REPORT_CSS + """
main.cmp{max-width:1240px;margin:0 auto;padding:0 16px 72px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.score b.big{font-size:30px;line-height:1.2;font-variant-numeric:tabular-nums}.score .lab{font-size:12.5px;color:var(--muted)}
.score .row2{display:flex;gap:18px;align-items:flex-end;margin-top:10px}.score.best{border-color:var(--accent)}
table.cmp{min-width:900px}table.cmp td:first-child{width:180px;min-width:180px}table.cmp td{font-size:13px}.ok{color:var(--low);font-weight:700}.ng{color:var(--high);font-weight:700}
.rsn{font-size:12.5px;margin-top:4px;color:var(--muted);overflow-wrap:anywhere}td.truth{white-space:nowrap;font-weight:600}
"""


def load_col(spec: str) -> dict:
    label, _, rest = spec.partition("=")
    path, _, key = rest.rpartition(":")
    if not path:  # 키를 안 적었으면 파일 전체에서 고른다
        path, key = rest, ""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    obj = data.get(key) if key else (data.get("triage") or data.get("rule_triage"))
    if not obj:
        raise SystemExit(f"{path}에 {key or 'triage'} 결과가 없습니다")
    raw = obj.get("raw", obj)
    mode = "rules" if obj.get("model") == "rules" or raw.get("mode") == "rules" \
        or (obj.get("meta") or {}).get("model") == "rules" else "claude"
    return {"label": label, "path": path, "data": data, "score": obj if "raw" in obj else None,
            "verdicts": {x["id"]: x for x in raw.get("incidents", [])},
            "cannot_tell": raw.get("cannot_tell", []), "campaigns": raw.get("campaigns", []),
            "mode": mode, "model": obj.get("model") or (obj.get("meta") or {}).get("model")}


def incidents_of(data: dict) -> list[dict]:
    if "incidents" in data and isinstance(data["incidents"], dict):  # 채점 결과
        return data["incidents"]["top10"]
    return data.get("incident_index", [])


def _txt(x) -> str:
    return x if isinstance(x, str) else x.get("what") or json.dumps(x, ensure_ascii=False)


def render(cols: list[dict], title: str, notes: list[str]) -> str:
    incs = incidents_of(cols[0]["data"])
    truth = {}
    for c in cols:
        for v in (c["score"] or {}).get("verdicts", []):
            truth[v["id"]] = v["is_attack"]
    has_truth = bool(truth)
    h = [f"<!doctype html><html lang=ko><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>{escape(title)}</title><style>{CSS}</style><header class=top><div class=brand>LogSight · 설명 방식 비교</div>"
         f"<h1>{escape(title)}</h1><div class=metaline><span>같은 사건을 설명 방식만 바꿔 판정한 결과입니다. "
         "탐지 규칙과 사건 묶기는 모든 열이 같습니다.</span></div></header><main class=cmp>"]

    # 점수판
    h.append("<div class=grid style='margin-top:14px'>")
    for c in cols:
        sc = c["score"] or {}
        ai = c["mode"] == "claude"
        h.append(f"<div class='card score'><span class='pill {'ai' if ai else 'rules'}'>"
                 f"{'Claude 사용' if ai else 'AI 사용 안 함'}</span><div style='margin-top:8px'><b>{escape(c['label'])}</b></div>"
                 "<div class='small muted'>" + ("Claude " + escape(str(c.get("model") or "")) + " · 가린 사건 요약만 외부로 전송"
                    if ai else "로그가 밖으로 나가지 않음 · 항상 같은 결과") + "</div>")
        if sc.get("verdict_accuracy"):
            h.append(f"<div class=row2><div><div class=lab>판정 맞음</div><b class=big>{escape(sc['verdict_accuracy'])}</b></div>"
                     f"<div><div class=lab>첫 공격 사건</div><b class=big>{sc.get('rank_of_first_attacker_incident_after')}위</b></div></div>")
        h.append("</div>")
    h.append("</div>")
    if notes:
        h.append("<div class='card note small'><ul>" + "".join(f"<li>{escape(n)}</li>" for n in notes) + "</ul></div>")

    # 사건별 비교
    h.append("<h2>사건별 판정</h2><div class='card tablewrap' style='padding:0'><table class=cmp><tr><th>사건</th>"
             + "".join(f"<th>{escape(c['label'])}</th>" for c in cols)
             + ("<th style='white-space:nowrap'>정답</th>" if has_truth else "") + "</tr>")
    for inc in incs:
        iid = inc["id"]
        rules = ", ".join(dict.fromkeys(RULES.get(r, ("", "", r))[2] for r in inc.get("rules", [])))
        h.append(f"<tr><td><b>{escape(iid)}</b><div class=muted style='font-size:12.5px'>{escape(rules)}"
                 f"<br>이벤트 {inc.get('n_events', '?')}건</div></td>")
        for c in cols:
            v = c["verdicts"].get(iid)
            if not v:
                h.append("<td class=muted>-</td>")
                continue
            mark = ""
            if iid in truth:
                ok = v["verdict"] == "attack" if truth[iid] else v["verdict"] in ("benign_activity", "risky_not_attack")
                mark = " <span class=ok>맞음</span>" if ok else " <span class=ng>틀림</span>"
            h.append(f"<td><span class='vd {escape(v['verdict'])}'>{VKO.get(v['verdict'], v['verdict'])}</span>{mark}"
                     f"<div class=rsn>{escape(v.get('reason', ''))}</div></td>")
        if has_truth:
            t = truth.get(iid)
            h.append(f"<td class=truth>{'공격' if t else '공격 아님' if t is not None else '-'}</td>")
        h.append("</tr>")
    h.append("</table></div>")
    if has_truth:
        h.append("<div class='small faint'>정답: 사건 이벤트의 절반 이상이 블루팀 보고서의 공격자 활동이면 공격. "
                 "'판단 불가'는 틀린 것으로 셉니다.</div>")

    # 알 수 없는 것
    h.append("<h2>이 로그로는 알 수 없는 것</h2><div class=grid>")
    for c in cols:
        items = c["cannot_tell"]
        h.append(f"<div class=card><b>{escape(c['label'])}</b> <span class=muted>{len(items)}개</span><ul>"
                 + "".join(f"<li>{escape(_txt(x))}</li>" for x in items[:12]) + "</ul></div>")
    h.append("</div>")

    # 공격 연결
    h.append("<h2>같은 공격으로 묶은 사건</h2><div class=grid>")
    for c in cols:
        camps = [x for x in c["campaigns"] if len(x.get("incident_ids", [])) > 1]
        body = "".join(f"<li><b>{escape(', '.join(x['incident_ids']))}</b>: {escape(x.get('link_reason', ''))}</li>"
                       for x in camps) or "<li class=muted>없음</li>"
        h.append(f"<div class=card><b>{escape(c['label'])}</b><ul>{body}</ul></div>")
    h.append("</div><footer>LogSight · 입력: " + ", ".join(escape(c["path"]) for c in cols) + "</footer></main></html>")
    return "".join(h)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔에서 한글 출력
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--col", action="append", required=True, help="'이름=파일:키' (여러 번)")
    ap.add_argument("--title", default="설명 방식 비교: 규칙 vs Claude")
    ap.add_argument("--note", action="append", default=[], help="점수판 아래에 적을 설명(여러 번)")
    ap.add_argument("--out", default="compare.html")
    a = ap.parse_args()
    cols = [load_col(s) for s in a.col]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(render(cols, a.title, a.note), encoding="utf-8")
    print(f"비교 화면: {a.out}")


if __name__ == "__main__":
    main()

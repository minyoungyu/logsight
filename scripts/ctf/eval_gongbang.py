"""
공방전 로그로 LogSight(규칙 + 사건 묶기)를 채점한다.

정답지는 블루팀 최종 보고서(2026-10-12)의 사건 타임라인에서 만들었다. 규칙을 고치기 전에
정답지를 먼저 고정했고, 이 데이터로 규칙을 바꾸지 않는다.

  python scripts/ctf/eval_gongbang.py --data data/gongbang --gt reports/ctf/gongbang_ground_truth.json \
      --out reports/ctf/gongbang_rules_only.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import load_paths  # noqa: E402
from logsight.triage import reorder, triage  # noqa: E402


KST = timezone(timedelta(hours=9))


def fingerprint(e) -> tuple:
    """통합로그에는 같은 행이 여러 번 들어 있다. 원본 이벤트 ID가 없어 같은 초에 실제로 두 번 일어난
    호출과 복사된 행을 구별할 수 없으므로, 행 기준과 이 지문 기준을 함께 보고한다."""
    return (e.source, e.ts, e.action, e.src_ip, e.actor, e.access_key, e.outcome,
            e.extra.get("params"), e.extra.get("errorCode"), e.extra.get("elb_status"))


def uniq(evs) -> int:
    return len({fingerprint(e) for e in evs})


def is_attacker(e, gt) -> bool:
    return e.src_ip in gt["attacker_ips"] or e.access_key in gt["attacker_keys"]


def match(e, m: dict, gt) -> bool:
    if e.source != m["source"]:
        return False
    if m.get("attacker_ip") and e.src_ip not in gt["attacker_ips"]:
        return False
    if m.get("attacker_key") and e.access_key not in gt["attacker_keys"]:
        return False
    if "outcome" in m and e.outcome != m["outcome"]:
        return False
    if "action_prefix" in m and not (e.action or "").startswith(tuple(m["action_prefix"])):
        return False
    if "action_contains" in m and m["action_contains"] not in (e.action or ""):
        return False
    t = e.ts.astimezone(KST).strftime("%H:%M:%S")
    if "from_kst" in m and t < m["from_kst"]:
        return False
    if "to_kst" in m and t > m["to_kst"]:
        return False
    return True


def category(e) -> str:
    a = e.actor or ""
    if "blue-team" in a:
        return "블루팀 대응 작업"
    if ":root" in a:
        return "루트 계정 사용"
    if e.extra.get("identity_type") in ("AWSService",) or (e.src_ip or "").endswith("amazonaws.com"):
        return "AWS 서비스 자체 호출"
    if "assumed-role" in a:
        return "서비스 역할(정상 운영)"
    return "기타"


def score_triage(inc_rows: list[dict], tri: dict | None, incidents: list[dict]) -> dict:
    """AI 재검토 채점. 공격자 이벤트가 절반 이상인 사건은 attack이 정답, 나머지는
    benign_activity 또는 risky_not_attack이 정답이다. unclear는 틀린 것으로 센다."""
    if not tri or "incidents" not in tri:
        return {"ran": False, "error": (tri or {}).get("error")}
    truth = {r["id"]: r["n_attacker_events"] * 2 >= r["n_events"] and r["n_attacker_events"] > 0
             for r in inc_rows}
    verdict = {v["id"]: v["verdict"] for v in tri["incidents"]}
    rows, correct = [], 0
    for r in inc_rows:
        v = verdict.get(r["id"], "unclear")
        ok = v == "attack" if truth[r["id"]] else v in ("benign_activity", "risky_not_attack")
        correct += ok
        rows.append({"id": r["id"], "is_attack": truth[r["id"]], "verdict": v, "correct": ok})
    attack_ids = {i for i, t in truth.items() if t}
    camps = [set(c["incident_ids"]) for c in tri.get("campaigns", [])]
    best = max(camps, key=lambda c: len(c & attack_ids), default=set())
    ordered = reorder([dict(i) for i in incidents], tri)
    return {
        "ran": True, "model": tri["meta"]["model"], "usage": tri["meta"]["usage"],
        "validation": tri["validation"],
        "verdict_accuracy": f"{correct}/{len(inc_rows)}", "verdicts": rows,
        "rank_of_first_attacker_incident_after": next(
            (n + 1 for n, i in enumerate(ordered) if truth.get(i["id"])), None),
        "campaign": {"attack_incidents": sorted(attack_ids),
                     "best_campaign": sorted(best),
                     "covers_all_attack_incidents": attack_ids <= best,
                     "includes_non_attack": sorted(best - attack_ids)},
        "raw": {k: tri[k] for k in ("incidents", "campaigns", "cannot_tell")},
    }


def evaluate(data: Path, gt: dict, use_ai: bool = False, model: str | None = None) -> dict:
    events, _ = load_paths([data])
    findings = run_detections(events)
    incidents = build_incidents(events, findings, max_events=10**9)
    lm = json.loads((data / "linemap.json").read_text())

    def md_line(ref: str) -> int | None:
        name, _, n = ref.rpartition(":")
        kind = name.split(".")[0]
        try:
            return lm[kind][int(n) - 1]
        except (KeyError, IndexError, ValueError):
            return None

    att = [e for e in events if is_attacker(e, gt)]
    ben = [e for e in events if not is_attacker(e, gt)]
    tp = sum(1 for e in att if e.findings)
    fp_events = [e for e in ben if e.findings]

    # 공격 단계별: 데이터에 있는가, 규칙이 표시했는가, 어느 사건에 들어갔는가
    inc_of: dict[int, str] = {}
    for inc in incidents:
        for ev in inc["events"]:
            inc_of[ev["ref"]] = inc["id"]
    stages = []
    for st in gt["stages"]:
        if not st.get("match"):
            stages.append({"id": st["id"], "title": st["title"], "in_data": False,
                           "why_missing": st.get("why_missing")})
            continue
        hits = [e for e in events if match(e, st["match"], gt)]
        flagged = [e for e in hits if e.findings]
        stages.append({
            "id": st["id"], "title": st["title"], "in_data": bool(hits), "n_events": len(hits),
            "n_events_unique": uniq(hits), "n_flagged": len(flagged),
            "n_flagged_unique": uniq(flagged), "detected": bool(flagged),
            "rules": sorted({r for e in flagged for r in e.findings}),
            "incidents": sorted({inc_of[e.raw_ref] for e in flagged if e.raw_ref in inc_of}),
            "evidence_md_lines": [md_line(e.raw_ref) for e in hits[:10]],
        })

    att_refs = {e.raw_ref for e in att}
    inc_rows = []
    for inc in incidents:
        refs = [ev["ref"] for ev in inc["events"]]
        n_att = sum(r in att_refs for r in refs)
        inc_rows.append({"id": inc["id"], "severity": inc["severity"], "stages": inc["stages"],
                         "start": inc["start"], "end": inc["end"], "n_events": len(refs),
                         "n_attacker_events": n_att,
                         "rules": sorted({f["rule"] for f in inc["findings"]}),
                         "sources": inc["sources"]})
    att_incs = [r for r in inc_rows if r["n_attacker_events"]]
    tri = triage(incidents, model=model) if use_ai else None

    return {
        "data": {"n_events": len(events), "n_events_unique": uniq(events),
                 "by_source": dict(Counter(e.source for e in events)),
                 "n_attacker_events": len(att), "n_attacker_events_unique": uniq(att),
                 "n_benign_events": len(ben)},
        "event_level": {
            "attacker_flagged": tp, "attacker_missed": len(att) - tp,
            "recall": round(tp / len(att), 3) if att else None,
            "benign_flagged": len(fp_events),
            "attacker_flagged_unique": uniq([e for e in att if e.findings]),
            "benign_flagged_unique": uniq(fp_events),
            "benign_flagged_unique_by_category": dict(Counter(
                category(e) for e in {fingerprint(e): e for e in fp_events}.values())),
            "precision": round(tp / (tp + len(fp_events)), 3) if tp + len(fp_events) else None,
            "benign_flagged_by_category": dict(Counter(category(e) for e in fp_events)),
            "benign_flagged_by_rule": dict(Counter(r for e in fp_events for r in e.findings)),
            "attacker_flagged_by_rule": dict(Counter(r for e in att if e.findings for r in e.findings)),
        },
        "stages": stages,
        "incidents": {
            "n_total": len(incidents), "n_with_attacker": len(att_incs),
            "n_attacker_only_or_mostly": sum(1 for r in att_incs
                                             if r["n_attacker_events"] * 2 >= r["n_events"]),
            "rank_of_first_attacker_incident": next(
                (i + 1 for i, r in enumerate(inc_rows) if r["n_attacker_events"]), None),
            "attacker_incidents": att_incs,
            "top10": inc_rows[:10],
        },
        "rules_fired": {f.rule: sum(1 for x in findings if x.rule == f.rule) for f in findings},
        **({"ai_triage": score_triage(inc_rows, tri, incidents)} if use_ai else {}),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/gongbang")
    ap.add_argument("--gt", default="reports/ctf/gongbang_ground_truth.json")
    ap.add_argument("--out")
    ap.add_argument("--ai", action="store_true", help="AI 재검토까지 돌려 채점(ANTHROPIC_API_KEY 필요)")
    ap.add_argument("--model", help="재검토 모델(기본 logsight.triage.TRIAGE_MODEL)")
    a = ap.parse_args()
    gt = json.loads(Path(a.gt).read_text(encoding="utf-8"))
    res = evaluate(Path(a.data), gt, use_ai=a.ai, model=a.model)
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

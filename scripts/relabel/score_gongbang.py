#!/usr/bin/env python3
"""다시 붙인 줄 단위 라벨(label_gongbang.py 출력)로 LogSight 규칙 결과를 채점한다.

라벨은 엔진 결과를 보지 않고 만들었고, 이 스크립트에서 처음 엔진을 돌린다.
uncertain 줄은 재현율·정밀도 계산에서 빼고, 모두 공격/모두 정상으로 볼 때의 범위를 함께 낸다.

  python scripts/relabel/score_gongbang.py --data data/gongbang \
      --labels reports/relabel/gongbang_labels.jsonl --out reports/relabel/gongbang_score.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ctf"))

from eval_gongbang import fingerprint  # noqa: E402
from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.explain import mark_known, rule_triage  # noqa: E402
from logsight.normalize import load_paths  # noqa: E402


def rate(a, b):
    return round(a / b, 3) if b else None


def score(data: Path, labels: dict[str, dict], env: dict | None = None) -> dict:
    events, _ = load_paths([data])
    mark_known(events, env or {})
    findings = run_detections(events)
    incidents = build_incidents(events, findings, max_events=10**9)
    cls = {e.raw_ref: labels[e.raw_ref]["class"] for e in events}
    assert len(cls) == len(labels), "라벨 줄 수와 이벤트 수가 다르다"

    def group(c):
        return [e for e in events if cls[e.raw_ref] == c]

    att, nor, unc = group("attack"), group("normal"), group("uncertain")
    f = lambda xs: [e for e in xs if e.findings]  # noqa: E731
    uq = lambda xs: len({fingerprint(e) for e in xs})  # noqa: E731
    tp, fp, uf = len(f(att)), len(f(nor)), len(f(unc))
    ev = {
        "n": {"attack": len(att), "normal": len(nor), "uncertain": len(unc)},
        "n_unique": {"attack": uq(att), "normal": uq(nor), "uncertain": uq(unc)},
        "flagged": {"attack": tp, "normal": fp, "uncertain": uf},
        "flagged_unique": {"attack": uq(f(att)), "normal": uq(f(nor)), "uncertain": uq(f(unc))},
        "recall": rate(tp, len(att)), "precision": rate(tp, tp + fp),
        "fp_rate_normal": rate(fp, len(nor)),
        "bounds_if_uncertain_all_attack": {"recall": rate(tp + uf, len(att) + len(unc)),
                                           "precision": rate(tp + uf, tp + uf + fp)},
        "bounds_if_uncertain_all_normal": {"recall": rate(tp, len(att)), "precision": rate(tp, tp + fp + uf),
                                           "fp_rate_normal": rate(fp + uf, len(nor) + len(unc))},
        "normal_flagged_by_rule": dict(Counter(r for e in f(nor) for r in e.findings)),
        "normal_flagged_by_label_rule": dict(Counter(labels[e.raw_ref]["rules"]["normal"][0] for e in f(nor))),
        "uncertain_flagged_by_rule": dict(Counter(r for e in f(unc) for r in e.findings)),
        "attack_flagged_by_rule": dict(Counter(r for e in f(att) for r in e.findings)),
    }
    steps = {}
    for lab in sorted({l for x in labels.values() for l in x["labels"]}):
        xs = [e for e in att if lab in labels[e.raw_ref]["labels"]]
        steps[lab] = {"n": len(xs), "flagged": len(f(xs)), "rules": sorted({r for e in f(xs) for r in e.findings})}
    inc_rows = []
    for inc in incidents:
        refs = [x["ref"] for x in inc["events"]]
        c = Counter(cls[r] for r in refs)
        inc_rows.append({"id": inc["id"], "n_events": len(refs), "attack": c["attack"], "normal": c["normal"],
                         "uncertain": c["uncertain"], "rules": sorted({x["rule"] for x in inc["findings"]})})
    truth = {r["id"]: ("attack" if r["attack"] * 2 >= r["n_events"] and r["attack"] else
                       "uncertain" if r["uncertain"] * 2 >= r["n_events"] else "not_attack") for r in inc_rows}
    tri = rule_triage(incidents, events)
    verdict = {v["id"]: v["verdict"] for v in tri.get("incidents", [])}
    judged = [(i, t, verdict.get(i, "unclear")) for i, t in truth.items() if t != "uncertain"]
    correct = sum((v == "attack") if t == "attack" else v in ("benign_activity", "risky_not_attack")
                  for _, t, v in judged)
    return {
        "event_level": ev, "steps": steps,
        "incidents": {"rows": inc_rows, "truth": truth,
                      "rank_of_first_attack_incident": next((n + 1 for n, r in enumerate(inc_rows)
                                                             if truth[r["id"]] == "attack"), None),
                      "rule_triage_accuracy": f"{correct}/{len(judged)}",
                      "rule_triage_excluded_uncertain": [i for i, t in truth.items() if t == "uncertain"],
                      "rule_triage_verdicts": {i: {"truth": t, "verdict": v} for i, t, v in judged}},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/gongbang")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--env")
    ap.add_argument("--out")
    a = ap.parse_args()
    labels = {}
    for line in Path(a.labels).read_text(encoding="utf-8").splitlines():
        x = json.loads(line)
        labels[x["ref"]] = x
    env = json.loads(Path(a.env).read_text(encoding="utf-8")) if a.env else None
    res = score(Path(a.data), labels, env)
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

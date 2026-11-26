#!/usr/bin/env python3
"""다시 붙인 BOTSv3 줄 라벨(label_botsv3.py 출력)로 LogSight 규칙 결과를 채점한다.

엔진은 한 줄에서 이벤트를 0개(읽지 않음) 또는 1개 이상 만들 수 있다. 채점은 줄 단위다:
그 줄에서 나온 이벤트 중 하나라도 탐지 규칙에 걸리면 '표시됨'으로 센다.

  python scripts/relabel/score_botsv3.py --data <꺼낸 로그 폴더> --labels reports/relabel/botsv3_labels.jsonl \
      [--env reports/remeasure_2026-11-26/botsv3/staff_list.json] --out reports/relabel/botsv3_score.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from logsight import normalize  # noqa: E402
from logsight.correlate import build_incidents  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.explain import mark_known, rule_triage  # noqa: E402


def rate(a, b):
    return round(a / b, 4) if b else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--env")
    ap.add_argument("--year", type=int, default=2018)
    ap.add_argument("--out")
    a = ap.parse_args()
    labels = {}
    raw = Path(a.labels).read_bytes()
    if a.labels.endswith(".gz"):
        import gzip
        raw = gzip.decompress(raw)
    for line in raw.decode("utf-8").splitlines():
        x = json.loads(line); labels[x["ref"]] = x
    normalize.SYSLOG["year"] = a.year
    events, _ = normalize.load_paths([Path(a.data)])
    env = json.loads(Path(a.env).read_text(encoding="utf-8")) if a.env else {}
    mark_known(events, env)
    findings = run_detections(events)
    incidents = build_incidents(events, findings)

    by_ref: dict[str, list] = defaultdict(list)
    for e in events:
        by_ref[e.raw_ref].append(e)
    missing_refs = sorted({r for r in by_ref if r not in labels})
    flagged_rules = {r: sorted({x for e in evs for x in e.findings}) for r, evs in by_ref.items()}

    cls_n, cls_flag, cls_read = Counter(), Counter(), Counter()
    rules_by_cls: dict[str, Counter] = defaultdict(Counter)
    for ref, x in labels.items():
        c = x["class"]; cls_n[c] += 1
        if ref in by_ref:
            cls_read[c] += 1
        if flagged_rules.get(ref):
            cls_flag[c] += 1
            rules_by_cls[c].update(flagged_rules[ref])
    tp, fp, uf = cls_flag["attack"], cls_flag["normal"], cls_flag["unlabeled"]
    steps = {}
    for lab in sorted({l for x in labels.values() for l in x["labels"]}):
        refs = [r for r, x in labels.items() if lab in x["labels"]]
        steps[lab] = {"n": len(refs), "flagged": sum(bool(flagged_rules.get(r)) for r in refs),
                      "rules": sorted({k for r in refs for k in flagged_rules.get(r, [])})}

    inc_rows, truth = [], {}
    for inc in incidents:
        refs = [ev["ref"] for ev in inc["events"]]
        c = Counter(labels.get(r, {"class": "unlabeled"})["class"] for r in refs)
        n = len(refs)
        t = ("attack" if c["attack"] * 2 >= n and c["attack"] else
             "risky" if c["risky"] else
             "not_attack" if c["normal"] * 2 > n else "unlabeled")
        truth[inc["id"]] = t
        inc_rows.append({"id": inc["id"], "n_events": n, **{k: c[k] for k in ("attack", "risky", "normal", "unlabeled")},
                         "rules": sorted({f["rule"] for f in inc["findings"]}), "truth": t})
    tri = rule_triage(incidents, events)
    verdict = {v["id"]: v["verdict"] for v in tri.get("incidents", [])}
    ok = {"attack": ("attack",), "risky": ("risky_not_attack",), "not_attack": ("benign_activity", "risky_not_attack")}
    judged = [(i, t, verdict.get(i, "unclear")) for i, t in truth.items() if t != "unlabeled"]
    correct = sum(v in ok[t] for _, t, v in judged)
    res = {
        "env": bool(env), "n_events": len(events), "refs_not_in_labels": missing_refs[:20],
        "lines": dict(cls_n), "lines_read_by_engine": dict(cls_read), "lines_flagged": dict(cls_flag),
        "recall_attack_lines": rate(tp, cls_n["attack"]),
        "precision_vs_labeled": rate(tp, tp + fp),
        "fp_rate_normal_lines": rate(fp, cls_n["normal"]),
        "precision_if_unlabeled_all_normal": rate(tp, tp + fp + uf),
        "flagged_rules_by_class": {k: dict(v) for k, v in rules_by_cls.items()},
        "steps": steps,
        "incidents": {"n": len(incidents), "truth_counts": dict(Counter(truth.values())),
                      "rule_triage_accuracy_on_labeled": f"{correct}/{len(judged)}",
                      "rule_triage": {i: {"truth": t, "verdict": v} for i, t, v in judged},
                      "rows": inc_rows},
    }
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""label_weblog_a123.py 라벨로 웹 규칙의 표시 결과를 채점한다.

  python scripts/relabel/score_weblog.py --profile <프로필 JSON> --labels reports/relabel/eclog_labels.jsonl \
      [--engine-root <다른 커밋의 작업 트리>] --out reports/relabel/eclog_score.json

--engine-root를 주면 그 트리의 logsight로 잰다(예: S7 판정 때의 커밋). 라벨은 엔진과 상관없이 같다.
"""
from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


def upper95(k: int, n: int) -> float | None:
    """윌슨 점수 구간 위쪽 끝(95%)."""
    if not n:
        return None
    z = 1.959963984540054; p = k / n
    return (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--engine-root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--out")
    a = ap.parse_args()
    sys.path.insert(0, a.engine_root)
    from logsight.web.webdetect import run_web_detections
    from logsight.web.webpipeline import load_events
    from logsight.web.webprofile import SiteProfile
    commit = subprocess.run(["git", "-C", a.engine_root, "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    labels = {}
    for line in Path(a.labels).read_text(encoding="utf-8").splitlines():
        x = json.loads(line); labels[x["ref"]] = x
    prof = SiteProfile.load(Path(a.profile))
    events, _ = load_events(prof)
    findings = run_web_detections(events, prof)
    for p in prof.resolved_logs().get("access", []):     # 라벨 파일에 없는 줄 = unlabeled
        with open(p, encoding="utf-8", errors="replace") as fh:
            for i, _ in enumerate(fh, 1):
                labels.setdefault(f"{Path(p).name}:{i}", {"class": "unlabeled"})
    flagged: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        for e in f.events:
            if e.source == "access":
                flagged[e.raw_ref].add(f.rule)
    cls = Counter(x["class"] for x in labels.values())
    fl = Counter(labels.get(r, {"class": "not_in_labels"})["class"] for r in flagged)
    n_assumed_normal = cls["unlabeled"] + cls["unparsed"]
    fp = fl["unlabeled"] + fl["unparsed"]
    res = {
        "engine_commit": commit, "lines": dict(cls), "flagged_lines": len(flagged), "flagged_by_class": dict(fl),
        "attack_lines_flagged": f'{fl["attack"]}/{cls["attack"]}',
        "attack_lines_missed": sorted(r for r, x in labels.items() if x["class"] == "attack" and r not in flagged),
        "fp_lines_assuming_unlabeled_normal": fp,
        "fp_rate": fp / n_assumed_normal if n_assumed_normal else None,
        "fp_upper95": upper95(fp, n_assumed_normal),
        "fp_rate_if_uncertain_normal": (fp + fl["uncertain"]) / (n_assumed_normal + cls["uncertain"]),
        "fp_by_rule": dict(Counter(r for ref in flagged if labels[ref]["class"] in ("unlabeled", "unparsed")
                                   for r in flagged[ref])),
        "attack_by_rule": dict(Counter(r for ref in flagged if labels[ref]["class"] == "attack" for r in flagged[ref])),
        "uncertain_flagged_by_rule": dict(Counter(r for ref in flagged if labels[ref]["class"] == "uncertain"
                                                  for r in flagged[ref])),
    }
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

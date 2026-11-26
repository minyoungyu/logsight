#!/usr/bin/env python3
"""Panther 공개 규칙(panther-labs/panther-analysis, Apache-2.0)의 AWS CloudTrail 시험 이벤트로 S6를 잰다.

  python scripts/public/eval_panther.py --pa <panther-analysis> --half A --out reports/public/panther_ct_A.json

- 대상: rules/aws_cloudtrail_rules/*.yml 중 AnalysisType=rule, Enabled가 false가 아닌 것, LogTypes에
  AWS.CloudTrail이 있는 것.
- 반 나누기: 규칙 파일 이름(확장자 뺀 것)의 sha256 첫 바이트가 짝수면 A, 홀수면 B. 내용을 보기 전에 정한
  결정적 규칙이라 다시 돌려도 같은 반이 나온다. 같은 규칙의 시험은 한 반에만 들어간다.
- 시험 하나(Tests[].Log, CloudTrail 레코드 한 건)마다 그 한 건만 LogFinder에 넣는다(parse_cloudtrail →
  run_detections, 설정 없음). 이벤트 하나짜리라 여러 이벤트를 묶는 규칙은 불리하다(한계로 적는다).
- 결과에는 규칙 ID·심각도·시험 이름·기대값·LogFinder 규칙만 적고 이벤트 원문은 넣지 않는다.
- 판정(맞게 탐지 / 다른 이유로만 걸림 / 놓침)은 사람이 judgement 칸에 적는다. 기계 숫자(아무 규칙이나
  걸림)도 함께 남긴다.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from logsight.detect import run_detections  # noqa: E402
from logsight.maturity import experimental_rules  # noqa: E402
from logsight.normalize import parse_cloudtrail  # noqa: E402

MEDIUM_UP = {"Medium", "High", "Critical"}
EXP = experimental_rules()


def half_of(stem: str) -> str:
    return "A" if hashlib.sha256(stem.encode()).digest()[0] % 2 == 0 else "B"


def wilson(k: int, n: int) -> list[float] | None:
    if not n:
        return None
    z, p = 1.96, k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - h) / d, 4), round((c + h) / d, 4)]


def rules(pa: Path, half: str):
    for f in sorted((pa / "rules" / "aws_cloudtrail_rules").glob("*.yml")):
        if half_of(f.stem) != half:
            continue
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if d.get("AnalysisType") != "rule" or d.get("Enabled") is False:
            continue
        if "AWS.CloudTrail" not in (d.get("LogTypes") or []):
            continue
        yield f.stem, d


def flag_one(log: dict) -> list[str]:
    rec = copy.deepcopy(log)
    rec.setdefault("eventTime", "2026-01-01T00:00:00Z")
    evs = parse_cloudtrail(json.dumps({"Records": [rec]}, default=str), "panther.json")
    return sorted({f.rule for f in run_detections(evs, {})}) if evs else []


def measure(pa: Path, half: str) -> dict:
    items, per_rule = [], []
    for stem, d in rules(pa, half):
        pos_hit = pos_n = pos_st = 0
        for t in d.get("Tests") or []:
            log = t.get("Log")
            if not isinstance(log, dict):
                continue
            hit = flag_one(log)
            exp = bool(t.get("ExpectedResult"))
            items.append({"rule": d.get("RuleID", stem), "file": stem, "severity": d.get("Severity"),
                          "test": t.get("Name", ""), "expected": exp, "eventName": log.get("eventName"),
                          "logfinder_rules": hit, "judgement": "", "judgement_reason": ""})
            if exp:
                pos_n += 1
                pos_hit += bool(hit)
                pos_st += bool(set(hit) - EXP)
        if pos_n:
            per_rule.append({"rule": d.get("RuleID", stem), "file": stem, "severity": d.get("Severity"),
                             "positive_tests": pos_n, "positive_flagged": pos_hit,
                             "positive_flagged_stable": pos_st})
    pos = [i for i in items if i["expected"]]
    neg = [i for i in items if not i["expected"]]
    r_hit = sum(r["positive_flagged"] > 0 for r in per_rule)
    mu = [r for r in per_rule if r["severity"] in MEDIUM_UP]
    mu_hit = sum(r["positive_flagged"] > 0 for r in mu)
    n_flag = sum(bool(i["logfinder_rules"]) for i in neg)
    s_hit = sum(r["positive_flagged_stable"] > 0 for r in per_rule)
    s_mu = sum(r["positive_flagged_stable"] > 0 for r in mu)
    return {
        "dataset": "panther-labs/panther-analysis rules/aws_cloudtrail_rules (Apache-2.0)",
        "panther_commit": subprocess.run(["git", "-C", str(pa), "rev-parse", "HEAD"],
                                         capture_output=True, text=True).stdout.strip(),
        "engine_commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                        capture_output=True, text=True).stdout.strip(),
        "half": half,
        "machine": {
            "rules_with_positive_tests": len(per_rule),
            "rules_any_flagged": r_hit, "rules_rate": r_hit / len(per_rule) if per_rule else None,
            "rules_ci95": wilson(r_hit, len(per_rule)),
            "medium_up_rules": len(mu), "medium_up_flagged": mu_hit, "medium_up_ci95": wilson(mu_hit, len(mu)),
            "positive_tests": len(pos), "positive_flagged": sum(bool(i["logfinder_rules"]) for i in pos),
            "negative_tests": len(neg), "negative_flagged": n_flag,
            "negative_flagged_rules": dict(Counter(r for i in neg for r in i["logfinder_rules"]).most_common()),
        },
        # 규칙 성숙도(계획 maturity): 주 숫자는 경보(stable) 규칙만. 위 machine은 모든 규칙(보조)
        "machine_stable": {
            "experimental_rules": sorted(EXP),
            "rules_any_flagged": s_hit, "rules_rate": s_hit / len(per_rule) if per_rule else None,
            "rules_ci95": wilson(s_hit, len(per_rule)), "medium_up_flagged": s_mu,
            "negative_flagged": sum(bool(set(i["logfinder_rules"]) - EXP) for i in neg),
        },
        "per_rule": per_rule,
        "items": items,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pa", required=True, help="panther-analysis 저장소 경로")
    ap.add_argument("--half", choices=["A", "B"], required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res = measure(Path(a.pa), a.half)
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    m = res["machine"]
    print(f"반 {a.half}: 규칙 {m['rules_any_flagged']}/{m['rules_with_positive_tests']} 걸림 {m['rules_ci95']}"
          f" · Medium 이상 {m['medium_up_flagged']}/{m['medium_up_rules']}"
          f" · 공격 시험 {m['positive_flagged']}/{m['positive_tests']}"
          f" · 정상 시험 표시 {m['negative_flagged']}/{m['negative_tests']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

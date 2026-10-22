#!/usr/bin/env python3
"""
탐지 결과를 정답(ground_truth.json)과 대조해 점수를 낸다.

각 공격 시나리오에 대해:
  - 그 공격자 IP가 "기대한 규칙"으로 실제 탐지됐는지(재현율)
  - 정상 트래픽(benign) IP가 하나라도 탐지에 걸렸는지(오탐)
을 센다. 결과를 표로 출력하고 lab/reports/eval.json 에 저장한다.

이것이 "그냥 붙여넣기보다 낫다"를 숫자로 보여 주기 위한 측정의 뼈대다. 나중에 기존 무료
도구(CrowdSec 등)·범용 LLM 붙여넣기도 같은 정답으로 돌려 같은 표에 넣는다.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logsight.web.webprofile import SiteProfile  # noqa: E402
from logsight.web.webpipeline import assess  # noqa: E402

LAB = Path(__file__).resolve().parent
PROFILES = {"shopmall": LAB / "profiles" / "shopmall.json",
            "board": LAB / "profiles" / "board.json"}


def rules_by_ip(result: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for inc in result["results"]:
        for f in inc["incident"]["findings"]:
            for ip in inc["incident"]["src_ips"]:
                out.setdefault(ip, set()).add(f["rule"])
        # IP 없는(파일 기반) finding 은 사건 단위로 합친다
        if not inc["incident"]["src_ips"]:
            out.setdefault("(no-ip)", set()).update(f["rule"] for f in inc["incident"]["findings"])
    return out


def main() -> int:
    truth = json.loads((LAB / "logs" / "ground_truth.json").read_text(encoding="utf-8"))
    results = {name: assess(SiteProfile.load(p), use_ai=False, top=500) for name, p in PROFILES.items()}
    detected = {name: rules_by_ip(r) for name, r in results.items()}

    rows = []
    tp = fn = 0
    benign_fp = 0
    blind: list[str] = []
    for sc in truth["scenarios"]:
        site = sc["site"]
        exp = set(sc["expected_rules"])
        if not sc["malicious"]:
            # 정상: 어떤 사이트든 203.0.113.* 가 탐지에 걸리면 오탐
            for name, det in detected.items():
                for ip, rules in det.items():
                    if ip.startswith("203.0.113") and rules:
                        benign_fp += 1
                        rows.append((sc["scenario"], name, ip, "오탐!", ", ".join(sorted(rules))))
            continue
        if not sc.get("detectable", True):
            rows.append((sc["scenario"], sc["attacker_ip"], "-", "-", "사각지대: 접속 로그로 볼 수 없음"))
            blind.append(sc["scenario"])
            continue
        targets = [site] if site in detected else list(detected)
        got: set[str] = set()
        for name in targets:
            got |= detected[name].get(sc["attacker_ip"], set())
        hit = exp & got
        miss = exp - got
        tp += len(hit)
        fn += len(miss)
        status = "✓" if not miss else ("△" if hit else "✗")
        rows.append((sc["scenario"], sc["attacker_ip"], status,
                     f"{len(hit)}/{len(exp)}", "놓침: " + ", ".join(sorted(miss)) if miss else "모두 탐지"))

    print("=" * 78)
    print(f"{'시나리오':18s} {'공격자IP/사이트':16s} {'':3s} {'탐지':6s} 비고")
    print("-" * 78)
    for r in rows:
        print(f"{r[0]:18s} {str(r[1]):16s} {r[2]:3s} {r[3]:6s} {r[4]}")
    print("=" * 78)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    print(f"기대 규칙 재현율: {tp}/{tp+fn} = {recall:.0%}   정상 트래픽 오탐: {benign_fp}건")
    print(f"사각지대(접속 로그로 볼 수 없는 공격, 재현율에서 제외): {len(blind)}건 {blind}")
    for name, r in results.items():
        print(f"  [{name}] 판정={r['overall_verdict_ko']} 사건={r['n_incidents']} "
              f"탐지={r['n_findings']} 처리={r['timing']['total_s']}초")

    out = {"recall": recall, "tp": tp, "fn": fn, "benign_fp": benign_fp, "blind_spots": blind,
           "per_site": {n: {"verdict": r["overall_verdict"], "incidents": r["n_incidents"],
                            "findings": r["n_findings"]} for n, r in results.items()}}
    (LAB / "reports").mkdir(exist_ok=True)
    (LAB / "reports" / "eval.json").write_text(json.dumps(out, ensure_ascii=False, indent=1),
                                               encoding="utf-8")
    return 0 if benign_fp == 0 and fn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""report.json → 규칙별 탐지 수, 사건 상위 목록을 마크다운 표로 요약한다."""
from __future__ import annotations

import json
import sys
from collections import Counter

r = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"- 이벤트 {r['n_events']:,}건 → 의심 {r['n_flagged']:,}건 → 탐지 {r['n_findings']:,}건 → "
      f"사건 {r['n_incidents']:,}건, 처리 {r['timing']['total_s']}초\n")
rules: Counter = Counter()
for res in r["results"]:
    for f in res["incident"]["findings"]:
        rules[f["rule"]] += f["n_events"]
print("| 상위 사건 | 심각도 | 기간(UTC) | 단계 | 이벤트 |\n| --- | --- | --- | --- | --- |")
for i in r["incident_index"][:20]:
    print(f"| {i['id']} | {i['severity']} | {i['start'][:16]} ~ {i['end'][:16]} | "
          f"{' → '.join(i['stages'])} | {i['n_events']:,} |")
print("\n| 규칙(상위 10개 사건 기준) | 이벤트 |\n| --- | --- |")
for k, v in rules.most_common():
    print(f"| {k} | {v:,} |")

print("\n| 파일 | 종류 | 이벤트 | 오류 |\n| --- | --- | --- | --- |")
for f in r["files"]:
    print(f"| {f['file'].split('/')[-1]} | {f.get('kind')} | {f['events']:,} | {f.get('error', '')} |")

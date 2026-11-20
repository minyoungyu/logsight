"""usage: python scripts/scale/bench_pivot.py DATADIR  → 사건별 출발지·서버·규칙·수정안(gen_pivot.py 결과)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # 저장소 루트의 logsight

import sys
from logsight import pipeline

d = Path(sys.argv[1])
res = pipeline.run_paths([str(d)], use_ai=False, preview=True, top=10)
print("rules:", {k: v["findings"] for k, v in res["rule_counts"].items()}, "| incidents:", res["n_incidents"])
for r in res["results"]:
    inc = r["incident"]
    print(f'- {inc["id"]} src={inc["src_ips"][:4]} inst={inc["instances"][:4]} stages={inc["stages"]}')
    print("    rules:", sorted({f["rule"] for f in inc["findings"]}))
    print("    checks:", [(c["id"], c["resource"]) for c in r["checks"]])

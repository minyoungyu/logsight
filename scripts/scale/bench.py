"""usage: python scripts/scale/bench.py DATADIR  → JSON 한 줄(시간·메모리·사건·수정안·AI 입력 크기)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # 저장소 루트의 logsight

import json, resource, time
from logsight.normalize import load_paths
from logsight import pipeline

d = Path(sys.argv[1])
t = time.time()
events, stats = load_paths([d / "vpcflow.log"])
t_parse = time.time() - t
env = pipeline.load_env(d / "environment.json")
t = time.time()
res = pipeline.run(events, env, use_ai=False, preview=True, top=5)
t_run = time.time() - t
t = time.time()
from logsight.report import render
html = render(res)
t_report = time.time() - t
rows = []
for r in res["results"]:
    inc = r["incident"]
    rows.append({"id": inc["id"], "src_ips": inc["src_ips"][:5], "instances": inc["instances"][:6],
                 "rules": sorted({f["rule"] for f in inc["findings"]}),
                 "checks": {c["id"]: sum(1 for x in r["checks"] if x["id"] == c["id"]) for c in r["checks"]},
                 "nacl_targets": [c["resource"] for c in r["checks"] if c["id"] == "NACL_BLOCK_ATTACKER"],
                 "sg_targets_n": len([c for c in r["checks"] if c["id"].startswith("SG_")]),
                 "payload_chars": len(json.dumps(r.get("ai_payload"), ensure_ascii=False))})
print(json.dumps({"events": len(events), "parse_s": round(t_parse, 2), "run_s": round(t_run, 2),
                  "detect_corr_s": res["timing"]["detect_correlate_s"], "report_s": round(t_report, 2),
                  "html_kb": len(html) // 1024, "maxrss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024,
                  "n_findings": res["n_findings"], "rule_counts": {k: v["findings"] for k, v in res["rule_counts"].items()},
                  "n_incidents": res["n_incidents"], "top": rows}, ensure_ascii=False))

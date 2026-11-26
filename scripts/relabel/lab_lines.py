#!/usr/bin/env python3
"""자체 lab 로그를 줄 단위로 라벨하고(공격 스크립트가 시나리오마다 다른 출처 IP를 썼으므로 IP → 시나리오),
'기대 규칙 이름'이 아니라 '그 줄이 어떤 규칙에든 표시됐나'로 다시 채점한다.

lab의 공격/정상 구분은 공격 스크립트(lab/attack.py)가 직접 만든 것이라 AIT-LDS처럼 실행 기록으로 보장된다.
보장되지 않는 것은 예전 채점의 '기대 규칙'(규칙 작성자가 정한 이름)이다. 이 스크립트는 그 부분을 뺀 숫자를 낸다.

  python scripts/relabel/lab_lines.py --logs reports/remeasure_2026-11-26/lab/logs --out reports/relabel/lab_lines.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    logs = Path(a.logs).resolve()
    gt = json.loads((logs / "ground_truth.json").read_text(encoding="utf-8"))
    by_ip = {}
    for sc in gt["scenarios"]:
        if sc["malicious"]:
            by_ip[(sc["site"], sc["attacker_ip"])] = sc

    # 1) 라벨(엔진을 보지 않음)
    labels = {}
    for site in ("shopmall", "board"):
        p = logs / f"{site}_access.log"
        for i, line in enumerate(p.read_text().splitlines(), 1):
            ip = line.split(" ", 1)[0]
            ref = f"{p.name}:{i}"
            sc = by_ip.get((site, ip))
            if sc:
                labels[ref] = {"class": "attack", "scenario": sc["scenario"], "rule": "lab.attack_script_ip",
                               "detectable": sc.get("detectable", True)}
            elif ip.startswith("203.0.113."):
                labels[ref] = {"class": "normal", "rule": "lab.benign_script_ip"}
            else:
                labels[ref] = {"class": "uncertain", "rule": "lab.ip_not_in_script", "ip": ip}

    # 2) 엔진
    from logsight.web.webdetect import run_web_detections
    from logsight.web.webpipeline import load_events
    from logsight.web.webprofile import SiteProfile
    flagged = defaultdict(set)
    for site in ("shopmall", "board"):
        prof = json.loads((Path(__file__).resolve().parents[2] / "lab" / "profiles" / f"{site}.json").read_text())
        prof["log_paths"] = {k: [str(logs / Path(v[0]).name)] for k, v in prof["log_paths"].items()}
        tmp = logs.parent / f".{site}_profile.json"
        tmp.write_text(json.dumps(prof, ensure_ascii=False))
        sp = SiteProfile.load(tmp); tmp.unlink()
        evs, _ = load_events(sp)
        for f in run_web_detections(evs, sp):
            for e in f.events:
                if e.source == "access":
                    flagged[e.raw_ref].add(f.rule)
    sc_lines, sc_flag, sc_rules = Counter(), Counter(), defaultdict(set)
    for ref, x in labels.items():
        if x["class"] == "attack":
            k = (x["scenario"], ref.split("_")[0]); sc_lines[k] += 1
            if flagged.get(ref):
                sc_flag[k] += 1; sc_rules[k] |= flagged[ref]
    scen = [{"scenario": s, "site": site, "lines": sc_lines[(s, site)], "flagged_lines": sc_flag[(s, site)],
             "any_rule": bool(sc_flag[(s, site)]), "rules": sorted(sc_rules[(s, site)])}
            for (s, site) in sorted(sc_lines)]
    cls = Counter(x["class"] for x in labels.values())
    fl = Counter(labels[r]["class"] for r in flagged if r in labels)
    res = {"lines": dict(cls), "flagged_by_class": dict(fl),
           "scenarios_any_rule": f'{sum(s["any_rule"] for s in scen)}/{len(scen)}',
           "attack_lines_flagged": f'{fl["attack"]}/{cls["attack"]}',
           "normal_lines_flagged": f'{fl["normal"]}/{cls["normal"]}',
           "uncertain": {r: x for r, x in labels.items() if x["class"] == "uncertain"},
           "scenarios": scen,
           "note": "access 로그만 본다. auth·error 로그만 남기는 시나리오(SSH 대입 등)는 줄 수가 0으로 나온다"}
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

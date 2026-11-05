"""Stratus 실행 시각(times.tsv)과 LogSight 결과(report.json)를 맞춰 기법별로 잡았는지 센다.

기법 실행 시간 [start - 1분, end + 5분] 안에 시작한 사건의 규칙을 그 기법의 결과로 본다.
expected.tsv(실행 전에 고정한 예상)와 나란히 적는다. 예상과 다른 것이 이번 측정에서 배운 것이다.

    python lab/aws/stratus/score.py data/stratus/<날짜>/times.tsv reports/stratus/report.json
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def expected() -> dict[str, tuple[str, set[str]]]:
    out = {}
    for line in (HERE / "expected.tsv").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            t, exp, rules, _ = line.split("\t", 3)
            out[t] = (exp, set() if rules == "-" else set(rules.split(",")))
    return out


def score(times: list[dict], incidents: list[dict], exp: dict) -> list[dict]:
    rows = []
    for r in times:
        t = r["technique"]
        e, want = exp.get(t, ("?", set()))
        if r["status"] != "ok":
            rows.append({"technique": t, "expected": e, "result": r["status"], "rules": []})
            continue
        lo, hi = _t(r["start"]) - timedelta(minutes=1), _t(r["end"]) + timedelta(minutes=5)
        got = sorted({x for i in incidents if lo <= _t(i["start"]) <= hi for x in i.get("rules", [])})
        if want and want & set(got):
            res = "caught"
        elif got:
            res = "other_rule"
        else:
            res = "missed"
        rows.append({"technique": t, "expected": e, "result": res, "rules": got})
    return rows


def main() -> None:
    times = list(csv.DictReader(open(sys.argv[1], encoding="utf-8"), delimiter="\t"))
    rep = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    rows = score(times, rep.get("incident_index", []), expected())
    for r in rows:
        print(f"{r['technique']:62s} 예상={r['expected']:5s} 결과={r['result']:11s} {','.join(r['rules'])}")
    n = sum(1 for r in rows if r["result"] == "caught")
    print(f"\n맞게 잡음 {n}/{len(rows)}")


if __name__ == "__main__":
    main()

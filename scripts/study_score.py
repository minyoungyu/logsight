"""사용자 평가 집계(docs/사용자평가/설계.md). 응답 CSV → 조건별 점수·시간, 사람별 차이, 부호 뒤집기 정확검정.

    python scripts/study_score.py docs/사용자평가/응답.csv

CSV 열: pid, group, order, scenario(A|B), condition(logsight|baseline), minutes, q1..q5(0~2), confidence(1~5),
false_accusations. 한 사람에 두 줄(조건 하나씩). 빈 칸이 있는 사람은 빼고, 뺀 사람을 출력에 적는다.
"""
from __future__ import annotations

import csv
import itertools
import statistics
import sys
from collections import defaultdict

Q = ("q1", "q2", "q3", "q4", "q5")


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def sign_flip_p(diffs: list[float]) -> float:
    """양측 부호 뒤집기 정확검정. 차이의 합이 우연히 이만큼 클 확률(0인 차이는 뺌, 20명까지)."""
    d = [x for x in diffs if x]
    if not d:
        return 1.0
    obs = abs(sum(d))
    hits = sum(1 for s in itertools.product((1, -1), repeat=len(d)) if abs(sum(a * b for a, b in zip(s, d))) >= obs)
    return hits / 2 ** len(d)


def summarize(rows: list[dict]) -> dict:
    by_p: dict[str, dict] = defaultdict(dict)
    dropped = []
    for r in rows:
        qs = [_f(r.get(q)) for q in Q]
        mins = _f(r.get("minutes"))
        if None in qs or mins is None or r.get("condition") not in ("logsight", "baseline"):
            dropped.append(r.get("pid"))
            continue
        by_p[r["pid"]][r["condition"]] = {"score": sum(qs), "minutes": mins, "scenario": r.get("scenario"),
                                          "confidence": _f(r.get("confidence")),
                                          "false": _f(r.get("false_accusations")) or 0}
    pairs = {p: v for p, v in by_p.items() if len(v) == 2}
    dropped += [p for p in by_p if p not in pairs]
    out = {"n": len(pairs), "dropped": sorted(set(x for x in dropped if x)), "people": []}
    for p, v in sorted(pairs.items()):
        out["people"].append({"pid": p, "d_score": v["logsight"]["score"] - v["baseline"]["score"],
                              "d_minutes": v["logsight"]["minutes"] - v["baseline"]["minutes"],
                              "logsight": v["logsight"], "baseline": v["baseline"]})
    for c in ("logsight", "baseline"):
        sc = [v[c]["score"] for v in pairs.values()]
        mn = [v[c]["minutes"] for v in pairs.values()]
        fa = [v[c]["false"] for v in pairs.values()]
        out[c] = {"score_mean": round(statistics.mean(sc), 2) if sc else None,
                  "score_median": statistics.median(sc) if sc else None,
                  "minutes_median": statistics.median(mn) if mn else None,
                  "false_accusations": sum(fa)}
    by_s = defaultdict(list)
    for v in pairs.values():
        for c in v.values():
            by_s[c["scenario"]].append(c["score"])
    out["scenario_mean"] = {s: round(statistics.mean(x), 2) for s, x in sorted(by_s.items())}
    ds = [x["d_score"] for x in out["people"]]
    dm = [x["d_minutes"] for x in out["people"]]
    out["d_score_median"] = statistics.median(ds) if ds else None
    out["d_minutes_median"] = statistics.median(dm) if dm else None
    out["n_not_worse"] = sum(1 for x in ds if x >= 0)
    out["p_score"] = round(sign_flip_p(ds), 4) if ds else None
    out["p_minutes"] = round(sign_flip_p(dm), 4) if dm else None
    # 설계.md 6절의 미리 정한 성공 기준
    out["success"] = bool(ds) and out["n_not_worse"] >= round(0.75 * len(ds)) and out["d_score_median"] >= 2
    return out


def main(path: str) -> None:
    s = summarize(load(path))
    print(f"짝을 이룬 참가자 {s['n']}명" + (f" (뺀 사람: {', '.join(s['dropped'])})" if s["dropped"] else ""))
    for c, name in (("logsight", "LogSight"), ("baseline", "기존 방식")):
        v = s[c]
        print(f"- {name}: 점수 평균 {v['score_mean']} / 중앙값 {v['score_median']}, 시간 중앙값 {v['minutes_median']}분, "
              f"정상 오지목 {v['false_accusations']}건")
    print(f"- 시나리오별 평균 점수: {s['scenario_mean']}")
    print(f"- 사람별 점수 차이(LogSight−기존): {[x['d_score'] for x in s['people']]}, 중앙값 {s['d_score_median']}, "
          f"같거나 높은 사람 {s['n_not_worse']}/{s['n']}, 부호 뒤집기 p={s['p_score']}")
    print(f"- 사람별 시간 차이(분): {[x['d_minutes'] for x in s['people']]}, 중앙값 {s['d_minutes_median']}, p={s['p_minutes']}")
    print(f"- 미리 정한 성공 기준 충족: {'예' if s['success'] else '아니오'}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

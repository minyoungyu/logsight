"""사용자 평가 준비물 만들기(docs/사용자평가/진행_대본.md). 시나리오 폴더 → 참가자에게 줄 묶음.

시나리오마다 두 묶음을 만든다.
- baseline/ : 원본 로그만(+ 있으면 GuardDuty 결과). '기존 방식' 조건
- logsight/ : 같은 원본 로그 + LogFinder 보고서(report.html, AI 없이 규칙 모드)
그리고 참가자 번호별 배정표(배정표.csv)와 비어 있는 응답 CSV를 만든다. 정답지는 묶음에 넣지 않는다.

    python scripts/study_prepare.py --scenario A=data/gongbang --scenario B=data/botsv3_aws \\
        --participants 8 --out study_kit
    python scripts/study_prepare.py --scenario A=samples/demo --scenario B=samples/combined --participants 4 --out /tmp/kit  # 연습
"""
from __future__ import annotations

import argparse
import csv
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 설계.md 3절의 교차 배정(묶음 1~4)
GROUPS = {1: (("A", "logsight"), ("B", "baseline")),
          2: (("A", "baseline"), ("B", "logsight")),
          3: (("B", "logsight"), ("A", "baseline")),
          4: (("B", "baseline"), ("A", "logsight"))}
SECRET_NAMES = ("ground_truth", "정답", "answer")


def _copy_logs(src: Path, dst: Path) -> list[str]:
    dst.mkdir(parents=True, exist_ok=True)
    copied = []
    for p in sorted(src.rglob("*")):
        if p.is_file() and not any(s in p.name.lower() for s in SECRET_NAMES):
            rel = p.relative_to(src)
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst / rel)
            copied.append(str(rel))
    return copied


def build(scenarios: dict[str, Path], participants: int, out: Path, year: int | None = None) -> dict:
    from logsight.normalize import SYSLOG
    from logsight.pipeline import run_paths
    from logsight.report import render

    out.mkdir(parents=True, exist_ok=True)
    made = {}
    for name, src in scenarios.items():
        logs = _copy_logs(src, out / name / "baseline" / "logs")
        shutil.copytree(out / name / "baseline" / "logs", out / name / "logsight" / "logs", dirs_exist_ok=True)
        saved = dict(SYSLOG)
        if year:
            SYSLOG["year"] = year
        try:
            res = run_paths([str(src)], use_ai=False)
        finally:
            SYSLOG.clear()
            SYSLOG.update(saved)
        (out / name / "logsight" / "report.html").write_text(render(res, f"시나리오 {name}"), encoding="utf-8")
        made[name] = {"files": len(logs), "events": res["n_events"], "incidents": res["n_groups"]}
    with open(out / "배정표.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pid", "group", "order", "scenario", "condition", "folder"])
        for i in range(1, participants + 1):
            g = (i - 1) % 4 + 1
            for order, (sc, cond) in enumerate(GROUPS[g], 1):
                w.writerow([f"P{i:02d}", g, order, sc, cond, f"{sc}/{cond}"])
    with open(out / "응답.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pid", "group", "order", "scenario", "condition", "minutes", "q1", "q2", "q3", "q4", "q5",
                    "confidence", "false_accusations"])
        for i in range(1, participants + 1):
            g = (i - 1) % 4 + 1
            for order, (sc, cond) in enumerate(GROUPS[g], 1):
                w.writerow([f"P{i:02d}", g, order, sc, cond] + [""] * 8)
    for doc in ("질문지.md",):
        shutil.copy2(ROOT / "docs" / "사용자평가" / doc, out / doc)
    return made


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scenario", action="append", required=True, help="이름=폴더 (예: A=data/gongbang)")
    ap.add_argument("--participants", type=int, default=8)
    ap.add_argument("--year", type=int, help="연도 없는 syslog 줄의 연도")
    ap.add_argument("--out", type=Path, default=Path("study_kit"))
    a = ap.parse_args()
    scen = {}
    for s in a.scenario:
        name, _, path = s.partition("=")
        if not path or not Path(path).is_dir():
            ap.error(f"폴더가 없음: {s}")
        scen[name] = Path(path)
    if set(scen) != {"A", "B"}:
        ap.error("시나리오는 A와 B 두 개가 필요합니다(교차 설계).")
    made = build(scen, a.participants, a.out, a.year)
    for k, v in made.items():
        print(f"시나리오 {k}: 파일 {v['files']}개, 이벤트 {v['events']}건, 사건 {v['incidents']}개")
    print(f"→ {a.out}/ (배정표.csv, 응답.csv, 질문지.md, A·B 아래 baseline·logsight 묶음)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

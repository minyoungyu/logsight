#!/usr/bin/env python3
"""라벨 없는 실제 웹 접근 로그로 정상 요청 오탐률(사양서 S7·NFR-12)을 잰다(규칙만, AI 호출 없음).

실제 로그에는 인터넷 스캐너의 진짜 공격도 섞여 있다. 그래서 두 단계로 잰다.

  1) 표시된 줄을 분류표로 내보낸다(원본 줄 포함. 개인정보가 있으니 data/ 아래에만 둔다).
     python scripts/public/eval_reallog.py --profile data/real/profile.json \
         --review data/real/review.tsv --out reports/public/reallog_<이름>.json
  2) 사람이 review.tsv의 class 칸에 attack(실제 공격) 또는 fp(오탐)를 적고 reason에 근거를 적는다.
     분류 기준은 재기 전에 계획 파일(reports/public/holdout_plan_*.json)에 적어 둔 것을 따른다.
  3) 같은 명령에 --labels data/real/review.tsv를 더해 다시 돌리면 라벨 보정 오탐률을 낸다.

결과 JSON에는 숫자와 `파일:줄` 위치만 남기고 원본 줄은 넣지 않는다.
규칙·파서는 바꾸지 않는다. 프로필에는 사이트 설명(로그 경로, 자기 호스트, 신뢰 IP 등)만 적는다.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from logsight.web.webdetect import run_web_detections  # noqa: E402
from logsight.web.webpipeline import load_events  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

CLASSES = {"attack", "fp"}
REVIEW_COLS = ["ref", "rules", "src_ip", "class", "reason", "line"]


def upper95(k: int, n: int) -> float | None:
    """오탐률의 95% 윌슨 상한(0건이어도 상한을 낸다)."""
    if n <= 0:
        return None
    z = 1.96
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c + h) / d


def raw_lines(profile: SiteProfile) -> dict[str, str]:
    """{파일이름:줄번호: 원본 줄} — LogFinder raw_ref와 같은 꼴. 접근 로그만."""
    out = {}
    for p in profile.resolved_logs().get("access", []):
        opener = __import__("gzip").open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if line.strip():
                    out[f"{p.name}:{i}"] = line.rstrip("\n")
    return out


def load_labels(path: Path) -> dict[str, tuple[str, str]]:
    out = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            c = (row.get("class") or "").strip().lower()
            if c:
                if c not in CLASSES:
                    raise SystemExit(f"{row['ref']}: class는 attack 또는 fp만 쓴다(받은 값: {c})")
                if c == "attack" and not (row.get("reason") or "").strip():
                    raise SystemExit(f"{row['ref']}: attack으로 뺄 때는 reason에 근거를 적는다")
                out[row["ref"]] = (c, (row.get("reason") or "").strip())
    return out


def measure(profile: SiteProfile, labels: dict[str, tuple[str, str]] | None = None) -> tuple[dict, list[dict]]:
    events, _ = load_events(profile)
    findings = run_web_detections(events, profile)
    access = [e for e in events if e.source == "access"]
    total = {e.raw_ref for e in access}
    flagged: dict[str, set[str]] = defaultdict(set)
    ip_of = {}
    for f in findings:
        for e in f.events:
            if e.raw_ref in total:
                flagged[e.raw_ref].add(f.rule)
                ip_of[e.raw_ref] = e.src_ip or "-"
    n, k = len(total), len(flagged)
    by_rule = Counter(r for rs in flagged.values() for r in rs)
    res = {
        "profile": profile.name,
        "engine_commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                                        capture_output=True, text=True).stdout.strip(),
        "access_lines": n,
        "flagged_lines": k,
        "raw_rate": k / n if n else None,
        "raw_upper95": upper95(k, n),
        "flagged_by_rule": dict(by_rule.most_common()),
        "flagged_ips": len(set(ip_of.values())),
    }
    if labels is not None:
        attack = {r for r in flagged if labels.get(r, ("",))[0] == "attack"}
        fp = {r for r in flagged if labels.get(r, ("",))[0] == "fp"}
        todo = set(flagged) - attack - fp
        normal = n - len(attack)
        res.update({
            "confirmed_attack_lines": len(attack),
            "fp_lines": len(fp),
            "unclassified_flagged": len(todo),
            "corrected_rate": len(fp) / normal if normal else None,
            "corrected_upper95": upper95(len(fp), normal),
            # 분류 안 한 줄을 모두 오탐으로 칠 때(보수적)
            "corrected_rate_if_unclassified_fp": (len(fp) + len(todo)) / normal if normal else None,
            "fp_by_rule": dict(Counter(r for ref in fp for r in flagged[ref]).most_common()),
            "attack_reasons": dict(Counter(labels[r][1] for r in attack).most_common()),
        })
    review = [{"ref": r, "rules": ",".join(sorted(flagged[r])), "src_ip": ip_of.get(r, "-")} for r in sorted(flagged)]
    return res, review


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, help="사이트 프로필 JSON(log_paths.access 필수)")
    ap.add_argument("--out", required=True, help="결과 JSON(숫자와 위치만)")
    ap.add_argument("--review", help="표시된 줄 분류표 TSV를 쓸 곳(원본 줄 포함. data/ 아래에 둘 것)")
    ap.add_argument("--labels", help="사람이 class·reason을 채운 분류표 TSV")
    a = ap.parse_args(argv)
    profile = SiteProfile.load(a.profile)
    labels = load_labels(Path(a.labels)) if a.labels else None
    res, review = measure(profile, labels)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.review:
        raws = raw_lines(profile)
        old = load_labels(Path(a.review)) if Path(a.review).exists() else {}
        with open(a.review, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=REVIEW_COLS, delimiter="\t")
            w.writeheader()
            for row in review:
                c, why = old.get(row["ref"], ("", ""))
                w.writerow({**row, "class": c, "reason": why, "line": raws.get(row["ref"], "")[:500]})
    pct = lambda x: "-" if x is None else f"{x:.4%}"  # noqa: E731
    print(f"접근 로그 {res['access_lines']:,}줄 · 표시 {res['flagged_lines']:,}줄 · 원래 오탐률 {pct(res['raw_rate'])}"
          f" (95% 상한 {pct(res['raw_upper95'])})")
    if labels is not None:
        print(f"실제 공격으로 뺌 {res['confirmed_attack_lines']:,} · 오탐 {res['fp_lines']:,} · 미분류 {res['unclassified_flagged']:,}"
              f" · 라벨 보정 {pct(res['corrected_rate'])} (95% 상한 {pct(res['corrected_upper95'])},"
              f" 미분류를 오탐으로 치면 {pct(res['corrected_rate_if_unclassified_fp'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

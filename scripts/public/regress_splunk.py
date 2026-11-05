"""회귀 시험: 처음 보는 데이터(Splunk attack_data)에서 한 번 잡은 것을 계속 잡는가.

측정 결과 파일(reports/public/splunk_attack_data.json)은 규칙을 고정한 커밋에서 한 번 만들고 다시 만들지 않는다.
이 스크립트는 그 파일을 '고정된 기준'으로 읽어, 지금 코드가 같은 표본에서 무엇을 잡는지 다시 돌려 본다.

- 실패(종료 코드 1): 기준에서 '맞게 탐지'였던 표본의 목표 행동을 지금 규칙이 더는 표시하지 않음
- 알림만: 기준에서 놓쳤던 표본을 이제 잡음(개선). 이것은 처음 보는 데이터 점수가 아니다.
  규칙을 고칠 때 이 표본을 봤다면 개발 데이터가 되므로 측정 문서의 31%를 바꾸지 않는다.

    python scripts/public/regress_splunk.py --cache data/public/attack_data
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from logsight.detect import run_detections  # noqa: E402
from logsight.normalize import parse_cloudtrail  # noqa: E402

BASE = ROOT / "reports" / "public" / "splunk_attack_data.json"
OK = "맞게 탐지"


def fetch(url: str, cache: Path) -> Path:
    """eval_splunk_attack_data.py와 같은 캐시 이름을 쓴다."""
    p = cache / (hashlib.sha1(url.encode()).hexdigest()[:16] + ".json")
    if not p.exists():
        with urllib.request.urlopen(url, timeout=60) as r:
            p.write_bytes(r.read())
    return p


def events(path: Path):
    """eval_splunk_attack_data.py와 같은 읽기(JSON Lines도 받음)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    s = text.lstrip()
    if s.startswith("{") and "\n{" in s:
        text = json.dumps({"Records": [json.loads(ln) for ln in s.splitlines() if ln.strip().startswith("{")]})
    return parse_cloudtrail(text, path.name)


def target_rules(urls: list[str], targets: list[str], cache: Path) -> set[str]:
    evs = []
    for u in urls:
        evs += events(fetch(u, cache))
    tg = set(targets)
    fs = run_detections(copy.deepcopy(evs), {})
    if not tg:  # 특정 API가 아니라 행동(예: 권한 거부 폭주)을 찾는 규칙: 걸린 규칙 전체를 본다
        return {f.rule for f in fs}
    return {f.rule for f in fs for e in f.events if (e.action or "").split(":")[-1] in tg}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--base", default=str(BASE))
    a = ap.parse_args()
    cache = Path(a.cache)
    cache.mkdir(parents=True, exist_ok=True)
    base = json.loads(Path(a.base).read_text(encoding="utf-8"))
    lost, gained, kept, memo = [], [], 0, {}
    for row in base["rows"]:
        if "error" in row:
            continue
        key = (tuple(sorted(row["data"])), tuple(sorted(row.get("targets", []))))
        if key not in memo:
            memo[key] = target_rules(row["data"], row.get("targets", []), cache)
        now = memo[key]
        was = set(row.get("target_rules") or (row.get("rules", []) if not row.get("targets") else []))
        if row.get("judgement") == OK:
            if was - now:
                lost.append((row["detection"], sorted(was - now)))
            else:
                kept += 1
        elif now - was:
            gained.append((row["detection"], sorted(now - was)))
    print(f"기준 커밋 {base['engine_commit']} · 탐지 규칙 {len(base['rows'])}개 기준")
    print(f"기준에서 맞게 탐지한 것 중 계속 잡음 {kept}개 · 더는 못 잡음 {len(lost)}개 · 새로 잡음 {len(gained)}개(개발 데이터로 셈)")
    for name, rules in lost:
        print(f"  [회귀] {name}: {', '.join(rules)}")
    for name, rules in gained:
        print(f"  [개선] {name}: {', '.join(rules)}")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())

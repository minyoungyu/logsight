"""테스트 체크리스트 회차 실행(사양서 NFR-21): 자동 TC의 결과를 pytest에서 받아 표로 만든다.

사람이 '통과'라고 적지 않는다. pytest 결과 파일(JUnit XML)에서 TC가 가리키는 테스트를 찾아
- 모두 통과 → 통과
- 하나라도 실패·오류 → 실패
- 하나라도 건너뜀(통과·실패 없음 포함) → 건너뜀(미실시로 센다)
- 결과에 없음 → 찾지 못함(미실시로 센다)
으로 적는다. 수동·스크립트 TC는 미실시로 세고, 사람이 결과를 따로 적는다.

    python scripts/checklist_run.py              # pytest를 돌리고 요약
    python scripts/checklist_run.py --rows       # TC별 결과까지
    python scripts/checklist_run.py --junit 결과.xml   # 이미 돌린 결과 파일을 읽기만
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from spec_trace import CHECK, read_checklist  # noqa: E402


def outcomes(junit: Path) -> dict[tuple[str, str], str]:
    """{(모듈, 클래스 또는 ''), 테스트 이름): passed|failed|skipped}"""
    out = {}
    for tc in ET.parse(junit).getroot().iter("testcase"):
        cls = tc.get("classname", "")
        name = tc.get("name", "").split("[")[0]
        if tc.find("failure") is not None or tc.find("error") is not None:
            st = "failed"
        elif tc.find("skipped") is not None:
            st = "skipped"
        else:
            st = "passed"
        prev = out.get((cls, name))
        out[(cls, name)] = st if prev in (None, "passed") or st == "failed" else prev
    return out


def status_of(ref: tuple[str, str], res: dict[tuple[str, str], str]) -> str:
    """ref = (tests/파일.py, 이름). 이름은 클래스이거나 함수다."""
    mod = ref[0][:-3].replace("/", ".")
    name = ref[1]
    hits = [st for (cls, n), st in res.items()
            if ((cls == mod or cls.startswith(mod + ".")) and n == name) or cls == f"{mod}.{name}"]
    if not hits:
        return "찾지 못함"
    if "failed" in hits:
        return "실패"
    if "skipped" in hits:
        return "건너뜀"
    return "통과"


def run_round(junit: Path | None) -> list[dict]:
    if junit is None:
        junit = Path(tempfile.mkdtemp()) / "junit.xml"
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        f"--junitxml={junit}"], cwd=ROOT, check=False, stdout=subprocess.DEVNULL)
    res = outcomes(junit)
    rows = []
    for tc in read_checklist(CHECK.read_text(encoding="utf-8")):
        if tc["auto"]:
            sts = [status_of(r, res) for r in tc["auto"]]
            st = next((s for s in ("실패", "찾지 못함", "건너뜀") if s in sts), "통과")
        else:
            st = "미실시(수동)"
        rows.append({"id": tc["id"], "reqs": tc["reqs"], "status": st})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--junit", type=Path)
    ap.add_argument("--rows", action="store_true")
    a = ap.parse_args()
    rows = run_round(a.junit)
    c = Counter(r["status"] for r in rows)
    not_run = c["건너뜀"] + c["찾지 못함"] + c["미실시(수동)"]
    if a.rows:
        for r in rows:
            print(f"{r['id']:<26} {','.join(r['reqs']):<18} {r['status']}")
    print(f"TC {len(rows)} | 통과 {c['통과']} | 실패 {c['실패']} | 미실시 {not_run} "
          f"(건너뜀 {c['건너뜀']}, 찾지 못함 {c['찾지 못함']}, 수동·스크립트 {c['미실시(수동)']})")
    return 1 if c["실패"] else 0


if __name__ == "__main__":
    sys.exit(main())

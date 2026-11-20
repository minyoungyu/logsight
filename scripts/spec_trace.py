"""사양서(docs/사양서.md) ↔ 테스트 체크리스트(docs/테스트_체크리스트.md) ↔ 테스트 코드(tests/) 추적표.

확인하는 것
1. 사양서의 요구사항(FR·NFR)마다 테스트 케이스(TC)가 하나 이상 있다. 상태가 ⬜(미구현)인 것은 빼고 센다.
2. 체크리스트의 TC가 가리키는 요구사항 ID가 사양서에 있다.
3. '자동' TC가 가리키는 tests/파일.py::이름 이 실제로 있다(클래스 또는 함수).

    python scripts/spec_trace.py            # 요약 출력, 어긋나면 종료 코드 1
    python scripts/spec_trace.py --matrix   # 요구사항별 TC 목록까지
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "사양서.md"
CHECK = ROOT / "docs" / "테스트_체크리스트.md"

REQ_ROW = re.compile(r"^\|\s*((?:FR|NFR)-\d+)\s*\|(.*)$")
TC_ROW = re.compile(r"^\|\s*(TC-[A-Z0-9-]+)\s*\|(.*)$")
REQ_ID = re.compile(r"\b(?:FR|NFR)-\d+\b")
AUTO_REF = re.compile(r"(tests/[\w./-]+\.py)::(\w+)")


def read_spec(text: str) -> dict[str, bool]:
    """{요구사항 ID: 미구현(⬜) 여부}"""
    out = {}
    for line in text.splitlines():
        m = REQ_ROW.match(line.strip())
        if m:
            out[m.group(1)] = "⬜" in m.group(2)
    return out


def read_checklist(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = TC_ROW.match(line.strip())
        if not m:
            continue
        cells = [c.strip() for c in m.group(2).split("|")]
        req_cell = cells[0] if cells else ""
        method = " ".join(cells[2:3]) if len(cells) > 2 else ""
        rows.append({"id": m.group(1), "reqs": REQ_ID.findall(req_cell), "method": method,
                     "auto": AUTO_REF.findall(method)})
    return rows


def defined(path: Path, name: str) -> bool:
    if not path.exists():
        return False
    return re.search(rf"^\s*(?:class|def)\s+{re.escape(name)}\b", path.read_text(encoding="utf-8"), re.M) is not None


def check(spec_text: str, check_text: str, root: Path = ROOT) -> tuple[list[str], dict]:
    spec = read_spec(spec_text)
    tcs = read_checklist(check_text)
    errors: list[str] = []
    by_req: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for tc in tcs:
        if tc["id"] in seen:
            errors.append(f"{tc['id']}: TC ID가 두 번 나옴")
        seen.add(tc["id"])
        if not tc["reqs"]:
            errors.append(f"{tc['id']}: 요구사항 ID가 없음")
        for r in tc["reqs"]:
            if r not in spec:
                errors.append(f"{tc['id']}: 사양서에 없는 요구사항 {r}")
            by_req[r].append(tc["id"])
        for f, name in tc["auto"]:
            if not defined(root / f, name):
                errors.append(f"{tc['id']}: 테스트 {f}::{name} 를 찾을 수 없음")
        if not tc["auto"] and not re.search(r"수동|스크립트", tc["method"]):
            errors.append(f"{tc['id']}: 방법 칸에 '자동 tests/..::이름', '수동' 또는 '스크립트'가 없음")
    for r, todo in spec.items():
        if not todo and not by_req.get(r):
            errors.append(f"{r}: 테스트 케이스가 없음")
    stats = {"reqs": len(spec), "todo": sum(spec.values()), "tcs": len(tcs),
             "auto": sum(1 for t in tcs if t["auto"]), "by_req": dict(by_req)}
    return errors, stats


def main(argv: list[str]) -> int:
    errors, st = check(SPEC.read_text(encoding="utf-8"), CHECK.read_text(encoding="utf-8"))
    print(f"요구사항 {st['reqs']}개(미구현 {st['todo']}개 제외하고 추적) · TC {st['tcs']}개 · "
          f"자동 {st['auto']}개 / 수동·스크립트 {st['tcs'] - st['auto']}개")
    if "--matrix" in argv:
        for r in sorted(st["by_req"], key=lambda x: (x.split("-")[0], int(x.split("-")[1]))):
            print(f"  {r}: {', '.join(st['by_req'][r])}")
    for e in errors:
        print("  ✗", e)
    print("추적 통과" if not errors else f"어긋남 {len(errors)}건")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

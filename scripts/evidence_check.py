"""문서의 측정 숫자를 결과 파일과 대조한다(근거 없는 숫자가 다시 생기지 않게).

    python scripts/evidence_check.py          # 문제가 있으면 목록을 출력하고 1로 끝난다

두 가지를 본다.
1. docs/근거_목록.json의 숫자마다: 결과 파일이 있는지, 파일에서 다시 계산한 값이 같은지, 문서에 그 문구가 있는지.
2. README·docs·lab 문서에 적힌 `reports/...` 경로가 실제로 있는지(명령 예시 경로는 path_allowlist에 이유와 함께 적는다).
"""
from __future__ import annotations

import glob
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "근거_목록.json"
PATH_RE = re.compile(r"(reports/[A-Za-z0-9_./\-가-힣]+?\.(?:json|md|html|txt|csv))")


def _get(obj, dotted: str):
    for part in dotted.split("."):
        obj = obj[part]
    return obj


def _same(a, b) -> bool:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= 1e-9 + 1e-6 * abs(b)
    return a == b


def check_claim(c: dict) -> list[str]:
    errs: list[str] = []
    cid = c["id"]
    doc = ROOT / c["doc"]
    if not doc.exists():
        return [f"{cid}: 문서 {c['doc']} 없음"]
    if c["quote"] not in doc.read_text(encoding="utf-8"):
        errs.append(f"{cid}: {c['doc']}에 '{c['quote']}' 문구가 없음(숫자를 바꿨다면 근거 목록도 함께 고칠 것)")
    if "rule_count" in c:
        sys.path.insert(0, str(ROOT))
        from logsight import detect
        if len(detect.RULES) != c["rule_count"]:
            errs.append(f"{cid}: 규칙 {len(detect.RULES)}개, 목록은 {c['rule_count']}")
        return errs
    f = ROOT / c["file"]
    if not f.exists():
        return errs + [f"{cid}: 결과 파일 {c['file']} 없음"]
    d = json.loads(f.read_text(encoding="utf-8"))
    for k, want in c.get("values", {}).items():
        try:
            got = _get(d, k)
        except (KeyError, TypeError):
            errs.append(f"{cid}: {c['file']}에 {k} 없음")
            continue
        if not _same(got, want):
            errs.append(f"{cid}: {k} = {got}, 목록은 {want}")
    if "count" in c and len(_get(d, c["count"]["path"])) != c["count"]["expect"]:
        errs.append(f"{cid}: {c['count']['path']} 개수 {len(_get(d, c['count']['path']))}, 목록은 {c['count']['expect']}")
    if "verdicts" in c:
        got = dict(Counter(i["verdict"] for i in _get(d, c["verdicts"]["path"])))
        if got != c["verdicts"]["expect"]:
            errs.append(f"{cid}: 판정 {got}, 목록은 {c['verdicts']['expect']}")
    if "host_sum" in c:
        fp = sum(h["line_level"]["fp"] for h in d["hosts"].values())
        tot = sum(h["line_level"]["fp"] + h["line_level"]["tn"] for h in d["hosts"].values())
        if (fp, tot) != (c["host_sum"]["fp"], c["host_sum"]["fp+tn"]):
            errs.append(f"{cid}: 서버 합 {fp}/{tot}, 목록은 {c['host_sum']['fp']}/{c['host_sum']['fp+tn']}")
    if "sum_fields" in c:
        s = sum(_get(d, k) for k in c["sum_fields"]["fields"])
        if s != c["sum_fields"]["expect"]:
            errs.append(f"{cid}: 합 {s}, 목록은 {c['sum_fields']['expect']}")
    if "nonempty" in c:
        n = c["nonempty"]
        rows = _get(d, n["path"])
        got = sum(1 for r in rows if r.get(n["field"]))
        if (got, len(rows)) != (n["expect"], n["total"]):
            errs.append(f"{cid}: {got}/{len(rows)}, 목록은 {n['expect']}/{n['total']}")
    return errs


def check_paths(allow: dict) -> list[str]:
    errs = []
    files = ["README.md"] + glob.glob("docs/**/*.md", root_dir=ROOT, recursive=True) \
        + glob.glob("lab/**/*.md", root_dir=ROOT, recursive=True)
    for rel in files:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for p in sorted(set(PATH_RE.findall(text))):
            if p in allow or not (ROOT / p).exists():
                if p not in allow:
                    errs.append(f"{rel}: 없는 결과 파일 {p}")
    return errs


def run() -> list[str]:
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    errs = check_paths(reg.get("path_allowlist", {}))
    for c in reg["claims"]:
        errs += check_claim(c)
    return errs


def main() -> int:
    errs = run()
    for e in errs:
        print(e)
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    print(f"근거 목록 {len(reg['claims'])}개 확인, 문제 {len(errs)}건")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

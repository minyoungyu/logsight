"""문서의 측정 숫자를 결과 파일과 대조한다(근거 없는 숫자가 다시 생기지 않게).

    python scripts/evidence_check.py          # 문제가 있으면 목록을 출력하고 1로 끝난다

세 가지를 본다.
1. docs/근거_목록.json의 숫자마다: 결과 파일이 있는지, 파일에서 다시 계산한 값이 같은지, 문서에 그 문구가 있는지.
2. README·docs·lab 문서에 적힌 `reports/...` 경로가 실제로 있는지(명령 예시 경로는 path_allowlist에 이유와 함께 적는다).
3. 사양서(docs/사양서.md) 성공 기준(S)·비기능(NFR) 표의 '지금' 칸에 적힌 측정 숫자마다
   (가) 사양서를 가리키는 근거 항목의 quote 안에 그 숫자가 있거나 (나) spec_unbacked에 이유와 함께 적혀 있는지.
   어느 쪽도 아니면 실패한다. 근거 파일 없이 숫자를 사양서에 새로 쓰면 CI가 막는다.
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
SPEC = "docs/사양서.md"
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
    if "sum_across" in c:  # 여러 결과 파일의 값을 더한 숫자
        total = 0
        for fn, path in c["sum_across"]["items"]:
            if not (ROOT / fn).exists():
                return errs + [f"{cid}: 결과 파일 {fn} 없음"]
            total += _get(json.loads((ROOT / fn).read_text(encoding="utf-8")), path)
        if total != c["sum_across"]["expect"]:
            errs.append(f"{cid}: 합 {total}, 목록은 {c['sum_across']['expect']}")
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
        hs = c["host_sum"]
        hosts = [d["hosts"][hs["host"]]] if "host" in hs else list(d["hosts"].values())
        fp = sum(h["line_level"]["fp"] for h in hosts)
        tot = sum(h["line_level"]["fp"] + h["line_level"]["tn"] for h in hosts)
        if (fp, tot) != (hs["fp"], hs["fp+tn"]):
            errs.append(f"{cid}: 서버 합 {fp}/{tot}, 목록은 {hs['fp']}/{hs['fp+tn']}")
        elif "pct" in hs and round(fp / tot * 100, hs["decimals"]) != hs["pct"]:
            errs.append(f"{cid}: {fp}/{tot} = {fp / tot * 100:.4f}%, 목록은 {hs['pct']}%")
    if "steps" in c:  # 공격 단계 표시 수: dict(step_detected) 또는 list(in_data·detected)
        st = _get(d, c["steps"]["path"])
        if isinstance(st, dict):
            got = (sum(1 for v in st.values() if v["step_detected"]), len(st))
        else:
            got = (sum(1 for v in st if v["in_data"] and v["detected"]), sum(1 for v in st if v["in_data"]))
        if list(got) != c["steps"]["expect"]:
            errs.append(f"{cid}: 단계 {got[0]}/{got[1]}, 목록은 {c['steps']['expect'][0]}/{c['steps']['expect'][1]}")
    if "rate" in c:  # 파일에 비율(0~1)이 있을 때 문서의 % 표기와 비교
        r = c["rate"]
        got = round(_get(d, r["path"]) * 100, r["decimals"])
        if got != r["pct"]:
            errs.append(f"{cid}: {r['path']} = {got}%, 목록은 {r['pct']}%")
    if "wilson" in c:  # k/n의 95% 윌슨 구간을 파일 값으로 다시 계산
        w = c["wilson"]
        lo, hi = _wilson(_get(d, w["k"]), _get(d, w["n"]))
        if [round(lo * 100), round(hi * 100)] != w["expect_pct"]:
            errs.append(f"{cid}: 95% 구간 {lo * 100:.1f}~{hi * 100:.1f}%, 목록은 {w['expect_pct']}")
    if "cost" in c:  # 토큰 수 × 공식 단가(100만 토큰당 달러)
        k = c["cost"]
        usd = (_get(d, k["in"]) * k["price_in"] + _get(d, k["out"]) * k["price_out"]) / 1e6
        if round(usd, 2) != k["expect_usd"]:
            errs.append(f"{cid}: 비용 ${usd:.4f}, 목록은 ${k['expect_usd']}")
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


def _wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return (c - a) / d, (c + a) / d


# 측정 숫자로 보는 표기: 범위(31~56%), 백분율, 분수(1,740/350,674), 시간(2분 3초, 0.6초), 메모리(MB), 달러.
# 날짜 10/26·11/3처럼 앞이 10·11인 분수는 이 프로젝트 기간(2026년 10~11월)의 날짜로 보고 뺀다.
# "95% 구간", "95% 상한"의 95%는 신뢰수준이라 뺀다.
_NUM = re.compile(r"\d+(?:\.\d+)?~\d+(?:\.\d+)?%|\d+(?:,\d{3})*(?:\.\d+)?%|\d+(?:,\d{3})*/\d+(?:,\d{3})*"
                  r"|\d+분 \d+초|\d+(?:\.\d+)?초|\d+(?:,\d{3})*MB|\$\d+(?:\.\d+)?")
_CONF = re.compile(r"95%(?= ?(?:구간|상한|\d))")
_ROW = re.compile(r"^\|\s*(S\d+|NFR-\d+)\s*\|(.*)$")


def spec_numbers(text: str) -> list[tuple[str, str]]:
    """사양서 S·NFR 표 '지금' 칸의 (행 ID, 측정 숫자) 목록."""
    out = []
    for line in text.splitlines():
        m = _ROW.match(line.strip())
        if not m:
            continue
        cells = [x.strip() for x in m.group(2).split("|")]
        if len(cells) < 5:
            continue
        now = _CONF.sub("", cells[3])
        for tok in _NUM.findall(now):
            frac = re.fullmatch(r"(\d+)/(\d+)", tok)
            if frac and frac.group(1) in ("10", "11") and int(frac.group(2)) <= 31:
                continue
            out.append((m.group(1), tok))
    return out


def check_spec(reg: dict) -> list[str]:
    text = (ROOT / SPEC).read_text(encoding="utf-8")
    quotes = [c["quote"] for c in reg["claims"] if c["doc"] == SPEC]
    unbacked = {(u["row"], u["token"]) for u in reg.get("spec_unbacked", [])}
    errs = []
    for row, tok in spec_numbers(text):
        if (row, tok) in unbacked or any(tok in q for q in quotes):
            continue
        errs.append(f"{SPEC} {row}: '{tok}'의 근거 항목이 없음(근거_목록.json claims에 결과 파일과 함께 더하거나,"
                    f" 파일이 없으면 spec_unbacked에 이유를 적을 것)")
    for u in reg.get("spec_unbacked", []):
        if not u.get("reason"):
            errs.append(f"spec_unbacked {u['row']} '{u['token']}': 이유가 비어 있음")
        if (u["row"], u["token"]) not in set(spec_numbers(text)):
            errs.append(f"spec_unbacked {u['row']} '{u['token']}': 사양서에 더는 없음(목록에서 지울 것)")
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
    errs += check_spec(reg)
    for c in reg["claims"]:
        errs += check_claim(c)
    return errs


def main() -> int:
    errs = run()
    for e in errs:
        print(e)
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    n_spec = sum(1 for c in reg["claims"] if c["doc"] == SPEC)
    print(f"근거 목록 {len(reg['claims'])}개 확인(사양서 {n_spec}개, 근거 파일 없음으로 적은 사양서 숫자 "
          f"{len(reg.get('spec_unbacked', []))}개), 문제 {len(errs)}건")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

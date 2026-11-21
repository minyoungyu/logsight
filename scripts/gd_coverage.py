"""GuardDuty 활성 탐지 유형 중 LogFinder가 한국어로 풀어 주는 것을 센다.

    python scripts/gd_coverage.py            # 요약
    python scripts/gd_coverage.py --list     # 유형별 결과(raw만 보려면 --raw)

유형 목록: samples/guardduty/finding_types.tsv (AWS 공식 문서의 활성 유형 표).
- specific: 유형별로 직접 쓴 제목·풀이·먼저 할 일
- composed: 위협 목적·자원·행동 낱말을 모두 알아 한국어로만 조합
- raw: 모르는 낱말이 있어 제목에 영어가 남음
- 규칙 연결: 같은 뜻의 LogFinder 규칙(GD_ALIAS)이 있어 그 규칙의 단계·기법을 씀
- 수정 명령: 그 규칙에 설정 수정안(config_audit)이 있어, 설정 스냅샷이 있으면 CLI 수정·되돌리기 명령까지 나옴
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.gd_types import describe  # noqa: E402
from logsight.normalize import GD_ALIAS  # noqa: E402

# config_audit.audit가 설정 수정안(CLI 명령)을 내는 규칙
FIX_RULES = {"SSH_BRUTE_FORCE", "VPC_REMOTE_ADMIN_EXPOSED", "VPC_PORT_SCAN", "CT_INSTANCE_CRED_OUTSIDE",
             "CT_INSTANCE_CRED_MULTI_IP", "CT_LOGGING_TAMPER", "CT_UNTRUSTED_IP", "CT_IAM_PERSISTENCE"}


def load(path: Path = ROOT / "samples/guardduty/finding_types.tsv") -> list[tuple[str, str, str]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            t, src, sev = (line.split("\t") + ["", ""])[:3]
            rows.append((t, src, sev))
    return rows


def measure(rows) -> dict:
    out = {"total": len(rows), "level": Counter(), "alias": 0, "fix": 0, "by_source": {}, "raw": []}
    for t, src, _ in rows:
        d = describe(t)
        out["level"][d["level"]] += 1
        rules = {r for k, r in GD_ALIAS if k in t}
        alias, fix = bool(rules), bool(rules & FIX_RULES)
        out["alias"] += alias
        out["fix"] += fix
        s = out["by_source"].setdefault(src, Counter())
        s["total"] += 1
        s[d["level"]] += 1
        s["alias"] += alias
        s["fix"] += fix
        if d["level"] == "raw":
            out["raw"].append(t)
    return out


def main(argv: list[str]) -> int:
    rows = load()
    if "--list" in argv or "--raw" in argv:
        for t, src, sev in rows:
            d = describe(t)
            if "--raw" in argv and d["level"] != "raw":
                continue
            print(f"{d['level']:9} {src:24} {t}\n          → {d['title']} / {d['action']}")
        return 0
    m = measure(rows)
    lv = m["level"]
    ko = lv["specific"] + lv["composed"]
    print(f"GuardDuty 활성 유형 {m['total']}종")
    print(f"  한국어 제목·풀이·먼저 할 일: {ko}종 ({ko / m['total']:.0%}) = 유형별 문장 {lv['specific']} + 낱말 조합 {lv['composed']}")
    print(f"  영어가 남는 유형: {lv['raw']}종")
    print(f"  같은 뜻의 LogFinder 규칙에 연결: {m['alias']}종, 그중 설정 수정 명령까지 나오는 것: {m['fix']}종")
    print("  데이터 원본별(전체 / 한국어 / 규칙 연결 / 수정 명령):")
    for src, c in sorted(m["by_source"].items(), key=lambda x: -x[1]["total"]):
        print(f"    {src:24} {c['total']:3} / {c['specific'] + c['composed']:3} / {c['alias']:3} / {c['fix']:3}")
    if "--json" in argv:
        print(json.dumps({**m, "level": dict(lv), "by_source": {k: dict(v) for k, v in m["by_source"].items()}},
                         ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""수정안 측정(사양서 S5): 원인 설정을 짚었나, 관련 없는 수정안을 냈나.

    python scripts/fix_eval.py [--json reports/fix_eval.json]

정답지는 설정 스냅샷(environment.json)이 있는 저장소 샘플 4개다. 샘플을 만들 때 심어 둔 원인 설정을
사건마다 적었다. 이 샘플은 규칙을 만들면서 본 데이터이므로 결과는 **개발 점수**이고 S5 달성으로 세지 않는다
(사양서 3절). 독립 정답지(다른 사람이 만든 사고 + 설정 스냅샷)가 생기면 CASES에 더한다.

- 원인(root): 사건이 일어나게 한 설정. 지목률 = 낸 수정안 중 원인에 든 것 / 원인 수
- 허용(ok): 원인은 아니지만 그 사건에 맞는 조치(세션 무효화, 계정 잠그기, 공격 IP 막기, 앱 코드 고치기)
- 관련 없음: 원인도 허용도 아닌 수정안. 목표 0개
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.pipeline import run_paths  # noqa: E402

CONTAIN = {"IAM_ROLE_SESSION_REVOKE", "IAM_KEY_COMPROMISED", "WEB_FIX_ACCOUNT", "NACL_BLOCK_ATTACKER"}

# (샘플, 사건 ID, 원인 설정, 원인 말고 맞는 조치, 심어 둔 이야기)
CASES = [
    ("combined", "INC-001", {"SG_ADMIN_PORT_OPEN", "WAF_SQLI_COUNT", "IMDSV1_ENABLED", "IAM_OVERBROAD"},
     CONTAIN | {"WEB_FIX_SQLI"},
     "SSH 22 전체 공개 → 대입 로그인, WAF SQLi 규칙 COUNT → SSRF, IMDSv1 → 역할 키 유출, 역할 권한 과다 → S3 읽기"),
    ("combined", "INC-002", {"SG_ADMIN_PORT_OPEN", "WEB_FIX_SQLI"}, CONTAIN,
     "포트 훑기 뒤 22 허용, nginx 앞단(WAF 없음)으로 SQLi 시도"),
    ("combined", "INC-003", set(), set(), "막힌 단발 시도: 수정안이 없어야 함"),
    ("demo", "INC-001", {"SG_ADMIN_PORT_OPEN", "WAF_SQLI_COUNT", "IMDSV1_ENABLED", "IAM_OVERBROAD"},
     CONTAIN | {"WEB_FIX_SQLI"}, "combined INC-001과 같은 이야기, 웹 로그는 ALB"),
    ("free", "INC-001", {"SG_ADMIN_PORT_OPEN", "WEB_NO_WAF", "WEB_FIX_SQLI"}, CONTAIN,
     "무료 구성(호스트 방화벽 + nginx): 22 공개, WAF 없음, SQLi"),
    ("guardduty", "INC-001", {"IMDSV1_ENABLED", "IAM_OVERBROAD", "SG_ADMIN_PORT_OPEN"}, CONTAIN,
     "GuardDuty 결과 2개(역할 키 외부 사용, SSH 대입)만 있는 입력"),
]


def evaluate() -> dict:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    cache: dict[str, dict] = {}
    rows = []
    for sample, iid, root, ok, story in CASES:
        if sample not in cache:
            d = ROOT / "samples" / sample
            cache[sample] = run_paths([str(d)], str(d / "environment.json"), use_ai=False)
        res = next((r for r in cache[sample]["results"] if r["incident"]["id"] == iid), None)
        got = {c["id"] for c in res["checks"]} if res else set()
        rows.append({"sample": sample, "incident": iid, "story": story, "root": sorted(root),
                     "hit": sorted(got & root), "missed": sorted(root - got),
                     "unrelated": sorted(got - root - ok)})
    n_root = sum(len(r["root"]) for r in rows)
    n_hit = sum(len(r["hit"]) for r in rows)
    return {"cases": len(rows), "root_total": n_root, "root_hit": n_hit,
            "root_rate": round(n_hit / n_root, 3) if n_root else None,
            "unrelated_total": sum(len(r["unrelated"]) for r in rows), "rows": rows,
            "note": "개발 점수(규칙을 만들며 본 샘플). S5 달성으로 세지 않음"}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    r = evaluate()
    for x in r["rows"]:
        print(f"{x['sample']:9} {x['incident']}  원인 {len(x['hit'])}/{len(x['root'])}"
              + (f"  놓침 {','.join(x['missed'])}" if x["missed"] else "")
              + (f"  관련 없음 {','.join(x['unrelated'])}" if x["unrelated"] else ""))
    rate = f"{r['root_rate']:.0%}" if r["root_rate"] is not None else "-"
    print(f"사건 {r['cases']}개 · 원인 지목 {r['root_hit']}/{r['root_total']} ({rate}) · 관련 없는 수정안 "
          f"{r['unrelated_total']}개 · {r['note']}")
    if a.json:
        Path(a.json).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

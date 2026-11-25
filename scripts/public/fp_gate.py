#!/usr/bin/env python3
"""규칙을 바꾸기 전에 돌리는 오탐 검사(정상 트래픽 회귀). 규칙만, AI 호출 없음.

  python scripts/public/fp_gate.py            # 기준과 비교. 규칙별 오탐 줄이 늘면 실패(종료 코드 1)
  python scripts/public/fp_gate.py --update   # 지금 결과를 기준으로 저장(늘어난 게 의도된 것일 때만)

왜: 11/24 CTF 리허설 한 사례로 넣은 WEBLOG_ROBOTS_HIDDEN이 처음 본 실제 로그(EClog)에서 정상 크롤러
1,740줄을 잡아 S7을 0.496%로 만들었다. 규칙을 넣을 때 정상 트래픽에서 재 보는 절차가 없었다.

재는 데이터(로컬에 있는 것만. data/는 저장소에 올리지 않으므로 CI가 아니라 사람이 병합 전에 돌린다):
  - EClog 하루치(data/public/eclog): 사람이 분류한 review.tsv로 실제 공격 9줄을 뺀다. 분류표에 없는
    새 표시 줄은 오탐으로 센다(보수적).
  - AIT-LDS 테스트베드(data/public/ait_<이름>, fetch_ait.py로 받음): 라벨 없는 줄의 표시 = 오탐.
  - (AWS) Panther 시험의 A 반 정상 이벤트(LOGSIGHT_PANTHER=<panther-analysis>). B 반은 봉인이라 넣지 않는다.
둘 다 이미 본 데이터라 이 숫자는 개발 점수다. 판정(S7)은 계획 파일의 처음 보는 데이터로만 한다.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "reports" / "public" / "fp_baseline.json"
TARGET = 0.001  # S7 목표 0.1%


def _mod(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "public" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def eclog() -> dict | None:
    base = ROOT / "data" / "public" / "eclog"
    if not (base / "access.log").exists():
        return None
    r = _mod("eval_reallog")
    from logsight.web.webprofile import SiteProfile
    labels = r.load_labels(base / "review.tsv") if (base / "review.tsv").exists() else {}
    res, _ = r.measure(SiteProfile.load(base / "profile.json"), labels)
    fp = res["fp_lines"] + res["unclassified_flagged"]
    normal = res["access_lines"] - res["confirmed_attack_lines"]
    by_rule = dict(res["fp_by_rule"])
    if res["unclassified_flagged"]:
        by_rule["(분류 안 된 새 표시)"] = res["unclassified_flagged"]
    return {"normal_lines": normal, "fp_lines": fp, "fp_by_rule": by_rule}


def ait(data: Path) -> dict:
    a = _mod("eval_ait")
    fp = normal = 0
    by_rule: dict[str, int] = {}
    for host in ("intranet_server", "webserver", "cloud_share"):
        if not (data / "gather" / host).exists():
            continue
        ll = a.line_level(a.host_profile(data, host), a.load_labels(data, host))
        fp += ll["fp"]
        normal += ll["fp"] + ll["tn"]
        for k, v in ll["fp_by_rule"].items():
            by_rule[k] = by_rule.get(k, 0) + v
    return {"normal_lines": normal, "fp_lines": fp, "fp_by_rule": by_rule}


def panther_a_negatives() -> dict | None:
    """Panther AWS CloudTrail 시험 중 A 반의 정상 시험(이미 잰 반). B 반은 봉인이라 절대 넣지 않는다.
    경로는 환경 변수 LOGSIGHT_PANTHER(panther-analysis 저장소)."""
    pa = os.environ.get("LOGSIGHT_PANTHER")
    if not pa or not Path(pa).exists():
        return None
    res = _mod("eval_panther").measure(Path(pa), "A")
    neg = [i for i in res["items"] if not i["expected"]]
    by_rule: dict[str, int] = {}
    for i in neg:
        for r in i["logfinder_rules"]:
            by_rule[r] = by_rule.get(r, 0) + 1
    return {"normal_lines": len(neg), "fp_lines": sum(bool(i["logfinder_rules"]) for i in neg), "fp_by_rule": by_rule,
            "note": "이벤트 단위. 실패한 시도·CI/CD 배포·루트 조회처럼 Panther와 기준이 다른 것도 섞여 있다"}


def run() -> dict:
    sys.path.insert(0, str(ROOT))
    out = {}
    e = eclog()
    if e:
        out["eclog_1day"] = e
    for d in sorted((ROOT / "data" / "public").glob("ait_*")):
        if (d / "gather").exists():
            out[d.name] = ait(d)
    p = panther_a_negatives()
    if p:
        out["panther_A_negatives(AWS)"] = p
    return out


def compare(base: dict, now: dict) -> list[str]:
    bad = []
    for name, cur in now.items():
        old = base.get(name)
        if old is None:
            continue
        for rule, n in cur["fp_by_rule"].items():
            was = old["fp_by_rule"].get(rule, 0)
            if n > was:
                bad.append(f"{name}: {rule} 오탐 {was} → {n}줄")
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true", help="지금 결과를 기준으로 저장")
    ap.add_argument("--baseline", default=str(BASELINE))
    a = ap.parse_args(argv)
    now = run()
    if not now:
        print("로컬에 정상 데이터가 없음(data/public/eclog, data/public/ait_*). 받는 법은 이 파일 맨 위 참고")
        return 2
    web = {k: v for k, v in now.items() if "AWS" not in k}
    tot_fp = sum(v["fp_lines"] for v in web.values())
    tot_n = sum(v["normal_lines"] for v in web.values())
    for name, v in now.items():
        rate = v["fp_lines"] / v["normal_lines"] if v["normal_lines"] else 0
        flag = "" if rate <= TARGET or "AWS" in name else "  ← 0.1% 넘음"
        print(f"{name:22s} 오탐 {v['fp_lines']:>5,}/{v['normal_lines']:>9,} = {rate:.4%}{flag}  {v['fp_by_rule']}")
    print(f"{'웹 합계':22s} 오탐 {tot_fp:>5,}/{tot_n:>9,} = {tot_fp / tot_n:.4%}  (개발 점수)")
    path = Path(a.baseline)
    if a.update:
        path.write_text(json.dumps(now, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"기준 저장: {path}")
        return 0
    if not path.exists():
        print("기준 파일이 없음. --update로 먼저 만든다")
        return 2
    bad = compare(json.loads(path.read_text(encoding="utf-8")), now)
    for b in bad:
        print("실패:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

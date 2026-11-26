"""규칙 성숙도: 시험 중(experimental) 규칙은 경보·사건에서 빼고 보고서에 따로 보인다.

근거: Sigma 규칙 규격의 status(stable·test·experimental — experimental은 "오탐이 나거나 시끄러울 수 있음"),
Elastic의 building block 규칙(경보를 Alerts 표에서 기본으로 숨김), Splunk의 Hunting·Anomaly 유형(기본 경보 없음).
11/24에 넣은 규칙 하나(WEBLOG_ROBOTS_HIDDEN)가 처음 본 실제 로그에서 오탐 1,740줄을 낸 뒤 도입했다.

승격 기준(reports/public/holdout_plan_2026-11-25.json maturity): 병합 전 오탐 검사(scripts/public/fp_gate.py)의
정상 데이터 3개 이상에서 그 규칙의 오탐이 각각 0.01% 이하이고, 남이 만든 데이터에서 실제 공격을 1번 이상 맞게 잡음.
"""
from __future__ import annotations

from .rulespec import SPEC


def status(rule: str) -> str:
    return (SPEC.get(rule) or {}).get("status", "stable")


def experimental_rules() -> set[str]:
    return {r for r in SPEC if status(r) == "experimental"}


def split(findings: list) -> tuple[list, list]:
    """(경보로 쓸 것, 시험 중). 시험 중 규칙 ID는 이벤트의 findings 표시에서도 지워 사건 묶기에 들어가지 않게 한다."""
    exp = experimental_rules()
    keep = [f for f in findings if f.rule not in exp]
    trial = [f for f in findings if f.rule in exp]
    for f in trial:
        for e in f.events:
            if f.rule in e.findings:
                e.findings.remove(f.rule)
    return keep, trial


def summary(trial: list, limit: int = 20) -> list[dict]:
    """보고서용 요약(규칙·대상별). 원본 줄은 넣지 않는다."""
    out = []
    for f in trial[:limit]:
        ts = sorted(e.ts for e in f.events)
        out.append({"rule": f.rule, "key": f.key, "n": len(f.events), "detail": f.detail,
                    "first": ts[0].isoformat() if ts else "", "last": ts[-1].isoformat() if ts else ""})
    return out

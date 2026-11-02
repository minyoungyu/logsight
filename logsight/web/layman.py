"""비숙련자용 요약 카드: 한 줄 판정, 쉬운 설명, 지금 할 일 몇 가지. 입력은 assess() 결과뿐이다."""
from __future__ import annotations

HEADLINE = {
    "breached": "서버가 뚫렸을 가능성이 매우 높습니다. 지금 바로 격리하세요.",
    "likely_breached": "서버가 뚫렸을 가능성이 큽니다. 아래 '지금 할 일'부터 처리하세요.",
    "suspicious": "공격 시도는 있었지만, 뚫렸다는 증거는 아직 로그에서 보이지 않습니다.",
    "no_evidence": "뚜렷한 침해 흔적은 보이지 않습니다.",
}
PRIORITY_KO = {"now": "지금", "soon": "곧", "later": "나중에"}


def _first_actions(result: dict, limit: int = 3) -> list[dict]:
    """모든 사건의 조치 중 '지금' 우선순위를 앞에 둔다. 같은 조치는 한 번만 보여 준다."""
    seen, out = set(), []
    order = {"now": 0, "soon": 1, "later": 2}
    actions = [a for r in result["results"] for a in r["report"].get("remediation", [])]
    for a in sorted(actions, key=lambda a: order.get(a.get("priority"), 3)):
        if a["action"] in seen:
            continue
        seen.add(a["action"])
        out.append({"action": a["action"], "priority": PRIORITY_KO.get(a.get("priority"), "나중에"),
                    "detail": a["detail"]})
    return out[:limit]


def layman_card(result: dict) -> dict:
    """비숙련자용 요약 카드."""
    verdict = result["overall_verdict"]
    inc_index = result.get("incident_index", [])
    when = ""
    if inc_index:
        first, last = inc_index[0], inc_index[-1]
        when = f"{first['start'][:16].replace('T', ' ')} ~ {last['end'][11:16]} (UTC)"
    return {
        "verdict": verdict,
        "verdict_ko": result["overall_verdict_ko"],
        "headline": HEADLINE.get(verdict, ""),
        "period": when,
        "n_incidents": result["n_incidents"],
        "now": _first_actions(result),
        "note": "자동 판정입니다. 중요한 결정 전에는 원본 로그와 상세 보고서를 함께 확인하세요.",
    }

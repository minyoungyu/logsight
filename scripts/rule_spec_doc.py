"""logsight/rulespec.py → docs/규칙_명세.md. 규칙을 바꾸면 다시 실행한다(테스트가 낡은 문서를 잡는다).

    python scripts/rule_spec_doc.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import RULES  # noqa: E402
from logsight.rulespec import SPEC  # noqa: E402

SEV = {"high": "높음", "medium": "중간", "low": "낮음"}


def render() -> str:
    n_meas = sum(1 for s in SPEC.values() for x in s["blind"] + s["fp"] if "[측정]" in x)
    out = ["# 탐지 규칙 명세", "",
           "> 이 문서는 `logsight/rulespec.py`에서 만든다(`python scripts/rule_spec_doc.py`). 직접 고치지 말 것.",
           "",
           f"규칙 {len(SPEC)}개마다 읽는 로그, 걸리는 조건, **사각지대**, **오탐**, 걸렸을 때 먼저 할 일을 적었다. "
           "Palantir ADS(Alerting and Detection Strategy) 형식을 줄인 것이다.",
           f"`[측정]`이 붙은 {n_meas}개 항목은 공개 데이터(BOTSv3, Splunk attack_data) 측정에서 확인한 것이다.",
           "검증: 모든 규칙에 '걸려야 하는 예'와 '기준 바로 아래라 걸리면 안 되는 예'가 "
           "`tests/test_rule_validation.py`에 있고 CI에서 돈다.",
           "",
           "| 규칙 | 이름 | 단계 | ATT&CK | 심각도 | 로그 |",
           "|---|---|---|---|---|---|"]
    for r, (tech, stage, name, sev) in RULES.items():
        out.append(f"| [{r}](#{r.lower()}) | {name} | {stage} | {tech} | {SEV.get(sev, sev)} | {SPEC[r]['logs']} |")
    out.append("")
    for r, (tech, stage, name, sev) in RULES.items():
        s = SPEC[r]
        out += [f"## {r}", "", f"**{name}** · {stage} · {tech} · 심각도 {SEV.get(sev, sev)}", "",
                f"- 로그: {s['logs']}", f"- 조건: {s['when']}", "- 사각지대:"]
        out += [f"  - {x}" for x in s["blind"]]
        out.append("- 오탐:")
        out += [f"  - {x}" for x in s["fp"]]
        out += [f"- 먼저 할 일: {s['first']}", f"- 검증: `tests/test_rule_validation.py` → `{r}`", ""]
    return "\n".join(out)


if __name__ == "__main__":
    p = ROOT / "docs" / "규칙_명세.md"
    p.write_text(render(), encoding="utf-8")
    print(f"{p.relative_to(ROOT)}: 규칙 {len(SPEC)}개")

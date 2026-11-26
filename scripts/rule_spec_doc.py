"""logsight/rulespec.py → docs/규칙_명세.md. 규칙을 바꾸면 다시 실행한다(테스트가 낡은 문서를 잡는다).

    python scripts/rule_spec_doc.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight.detect import RULES  # noqa: E402
from logsight.maturity import experimental_rules, status  # noqa: E402
from logsight.rulespec import SPEC  # noqa: E402

SEV = {"high": "높음", "medium": "중간", "low": "낮음"}
ST = {"stable": "경보", "experimental": "시험 중"}


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
           "`WEBLOG_` 규칙은 웹서버 점검(`scan`)과 AWS 분석(`analyze`·`watch`·`on-alert`)에서 함께 돈다. "
           "AWS 분석에서는 nginx·ALB 로그를 읽고, 사이트 프로필 대신 환경 파일의 `trusted_ips`와 `web` 항목"
           "(admin_paths·login_paths·upload_dirs·sensitive_files·own_hosts)을 쓴다. "
           "예전 사후 분석 이름 WEB_SQLI_PATTERN·WEB_PATH_PROBE·WEB_OBJECT_ENUM은 WEBLOG_SQLI·WEBLOG_ENUM_404·"
           "WEBLOG_IDOR_ENUM으로 합쳤다(저장된 결과는 detect.RULE_ALIASES로 읽는다). WEBLOG_CSRF_SUSPECT는 사이트 이름(`web.own_hosts` "
           "또는 ALB 로그의 Host)을 알 때만 돈다.",
           f"**상태:** 시험 중(experimental) 규칙 {len(experimental_rules())}개는 경보·사건에 넣지 않고 결과의 "
           "'시험 중 규칙' 칸에만 보인다. 오탐 검사(fp_gate) 정상 데이터 3개 이상에서 오탐 0.01% 이하이고 외부 데이터에서 "
           "실제 공격을 1번 이상 잡으면 stable로 올린다(Sigma status의 experimental·stable 구분을 따름).",
           "",
           "| 규칙 | 이름 | 단계 | ATT&CK | 심각도 | 상태 | 로그 |",
           "|---|---|---|---|---|---|---|"]
    for r, (tech, stage, name, sev) in RULES.items():
        out.append(f"| [{r}](#{r.lower()}) | {name} | {stage} | {tech} | {SEV.get(sev, sev)} | {ST[status(r)]} | {SPEC[r]['logs']} |")
    out.append("")
    for r, (tech, stage, name, sev) in RULES.items():
        s = SPEC[r]
        out += [f"## {r}", "", f"**{name}** · {stage} · {tech} · 심각도 {SEV.get(sev, sev)} · {ST[status(r)]}", "",
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

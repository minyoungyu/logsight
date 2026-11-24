"""규칙 표에 쓴 ATT&CK 기법의 이름과 전술을 MITRE 공식 STIX 데이터에서 뽑아 logsight/attack_v15.json으로 저장한다.

    curl -LO https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v15.1/enterprise-attack/enterprise-attack.json
    python scripts/attack_techniques.py enterprise-attack.json > logsight/attack_v15.py

규칙을 더하거나 기법을 바꾸면 다시 만든다. tests/test_ocsf.py가 모든 규칙의 기법이 이 파일에 있는지 검사한다.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logsight.detect import RULES  # noqa: E402

d = json.load(open(sys.argv[1], encoding="utf-8"))
tech = {}
for o in d["objects"]:
    if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
        tid = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
        tech[tid] = {"name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])]}
used = sorted({t for t, *_ in RULES.values() if t.startswith("T")} | {t.split(".")[0] for t, *_ in RULES.values()
                                                                    if t.startswith("T")})
lines = ['"""규칙 표에 쓴 MITRE ATT&CK 기법의 이름과 전술(ATT&CK v15.1, Enterprise).', "",
         "scripts/attack_techniques.py가 MITRE 공식 STIX 데이터에서 만든다. 손으로 고치지 않는다.", '"""', "",
         'ATTACK_VERSION = "15.1"', 'SOURCE = "https://github.com/mitre/cti/tree/ATT%26CK-v15.1"', "",
         "TECHNIQUES: dict[str, dict] = {"]
for t in used:
    if t in tech:
        lines.append(f'    {t!r}: {{"name": {tech[t]["name"]!r}, "tactics": {tech[t]["tactics"]!r}}},')
lines.append("}")
print("\n".join(lines))

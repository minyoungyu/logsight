"""규칙 표를 MITRE ATT&CK Navigator 레이어로 내보낸다.

    python scripts/attack_layer.py > docs/attack_layer.json

https://mitre-attack.github.io/attack-navigator/ 에서 "Open Existing Layer"로 열면 규칙이 덮는 기법이 칠해진다.
탐지 범위(규칙이 있는 기법)일 뿐 탐지 정확도가 아니다. 정확도는 docs/처음보는데이터_측정.md.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logsight.ocsf import attack_layer  # noqa: E402

json.dump(attack_layer(), sys.stdout, ensure_ascii=False, indent=1)
print()

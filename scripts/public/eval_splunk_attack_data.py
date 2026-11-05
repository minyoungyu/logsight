"""처음 보는 데이터로 측정: Splunk attack_data의 AWS CloudTrail 표본.

Splunk Security Content(https://github.com/splunk/security_content, Apache-2.0)의 탐지 규칙은
각자 시험용 로그(attack_data)를 하나씩 가리킨다. 표본마다 "이 로그에는 이 행동이 들어 있다"는
라벨이 붙은 셈이다. 이 스크립트는 AWS CloudTrail 표본마다 LogSight를 따로 돌려 무엇이 걸렸는지 적는다.

    git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content sc
    (cd sc && git sparse-checkout set detections/cloud)
    python scripts/public/eval_splunk_attack_data.py --sc sc --cache data/public/attack_data \\
        --out reports/public/splunk_attack_data.json

측정 원칙(docs/처음보는데이터_측정.md): 규칙을 고정한 커밋을 결과에 적고, 측정 뒤에 규칙을 고쳐도
이 결과 파일은 다시 만들지 않는다. 고친 효과는 다음 버전 측정에서 따로 적는다.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from logsight.normalize import parse_cloudtrail  # noqa: E402
from logsight.detect import run_detections  # noqa: E402
from logsight.pipeline import run  # noqa: E402


def _yaml_fields(text: str) -> dict:
    """필요한 필드만 정규식으로 읽는다(PyYAML 없이)."""
    name = re.search(r"^name:\s*(.+)$", text, re.M)
    mitre = re.findall(r"^\s+-\s+(T\d{4}(?:\.\d{3})?)\s*$", text.split("mitre_attack_id:", 1)[-1].split("\n\n")[0]
                       if "mitre_attack_id:" in text else "", re.M)
    status = re.search(r"^status:\s*(\S+)", text, re.M)
    kind = re.search(r"^type:\s*(\S+)", text, re.M)
    data = []
    for m in re.finditer(r"-\s*data:\s*(\S+)\s*\n\s*sourcetype:\s*(\S+)", text):
        data.append({"url": m.group(1), "sourcetype": m.group(2)})
    srch = text.split("search:", 1)[-1].split("\nhow_to_implement", 1)[0]
    targets = set()
    for m in re.finditer(r'eventName\s*!?=\s*"?([A-Za-z0-9]+)"?', srch):
        if "!=" not in m.group(0):
            targets.add(m.group(1))
    for m in re.finditer(r'eventName\s+IN\s*\(([^)]*)\)', srch):
        targets |= set(re.findall(r'"?([A-Za-z0-9]+)"?', m.group(1)))
    return {"targets": sorted(targets), "name": name.group(1).strip() if name else "", "mitre": mitre,
            "status": status.group(1) if status else "", "type": kind.group(1) if kind else "", "data": data}


def _fetch(url: str, cache: Path) -> Path:
    p = cache / (hashlib.sha1(url.encode()).hexdigest()[:16] + ".json")
    if not p.exists():
        with urllib.request.urlopen(url, timeout=60) as r:
            p.write_bytes(r.read())
    return p


def _events(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    s = text.lstrip()
    if s.startswith("{") and "\n{" in s:  # 한 줄에 레코드 하나(JSON Lines)
        text = json.dumps({"Records": [json.loads(ln) for ln in s.splitlines() if ln.strip().startswith("{")]})
    return parse_cloudtrail(text, path.name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sc", required=True, help="security_content 폴더(detections/cloud 포함)")
    ap.add_argument("--cache", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cache = Path(a.cache)
    cache.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    rows, seen = [], set()
    for y in sorted((Path(a.sc) / "detections" / "cloud").glob("aws_*.yml")):
        f = _yaml_fields(y.read_text(encoding="utf-8"))
        ct = [d for d in f["data"] if d["sourcetype"] == "aws:cloudtrail"]
        if not ct:
            continue
        row = {"detection": f["name"], "file": y.name, "mitre": f["mitre"], "type": f["type"],
               "status": f["status"], "data": [d["url"] for d in ct]}
        try:
            evs = []
            for d in ct:
                evs += _events(_fetch(d["url"], cache))
        except Exception as e:  # 받기 실패도 결과에 남긴다
            rows.append(row | {"error": str(e)[:200]})
            continue
        key = tuple(sorted(row["data"]))
        row["duplicate_data"] = key in seen
        seen.add(key)
        # 판정 기준: Splunk 규칙이 찾는 API 호출(eventName)을 LogSight 규칙이 표시했는가
        tg = set(f["targets"])
        present = sum(1 for e in evs if (e.action or "").split(":")[-1] in tg)
        hit_rules = sorted({fd.rule for fd in run_detections(copy.deepcopy(evs), {})
                            for e in fd.events if (e.action or "").split(":")[-1] in tg})
        row |= {"targets": f["targets"], "n_target_events": present, "target_rules": hit_rules}
        res = run(evs, {}, use_ai=False, top=20)
        verdicts = {i["id"]: i.get("verdict") for i in res.get("incident_index", [])}
        row |= {"n_events": len(evs),
                "rules": sorted(res.get("rule_counts", {})),
                "incidents": [{"id": i["id"], "rules": i.get("rules", []), "verdict": verdicts.get(i["id"]),
                               "severity": i.get("severity")} for i in res.get("incident_index", [])]}
        rows.append(row)
        print(f"{len(evs):5d} {present:4d} {','.join(hit_rules) or '-':30.30s} {','.join(row['rules']) or '-':45.45s} {f['name']}")
    out = {"engine_commit": commit, "source": "splunk/security_content detections/cloud aws_*.yml",
           "n_detections": len(rows), "rows": rows}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

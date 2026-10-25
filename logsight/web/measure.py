"""정답 파일(ground truth)과 판정 결과를 대조해 재현율·정밀도·오탐률·F1을 낸다.

정답 파일 형식(docs/CTF_로그_수집_가이드.md 3절)은 항목 목록이다. 항목마다:
  attacker_ip   필수. 공격자(또는 정상 트래픽 출처) IP
  malicious     선택. false면 정상 트래픽(오탐 측정용). 기본 true
  detectable    선택. false면 접속 로그로 볼 수 없는 공격이라 재현율 계산에서 뺀다. 기본 true
  expected_rules 선택. 기대하는 탐지 규칙 ID 목록. 비면 "어떤 규칙이든 걸리면 탐지"로 본다
  time_utc, scenario, note 등은 기록용이며 계산에 쓰지 않는다.

계산 기준:
  재현율    = 탐지된 공격 항목 수 / 탐지 가능한 공격 항목 수 (항목 단위)
  정밀도    = 정답에 있는 IP 중 탐지된 것 / 탐지된 IP 중 정답에 있는 것 (IP 단위)
  오탐률    = 정상 트래픽 IP 중 탐지된 것 / 정상 트래픽 IP 수
  F1        = 2·정밀도·재현율 / (정밀도 + 재현율)
정답 파일에 없는 IP가 탐지되면 따로 세어 보여 준다. 정답이 없으니 맞고 틀림을 알 수 없다.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from ..detect import RULES


class TruthError(ValueError):
    """정답 파일 형식 오류. 메시지에 고치는 방법(hint)을 함께 담는다."""


def load_truth(path: str | Path) -> list[dict]:
    """정답 파일을 읽어 항목 목록으로 돌려준다. 목록 또는 {"entries": [...]} 둘 다 받는다."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise TruthError(f"정답 파일을 찾을 수 없음: {p}. hint: 경로를 확인하세요.") from None
    except json.JSONDecodeError as e:
        raise TruthError(f"정답 파일이 JSON이 아님: {p} ({e.msg} at 줄 {e.lineno}). "
                         "hint: 쉼표·따옴표를 확인하세요.") from None
    entries = data.get("entries") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise TruthError(f"정답 파일은 항목 목록이어야 함: {p}. hint: [ {{...}}, {{...}} ] 형식을 쓰세요.")
    return [validate_entry(e, i) for i, e in enumerate(entries, 1)]


def validate_entry(e: dict, n: int = 1) -> dict:
    if not isinstance(e, dict):
        raise TruthError(f"{n}번째 항목이 객체가 아님. hint: {{\"attacker_ip\": ...}} 형식으로 쓰세요.")
    ip = e.get("attacker_ip")
    if not ip:
        raise TruthError(f"{n}번째 항목에 attacker_ip가 없음. hint: 공격자 IP를 적으세요.")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise TruthError(f"{n}번째 항목의 attacker_ip가 IP가 아님: {ip!r}. "
                         "hint: 203.0.113.* 같은 와일드카드는 쓸 수 없으니 실제 IP를 적으세요.") from None
    rules = e.get("expected_rules") or []
    unknown = [r for r in rules if r not in RULES]
    if unknown:
        raise TruthError(f"{n}번째 항목의 규칙 ID를 모름: {unknown}. "
                         "hint: `python -m logsight rules`로 목록을 확인하세요.")
    return {
        "attacker_ip": ip,
        "malicious": bool(e.get("malicious", True)),
        "detectable": bool(e.get("detectable", True)),
        "expected_rules": list(rules),
        "label": e.get("scenario") or e.get("step_note") or f"항목 {n}",
    }


def rules_by_ip(result: dict) -> dict[str, set[str]]:
    """assess() 결과에서 IP별로 걸린 규칙 집합을 만든다."""
    out: dict[str, set[str]] = {}
    for r in result.get("results", []):
        inc = r["incident"]
        for f in inc["findings"]:
            ips = set(inc["src_ips"]) | ({f["key"]} if f.get("key") else set())
            for ip in ips:
                out.setdefault(ip, set()).add(f["rule"])
    return out


def _hit(entry: dict, detected: dict[str, set[str]]) -> bool:
    got = detected.get(entry["attacker_ip"], set())
    if not entry["expected_rules"]:
        return bool(got)
    return bool(got & set(entry["expected_rules"]))


def score(truth: list[dict], result: dict) -> dict:
    """정답 목록과 판정 결과를 대조한다. 숫자 자체보다 놓친 항목과 오탐 목록이 중요하다."""
    detected = rules_by_ip(result)
    attacks = [t for t in truth if t["malicious"] and t["detectable"]]
    blind = [t for t in truth if t["malicious"] and not t["detectable"]]
    negatives = [t for t in truth if not t["malicious"]]

    hits = [t for t in attacks if _hit(t, detected)]
    misses = [t for t in attacks if not _hit(t, detected)]

    truth_attack_ips = {t["attacker_ip"] for t in truth if t["malicious"]}
    truth_neg_ips = {t["attacker_ip"] for t in negatives} - truth_attack_ips
    flagged = {ip for ip, rules in detected.items() if rules}
    flagged_truth_attack = flagged & truth_attack_ips
    flagged_neg = flagged & truth_neg_ips
    unknown_flagged = sorted(flagged - truth_attack_ips - truth_neg_ips)

    recall = len(hits) / len(attacks) if attacks else None
    precision = (len(flagged_truth_attack) / len(flagged & (truth_attack_ips | truth_neg_ips))
                 if flagged & (truth_attack_ips | truth_neg_ips) else None)
    fpr = len(flagged_neg) / len(truth_neg_ips) if truth_neg_ips else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) > 0 else None)

    return {
        "counts": {"attack_entries": len(attacks), "detected": len(hits), "missed": len(misses),
                   "blind_spot_entries": len(blind), "negative_ips": len(truth_neg_ips),
                   "truth_attack_ips": len(truth_attack_ips), "flagged_ips": len(flagged),
                   "unknown_flagged_ips": len(unknown_flagged)},
        "recall": recall, "precision": precision, "false_positive_rate": fpr, "f1": f1,
        "missed": [{"label": t["label"], "ip": t["attacker_ip"], "expected": t["expected_rules"],
                    "got": sorted(detected.get(t["attacker_ip"], set()))} for t in misses],
        "false_positives": sorted(flagged_neg),
        "unknown_flagged": unknown_flagged,
        "blind_spots": [{"label": t["label"], "ip": t["attacker_ip"]} for t in blind],
    }


def _pct(x) -> str:
    return "-" if x is None else f"{x * 100:.1f}%"


def format_report(s: dict) -> str:
    c = s["counts"]
    lines = [
        "=" * 60,
        f"재현율     {_pct(s['recall'])}   ({c['detected']}/{c['attack_entries']} 탐지 가능한 공격 항목)",
        f"정밀도     {_pct(s['precision'])}   (IP 단위, 정답에 있는 IP 기준)",
        f"오탐률     {_pct(s['false_positive_rate'])}   ({len(s['false_positives'])}/{c['negative_ips']} 정상 IP)",
        f"F1         {_pct(s['f1'])}",
        f"사각지대   {c['blind_spot_entries']}건 (재현율 계산에서 제외)",
        f"정답에 없는 IP가 탐지됨 {c['unknown_flagged_ips']}개 (맞고 틀림을 알 수 없음)",
        "-" * 60,
    ]
    if s["missed"]:
        lines.append("놓친 공격:")
        lines += [f"  - {m['label']} {m['ip']} 기대={m['expected'] or '아무 규칙'} 실제={m['got'] or '없음'}"
                  for m in s["missed"]]
    if s["false_positives"]:
        lines.append("오탐(정상 IP가 탐지됨): " + ", ".join(s["false_positives"]))
    if s["blind_spots"]:
        lines.append("사각지대: " + ", ".join(b["label"] for b in s["blind_spots"]))
    lines.append("=" * 60)
    return "\n".join(lines)

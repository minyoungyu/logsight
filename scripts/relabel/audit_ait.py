#!/usr/bin/env python3
"""AIT-LDS 라벨 자체를 원본과 대조한다(라벨 빈틈 찾기).

AIT 라벨은 공격자 실행 기록(attacks.log)에서 만들어졌지만, 라벨 파일이 없는 호스트가 있고
라벨이 빠진 줄도 있을 수 있다. 이 스크립트는 탐지 엔진을 쓰지 않고 원본 로그만 읽어 다음을 찾는다.

  1) 라벨이 붙은 줄의 시각이 attacks.log의 공격 시간(첫 단계 ~ 마지막 단계) 안인가.
  2) 라벨이 없는 줄 중 공격 시간 안에 있고, 공격 도구임이 줄 자체에 적힌 것
     (User-Agent에 Nmap·WPScan·DirBuster·Nikto 등, 또는 라벨 줄에서 나온 웹셸 경로 접근).
     이것이 '라벨 빈틈 후보'다. 근거는 줄 안의 문자열과 attacks.log 시각이다.
  3) 웹 로그에 라벨 파일이 아예 없는 호스트.

그다음 --score를 주면 eval_ait.py와 같은 엔진·프로필로 표시 여부를 구해, 빈틈 줄을 공격으로 고쳐
셌을 때 숫자가 어떻게 바뀌는지 적는다(라벨 판단에는 엔진을 쓰지 않는다).

  python scripts/relabel/audit_ait.py --data data/public/ait --name russellmitchell --score \
      --out reports/relabel/ait_audit_russellmitchell.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOL_UA = re.compile(r"Nmap Scripting Engine|WPScan|DirBuster|dirb|Nikto|sqlmap|gobuster|ffuf|hydra|masscan|zgrab",
                     re.I)
TS = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
LOGS = re.compile(r"(?:^|/)[^/]*access\.log(?:\.\d+)?$")


def parse_ts(line: str):
    m = TS.search(line)
    if not m:
        return None
    return datetime.strptime(m.group(1) + " " + m.group(2), "%d/%b/%Y:%H:%M:%S %z")


def attack_window(data: Path):
    rows = []
    for line in (data / "gather/attacker_0/logs/attacks.log").read_text().splitlines():
        m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?\+00:00 (\S+)", line)
        if m:
            rows.append((datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc),
                         m.group(2)))
    # dnsteal_stop 같은 정리 단계는 몇 시간 뒤라 창을 늘리지 않게 뺀다.
    core = [t for t, s in rows if not s.endswith("_stop") and s != "vpn_disconnect"]
    return min(core), max(t for t, s in rows if s == "vpn_disconnect") if any(
        s == "vpn_disconnect" for _, s in rows) else max(core), rows


def load_label_file(p: Path) -> dict[int, list[str]]:
    if not p.exists():
        return {}
    return {d["line"]: d["labels"] for d in map(json.loads, p.read_text().splitlines())}


def ua(line: str) -> str:
    parts = line.split('"')
    return parts[-2] if len(parts) >= 3 else ""


def audit(data: Path) -> dict:
    lo, hi, steps = attack_window(data)
    lo_w, hi_w = lo - timedelta(minutes=1), hi + timedelta(minutes=1)
    shells: set[str] = set()
    hosts = {}
    files = sorted(p for p in (data / "gather").glob("*/logs/apache2/*") if LOGS.search(p.name))
    # 1차: 라벨 줄에서 웹셸 경로를 모은다(webshell_cmd 라벨 줄의 경로)
    for p in files:
        lab = load_label_file(data / "labels" / p.relative_to(data / "gather"))
        if not lab:
            continue
        lines = p.read_text(errors="replace").splitlines()
        for n, labels in lab.items():
            # 업로드 줄(webshell_upload)은 워드프레스 공용 경로(admin-ajax.php)라서 빼고, 명령 실행 줄만 본다.
            if "webshell_cmd" in labels and n <= len(lines):
                m = re.search(r'"(?:GET|POST) (/[^ ?"]+\.(?:php|phtml|php\d))', lines[n - 1])
                if m:
                    shells.add(m.group(1))
    for p in files:
        host = p.parts[p.parts.index("gather") + 1]
        rel = p.relative_to(data / "gather")
        lab_path = data / "labels" / rel
        lab = load_label_file(lab_path)
        lines = p.read_text(errors="replace").splitlines()
        h = hosts.setdefault(host, {"label_files": 0, "labeled_lines": 0, "labeled_outside_window": [],
                                    "gap_candidates": []})
        h["label_files"] += lab_path.exists()
        h["labeled_lines"] += len(lab)
        for n in lab:
            t = parse_ts(lines[n - 1]) if n <= len(lines) else None
            if t is None or not (lo_w <= t <= hi_w):
                h["labeled_outside_window"].append(f"{p.name}:{n}")
        for n, line in enumerate(lines, 1):
            if n in lab:
                continue
            t = parse_ts(line)
            if t is None or not (lo_w <= t <= hi_w):
                continue
            why = None
            if TOOL_UA.search(ua(line)):
                why = "tool_user_agent:" + TOOL_UA.search(ua(line)).group(0)
            elif shells and any(f" {s}" in line for s in shells):
                why = "webshell_path"
            if why:
                h["gap_candidates"].append({"ref": f"{p.name}:{n}", "why": why,
                                            "ts": t.astimezone(timezone.utc).isoformat()})
    return {"window_utc": [lo.isoformat(), hi.isoformat()], "n_steps": len(steps),
            "webshell_paths_from_labels": sorted(shells), "hosts": hosts}


def score(data: Path, res: dict) -> dict:
    """eval_ait.py와 같은 프로필·엔진으로, 빈틈 줄의 표시 여부와 고친 숫자를 낸다."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "public"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from eval_ait import all_lines, host_profile, load_labels  # noqa: E402
    from logsight.web.webdetect import run_web_detections  # noqa: E402
    from logsight.web.webpipeline import load_events  # noqa: E402

    out = {}
    for host in ("intranet_server", "webserver", "cloud_share"):
        if not (data / "gather" / host).exists():
            continue
        prof = host_profile(data, host)
        labels = load_labels(data, host)
        events, _ = load_events(prof)
        flagged = {e.raw_ref for f in run_web_detections(events, prof) for e in f.events}
        universe = set(all_lines(prof))
        gap = {g["ref"] for g in res["hosts"].get(host, {}).get("gap_candidates", [])} & universe
        pos0 = {r for r in universe if r in labels}
        pos1 = pos0 | gap

        def m(pos):
            tp = len(pos & flagged)
            fp = len((flagged & universe) - pos)
            return {"attack_lines": len(pos), "tp": tp, "fn": len(pos) - tp, "fp": fp,
                    "recall": round(tp / len(pos), 4) if pos else None,
                    "precision": round(tp / (tp + fp), 4) if tp + fp else None}
        out[host] = {"ait_labels": m(pos0), "ait_labels_plus_gaps": m(pos1),
                     "gap_lines": len(gap), "gap_flagged": len(gap & flagged)}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    data = Path(a.data)
    res = {"testbed": a.name, **audit(data)}
    if a.score:
        res["score"] = score(data, res)
    summ = {h: {"label_files": v["label_files"], "labeled": v["labeled_lines"],
                "labeled_outside_window": len(v["labeled_outside_window"]),
                "gap_candidates": len(v["gap_candidates"])} for h, v in res["hosts"].items()}
    res["summary"] = summ
    text = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    print(json.dumps({"testbed": a.name, "window": res["window_utc"], "shells": res["webshell_paths_from_labels"],
                      "summary": summ, "score": res.get("score")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""AIT-LDS v2.0 라벨로 LogSight 웹 탐지를 잰다(규칙만, AI 호출 없음).

  python scripts/public/fetch_ait.py --out data/public/ait
  python scripts/public/eval_ait.py --data data/public/ait --out reports/public/ait_russellmitchell.json

두 가지로 잰다.
  1) 줄 단위: 데이터셋이 공격으로 라벨한 로그 줄을 LogSight가 탐지 규칙으로 표시했는가.
     AIT 라벨이 줄 단위라서 이것이 주 지표다.
  2) IP 단위: scripts/ctf_evaluate.py와 같은 정답 형식(measure.score)으로 바꿔 잰다.
     이 데이터셋은 외부 사용자와 공격자가 같은 방화벽 NAT 주소를 쓰므로 IP 단위 숫자는
     참고용이다(공격 IP = 정상 사용자 IP).

규칙·파서는 바꾸지 않는다. 프로필은 사이트 설명(로그 경로, 자기 호스트 이름, syslog 연도)만 적는다.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from logsight.web.measure import format_report, score, validate_entry  # noqa: E402
from logsight.web.webdetect import run_web_detections  # noqa: E402
from logsight.web.webpipeline import assess, load_events  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

# 공격 단계 라벨(AIT). 상위 묶음 라벨(foothold, attacker_http 등)은 단계 표에서 뺀다.
STEPS = ["service_scan", "dirb", "wpscan", "webshell_upload", "webshell_cmd",
         "attacker_change_user", "escalated_command"]


def host_profile(data: Path, host: str) -> SiteProfile:
    logs = data / "gather" / host / "logs"
    vhosts = sorted({p.name.split("-access")[0].split("-error")[0]
                     for p in (logs / "apache2").glob("*.log*") if "." in p.name.split("-")[0]})
    return SiteProfile(
        name=f"AIT-LDS {data.name}/{host}",
        log_paths={"access": [str(logs / "apache2" / "*access.log*")],
                   "weberror": [str(logs / "apache2" / "*error.log*")],
                   "auth": [str(logs / "auth.log*")]},
        own_hosts=["127.0.0.1", "localhost", *vhosts],
        year=2022,
    )


def load_labels(data: Path, host: str) -> dict[str, list[str]]:
    """{파일이름:줄번호: [라벨...]} — LogSight raw_ref와 같은 꼴."""
    out: dict[str, list[str]] = {}
    root = data / "labels" / host / "logs"
    for p in root.rglob("*"):
        if p.is_file() and (p.parent.name == "apache2" or p.name.startswith("auth.log")):
            for line in p.read_text(encoding="utf-8").splitlines():
                d = json.loads(line)
                out[f"{p.name}:{d['line']}"] = d["labels"]
    return out


def all_lines(profile: SiteProfile) -> list[str]:
    refs = []
    for files in profile.resolved_logs().values():
        for p in files:
            with open(p, encoding="utf-8", errors="replace") as f:
                refs += [f"{p.name}:{i}" for i, line in enumerate(f, 1) if line.strip()]
    return refs


def ratio(a: int, b: int):
    return a / b if b else None


def line_level(profile: SiteProfile, labels: dict[str, list[str]]) -> dict:
    events, stats = load_events(profile)
    findings = run_web_detections(events, profile)
    flagged: dict[str, set[str]] = defaultdict(set)
    ev_by_ref = {}
    for f in findings:
        for e in f.events:
            flagged[e.raw_ref].add(f.rule)
            ev_by_ref[e.raw_ref] = e
    universe = all_lines(profile)
    parsed = {e.raw_ref for e in events}
    pos = {r for r in universe if r in labels}
    tp = [r for r in pos if flagged.get(r)]
    fn = [r for r in pos if not flagged.get(r)]
    fp = [r for r in universe if r not in labels and flagged.get(r)]
    tn = len(universe) - len(pos) - len(fp)
    rec, prec, fpr = ratio(len(tp), len(pos)), ratio(len(tp), len(tp) + len(fp)), ratio(len(fp), len(fp) + tn)
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None

    steps = {}
    for s in STEPS:
        refs = [r for r in pos if s in labels[r]]
        if refs:
            hit = [r for r in refs if flagged.get(r)]
            steps[s] = {"lines": len(refs), "flagged": len(hit), "line_recall": ratio(len(hit), len(refs)),
                        "step_detected": bool(hit),
                        "rules": sorted({x for r in hit for x in flagged[r]}),
                        "parsed": sum(r in parsed for r in refs)}
    fp_rules = Counter(x for r in fp for x in flagged[r])
    fp_ips = Counter(ev_by_ref[r].src_ip or "-" for r in fp)
    return {
        "files": stats,
        "lines": len(universe), "parsed_lines": len(parsed & set(universe)),
        "attack_lines": len(pos), "tp": len(tp), "fn": len(fn), "fp": len(fp), "tn": tn,
        "recall": rec, "precision": prec, "false_positive_rate": fpr, "f1": f1,
        "steps": steps,
        "fp_by_rule": dict(fp_rules.most_common()), "fp_by_ip": dict(fp_ips.most_common()),
        "tp_by_rule": dict(Counter(x for r in tp for x in flagged[r]).most_common()),
        "fp_examples": [{"ref": r, "rules": sorted(flagged[r]),
                         "raw": ev_by_ref[r].extra.get("raw", "")[:240]} for r in sorted(fp)[:40]],
        "fn_examples": [{"ref": r, "labels": labels[r]} for r in sorted(fn)[:20]],
    }


def ip_level(profile: SiteProfile, labels: dict[str, list[str]]) -> dict:
    """라벨 줄의 IP = 공격, 나머지 IP = 정상으로 정답 파일을 만들어 measure.score로 잰다."""
    events, _ = load_events(profile)
    attack_ips = {e.src_ip for e in events if e.raw_ref in labels and e.src_ip}
    other = {e.src_ip for e in events if e.src_ip} - attack_ips
    truth = [validate_entry({"attacker_ip": ip, "scenario": "AIT 라벨 공격"}, i)
             for i, ip in enumerate(sorted(attack_ips), 1)]
    truth += [validate_entry({"attacker_ip": ip, "malicious": False, "scenario": "라벨 없는 IP"}, i)
              for i, ip in enumerate(sorted(other), len(truth) + 1)]
    result = assess(profile, use_ai=False, top=500)
    s = score(truth, result)
    s["truth"] = [{"ip": t["attacker_ip"], "malicious": t["malicious"]} for t in truth]
    s["overall_verdict"] = result["overall_verdict"]
    return s


def pct(x) -> str:
    return "-" if x is None else f"{x * 100:.1f}%"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AIT-LDS v2.0 라벨로 LogSight 웹 탐지 재기")
    ap.add_argument("--data", required=True, help="fetch_ait.py로 받은 폴더")
    ap.add_argument("--hosts", nargs="+", default=["intranet_server", "webserver", "cloud_share"])
    ap.add_argument("--out", help="결과 JSON 경로")
    args = ap.parse_args(argv)
    data = Path(args.data)
    out = {"dataset": "AIT-LDS v2.0", "doi": "10.5281/zenodo.5789064", "license": "CC BY-NC-SA 4.0",
           "testbed": data.name, "hosts": {}}
    for host in args.hosts:
        profile = host_profile(data, host)
        labels = load_labels(data, host)
        ll = line_level(profile, labels)
        ipl = ip_level(profile, labels)
        out["hosts"][host] = {"profile": profile.to_dict(), "line_level": ll, "ip_level": ipl}
        print(f"\n### {host}  (줄 {ll['lines']}, 파싱 {ll['parsed_lines']}, 공격 라벨 줄 {ll['attack_lines']})")
        print(f"줄 단위  재현율 {pct(ll['recall'])}  정밀도 {pct(ll['precision'])}  "
              f"오탐률 {pct(ll['false_positive_rate'])}  F1 {pct(ll['f1'])}  "
              f"(TP {ll['tp']} FN {ll['fn']} FP {ll['fp']} TN {ll['tn']})")
        for s, v in ll["steps"].items():
            print(f"  {s:22s} {'탐지' if v['step_detected'] else '놓침'}  줄 {v['flagged']}/{v['lines']}"
                  f" (파싱 {v['parsed']})  {', '.join(v['rules'])}")
        if ll["fp_by_rule"]:
            print("  오탐 규칙:", ll["fp_by_rule"], " 오탐 IP:", ll["fp_by_ip"])
        print("IP 단위(참고):")
        print(format_report(ipl))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
        print(f"저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

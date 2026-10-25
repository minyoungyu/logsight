#!/usr/bin/env python3
"""HTTP CSIC 2010 요청을 Apache 접속 로그 형식으로 바꿔 LogSight 웹 탐지를 잰다(규칙만).

  python scripts/public/eval_csic.py --normal data/public/csic/normalTrafficTest.txt \
      --anomalous data/public/csic/anomalousTrafficTest.txt --out reports/public/csic2010.json

CSIC 2010은 원시 HTTP 요청 묶음이다(응답·IP·시각 없음). 그래서 변환할 때 다음을 가정한다.
  - 요청마다 서로 다른 출발 IP(10.x.y.z)를 준다. 같은 IP 연속 요청 규칙(열거·무차별 대입)은
    이 데이터로 잴 수 없다.
  - 응답 코드는 200, 크기는 0, 시각은 1초 간격으로 둔다.
  - 실제 Apache 접속 로그에는 POST 본문이 남지 않는다. 기본(--body off)은 본문을 버리고,
    --body on이면 본문을 쿼리에 붙인다(로그에 본문이 남는다고 가정한 상한).
정답은 요청 단위: anomalous 파일의 요청 = 공격, normal 파일의 요청 = 정상.

데이터셋: C. Torrano Giménez, A. Pérez Villegas, G. Álvarez Marañón, "HTTP data set CSIC 2010",
CSIC. https://www.tic.itefi.csic.es/dataset/ (이용 조건은 공식 사이트에서 확인하고 인용한다)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from logsight.web.weblog import parse_access  # noqa: E402
from logsight.web.webdetect import run_web_detections  # noqa: E402
from logsight.web.webprofile import SiteProfile  # noqa: E402

METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")


def read_requests(path: Path) -> list[dict]:
    """원시 HTTP 요청 파일을 {method, uri, headers, body} 목록으로 읽는다."""
    reqs: list[dict] = []
    cur = None
    in_body = False
    for line in path.read_text(encoding="latin-1").splitlines():
        if line.startswith(METHODS) and line.rstrip().endswith(("HTTP/1.1", "HTTP/1.0")):
            if cur:
                reqs.append(cur)
            method, rest = line.split(" ", 1)
            cur = {"method": method, "uri": rest.rsplit(" ", 1)[0], "headers": {}, "body": ""}
            in_body = False
        elif cur is None:
            continue
        elif not line.strip():
            in_body = True
        elif in_body:
            cur["body"] += line.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            cur["headers"][k.strip().lower()] = v.strip()
    if cur:
        reqs.append(cur)
    return reqs


def to_log_line(req: dict, n: int, t0: datetime, with_body: bool) -> str:
    u = urlsplit(req["uri"])
    target = u.path + (f"?{u.query}" if u.query else "")
    if with_body and req["body"]:
        target += ("&" if "?" in target else "?") + req["body"]
    ip = f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"
    ts = (t0 + timedelta(seconds=n)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ua = req["headers"].get("user-agent", "-").replace('"', "'")
    ref = req["headers"].get("referer", "-").replace('"', "'")
    target = target.replace(" ", "%20").replace('"', "%22")
    return f'{ip} - - [{ts}] "{req["method"]} {target} HTTP/1.1" 200 0 "{ref}" "{ua}"'


def evaluate(normal: list[dict], anomalous: list[dict], with_body: bool) -> dict:
    t0 = datetime(2010, 1, 1, tzinfo=timezone.utc)
    reqs = [(r, False) for r in normal] + [(r, True) for r in anomalous]
    lines = [to_log_line(r, i, t0, with_body) for i, (r, _) in enumerate(reqs)]
    events = parse_access("\n".join(lines), name="csic")
    profile = SiteProfile(name="CSIC 2010", own_hosts=["localhost", "127.0.0.1"])
    findings = run_web_detections(events, profile)
    flagged: dict[int, set[str]] = {}
    for f in findings:
        for e in f.events:
            flagged.setdefault(int(e.raw_ref.split(":")[1]) - 1, set()).add(f.rule)
    truth = [m for _, m in reqs]
    tp = sum(1 for i, m in enumerate(truth) if m and i in flagged)
    fp = sum(1 for i, m in enumerate(truth) if not m and i in flagged)
    pos, neg = sum(truth), len(truth) - sum(truth)
    rec = tp / pos if pos else None
    prec = tp / (tp + fp) if tp + fp else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    return {
        "body_in_log": with_body, "requests": len(truth), "parsed": len(events),
        "attacks": pos, "normal": neg, "tp": tp, "fn": pos - tp, "fp": fp, "tn": neg - fp,
        "recall": rec, "precision": prec, "false_positive_rate": fp / neg if neg else None, "f1": f1,
        "tp_by_rule": dict(Counter(x for i, m in enumerate(truth) if m for x in flagged.get(i, ()))),
        "fp_by_rule": dict(Counter(x for i, m in enumerate(truth) if not m for x in flagged.get(i, ()))),
        "fp_examples": [lines[i] for i, m in enumerate(truth) if not m and i in flagged][:20],
        "fn_examples": [lines[i] for i, m in enumerate(truth) if m and i not in flagged][:20],
    }


def pct(x) -> str:
    return "-" if x is None else f"{x * 100:.1f}%"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HTTP CSIC 2010으로 LogSight 웹 탐지 재기")
    ap.add_argument("--normal", required=True, nargs="+", help="정상 요청 파일(normalTraffic*.txt)")
    ap.add_argument("--anomalous", required=True, nargs="+", help="공격 요청 파일(anomalousTraffic*.txt)")
    ap.add_argument("--out", help="결과 JSON 경로")
    args = ap.parse_args(argv)
    normal = [r for p in args.normal for r in read_requests(Path(p))]
    anomalous = [r for p in args.anomalous for r in read_requests(Path(p))]
    out = {"dataset": "HTTP CSIC 2010", "runs": []}
    for with_body in (False, True):
        s = evaluate(normal, anomalous, with_body)
        out["runs"].append(s)
        print(f"본문 {'포함' if with_body else '제외'}: 요청 {s['requests']} (공격 {s['attacks']}, 정상 {s['normal']})  "
              f"재현율 {pct(s['recall'])}  정밀도 {pct(s['precision'])}  "
              f"오탐률 {pct(s['false_positive_rate'])}  F1 {pct(s['f1'])}")
        print(f"  탐지 규칙 {s['tp_by_rule']}  오탐 규칙 {s['fp_by_rule']}")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""웹 접근 로그(Apache combined)의 모든 줄에 사전 등록한 A1~A3 기준으로 라벨을 붙인다. LogSight 코드는 읽지 않는다.

예전 EClog 측정은 엔진이 표시한 줄만 사람이 A1~A3로 나눴고, 표시되지 않은 34만여 줄은 정상으로 가정했다.
여기서는 같은 기준(reports/public/holdout_plan_2026-11-25.json S7.review_rule, 데이터를 받기 전에 커밋)을
표시 여부와 상관없이 모든 줄에 적용한다. AIT-LDS처럼 줄마다 라벨과 규칙 id를 남기고, 근거 문자열을 적는다.

  A1 알려진 공격 문자열(SQL 삽입, 경로 이동, 명령 삽입, Shellshock, 원격 파일 포함)
  A2 스캐너 도구 User-Agent
  A3 이 사이트가 쓰지 않는 소프트웨어의 알려진 공격 경로. '쓰지 않음'은 같은 로그에서 그 경로가 늘 404·403인 것

해당하지 않는 줄은 'unlabeled'다. 정상이라는 근거가 아니라 위 기준에 걸리지 않았다는 뜻이다.

  python scripts/relabel/label_weblog_a123.py data/public/eclog/access.log --out reports/relabel/eclog_labels.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote_plus

LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)(?: \S+)?" (\d{3}) \S+(?: "([^"]*)" "([^"]*)")?')
A1 = [
    ("sqli", re.compile(r"union(\s|/\*.*?\*/)+(all\s+)?select|sleep\s*\(|benchmark\s*\(|'\s*or\s+'?1'?\s*=\s*'?1|"
                        r"\bor\s+1\s*=\s*1\b|information_schema|waitfor\s+delay", re.I)),
    ("traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini", re.I)),
    ("cmd_injection", re.compile(r"\$\(|;\s*(wget|curl|cat|id|uname)\b|\|\s*(sh|bash)\b|`[^`]+`", re.I)),
    ("shellshock", re.compile(r"\(\)\s*\{")),
    ("rfi", re.compile(r"=(https?|ftp)://[^&\s]+\.(txt|php|sh|pl)\b", re.I)),
]
A2 = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|acunetix|nessus|openvas|"
                r"w3af|zmeu|morfeus|jaeles|httpx|fuzz", re.I)
# 계획에 적힌 경로(…'등')와 같은 종류만 둔다. 계획 밖에서 더한 것은 A3_EXTRA로 따로 적는다
A3 = ["/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/.env", "/.git/", "/cgi-bin/", "/HNAP1", "/boaform",
      "/actuator", "/wp-admin", "/pma", "/myadmin", "/vendor/phpunit", "/solr/", "/manager/html", "/.aws/"]
A3_EXTRA = ["/admin/config.php"]   # FreePBX. 11/25 사람 분류가 A3로 본 경로(계획 목록 밖이라 따로 표시)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    p = Path(a.log)
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed = []
    status_by_prefix: dict[str, Counter] = defaultdict(Counter)
    for line in lines:
        m = LINE.match(line)
        parsed.append(m)
        if m:
            path = m.group(3).lower().lstrip("/")
            path = "/" + path.lstrip("/")
            for pre in A3 + A3_EXTRA:
                if path.startswith(pre.lower()):
                    status_by_prefix[pre][m.group(4)] += 1
    unused = {pre for pre, c in status_by_prefix.items() if set(c) <= {"404", "403"}}
    rows = []
    for i, (line, m) in enumerate(zip(lines, parsed), 1):
        ref = f"{p.name}:{i}"
        if not m:
            req = line.split('"')[1] if line.count('"') >= 2 else ""
            if req.startswith("- "):   # HTTP가 아닌 바이트(RDP 접속 쿠키, TLS 등)를 웹 포트로 보냄
                rows.append({"ref": ref, "class": "uncertain", "rules": {"uncertain": ["U.non_http_bytes"]},
                             "evidence_text": {"request": req[:40]},
                             "note": "웹 포트에 HTTP가 아닌 요청. 포트 탐색일 가능성이 높지만 A1~A3 밖이라 공격으로 세지 않는다"})
            else:
                rows.append({"ref": ref, "class": "unparsed"})
            continue
        target = unquote_plus(unquote_plus(m.group(3)))
        ua = m.group(6) or ""
        labels, rules, ev = [], {}, {}
        for name, rx in A1:
            mm = rx.search(target)
            if mm:
                labels.append(name); rules[name] = ["A1"]; ev[name] = mm.group(0)[:60]
        mm = A2.search(ua)
        if mm:
            labels.append("scanner_ua"); rules["scanner_ua"] = ["A2"]; ev["scanner_ua"] = mm.group(0)
        path = "/" + m.group(3).lower().lstrip("/")
        for pre in A3 + A3_EXTRA:
            if path.startswith(pre.lower()) and pre in unused:
                labels.append("unused_software_path")
                rules["unused_software_path"] = ["A3" if pre in A3 else "A3_extra"]
                ev["unused_software_path"] = pre
                break
        if not labels and any(path.startswith(pre.lower()) for pre in A3 + A3_EXTRA):
            rows.append({"ref": ref, "class": "uncertain", "rules": {"uncertain": ["U.a3_path_not_always_404"]},
                         "evidence_text": {"path": m.group(3)[:60], "status": m.group(4)},
                         "note": "A3 목록 경로지만 이 로그에서 늘 404·403은 아니어서 A3 조건을 채우지 못함"})
            continue
        if labels:
            rows.append({"ref": ref, "class": "attack", "labels": labels, "rules": rules, "evidence_text": ev})
        else:
            rows.append({"ref": ref, "class": "unlabeled"})
    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    # unlabeled 줄은 쓰지 않는다(줄 수가 많다). 목록에 없는 줄 = unlabeled
    out.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows if x["class"] != "unlabeled"),
                   encoding="utf-8")
    summary = {
        "input": p.name, "input_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        "criteria": "reports/public/holdout_plan_2026-11-25.json S7.review_rule A1~A3",
        "a3_paths_seen": {k: dict(v) for k, v in status_by_prefix.items()},
        "a3_paths_unused_here": sorted(unused),
        "n_lines": len(rows),
        "by_class": dict(Counter(x["class"] for x in rows)),
        "file_note": "jsonl에는 unlabeled가 아닌 줄만 있다",
        "by_rule": dict(Counter(r for x in rows for v in x.get("rules", {}).values() for r in v)),
        "by_label": dict(Counter(l for x in rows for l in x.get("labels", []))),
    }
    Path(str(out).replace(".jsonl", "_summary.json")).write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                                                                 encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

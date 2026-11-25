#!/usr/bin/env python3
"""Docker json-file 로그(/var/lib/docker/containers/<id>/<id>-json.log)에서 stdout 줄만 꺼낸다.

  python scripts/public/docker_json_to_lines.py <id>-json.log [<id>-json.log.1 ...] -o data/ctf/access.log

CTFd 3.7.4 이미지는 gunicorn 접근 로그를 stdout으로 낸다(docker-entrypoint.sh ACCESS_LOG 기본값 '-').
gunicorn 기본 형식은 Apache combined와 같다. stderr(오류 로그)는 버린다.
`docker logs ctfd`로 받은 평문이면 이 단계 없이 그대로 쓴다(오류 줄은 파서가 못 읽은 줄로 센다).
여러 파일을 주면 이름 순서가 아니라 주어진 순서대로 잇는다(회전된 .1이 더 오래된 것).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def extract(srcs: list[Path], dst: Path) -> tuple[int, int]:
    kept = dropped = 0
    with open(dst, "w", encoding="utf-8") as out:
        for src in srcs:
            with open(src, encoding="utf-8", errors="replace") as f:
                for raw in f:
                    try:
                        d = json.loads(raw)
                    except ValueError:
                        dropped += 1
                        continue
                    if d.get("stream") != "stdout":
                        dropped += 1
                        continue
                    for ln in str(d.get("log", "")).splitlines():
                        if ln.strip():
                            out.write(ln + "\n")
                            kept += 1
    return kept, dropped


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", nargs="+")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    k, d = extract([Path(s) for s in a.src], Path(a.out))
    print(f"stdout {k:,}줄 꺼냄, 버린 줄 {d:,}")

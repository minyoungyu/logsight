#!/usr/bin/env python3
"""EClog(Chodak·Suchacka·Chawla 2020, doi:10.7910/DVN/Z834IK, CC0) CSV를 Apache combined 줄로 바꾼다.

  python scripts/public/eclog_to_combined.py data/public/eclog/eclog_1day.csv data/public/eclog/access.log

- EClog는 IP를 번호(IP ID)로 바꿔 두었다. 같은 번호는 늘 같은 가짜 주소(100.64.0.0/10, 사설·공인 어디에도
  쓰이지 않는 CGNAT 대역)로 바꾼다. 그래서 '같은 IP의 연속 요청' 규칙은 그대로 동작한다.
- 머리글 이름은 대소문자·밑줄을 무시하고 맞춘다. 필요한 칸을 못 찾으면 머리글을 보여 주고 멈춘다
  (데이터 내용은 보지 않고 머리글만 본다).
- 원본 데이터와 변환 결과는 저장소에 올리지 않는다(data/는 .gitignore).
"""
from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

WANT = {
    "ip": ["ipid", "ip", "clientip", "ipaddress"],
    "time": ["timestamp", "time", "datetime", "date"],
    "method": ["httpmethod", "method"],
    "uri": ["uri", "url", "requesturi", "path"],
    "proto": ["httpversion", "protocol", "version"],
    "status": ["responsecode", "status", "statuscode", "code"],
    "bytes": ["bytes", "size", "responsesize", "bytessent"],
    "referer": ["referrer", "referer"],
    "ua": ["useragent", "agent", "ua"],
}
NEED = ["ip", "time", "method", "uri", "status"]


def norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def columns(header: list[str]) -> dict[str, int]:
    idx = {norm(h): i for i, h in enumerate(header)}
    out = {}
    for k, names in WANT.items():
        for n in names:
            if n in idx:
                out[k] = idx[n]
                break
    missing = [k for k in NEED if k not in out]
    if missing:
        raise SystemExit(f"필요한 칸을 못 찾음: {missing}. 머리글: {header}")
    return out


def fake_ip(ip_id: str) -> str:
    try:
        n = int(float(ip_id))
    except ValueError:
        n = abs(hash(ip_id)) % (1 << 22)  # 숫자가 아니면 같은 실행 안에서만 일관됨
    n %= 1 << 22  # 100.64.0.0/10 안
    return f"100.{64 + (n >> 16)}.{(n >> 8) & 255}.{n & 255}"


def apache_time(v: str) -> str:
    v = v.strip()
    dt = None
    if v.replace(".", "", 1).isdigit():
        x = float(v)
        dt = datetime.fromtimestamp(x / 1000 if x > 1e11 else x, tz=timezone.utc)
    else:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                dt = datetime.strptime(v, fmt)
                break
            except ValueError:
                pass
    if dt is None:
        raise SystemExit(f"시각 형식을 모름: {v!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # [추정] EClog 시각대는 논문 확인 전까지 UTC로 둔다
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def q(v: str) -> str:
    return (v or "-").replace('"', "%22")


def convert(src: Path, dst: Path) -> int:
    n = 0
    with open(src, encoding="utf-8", errors="replace", newline="") as f, open(dst, "w", encoding="utf-8") as out:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        r = csv.reader(f, dialect)
        col = columns(next(r))
        g = lambda row, k, d="-": (row[col[k]] if k in col and col[k] < len(row) and row[col[k]] != "" else d)  # noqa: E731
        for row in r:
            if not row:
                continue
            proto = g(row, "proto", "HTTP/1.1")
            if not proto.upper().startswith("HTTP"):
                proto = f"HTTP/{proto}"
            out.write(f'{fake_ip(g(row, "ip"))} - - [{apache_time(g(row, "time"))}] '
                      f'"{g(row, "method")} {q(g(row, "uri"))} {proto}" {g(row, "status")} {g(row, "bytes", "0")} '
                      f'"{q(g(row, "referer"))}" "{q(g(row, "ua"))}"\n')
            n += 1
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(f"{convert(Path(sys.argv[1]), Path(sys.argv[2])):,}줄 변환")

#!/usr/bin/env python3
"""EClog(Chodak·Suchacka·Chawla 2020, doi:10.7910/DVN/Z834IK, CC0) CSV를 Apache combined 줄로 바꾼다.

  python scripts/public/eclog_to_combined.py data/public/eclog/eclog_1day.csv data/public/eclog/access.log

- EClog는 IP를 ID('1PL'처럼 번호+국가 코드)로 바꿔 두었다. 같은 ID는 늘 같은 가짜 주소(100.64.0.0/10,
  공인 인터넷에 쓰이지 않는 CGNAT 대역)로 바꾼다.
- TimeStamp는 .NET ticks다(받은 파일로 확인). 그래서 '같은 IP의 연속 요청' 규칙은 그대로 동작한다.
- 머리글 이름은 대소문자·밑줄을 무시하고 맞춘다. 필요한 칸을 못 찾으면 머리글을 보여 주고 멈춘다
  (데이터 내용은 보지 않고 머리글만 본다).
- 원본 데이터와 변환 결과는 저장소에 올리지 않는다(data/는 .gitignore).
"""
from __future__ import annotations

import csv
import sys
from datetime import datetime, timedelta, timezone
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


def fake_ip(ip_id: str, seen: dict[str, int]) -> str:
    """IP ID(EClog 실제 값은 '1PL'처럼 번호+국가 코드)를 처음 나온 순서대로 번호 매겨 가짜 주소로 바꾼다.
    같은 ID는 늘 같은 주소, 다른 ID는 늘 다른 주소(400만 개까지)."""
    n = seen.setdefault(ip_id, len(seen) + 1)
    if n >= 1 << 22:
        raise SystemExit("IP ID가 너무 많음(100.64.0.0/10을 넘음)")
    return f"100.{64 + (n >> 16)}.{(n >> 8) & 255}.{n & 255}"


DOTNET_EPOCH = datetime(1, 1, 1)


def apache_time(v: str) -> str:
    v = v.strip()
    dt = None
    if v.isdigit() and int(v) > 10**17:
        # .NET DateTime ticks(100ns, 0001-01-01부터). EClog TimeStamp가 이 꼴.
        # 받은 하루치는 2019-12-10 23:00:00 ~ 12-11 22:59:59(ticks 그대로). 폴란드(UTC+1)의 12월 11일
        # 하루와 맞으므로 ticks를 UTC로 본다 [추정: 데이터 설명 '11 December'와 범위로 판단]
        dt = DOTNET_EPOCH.replace(tzinfo=timezone.utc) + timedelta(microseconds=int(v) // 10)
    elif v.replace(".", "", 1).isdigit():
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
        dt = dt.replace(tzinfo=timezone.utc)  # [추정] 시각대가 없는 문자열은 UTC로 둔다
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
        seen: dict[str, int] = {}
        g = lambda row, k, d="-": (row[col[k]] if k in col and col[k] < len(row) and row[col[k]] != "" else d)  # noqa: E731
        for row in r:
            if not row:
                continue
            proto = g(row, "proto", "HTTP/1.1")
            if not proto.upper().startswith("HTTP"):
                proto = f"HTTP/{proto}"
            out.write(f'{fake_ip(g(row, "ip"), seen)} - - [{apache_time(g(row, "time"))}] '
                      f'"{g(row, "method")} {q(g(row, "uri"))} {proto}" {g(row, "status")} {g(row, "bytes", "0")} '
                      f'"{q(g(row, "referer"))}" "{q(g(row, "ua"))}"\n')
            n += 1
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(f"{convert(Path(sys.argv[1]), Path(sys.argv[2])):,}줄 변환")

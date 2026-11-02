#!/usr/bin/env python3
"""AIT-LDS v2.0 테스트베드 zip에서 웹·인증 로그와 라벨만 내려받는다.

  python scripts/public/fetch_ait.py --testbed russellmitchell --out data/public/ait

zip 전체(7~26GB)를 받지 않고 HTTP Range 요청으로 중앙 디렉터리와 필요한 항목만 읽는다.
그래서 디스크에는 zip이 남지 않는다. 받는 항목:
  - gather/<호스트>/logs/apache2/*, gather/<호스트>/logs/auth.log*  (웹·인증 로그)
  - labels/**                                                       (줄 단위 정답)
  - gather/attacker_0/logs/attacks.log, dataset.yaml                (공격 단계 시각표)

데이터셋: Landauer et al., "Maintainable Log Datasets for Evaluation of Intrusion Detection
Systems", IEEE TDSC 2022. https://doi.org/10.5281/zenodo.5789064 (CC BY-NC-SA 4.0)
"""
from __future__ import annotations

import argparse
import io
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

RECORD = "https://zenodo.org/api/records/5789064/files/{name}.zip/content"
WANTED = re.compile(
    r"^(?:labels/.+|dataset\.yaml|gather/attacker_0/logs/attacks\.log|"
    r"gather/[^/]+/logs/(?:apache2/.+|auth\.log.*))$")


class RangeFile(io.RawIOBase):
    """원격 파일을 Range 요청으로 읽는 파일 객체. 8MB씩 읽어 둔다."""

    def __init__(self, url: str, chunk: int = 8 << 20):
        self.url, self.chunk, self.pos = url, chunk, 0
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Range": "bytes=0-0"})) as r:
            if r.status != 206:
                raise OSError("서버가 Range 요청을 지원하지 않음")
            self.size = int(r.headers["Content-Range"].split("/")[1])
        self.buf_start, self.buf = 0, b""

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = {0: off, 1: self.pos + off, 2: self.size + off}[whence]
        return self.pos

    def _fetch(self, start: int, end: int) -> bytes:
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={start}-{end - 1}"})
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return r.read()
            except OSError as e:
                print(f"재시도 {attempt + 1}: {e}", file=sys.stderr)
                time.sleep(2 ** attempt)
        raise OSError(f"내려받기 실패: bytes {start}-{end}")

    def readinto(self, b) -> int:
        n = min(len(b), self.size - self.pos)
        if n <= 0:
            return 0
        end = self.pos + n
        if not (self.buf_start <= self.pos and end <= self.buf_start + len(self.buf)):
            self.buf_start = self.pos
            self.buf = self._fetch(self.pos, min(max(end, self.pos + self.chunk), self.size))
        off = self.pos - self.buf_start
        b[:n] = self.buf[off:off + n]
        self.pos += n
        return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AIT-LDS v2.0에서 웹·인증 로그와 라벨만 내려받기")
    ap.add_argument("--testbed", default="russellmitchell", help="테스트베드 이름(가장 작은 것: russellmitchell)")
    ap.add_argument("--out", required=True, help="저장 폴더(저장소 밖 또는 .gitignore된 data/)")
    args = ap.parse_args(argv)
    z = zipfile.ZipFile(io.BufferedReader(RangeFile(RECORD.format(name=args.testbed)), 1 << 20))
    members = [i for i in z.infolist() if not i.is_dir() and WANTED.match(i.filename)]
    out = Path(args.out)
    total = 0
    for info in members:
        # zip 안 경로를 그대로 쓰되 out 밖으로 나가는 경로는 거른다
        dest = (out / info.filename).resolve()
        if out.resolve() not in dest.parents:
            print(f"건너뜀(경로 이상): {info.filename}", file=sys.stderr)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with z.open(info) as src, open(dest, "wb") as f:
            while chunk := src.read(1 << 20):
                f.write(chunk)
        total += info.file_size
    print(f"{len(members)}개 파일, {total / 1e6:.1f}MB → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

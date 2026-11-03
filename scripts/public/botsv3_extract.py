"""Splunk BOTSv3 공개 데이터셋에서 AWS·서버 로그를 원래 파일 형식으로 꺼낸다.

BOTSv3(https://github.com/splunk/botsv3, CC0)는 Splunk 색인(버킷) 형태로만 배포된다.
Splunk를 설치하지 않고 측정하려고, 버킷 안 rawdata/journal.gz를 직접 읽는 최소 해석기를 만들었다.
형식은 공개 문서가 없어 관찰로 맞췄고, 모르는 코드가 나오면 멈추고 오류를 낸다(조용히 건너뛰지 않음).

    python scripts/public/botsv3_extract.py <botsv3 db 폴더> <출력 폴더>
    python -m logsight analyze <출력 폴더> --year 2018 --no-ai

데이터는 저장소에 넣지 않는다. 결과는 docs/BOTSv3_측정.md를 본다.
"""
from __future__ import annotations

import glob
import gzip
import json
import re
import sys
from pathlib import Path

# Splunk sourcetype -> 출력 파일 이름(LogSight가 내용으로 종류를 알아낸다)
OUTPUTS = {
    "aws:cloudtrail": "cloudtrail.json",
    "aws:cloudwatchlogs:vpcflow": "vpcflow.log",
    "aws:elb:accesslogs": "alb.log",
    "linux_secure": "auth.log",
    "access_combined": "access.log",
    "aws:cloudwatch:guardduty": "guardduty_findings.jsonl",
}


def read_journal(path: str):
    """journal.gz 하나에서 (host, source, sourcetype, 원문 bytes)를 차례로 돌려준다.

    관찰한 형식(1바이트 명령 + 가변 길이 정수):
      0x00 빈칸, 0x0a 머리말(뒤 6바이트), 0x09 길이+자료(건너뜀)
      0x03/04/05/06 host/source/sourcetype/기타 문자열 추가(길이+문자열)
      0x10~0x1f 현재 상태 바꾸기: 비트 8=host 번호, 4=source 번호, 2=sourcetype 번호, 1=기준 시각(4바이트)
      0x20~0x2f 이벤트: 길이, 그 안에 정수 12개, 필드 개수, (키,값) 정수 쌍, 나머지가 원문
    """
    b = gzip.open(path).read()
    n = len(b)

    def vi(p: int):
        r = s = 0
        while True:
            x = b[p]
            p += 1
            r |= (x & 0x7F) << s
            s += 7
            if x < 0x80:
                return r, p

    tables: dict[int, list[str]] = {3: [], 4: [], 5: [], 6: []}
    cur = [0, 0, 0]
    p = 0
    while p < n:
        op = b[p]
        p += 1
        if op == 0:
            continue
        if op == 0x0A:
            p += 6
        elif op == 0x09:
            ln, p = vi(p)
            p += ln
        elif op in tables:
            ln, p = vi(p)
            tables[op].append(b[p:p + ln].decode("utf-8", "replace"))
            p += ln
            if op in (3, 4, 5):
                cur[op - 3] = len(tables[op])
        elif 0x10 <= op <= 0x1F:
            if op & 8:
                cur[0], p = vi(p)
            if op & 4:
                cur[1], p = vi(p)
            if op & 2:
                cur[2], p = vi(p)
            if op & 1:
                p += 4
        elif 0x20 <= op <= 0x2F:
            ln, p = vi(p)
            end, q = p + ln, p
            for _ in range(12):
                _, q = vi(q)
            cnt, q = vi(q)
            for _ in range(cnt):
                _, q = vi(q)
                _, q = vi(q)
            names = [tables[3], tables[4], tables[5]]
            meta = [names[i][cur[i] - 1] if cur[i] else "" for i in range(3)]
            yield meta[0], meta[1], meta[2], b[q:end]
            p = end
        else:
            raise ValueError(f"모르는 코드 {op:#x} (위치 {p - 1}, {path})")


def main(db: str, out: str) -> None:
    o = Path(out)
    o.mkdir(parents=True, exist_ok=True)
    rows: dict[str, list[str]] = {k: [] for k in OUTPUTS}
    files = sorted(glob.glob(str(Path(db) / "*" / "rawdata" / "journal.gz")))
    if not files:
        sys.exit(f"{db} 아래에 */rawdata/journal.gz가 없습니다")
    for f in files:
        for _h, _s, st, raw in read_journal(f):
            st = st.split("::", 1)[-1]
            if st in rows:
                rows[st].append(raw.decode("utf-8", "replace").rstrip("\n"))
    for st, name in OUTPUTS.items():
        lines = rows[st]
        if name == "cloudtrail.json":
            recs = sorted((json.loads(r) for r in lines), key=lambda r: r.get("eventTime", ""))
            (o / name).write_text(json.dumps({"Records": recs}), encoding="utf-8")
        else:
            if name.startswith("guardduty"):
                # 원본 GuardDuty 결과의 시각 일부가 '2018-08-20Y13:50:..' 꼴로 깨져 있어 T로 고친다
                lines = [re.sub(r"(\d{4}-\d\d-\d\d)Y(\d\d:)", r"\1T\2", ln) for ln in lines]
            (o / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"{name}: {len(lines)}건")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])

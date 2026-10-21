"""
대용량 처리 성능 측정용: 정상(일상) CloudTrail 레코드를 N건 만들어 gzip 파일로 쓰고
파이프라인 처리 시간과 메모리를 잰다. 공격 데이터가 아니라 처리량 측정용 부하 데이터다.
  python scripts/bench.py 200000
"""
from __future__ import annotations

import gzip
import json
import random
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logsight.pipeline import run_paths  # noqa: E402

NAMES = [("s3", "GetObject"), ("s3", "PutObject"), ("ec2", "DescribeInstances"),
         ("logs", "PutLogEvents"), ("sts", "AssumeRole"), ("kms", "Decrypt")]


def make(n: int, d: Path, per_file: int = 50000) -> None:
    rnd = random.Random(1)
    t = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for f in range(0, n, per_file):
        recs = []
        for i in range(f, min(n, f + per_file)):
            src, name = rnd.choice(NAMES)
            u = rnd.randint(1, 20)
            recs.append({"eventTime": (t + timedelta(seconds=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "eventSource": f"{src}.amazonaws.com", "eventName": name,
                         "sourceIPAddress": f"198.51.100.{u}", "awsRegion": "ap-northeast-2",
                         "userIdentity": {"type": "IAMUser",
                                          "arn": f"arn:aws:iam::111122223333:user/app{u}"}})
        (d / f"bench_cloudtrail{f // per_file:02d}.json.gz").write_bytes(
            gzip.compress(json.dumps({"Records": recs}).encode()))


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    with tempfile.TemporaryDirectory() as d:
        make(n, Path(d))
        tracemalloc.start()
        t = time.time()
        res = run_paths([d], use_ai=False)
        peak = tracemalloc.get_traced_memory()[1] / 1e6
        print(f"{n:,}건: {time.time() - t:.1f}초, 최대 메모리 {peak:.0f}MB, 사건 {res['n_incidents']}건")

"""
서버 로그 전송이 끊겼는지 본다(수집 보호 방안 2).

서버의 Fluent Bit가 1분마다 s3://<보관 버킷>/heartbeat/<서버>/YYYY/MM/DD/ 에 생존 신호를 남긴다.
마지막 신호가 max_age_min분보다 오래되면 "끊김"이다. 공격자가 서버를 장악해 전송을 끄면 그 자체가 경보가 된다.
숨기지는 못하지만, 끄는 순간 알게 되고 그 전까지 보낸 로그는 보관 버킷에 지울 수 없게 남는다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _split(uri: str) -> tuple[str, str]:
    if not uri.startswith("s3://"):
        raise ValueError(f"s3:// 로 시작해야 함: {uri}")
    bucket, _, prefix = uri[5:].partition("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return bucket, prefix


def check(uri: str, s3=None, max_age_min: float = 5.0, now: datetime | None = None) -> list[dict]:
    """서버마다 {host, last, age_min, ok}. 오늘·어제 날짜 폴더만 본다(그보다 오래면 last=None, 끊김)."""
    if s3 is None:
        import boto3
        s3 = boto3.client("s3")
    now = now or datetime.now(timezone.utc)
    bucket, prefix = _split(uri)
    hosts = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
        hosts.extend(cp["Prefix"][len(prefix):].rstrip("/") for cp in page.get("CommonPrefixes", []))
    out = []
    for h in sorted(hosts):
        last = None
        for day in (now, now - timedelta(days=1)):
            for page in s3.get_paginator("list_objects_v2").paginate(
                    Bucket=bucket, Prefix=f"{prefix}{h}/{day:%Y/%m/%d}/"):
                for o in page.get("Contents", []):
                    lm = o["LastModified"] if o["LastModified"].tzinfo else o["LastModified"].replace(tzinfo=timezone.utc)
                    last = lm if last is None or lm > last else last
            if last:
                break
        age = round((now - last).total_seconds() / 60, 1) if last else None
        out.append({"host": h, "last": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None, "age_min": age,
                    "ok": age is not None and age <= max_age_min})
    return out


def to_event(row: dict, uri: str, now: datetime | None = None) -> dict:
    """끊긴 서버 하나를 EventBridge 모양 이벤트로(경보 처리 흐름을 그대로 쓰려고)."""
    now = now or datetime.now(timezone.utc)
    return {"source": "logsight.heartbeat", "detail-type": "LogSight Host Log Shipping Stopped",
            "id": f"{row['host']}", "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "detail": {**row, "uri": uri}}

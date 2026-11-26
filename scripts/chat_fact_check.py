"""채팅 AI 기준선 최종 보고서의 구체적 사실(IP, AWS API 이름, 초 단위 시각)을 원본 로그와 대조한다.

로그에 없는 값이 나오면 '지어낸 사실 후보'로 적는다. 후보는 사람이 확인하고 그 판단을
NOTES에 이유와 함께 적는다(예: CloudTrail은 GetFunction을 GetFunction20150331v2로 남긴다).
해석이나 결론(예: '유출 흔적 없음')이 맞는지는 이 스크립트가 보지 않는다.

    python scripts/chat_fact_check.py --data data/gongbang \\
        --runs reports/remeasure_2026-11-26/chat_baseline/run1 ... \\
        --out reports/remeasure_2026-11-26/chat_baseline/fact_check.json
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

IP_RE = re.compile(r"(?<![\d.])198\.18\.\d{1,3}\.\d{1,3}(?![\d.])")
TIME_RE = re.compile(r"(?<!\d)(\d\d:\d\d:\d\d)(?!\d)")
API_RE = re.compile(r"(?<![A-Za-z])((?:Get|List|Describe|Start|Send|Put|Create|Delete|Update|Assume|Decrypt|Invoke|Run|"
                    r"Stop|Terminate|Authorize|Modify|Attach|Detach|Filter|Lookup|Sign|Initiate|Respond|Admin)"
                    r"[A-Z][A-Za-z]+)(?![A-Za-z])")

# 사람이 확인한 후보 판단(값: 이유). 여기 없는 후보는 'unreviewed'로 남는다.
NOTES = {
    "api:GetFunction": "CloudTrail은 lambda:GetFunction을 GetFunction20150331v2로 남긴다(포털 18회). 같은 호출이다.",
    "api:GetFunctionConfiguration": "CloudTrail 이름은 GetFunctionConfiguration20150331v2다. 같은 호출이다.",
    "api:GetCredentialsForIdentity": "'기록이 없다'는 문장에 쓰였다. 로그에 실제로 0건이므로 맞는 진술이다.",
    "api:GetId": "'기록이 없다'는 문장에 쓰였다. 로그에 실제로 0건이므로 맞는 진술이다.",
    "api:AdminDisableUser": "조치 권고('실행하세요')와 '막은 기록이 없다'는 문장에 쓰였다. 로그에 0건이므로 맞는 진술이다.",
    "api:AdminUserGlobalSignOut": "조치 권고('실행하세요')에 쓰였다. 로그의 사실을 주장한 것이 아니다.",
    "api:ModifyInstanceMetadataOptions": "'IMDS 설정 변경은 이 이벤트인데 로그에 없으니 IMDSv2 적용 여부는 모른다'는 문장이다. 로그에 0건이므로 맞는 진술이다.",
    "time:07:03:43": "실행 이름 test-run-1791702223의 유닉스 시각을 UTC로 바꾼 값이다(계산 맞음).",
    "time:07:05:00": "실행 이름 test-run-1791702300의 유닉스 시각을 UTC로 바꾼 값이다(계산 맞음).",
    "time:07:05:44": "실행 이름 test-run-1791702344의 유닉스 시각을 UTC로 바꾼 값이다(계산 맞음).",
}


def check_run(run: Path, raw: str, event_names: set[str]) -> dict:
    chat = json.loads((run / "transcript.json").read_text(encoding="utf-8"))["chat"]
    report = chat[-1]["content"]
    found = {"ip": sorted(set(IP_RE.findall(report))),
             "time": sorted(set(TIME_RE.findall(report))),
             "api": sorted(set(API_RE.findall(report)))}
    cands = []
    for kind, vals in found.items():
        for v in vals:
            ok = (v in event_names) if kind == "api" else (v in raw)
            if not ok:
                key = f"{kind}:{v}"
                cands.append({"kind": kind, "value": v,
                              "review": "explained" if key in NOTES else "unreviewed",
                              "note": NOTES.get(key)})
    return {"run": run.name, "n_checked": {k: len(v) for k, v in found.items()},
            "candidates": cands,
            "n_unexplained": sum(1 for c in cands if c["review"] != "explained")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/gongbang")
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    d = Path(a.data)
    raw = "".join((d / n).read_text(encoding="utf-8") for n in ("cloudtrail.json", "waf.jsonl", "alb.log"))
    names = {r["eventName"] for r in json.loads((d / "cloudtrail.json").read_text(encoding="utf-8"))["Records"]}
    rows = [check_run(Path(r), raw, names) for r in a.runs]
    out = {"what": "최종 보고서의 IP·API 이름·초 단위 시각을 원본 로그와 대조. 해석·결론은 보지 않음",
           "runs": rows, "n_unexplained_total": sum(r["n_unexplained"] for r in rows)}
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({r["run"]: [r["n_checked"], r["n_unexplained"]] for r in rows}, ensure_ascii=False))


if __name__ == "__main__":
    main()

"""Splunk attack_data 측정(31%)을 대상 고객 기준으로 다시 센다.

기준(docs/처음보는데이터_측정.md 5절, 계산 전에 글로 고정):
대상 고객은 보안 담당자 없이 AWS를 쓰는 소규모 팀이다. 행동을 빼는 조건은 하나다.
"고객이 미리 만들어 둔 그 서비스 자원이 있어야만 일어나는 행동"이고, 그 서비스가 아래
EXCLUDED_SERVICES에 있을 때. 공격자가 아무 계정에서나 새로 만들 수 있는 행동
(예: DataSync 작업 생성, Batch 작업, Bedrock 호출)은 서비스와 상관없이 남긴다.
판정(맞게 탐지/놓침/다른 이유로만 걸림)은 원래 파일 그대로 쓰고 바꾸지 않는다.
"""
import json
import sys
from collections import Counter

EXCLUDED_SERVICES = {
    "bedrock": "생성형 AI 서비스. 대상 고객이 가드레일·지식 기반을 운영한다고 보기 어렵다",
    "ecr": "컨테이너 이미지 저장소와 이미지 취약점 검사",
    "saml": "회사 SSO(SAML 자격 공급자) 연동",
}
# 고객 자원이 있어야만 일어나는 행동(대상 서비스 안에서만 고른다)
NEEDS_EXISTING = {
    "DeleteGuardrail": "bedrock",
    "DeleteKnowledgeBase": "bedrock",
    "DeleteModelInvocationLoggingConfiguration": "bedrock",
    "DescribeImageScanFindings": "ecr",
    "PutImage": "ecr",
    "UpdateSAMLProvider": "saml",
}


def excluded(row):
    services = {NEEDS_EXISTING[t] for t in row["targets"] if t in NEEDS_EXISTING}
    return sorted(services)


def main(path):
    d = json.load(open(path, encoding="utf-8"))
    rows = d["rows"]
    keep, drop = [], []
    for r in rows:
        (drop if excluded(r) else keep).append(r)
    out = {
        "criteria": {"excluded_services": EXCLUDED_SERVICES, "needs_existing": NEEDS_EXISTING},
        "all": dict(Counter(r["judgement"] for r in rows)),
        "subset": dict(Counter(r["judgement"] for r in keep)),
        "dropped": [{"detection": r["detection"], "judgement": r["judgement"],
                     "services": excluded(r)} for r in drop],
        "subset_missed": [r["detection"] for r in keep if r["judgement"] != "맞게 탐지"],
    }
    n_all, n_sub = len(rows), len(keep)
    hit_all, hit_sub = out["all"].get("맞게 탐지", 0), out["subset"].get("맞게 탐지", 0)
    out["summary"] = {"all": f"{hit_all}/{n_all}", "subset": f"{hit_sub}/{n_sub}"}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "reports/public/splunk_attack_data.json")

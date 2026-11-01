"""
로그를 켰을 때 드는 월 비용 어림셈 (`python -m logsight cost`).

단가는 us-east-1 공개 요금표 기준(아래 출처). 리전·시점마다 다를 수 있으니
실제 결정 전에는 AWS Pricing Calculator로 다시 확인한다.
- CloudTrail: https://aws.amazon.com/cloudtrail/pricing/
- CloudWatch(Vended Logs): https://aws.amazon.com/cloudwatch/pricing/
- WAF: https://aws.amazon.com/waf/pricing/
- S3: https://aws.amazon.com/s3/pricing/
"""
from __future__ import annotations

PRICES = {
    "_checked": "2026-11-01",
    "ct_mgmt_first_copy": 0.0,          # 관리 이벤트 첫 사본 무료
    "ct_mgmt_extra_per_100k": 2.00,     # 추가 사본
    "ct_data_per_100k": 0.10,           # 데이터 이벤트(S3 객체 읽기 등)
    "ct_event_history": 0.0,            # 최근 90일 이벤트 기록(LookupEvents) 무료
    "vended_s3_per_gb": 0.25,           # VPC Flow Logs → S3 전송(us-east-1 첫 10TB, 서울은 0.38)
    "vended_cwl_per_gb": 0.50,          # VPC Flow Logs → CloudWatch Logs
    "s3_storage_per_gb_month": 0.023,   # S3 Standard
    "waf_acl_month": 5.00,
    "waf_rule_month": 1.00,
    "waf_per_million_req": 0.60,
    "guardduty_trial_days": 30,
}

# 리전별로 다른 단가(AWS Price List API에서 확인, 2026-11-01)
REGION_OVERRIDES = {
    "us-east-1": {},
    "ap-northeast-2": {"vended_s3_per_gb": 0.38, "vended_cwl_per_gb": 0.76,
                       "s3_storage_per_gb_month": 0.025},
}

# 이벤트·로그 크기 어림값(추정): CloudTrail 1건 ≈ 1.5KB(gzip 전), Flow Logs 1줄 ≈ 150B
CT_EVENT_KB = 1.5
FLOW_LINE_B = 150
GZIP_RATIO = 0.12


def estimate(*, mgmt_events_month: int = 300_000, s3_data_events_month: int = 0,
             flow_lines_month: int = 5_000_000, web_requests_month: int = 1_000_000,
             waf_rules: int = 3, retention_months: int = 3, region: str = "ap-northeast-2") -> dict:
    """입력: 월간 규모. 출력: 로그별 월 비용(달러)과 무료 대안."""
    p = {**PRICES, **REGION_OVERRIDES.get(region, {})}
    ct_gb = mgmt_events_month * CT_EVENT_KB / 1024 / 1024 * GZIP_RATIO
    flow_gb = flow_lines_month * FLOW_LINE_B / 1024 ** 3
    rows = [
        {"id": "cloudtrail_mgmt", "name": "CloudTrail 관리 이벤트(S3 저장)",
         "monthly": round(ct_gb * retention_months * p["s3_storage_per_gb_month"], 2),
         "basis": f"첫 사본 무료, S3 저장 {ct_gb:.2f}GB×{retention_months}개월",
         "free_alt": "최근 90일 이벤트 기록은 켜지 않아도 무료(LookupEvents)"},
        {"id": "cloudtrail_s3_data", "name": "CloudTrail S3 데이터 이벤트",
         "monthly": round(s3_data_events_month / 100_000 * p["ct_data_per_100k"], 2),
         "basis": f"{s3_data_events_month:,}건 × 0.10달러/10만 건",
         "free_alt": "민감 버킷에만 선택적으로 켜기(이벤트 선택기)"},
        {"id": "vpc_flow_s3", "name": "VPC Flow Logs → S3",
         "monthly": round(flow_gb * (p["vended_s3_per_gb"] + p["s3_storage_per_gb_month"] * retention_months), 2),
         "basis": f"{flow_gb:.2f}GB × (전송 {p['vended_s3_per_gb']} + 저장)",
         "free_alt": "서버 방화벽 로그(iptables/nftables LOG): 0원, 보안그룹이 막은 트래픽은 안 보임"},
        {"id": "vpc_flow_cwl", "name": "VPC Flow Logs → CloudWatch Logs",
         "monthly": round(flow_gb * p["vended_cwl_per_gb"], 2),
         "basis": f"{flow_gb:.2f}GB × {p['vended_cwl_per_gb']}달러/GB(저장 별도)",
         "free_alt": "S3로 보내는 편이 싸다"},
        {"id": "waf", "name": "AWS WAF(+로그)",
         "monthly": round(p["waf_acl_month"] + waf_rules * p["waf_rule_month"]
                          + web_requests_month / 1e6 * p["waf_per_million_req"], 2),
         "basis": f"ACL 5 + 규칙 {waf_rules}개 + 요청 {web_requests_month:,}건(로그는 100만 건당 500MB 포함)",
         "free_alt": "nginx/apache 접속 로그 분석: 0원(탐지만, 차단은 안 됨). 차단까지 원하면 ModSecurity+OWASP CRS"},
    ]
    return {"inputs": {"mgmt_events_month": mgmt_events_month,
                       "s3_data_events_month": s3_data_events_month,
                       "flow_lines_month": flow_lines_month,
                       "web_requests_month": web_requests_month, "waf_rules": waf_rules,
                       "retention_months": retention_months},
            "rows": rows, "prices_checked": p["_checked"], "region": region,
            "note": "어림셈이다. 이벤트 크기·압축률은 추정값이며 리전마다 단가가 다르다."}


def format_text(res: dict) -> str:
    out = [f"월 비용 어림셈 (단가 확인일 {res['prices_checked']}, {res['region']})"]
    for r in res["rows"]:
        out.append(f"  {r['name']:<34} 약 ${r['monthly']:>7.2f}/월  ({r['basis']})")
        out.append(f"      대안: {r['free_alt']}")
    out.append(res["note"])
    return "\n".join(out)

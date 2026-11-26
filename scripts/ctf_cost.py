"""CTF 본대회 인프라 비용을 단가 × 자원 × 시간으로 다시 계산한다(어림셈의 근거 파일).

    python scripts/ctf_cost.py reports/remeasure_2026-11-26/ctf/cost_inputs.json --out reports/remeasure_2026-11-26/ctf/cost.json
"""
from __future__ import annotations

import argparse
import json


def compute(inp: dict) -> dict:
    h = inp["hours"]
    r, p, u = inp["resources"], inp["prices_usd"], inp["assumed_usage"]
    month = 730.0
    items = {
        "EC2 t3.small": r["ec2_t3_small"] * p["ec2_t3_small_hr"] * h,
        "EBS gp3": r["ebs_gp3_gb"] * p["ebs_gp3_gb_month"] / month * h,
        "ALB 시간": r["alb"] * p["alb_hr"] * h,
        "ALB LCU(가정)": u["alb_lcu_per_hour"] * p["alb_lcu_hr"] * h,
        "공인 IPv4(ALB AZ별 + EC2)": (r["alb_azs"] + r["ec2_public_ipv4"]) * p["public_ipv4_hr"] * h,
        "VPC 인터페이스 엔드포인트": r["vpce_interface"] * r["vpce_interface_azs_each"] * p["vpce_interface_hr"] * h,
        "WAF ACL·규칙": (r["waf_web_acl"] * p["waf_web_acl_month"] + r["waf_rules"] * p["waf_rule_month"]) / month * h,
        "WAF 요청(가정)": u["waf_requests"] / 1e6 * p["waf_per_million_requests"],
    }
    sub = sum(items.values())
    per_day = sub / h * 24
    return {
        "hours": h,
        "items_usd": {k: round(v, 3) for k, v in items.items()},
        "subtotal_usd": round(sub, 2),
        "with_vat_usd": round(sub * (1 + inp["vat"]), 2),
        "per_day_usd_before_vat": round(per_day, 2),
        "not_counted": inp["not_counted"],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = compute(json.load(open(a.inputs, encoding="utf-8")))
    txt = json.dumps(res, ensure_ascii=False, indent=1)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()

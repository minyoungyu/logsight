"""침해 판단 결과의 숙련자용 상세 보고서. 입력은 assess() 결과(공개 API)뿐이다.

숙련자용 상세 보고서: 시간순 타임라인, IOC(IP·UA·경로·웹셸), ATT&CK 매핑,
복붙 가능한 차단 규칙(nginx·iptables·ufw). 비숙련자용 카드는 layman.py에 있다.

차단 규칙은 자동 적용되지 않는다. 사람이 검토한 뒤 직접 넣는 용도다.
"""
from __future__ import annotations

import ipaddress

from logsight.detect import RULES

def _exclusions(profile: dict) -> list[ipaddress._BaseNetwork]:
    """차단하면 안 되는 대역: 우리 호스트 IP와 신뢰 IP(CIDR 가능). 호스트 이름은 무시한다."""
    raw = list(profile.get("own_hosts", []))
    for t in profile.get("trusted_ips", []):
        raw.append(t if isinstance(t, str) else t.get("cidr", ""))
    nets = []
    for r in raw:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            continue
    return nets


def _is_blockable(ip: str, excluded: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
        return False
    return not any(addr in net for net in excluded)


def _ioc_ips(inc: dict) -> set[str]:
    ips = set(inc["src_ips"])
    for f in inc["findings"]:
        if f.get("key") and _looks_ip(f["key"]):
            ips.add(f["key"])
    for e in inc.get("events", []):
        if e.get("src_ip"):
            ips.add(e["src_ip"])
    return ips


def _looks_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def expert_report(result: dict, profile: dict | None = None) -> dict:
    """숙련자용 보고서. profile['trusted_ips']와 own_hosts는 차단 규칙에서 뺀다."""
    excluded = _exclusions(profile or {})

    timeline, iocs_ips, uas, paths, mitre = [], set(), set(), set(), {}
    for r in result["results"]:
        inc = r["incident"]
        iocs_ips |= _ioc_ips(inc)
        for e in inc.get("events", []):
            if e.get("ua"):
                uas.add(e["ua"])
        for f in inc["findings"]:
            mitre[f["technique"]] = {"technique": f["technique"], "title": f["title"], "stage": f["stage"]}
            if f.get("key") and f["key"].startswith("/"):
                paths.add(f["key"])
            timeline.append({
                "incident": inc["id"], "time": f["first"], "stage": f["stage"],
                "technique": f["technique"], "rule": f["rule"], "what": f["detail"],
                "key": f.get("key", ""), "evidence": f.get("evidence", [])[:6],
            })
    timeline.sort(key=lambda t: t["time"])

    block_ips = sorted(ip for ip in iocs_ips if _is_blockable(ip, excluded))
    rules = {
        "nginx": [f"deny {ip};" for ip in block_ips],
        "iptables": [f"iptables -I INPUT -s {ip} -j DROP" for ip in block_ips],
        "ufw": [f"ufw deny from {ip}" for ip in block_ips],
    }
    shell_paths = sorted(p for p in paths if p.lower().endswith((".php", ".phtml", ".php5", ".jsp", ".asp", ".aspx")))
    if shell_paths:
        rules["nginx_path"] = [f"location = {p} {{ deny all; return 404; }}" for p in shell_paths]

    return {
        "timeline": timeline,
        "iocs": {"ips": block_ips, "user_agents": sorted(uas), "paths": sorted(paths)},
        "mitre": [mitre[k] for k in sorted(mitre)],
        "block_rules": rules,
        "block_rules_note": "자동 적용하지 않습니다. 검토 후 직접 넣고, 관리자 IP가 막히지 않는지 먼저 확인하세요.",
        "rule_titles": {f["rule"]: RULES.get(f["rule"], ("", "", f["rule"]))[2]
                        for r in result["results"] for f in r["incident"]["findings"]},
    }

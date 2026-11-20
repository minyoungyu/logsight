"""사내(내부) IP 판단을 한 곳에서 한다.

예전에는 모듈마다 기준이 달랐다(정규화는 100.64/10·IPv6 포함, 탐지는 10/172.16/192.168/127만 문자열로,
그림·판정은 또 다름). 그래서 같은 IP가 한쪽에선 사내, 한쪽에선 외부 공격자가 됐다.

기준: RFC 1918, CGNAT(100.64/10, EKS 등 VPC 보조 대역으로 흔함), 루프백, 링크 로컬, IPv6 ULA·링크 로컬,
그리고 설정(environment.json)에 적힌 고객 VPC 대역(vpcs[].cidrs, subnets[].cidr). 공인 대역을 VPC에 쓰는
고객(BYOIP 등)도 그 대역을 사내로 본다. 분석 시작 때 set_vpc_cidrs(env)로 한 번 정한다.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

_BASE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10"))
_extra: tuple = ()


def env_cidrs(env: dict | None) -> list[str]:
    """설정에 적힌 VPC·서브넷 대역."""
    env = env or {}
    out = [c for v in env.get("vpcs", []) for c in (v.get("cidrs") or [])]
    out += [s["cidr"] for s in env.get("subnets", []) if s.get("cidr")]
    return out


def set_vpc_cidrs(env_or_cidrs) -> None:
    """고객 VPC 대역을 사내 대역에 더한다(설정 dict 또는 CIDR 목록). 빈 값이면 기본 대역만."""
    global _extra
    cidrs = env_or_cidrs if isinstance(env_or_cidrs, (list, tuple)) else env_cidrs(env_or_cidrs)
    nets = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if not any(n.subnet_of(b) for b in _BASE if b.version == n.version):
            nets.append(n)
    new = tuple(nets)
    if new != _extra:
        _extra = new
        is_internal.cache_clear()


@lru_cache(maxsize=131072)
def is_internal(ip: str | None) -> bool:
    """사내 주소면 True. IP가 아니면 False."""
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(a in n for n in _BASE + _extra if n.version == a.version)


def is_public(ip: str | None) -> bool:
    """올바른 IP이고 사내 주소가 아니면 True."""
    try:
        ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return not is_internal(ip)

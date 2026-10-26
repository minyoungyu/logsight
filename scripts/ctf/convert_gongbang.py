"""
공방전 통합로그(Markdown 표)를 LogSight 입력 형식으로 바꾸고 가명 처리한다.

입력 표의 출처별 처리
  event_history  → CloudTrail 레코드(cloudtrail.json)
  waf            → AWS WAF 로그(waf.jsonl, 경로만 남아 있어 쿼리·헤더는 없음)
  apigw-pagesnap → ALB 접속 로그 형식(alb.log)
  CLI:*          → 제외. 블루팀이 공격자를 찾으려고 직접 조회한 결과라 선택 편향이 있다.

가명 처리(같은 값은 항상 같은 가명)
  공인 IP → 198.18.0.0/15, IPv6 → 2001:db8::/32, 계정 ID → 111122223333,
  IP는 대역 관계를 남긴다. 실제로 같은 /24(IPv6는 /64)에 있던 주소는 가명도 같은 /24에 둔다.
  실제 대역 번호와 호스트 번호는 드러나지 않는다(나타난 순서대로 번호를 매긴다).
  대역이 같다는 사실은 같은 공격자의 다른 IP를 잇는 근거가 되므로 지우지 않는다.
  액세스 키 → ASIA + 해시 16자. 사설 IP와 AWS 서비스 이름은 그대로 둔다.
  대응표(mapping.json)는 출력 폴더에만 쓰고 저장소에는 올리지 않는다.

  python scripts/ctf/convert_gongbang.py 통합로그.md --out data/gongbang
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

KST = timezone(timedelta(hours=9))
YEAR = 2026
ACCOUNT_RE = re.compile(r"\b\d{12}\b")
KEY_RE = re.compile(r"\b(ASIA|AKIA)[0-9A-Z]{16}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 가명 처리하지 않는 내부 주소. ipaddress의 is_private는 문서용 대역(203.0.113.0/24 등)까지 포함해 쓰지 않는다
KEEP_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128")]
WAF_RE = re.compile(r"^(\S+) (\S+) · WAF (ALLOW|BLOCK|COUNT) \((\S+)\)$")
APIGW_RE = re.compile(r"^(\S+) (\S+) · status (\d{3}) \((\d+)B\)$")


class Pseudo:
    def __init__(self, fake_account: str = "111122223333"):
        self.ip: dict[str, str] = {}
        self.prefix: dict = {}   # 실제 /24(/64) → 가명 대역 번호
        self.hosts: dict = {}    # 실제 /24(/64) → 지금까지 나온 호스트 수
        self.key: dict[str, str] = {}
        self.account: dict[str, str] = {}
        self.fake_account = fake_account

    def ip_of(self, s: str) -> str:
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return s
        if any(addr in n for n in KEEP_NETS if n.version == addr.version):
            return s
        if s not in self.ip:
            if addr.version == 4:
                net = ipaddress.ip_network(f"{s}/24", strict=False)
                p = self.prefix.setdefault(net, len(self.prefix))
                h = self.hosts[net] = self.hosts.get(net, 0) + 1
                if p >= 512 or h > 254:
                    raise ValueError("가명 대역(198.18.0.0/15)이 모자란다")
                self.ip[s] = str(ipaddress.ip_address(int(ipaddress.ip_address("198.18.0.0")) + p * 256 + h))
            else:
                net = ipaddress.ip_network(f"{s}/64", strict=False)
                p = self.prefix.setdefault(net, len(self.prefix))
                h = self.hosts[net] = self.hosts.get(net, 0) + 1
                self.ip[s] = f"2001:db8:0:{p:x}::{h:x}"
        return self.ip[s]

    def key_of(self, s: str) -> str:
        if s not in self.key:
            h = hashlib.sha256(s.encode()).hexdigest().upper()
            self.key[s] = s[:4] + "".join(c if c.isalnum() else "X" for c in h[:16])
        return self.key[s]

    def text(self, s: str) -> str:
        def acct(m):
            self.account.setdefault(m.group(0), self.fake_account)
            return self.fake_account
        s = KEY_RE.sub(lambda m: self.key_of(m.group(0)), s)
        s = ACCOUNT_RE.sub(acct, s)
        return IP_RE.sub(lambda m: self.ip_of(m.group(0)), s)

    def dump(self) -> dict:
        return {"ip": self.ip, "access_key": self.key, "account": self.account}


def _ts(cell: str) -> datetime:
    return datetime.strptime(f"{YEAR}-{cell.strip()}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=KST)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity(actor: str, key: str, ps: Pseudo) -> dict:
    a = actor.strip()
    ident: dict = {}
    if a.startswith("arn:aws:sts::") and ":assumed-role/" in a:
        ident = {"type": "AssumedRole", "arn": ps.text(a)}
    elif a.endswith(":root"):
        ident = {"type": "Root", "arn": ps.text(a), "accountId": ps.fake_account}
    elif a.startswith("arn:aws:iam::"):
        ident = {"type": "IAMUser", "arn": ps.text(a)}
    elif a.endswith(".amazonaws.com"):
        ident = {"type": "AWSService", "invokedBy": a}
    elif a in ("", "-", "Unknown"):
        ident = {"type": "Unknown"}
    elif a == "AWS Internal":
        ident = {"type": "AWSService", "invokedBy": "AWS Internal"}
    else:  # 표에는 IAM 사용자가 이름만 적혀 있다
        ident = {"type": "IAMUser", "arn": f"arn:aws:iam::{ps.fake_account}:user/{a}"}
    if key.strip() and key.strip() != "-":
        ident["accessKeyId"] = ps.key_of(key.strip())
    return ident


def convert(md: Path, out: Path) -> dict:
    ps = Pseudo()
    records, waf, alb = [], [], []
    linemap = {"cloudtrail": [], "waf": [], "alb": []}
    skipped: dict[str, int] = {}
    for lineno, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("| 10-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) < 6:
            cells += [""] * (6 - len(cells))
        when, src, body, actor, ip, key = cells[:6]
        ts = _ts(when)
        if src == "event_history":
            parts = body.split(" · ")
            if len(parts) < 3:
                skipped["event_history_malformed"] = skipped.get("event_history_malformed", 0) + 1
                continue
            name, service, rest = parts[0], parts[1], " · ".join(parts[2:])
            status, _, param = rest.partition(" ")
            rec = {"eventTime": _iso(ts), "eventSource": service, "eventName": name,
                   "sourceIPAddress": ps.ip_of(ip) if ip else service,
                   "userIdentity": _identity(actor, key, ps)}
            if status != "OK":
                rec["errorCode"] = status
            if "=" in param:
                k, v = param.split("=", 1)
                rec["requestParameters"] = {k: ps.text(v)}
            records.append(rec)
            linemap["cloudtrail"].append(lineno)
        elif src == "waf":
            m = WAF_RE.match(body)
            if not m:
                skipped["waf_malformed"] = skipped.get("waf_malformed", 0) + 1
                continue
            method, uri, action, acl = m.groups()
            waf.append({"timestamp": int(ts.timestamp() * 1000), "action": action,
                        "webaclId": f"arn:aws:wafv2:us-west-1:{ps.fake_account}:regional/webacl/{acl}/x",
                        "terminatingRuleId": "unknown" if action == "BLOCK" else "Default_Action",
                        "httpRequest": {"clientIp": ps.ip_of(ip), "httpMethod": method,
                                        "uri": uri, "args": "", "headers": []}})
            linemap["waf"].append(lineno)
        elif src == "apigw-pagesnap":
            m = APIGW_RE.match(body)
            if not m:
                skipped["apigw_malformed"] = skipped.get("apigw_malformed", 0) + 1
                continue
            method, path, status, size = m.groups()
            alb.append(f'https {_iso(ts)} app/pagesnap-api/x {ps.ip_of(ip)}:0 - 0 0 0 '
                       f'{status} {status} 0 {size} "{method} https://pagesnap:443{path} HTTP/1.1" "-"')
            linemap["alb"].append(lineno)
        else:
            skipped[src.split(":")[0]] = skipped.get(src.split(":")[0], 0) + 1

    out.mkdir(parents=True, exist_ok=True)
    (out / "cloudtrail.json").write_text(json.dumps({"Records": records}, ensure_ascii=False))
    (out / "waf.jsonl").write_text("\n".join(json.dumps(r) for r in waf) + "\n")
    (out / "alb.log").write_text("\n".join(alb) + "\n")
    (out / "linemap.json").write_text(json.dumps(linemap))
    (out / "mapping.json").write_text(json.dumps(ps.dump(), indent=1))
    return {"cloudtrail": len(records), "waf": len(waf), "alb": len(alb), "skipped": skipped,
            "pseudonyms": {k: len(v) for k, v in ps.dump().items()}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("md")
    ap.add_argument("--out", default="data/gongbang")
    a = ap.parse_args()
    print(json.dumps(convert(Path(a.md), Path(a.out)), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

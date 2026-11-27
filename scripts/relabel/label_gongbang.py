#!/usr/bin/env python3
"""공방전 로그를 이벤트(줄) 단위로 다시 라벨한다. LogSight 탐지 코드는 읽지 않는다.

왜 다시 하나: 예전 정답지(reports/ctf/gongbang_ground_truth.json)는 블루팀 보고서에서 뽑은
공격 9단계와 공격자 IP 3개·키 1개였다. 보고서는 방어자가 쓴 해석이라 공격자의 실행 기록이 아니다.
여기서는 AIT-LDS v2.0의 라벨 방식(줄마다 라벨 + 그 라벨을 붙인 규칙 id, 붙지 않은 줄은 정상)을
따르되, 공격자의 실행 기록이 없으므로 "공격자 식별자"를 로그 안의 근거 줄로 먼저 세우고
모든 라벨에 근거 줄(ref)을 적는다. 근거로 판단할 수 없는 줄은 정상으로 두지 않고 uncertain으로 둔다.

규칙 id 체계(AIT의 attacker.<단계>.<로그>.<규칙> 꼴을 따름)
  식별자  id.ip.waf_managed_ssrf    AWS 관리형 규칙(EC2MetaDataSSRF_BODY·GenericRFI_BODY)이 막은 요청의 출처 IP
          id.key.instance_outside   EC2 인스턴스 역할 세션 키(assumed-role/*/i-*)를 AWS 공개 대역 밖 공인 IP에서 사용
          id.ip.stolen_key_user     위 키를 쓴 IP
  공격    origin.*                  식별자에서 나온 줄(AIT의 attacker_http와 같은 '출처' 라벨)
          step.*                    단계 라벨. 줄 자체에 단계의 흔적이 있을 때만 붙인다
  정상    normal.*                  방어자 계정, AWS 서비스, AWS 안에서 쓴 서비스 역할 등
  미정    uncertain.*               공격·정상 어느 쪽 근거도 없는 줄

  python scripts/relabel/label_gongbang.py --data data/gongbang --waf-raw <attacker_evidence/evt_waf.tsv> \
      --aws-ranges ip-ranges.json --out reports/relabel/gongbang_labels.jsonl

data/gongbang/mapping.json(가명 대응표)은 AWS 대역 확인과 WAF 원본 대조에만 쓰고, 출력에는 가명만 남긴다.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SSRF_SUBRULES = {"EC2MetaDataSSRF_BODY", "GenericRFI_BODY"}
RECON_PATHS = ("/robots.txt", "/sitemap.xml", "/swagger-ui", "/v3/api-docs", "/.well-known/jwks.json",
               "/actuator")
INSTANCE_ROLE = re.compile(r":assumed-role/[^/]+/i-[0-9a-f]+$")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Ctx:
    def __init__(self, mapping: dict, aws_ranges: dict):
        self.real = {v: k for k, v in mapping["ip"].items()}
        nets = [p["ip_prefix"] for p in aws_ranges["prefixes"]] + \
               [p["ipv6_prefix"] for p in aws_ranges["ipv6_prefixes"]]
        self.aws = [ipaddress.ip_network(n) for n in nets]

    def where(self, ip: str) -> str:
        """'service'(AWS 서비스 이름), 'private', 'aws', 'outside', 'unknown'"""
        if not ip or ip.endswith("amazonaws.com") or ip == "AWS Internal":
            return "service"
        try:
            a = ipaddress.ip_address(self.real.get(ip, ip))
        except ValueError:
            return "unknown"
        if any(a.version == n.version and a in n for n in PRIVATE):
            return "private"
        if any(a.version == n.version and a in n for n in self.aws):
            return "aws"
        return "outside"


def load(data: Path):
    ct = json.loads((data / "cloudtrail.json").read_text())["Records"]
    waf = [json.loads(l) for l in (data / "waf.jsonl").read_text().splitlines() if l.strip()]
    alb = [l for l in (data / "alb.log").read_text().splitlines() if l.strip()]
    return ct, waf, alb


ALB_RE = re.compile(r'^\S+ (\S+) \S+ (\S+):\d+ \S+ \S+ \S+ \S+ (\d{3}) \S+ \S+ \S+ "(\S+) https?://[^/]+(\S*) ')


def parse_alb(line: str) -> dict:
    m = ALB_RE.match(line)
    ts, ip, st, meth, path = m.groups()
    return {"ts": ts, "ip": ip, "status": int(st), "method": meth, "path": path}


def waf_subrules(waf: list[dict], raw_path: Path | None, mapping: dict) -> list[str | None]:
    """변환된 waf.jsonl 줄마다 원본 WAF 로그의 종료 규칙(관리형 규칙이면 그 하위 규칙)을 붙인다.
    통합로그 표에는 이 값이 없어서 원본(블루팀이 보존한 evt_waf.tsv)과 (초, 출처, 메서드, 경로, 결과)로 맞춘다."""
    if not raw_path:
        return [None] * len(waf)
    ipmap = mapping["ip"]
    pool: dict[tuple, list[str]] = defaultdict(list)
    for line in raw_path.read_text().splitlines():
        if not line.strip():
            continue
        d = json.loads(line.split("\t", 1)[1])
        h = d["httpRequest"]
        xff = next(x["value"] for x in h["headers"] if x["name"].lower() == "x-forwarded-for")
        if xff.count(":") == 1:                     # IPv4:port
            xff = xff.split(":")[0]
        elif xff.count(":") == 8:                   # IPv6:port
            xff = xff.rsplit(":", 1)[0]
        sub = [g["terminatingRule"]["ruleId"] for g in d.get("ruleGroupList", []) if g.get("terminatingRule")]
        key = (d["timestamp"] // 1000, ipmap.get(xff, xff), h["httpMethod"], h["uri"], d["action"].lower())
        pool[key].append(sub[0] if sub else d["terminatingRuleId"])
    out = []
    for w in waf:
        h = w["httpRequest"]
        key = (w["timestamp"] // 1000, h["clientIp"], h["httpMethod"], h["uri"], w["action"].lower())
        cands = pool.get(key) or []
        if not cands:
            out.append(None)
            continue
        # 같은 초·같은 요청 여러 줄의 종료 규칙이 서로 다르면 어느 줄인지 정할 수 없다
        out.append(cands.pop(0) if len(set(cands)) == 1 else "AMBIGUOUS:" + "|".join(sorted(set(cands))))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/gongbang")
    ap.add_argument("--waf-raw", help="블루팀이 보존한 WAF 원본(evt_waf.tsv)")
    ap.add_argument("--aws-ranges", required=True, help="https://ip-ranges.amazonaws.com/ip-ranges.json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    data = Path(a.data)
    mapping = json.loads((data / "mapping.json").read_text())
    ranges = json.loads(Path(a.aws_ranges).read_text())
    ctx = Ctx(mapping, ranges)
    ct, waf, alb = load(data)
    subs = waf_subrules(waf, Path(a.waf_raw) if a.waf_raw else None, mapping)

    # ---- 1) 공격자 식별자: 로그 안의 근거 줄로만 세운다 ----
    anchors: dict[str, dict] = {}       # 식별자 → {"rule", "evidence": [ref]}

    def anchor(ident, rule, ref):
        anchors.setdefault(ident, {"rule": rule, "evidence": []})["evidence"].append(ref)

    for i, (w, s) in enumerate(zip(waf, subs), 1):
        if s in SSRF_SUBRULES:
            anchor("ip:" + w["httpRequest"]["clientIp"], "id.ip.waf_managed_ssrf", f"waf.jsonl:{i}")
    for i, r in enumerate(ct, 1):
        ui = r.get("userIdentity", {})
        if INSTANCE_ROLE.search(ui.get("arn") or "") and ctx.where(r["sourceIPAddress"]) == "outside":
            anchor("key:" + ui["accessKeyId"], "id.key.instance_outside", f"cloudtrail.json:{i}")
    stolen = {k[4:] for k in anchors if k.startswith("key:")}
    for i, r in enumerate(ct, 1):
        if r.get("userIdentity", {}).get("accessKeyId") in stolen:
            anchor("ip:" + r["sourceIPAddress"], "id.ip.stolen_key_user", f"cloudtrail.json:{i}")
    att_ips = {k[3:] for k in anchors if k.startswith("ip:")}

    defender_ips = {r["sourceIPAddress"] for r in ct
                    if re.search(r":user/blue-team-\d+$", r.get("userIdentity", {}).get("arn") or "")
                    and ctx.where(r["sourceIPAddress"]) not in ("service",)}
    defender_24 = {ip.rsplit(".", 1)[0] for ip in defender_ips if ip.count(".") == 3}

    rows = []

    def emit(ref, cls, labels, rules, evidence=None, note=None):
        rows.append({"ref": ref, "class": cls, "labels": labels, "rules": rules,
                     **({"evidence": evidence} if evidence else {}), **({"note": note} if note else {})})

    def origin_ev(ip=None, key=None):
        ev = []
        for ident in ((f"ip:{ip}" if ip else None), (f"key:{key}" if key else None)):
            if ident and ident in anchors:
                ev += anchors[ident]["evidence"][:3]
        return ev

    # ---- 2) WAF ----
    for i, (w, s) in enumerate(zip(waf, subs), 1):
        h = w["httpRequest"]; ip = h["clientIp"]; uri = h["uri"]; ref = f"waf.jsonl:{i}"
        if ip in att_ips:
            labels, rules = ["attacker_http"], {"attacker_http": ["origin.ip"]}
            note = None
            if s in SSRF_SUBRULES:
                lab = "ssrf_imds" if s == "EC2MetaDataSSRF_BODY" else "rfi"
                labels += ["foothold", lab]; rules[lab] = [f"step.waf.{s}"]; rules["foothold"] = [f"step.waf.{s}"]
            elif uri.startswith(RECON_PATHS):
                labels += ["recon", "web_recon"]; rules["web_recon"] = ["step.waf.recon_path"]
            elif re.search(r"^/api/cases/(?:/|all$|case-0{8,})", uri) or re.search(r"^/api/cases.+/api/", uri):
                labels += ["foothold", "idor_probe"]; rules["idor_probe"] = ["step.waf.case_id_probe"]
            elif uri.lstrip("/").startswith("api/support/"):
                note = "지원 API 호출. 서명 없는 토큰을 썼는지는 헤더가 로그에 없어 줄로 확인할 수 없다(단계 라벨 없음)"
            if s == "BlockForwardedIP":
                note = "블루팀이 출처 IP를 막아 BLOCK됨. 요청 내용으로 막힌 것이 아니다"
            emit(ref, "attack", labels, rules, origin_ev(ip=ip), note)
        else:
            emit(ref, "uncertain", [], {"uncertain": ["uncertain.waf.no_attacker_link"]},
                 note="블루팀이 '공격자 증거'로 뽑은 WAF 묶음에 들어 있으나 공격 흔적(관리형 규칙 차단 등)과 공격자 식별자 연결이 없다")

    # ---- 3) PageSnap API(ALB 형식) ----
    for i, line in enumerate(alb, 1):
        d = parse_alb(line); ref = f"alb.log:{i}"
        if d["ip"] in att_ips:
            labels, rules = ["attacker_http"], {"attacker_http": ["origin.ip"]}
            if d["path"].startswith("/api/jobs/job-") and d["status"] in (403, 404):
                labels += ["foothold", "idor_probe"]; rules["idor_probe"] = [f"step.alb.job_{d['status']}"]
            emit(ref, "attack", labels, rules, origin_ev(ip=d["ip"]))
        else:
            emit(ref, "uncertain", [], {"uncertain": ["uncertain.alb.no_attacker_link"]},
                 note="블루팀이 뽑은 PageSnap 로그 묶음에 들어 있으나 공격 흔적·공격자 식별자 연결이 없다")

    # ---- 4) CloudTrail ----
    for i, r in enumerate(ct, 1):
        ref = f"cloudtrail.json:{i}"
        ui = r.get("userIdentity", {}); arn = ui.get("arn") or ""; ip = r["sourceIPAddress"]
        key = ui.get("accessKeyId"); name = r["eventName"]; err = r.get("errorCode")
        where = ctx.where(ip)
        if key in stolen or ip in att_ips:
            labels, rules = ["attacker"], {"attacker": ["origin.key" if key in stolen else "origin.ip"]}
            if key in stolen:
                labels.append("credential_misuse"); rules["credential_misuse"] = ["step.ct.instance_key_outside"]
                if name == "StartExecution" and not err:
                    labels.append("execution"); rules["execution"] = ["step.ct.states_start_ok"]
                if r["eventSource"].startswith("ssm.") and err:
                    labels.append("lateral_attempt"); rules["lateral_attempt"] = ["step.ct.ssm_denied"]
            elif r["eventSource"].startswith("s3."):
                labels.append("collection_attempt"); rules["collection_attempt"] = ["step.ct.s3_from_attacker_ip"]
            emit(ref, "attack", labels, rules, origin_ev(ip=ip if ip in att_ips else None, key=key if key in stolen else None))
            continue
        if re.search(r":user/blue-team-\d+$", arn):
            emit(ref, "normal", [], {"normal": ["normal.defender_iam_user"]}); continue
        if where == "service" or ui.get("type") == "AWSService":
            emit(ref, "normal", [], {"normal": ["normal.aws_service"]}); continue
        if (ui.get("type") == "AssumedRole" or name == "AssumeRoleWithWebIdentity") and where in ("aws", "private"):
            emit(ref, "normal", [], {"normal": ["normal.role_inside_aws"]}); continue
        if ip in defender_ips:
            emit(ref, "normal", [], {"normal": ["normal.defender_ip"]}); continue
        if ui.get("type") == "Unknown" and where == "aws":
            emit(ref, "normal", [], {"normal": ["normal.unknown_identity_inside_aws"]}); continue
        if ui.get("type") == "Root" and ip.count(".") == 3 and ip.rsplit(".", 1)[0] in defender_24:
            emit(ref, "normal", [], {"normal": ["normal.root_defender_subnet"]},
                 note="방어자 IAM 사용자가 쓴 IP와 같은 /24에서 쓴 루트. 누가 썼는지는 로그에 없다"); continue
        if ui.get("type") == "Root":
            emit(ref, "uncertain", [], {"uncertain": ["uncertain.root_unattributed"]},
                 note="공격자 식별자와도 방어자 IP와도 이어지지 않는 루트 사용"); continue
        emit(ref, "uncertain", [], {"uncertain": ["uncertain.ct.unattributed"]})

    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows), encoding="utf-8")
    summary = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": {"cloudtrail.json": sha(data / "cloudtrail.json"), "waf.jsonl": sha(data / "waf.jsonl"),
                   "alb.log": sha(data / "alb.log"),
                   "waf_raw": sha(Path(a.waf_raw)) if a.waf_raw else None,
                   "aws_ip_ranges_createDate": ranges.get("createDate")},
        "anchors": {(k[:12] + "********" + k[-4:] if k.startswith("key:") else k): {"rule": v["rule"], "n_evidence": len(v["evidence"]), "evidence": v["evidence"][:10]}
                    for k, v in sorted(anchors.items())},
        "waf_subrule_join": dict(Counter("none" if s is None else ("ambiguous" if s.startswith("AMBIGUOUS") else "ok")
                                         for s in subs)),
        "by_class": dict(Counter(x["class"] for x in rows)),
        "by_rule": dict(Counter(r for x in rows for v in x["rules"].values() for r in v)),
        "by_label": dict(Counter(l for x in rows for l in x["labels"])),
    }
    Path(str(out).replace(".jsonl", "_summary.json")).write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

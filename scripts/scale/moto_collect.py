"""usage: python scripts/scale/moto_collect.py N_VPC N_SUBNETS  → moto 계정에서 collect environment 시간·API 호출 수·결과"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # 저장소 루트의 logsight

import time, collections, os
os.environ.update(AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x", AWS_DEFAULT_REGION="ap-northeast-2")
import boto3
from moto import mock_aws
from logsight.aws_collect import export_environment
V, SUB = int(sys.argv[1]), int(sys.argv[2])
with mock_aws():
    s = boto3.Session(region_name="ap-northeast-2"); ec2 = s.client("ec2")
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    t = time.time(); n_inst = 0
    for v in range(V):
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]   # 모든 VPC가 같은 대역(겹침)
        for i in range(SUB):
            sub = ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{i}.0/24")["Subnet"]["SubnetId"]
            acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
            assoc = [a for a in ec2.describe_network_acls(Filters=[{"Name":"association.subnet-id","Values":[sub]}])["NetworkAcls"][0]["Associations"] if a["SubnetId"]==sub][0]
            ec2.replace_network_acl_association(AssociationId=assoc["NetworkAclAssociationId"], NetworkAclId=acl)
            sg = ec2.create_security_group(GroupName=f"g{v}-{i}", Description="d", VpcId=vpc)["GroupId"]
            ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=sub, SecurityGroupIds=[sg]); n_inst += 1
    print(f"setup {time.time()-t:.1f}s")
    calls = collections.Counter()
    s.events.register("before-call.*.*", lambda model, **k: calls.update([model.name]))
    t = time.time(); env = export_environment(session=s)
    print(f"export {time.time()-t:.1f}s calls={dict(calls)} errors={env['_errors']}")
    print("instances", len(env["instances"]), "/", n_inst, "nacls", len(env["network_acls"]), "sgs", len(env["security_groups"]))
    print("subnet keys in env:", [k for k in env if 'subnet' in k or 'vpc' in k])
    from collections import Counter
    dup = Counter(i["private_ip"] for i in env["instances"])
    print("private IPs shared by >1 instance:", sum(1 for c in dup.values() if c > 1))
    print("instance has vpc_id field:", "vpc_id" in env["instances"][0])

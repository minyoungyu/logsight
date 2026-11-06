"""경보 → 대기열 → 로그 주입 → 보고서 → 디스코드 알림 → 자동 격리 예고를 AWS 없이 끝에서 끝까지 돌린다.

가짜 AWS(moto)에 SQS 대기열과 CloudTrail 로그 버킷을 만들고, 실제 계정 시연(docs/시연_실계정.md)과 같은
"탈취한 키로 보안그룹 22번을 연다" 공격 이벤트와 GuardDuty 높음 경보를 넣는다. 디스코드는 이 PC 안의 임시
HTTP 서버가 받는다. 실제 AWS·디스코드에는 아무것도 보내지 않는다.

    pip install "moto[sqs,s3]"
    python scripts/demo_e2e_moto.py            # 결과: reports/e2e_demo/
"""
import json, os, sys, threading, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "reports" / "e2e_demo")
OUT.mkdir(parents=True, exist_ok=True)
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="ap-northeast-2",
                  NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from logsight import alert as al  # noqa: E402
from logsight import respond as rs  # noqa: E402
REGION, ACCT = "ap-northeast-2", "111122223333"
got = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"])))); self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["DEMO_DISCORD"] = f"http://127.0.0.1:{srv.server_port}/webhook"
(OUT / "notify.json").write_text(json.dumps({"channels": [{"type": "discord", "url_env": "DEMO_DISCORD"}]}), encoding="utf-8")
log = []
def say(s):
    log.append(s)
    print(s)
now = datetime.now(timezone.utc).replace(microsecond=0)
iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
ATT = f"arn:aws:iam::{ACCT}:user/app"
def ct(name, t, req, resp=None, ip="203.0.113.66"):
    return {"eventVersion": "1.08", "eventTime": iso(t), "eventSource": "ec2.amazonaws.com" if "Security" in name else "iam.amazonaws.com",
            "eventName": name, "awsRegion": REGION, "sourceIPAddress": ip, "userAgent": "aws-cli/2.15",
            "userIdentity": {"type": "IAMUser", "arn": ATT, "accountId": ACCT, "userName": "app", "accessKeyId": "AKIABASEKEY",
                             "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}},
            "requestParameters": req, "responseElements": resp, "eventID": f"ev-{name}-{t.minute}", "recipientAccountId": ACCT}
sg_req = {"groupId": "sg-0demo0000000001", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
          "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
records = [ct("GetCallerIdentity", now - timedelta(minutes=6), {}),
           ct("CreateAccessKey", now - timedelta(minutes=4), {"userName": "backup-svc"},
              {"accessKey": {"accessKeyId": "AKIANEWATTACKER1", "userName": "backup-svc", "status": "Active"}}),
           ct("AuthorizeSecurityGroupIngress", now - timedelta(minutes=2), sg_req)]
with mock_aws():
    sqs, s3 = boto3.client("sqs", region_name=REGION), boto3.client("s3", region_name=REGION)
    q = sqs.create_queue(QueueName="logsight-alerts")["QueueUrl"]
    s3.create_bucket(Bucket="demo-log-archive", CreateBucketConfiguration={"LocationConstraint": REGION})
    key = f"AWSLogs/{ACCT}/CloudTrail/{REGION}/{now:%Y/%m/%d}/{ACCT}_CloudTrail_{REGION}_demo.json"
    s3.put_object(Bucket="demo-log-archive", Key=key, Body=json.dumps({"Records": records}).encode())
    say(f"[준비] 가짜 AWS: SQS 대기열 1개, S3 로그 버킷에 CloudTrail 파일 1개({len(records)}건, 오늘 날짜 폴더)")
    # 1) 공격: 보안그룹 22번 개방 → EventBridge가 SQS로 보내는 이벤트 모양 그대로
    ev = {"version": "0", "id": "demo-sg-1", "detail-type": "AWS API Call via CloudTrail", "source": "aws.ec2",
          "account": ACCT, "time": iso(now - timedelta(minutes=2)), "region": REGION, "detail": records[2]}
    sqs.send_message(QueueUrl=q, MessageBody=json.dumps(ev))
    # 2) 같은 계정의 GuardDuty 높음 경보(샘플)
    gd = json.loads((ROOT / "samples/alerts/guardduty_event.json").read_text(encoding="utf-8"))
    sqs.send_message(QueueUrl=q, MessageBody=json.dumps(gd))
    say("[1 경보 발생 → 2 전달] EventBridge 형식 이벤트 2개를 SQS에 넣음: 보안그룹 22번 개방(위험 API 호출), GuardDuty 결과")
    base = OUT / "respond"; base.mkdir(exist_ok=True)
    (base / "baseline.json").write_text(json.dumps({"users": ["app"], "roles": ["ec2-app-role"], "access_keys": ["AKIABASEKEY"], "sg_rules": []}))
    (base / "respond.json").write_text(json.dumps({"mode": "dry-run", "deadline_min": 10}))
    opt = al.Options(logs=[str(ROOT / "samples/demo")], s3=[f"s3://demo-log-archive/AWSLogs/{ACCT}/CloudTrail/{REGION}/{{date}}/"],
                     env=str(ROOT / "samples/demo/environment.json"), out=str(OUT / "alerts"), use_ai=False,
                     notify=str(OUT / "notify.json"), respond=str(base / "respond.json"), min_severity="medium")
    t0 = time.time()
    done = al.watch(q, opt, sqs=sqs, s3=s3, once=True, wait_s=0, log=say)
    say(f"[3~6] watch 1회 처리: {len(done)}건, {time.time()-t0:.1f}초")
    for d in done:
        say(f"  - {d['status']}: {d.get('out','')}  격리={((d.get('response') or {}).get('status'))}")
    left = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    say(f"[2 확인] 처리 뒤 대기열에 남은 메시지: {left['ApproximateNumberOfMessages']}개(분석 성공 후 지움)")
    say(f"[6 알림] 임시 디스코드 서버가 받은 카드: {len(got)}개")
    rcfg = rs.Config.load(base / "respond.json")
    before = rs.tick(rcfg, OUT / "alerts", now=datetime.now(timezone.utc) + timedelta(minutes=9))
    say(f"[7 격리] 9분 뒤 점검: 실행 {len(before)}건(마감 전이라 기다림)")
    after = rs.tick(rcfg, OUT / "alerts", now=datetime.now(timezone.utc) + timedelta(minutes=11))
    for r in after:
        for a in r.get("actions", []):
            say(f"[7 격리] 11분 뒤(아무도 확인 안 함): {a.get('kind') or a.get('type')} {a.get('target') or a.get('id')} → {a['outcome']['result']} (시험 모드라 실제로 바꾸지 않음)")
(OUT / "discord_cards.json").write_text(json.dumps(got, ensure_ascii=False, indent=1), encoding="utf-8")
(OUT / "실행기록.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
srv.shutdown()

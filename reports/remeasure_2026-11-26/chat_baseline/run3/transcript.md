## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

침착하게 순서대로 진행하면 됩니다. 아래는 보안 전문가가 아니어도 따라 할 수 있도록 우선순위대로 정리한 것입니다.

---

## 0단계: 연락이 진짜인지 확인 (2분)

"공격받았다"는 연락 자체가 피싱일 수도 있습니다.
- 메일/문자의 **링크로 로그인하지 마세요.** 브라우저에 직접 `console.aws.amazon.com`을 입력해 접속하세요.
- 콘솔에서 **Support Center**(지원 케이스)와 **Health Dashboard**에 AWS의 알림이 실제로 와 있는지 확인하세요.
- 누가, 어떤 내용으로 연락했는지 알려 주시면 판단에 도움이 됩니다. (예: "Your AWS account may be compromised", "Exposed access key", 외부 abuse 신고 등)

---

## 1단계: 지금 당장 할 일 (피해 확산 방지)

**원칙: 지우지 말고 막으세요.** 삭제하면 조사에 필요한 증거가 사라집니다.

1. **루트 계정 보호**: 루트 비밀번호를 변경하고 MFA가 켜져 있는지 확인합니다.
2. **청구 금액 확인**: Billing → Bills / Cost Explorer에서 오늘 비용이 비정상적으로 늘었는지 봅니다. 채굴용 EC2/GPU 인스턴스가 가장 흔한 피해입니다.
3. **AWS Support 케이스 열기**: "Account and billing" → 계정 침해 의심으로 접수하세요. AWS가 조사를 도와주고, 공격으로 발생한 요금을 감면해 주는 경우가 많습니다.
4. 어떤 키가 유출됐는지 확인되면 해당 Access Key를 **Delete 말고 Deactivate** 하세요. (로그로 범위를 좁힌 뒤 진행해도 됩니다.)

---

## 2단계: 로그 뽑기

### ⚠️ 시간대 주의
CloudTrail은 **UTC** 기준입니다. 한국 시간 13:30은 **UTC 04:30**입니다.

### (1) 13:30 이후 모든 API 활동, 전 리전

공격자는 평소 쓰지 않는 리전에 리소스를 만드는 경우가 많아서 전 리전을 확인해야 합니다. `YYYY-MM-DD`를 오늘 날짜로 바꿔 실행하세요.

```bash
START="YYYY-MM-DDT04:30:00Z"
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo ">>> $r"
  aws cloudtrail lookup-events --region "$r" --start-time "$START" \
    --output json > "events_$r.json"
done
```

### (2) 보기 좋게 요약 (jq가 있다면)

```bash
for f in events_*.json; do
  jq -r --arg f "$f" '.Events[] | .CloudTrailEvent | fromjson |
    [$f, .eventTime, .eventSource, .eventName, (.userIdentity.arn // .userIdentity.type),
     .userIdentity.accessKeyId, .sourceIPAddress, (.errorCode // "OK")] | @tsv' "$f"
done | sort -k2 > summary.tsv
```

### (3) IAM 현황

```bash
aws iam generate-credential-report && sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv
aws iam list-users --output json > users.json
```

---

## 3단계: 직접 먼저 훑어볼 위험 신호

`summary.tsv`에서 아래 이벤트 이름을 검색해 보세요.

| 분류 | 이벤트 이름 | 의미 |
|---|---|---|
| 흔적 지우기 | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `DeleteDetector` | 매우 위험. 로그를 끄려는 시도 |
| 백도어 생성 | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, `UpdateAssumeRolePolicy` | 다시 들어오기 위한 계정/키 생성 |
| 자원 도용 | `RunInstances`, `RequestSpotInstances`, `CreateFunction`, `RunTask` | 채굴 등 |
| 정찰 | `GetCallerIdentity`, `ListBuckets`, `ListUsers`, `DescribeInstances`가 짧은 시간에 몰림 | 유출된 키를 테스트하는 전형적 패턴 |
| 데이터 탈취 | `GetSecretValue`, `GetParameter`, `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock` | 비밀값 열람, 버킷 공개 전환 |
| 메일 악용 | `UpdateAccountSendingEnabled`, `CreateEmailIdentity`, SES 관련 | 스팸 발송 |
| 로그인 | `ConsoleLogin` | 낯선 IP나 국가에서의 콘솔 로그인 |

**처음 보는 IP**와 **`AccessDenied`가 연달아 찍힌 키**가 핵심 단서입니다. 공격자가 권한을 더듬어 보는 흔적이기 때문입니다.

---

## 4단계: 저에게 보내 주실 것

- `summary.tsv` (가장 중요)
- 연락받은 메시지 내용
- 해당 시간대 비용 변화 (대략적인 금액이면 충분)

**보내기 전 마스킹할 것**
- Secret Access Key, 비밀번호, 세션 토큰은 **절대 붙여 넣지 마세요.** (`AKIA...`로 시작하는 Access Key **ID**는 괜찮습니다.)
- 계정 ID나 회사 IP는 원하시면 `XXXX`로 가려도 분석에 지장 없습니다.

---

## 참고: 흔한 원인 (나중에 막아야 할 곳)

백엔드 개발자분이시니 이쪽을 먼저 의심해 보세요.
1. **GitHub 등에 Access Key 커밋**: `.env`, `config`, 테스트 코드 등. public 저장소에 올라가면 수 분 안에 악용됩니다.
2. **EC2 메타데이터 탈취 (SSRF)**: 앱에 URL을 받아 요청하는 기능이 있고 IMDSv1을 쓰면 인스턴스 역할 자격 증명이 털릴 수 있습니다.
3. **오래된 IAM 사용자 키**: 퇴사자 키나 CI용 키가 방치된 경우입니다.

로그를 주시면 ① 어떤 자격 증명이 털렸는지 ② 공격자가 무엇을 했는지 ③ 남겨 둔 백도어가 있는지 ④ 무엇을 어떤 순서로 정리할지 구체적으로 짚어 드리겠습니다.

혹시 지금 상황에서 **비용이 빠르게 오르고 있거나 낯선 IAM 사용자가 보인다면** 그것부터 알려 주세요. 그 경우는 로그 분석보다 차단을 먼저 해야 합니다.

## 사용자

요청하신 것 가운데 제가 가진 로그로 뽑을 수 있는 것만 정리해서 보냅니다. summary.tsv는 너무 길어서 통째로 보내지 못하고 요약으로 대신했습니다.

**못 하는 것**
- 지금은 AWS 콘솔과 CLI에 접속할 수 없습니다. 그래서 0단계(Support Center·Health Dashboard 확인)와 1단계(루트 비밀번호 변경·MFA 확인, 청구 금액 확인, Support 케이스 열기, 키 비활성화)는 진행하지 못했습니다.
- 제가 가진 건 내려받아 둔 CloudTrail 파일 하나뿐입니다. 서울 리전(ap-northeast-2)만 들어 있고, 시간은 2026-10-11 04:30:01Z ~ 07:25:01Z(한국 시간 13:30 ~ 16:25)입니다. 이 파일만으로는 다른 리전을 확인할 수 없습니다.
- credential report, users.json, 비용 변화도 확인하지 못했습니다(그 로그는 없어요).
- 연락 메시지의 원문, 누가 어떤 내용으로 연락했는지는 제가 정확히 모릅니다.

**요약 형태로 보내는 이유**
- 2단계 (2)대로 cloudtrail.json에서 같은 칸(eventTime, eventSource, eventName, arn, accessKeyId, sourceIPAddress, errorCode)을 뽑으면 10,223줄이 나옵니다. 너무 길어서 그대로 붙이지 못했습니다.
- 대신 같은 데이터를 아래처럼 묶어서 보냅니다. 붙인 결과는 고치지 않은 원본입니다.
  1. 3단계 표에 있는 이벤트 이름만 골라, 같은 이벤트·사용자(arn)·IP·결과끼리 묶은 것(처음·마지막 시각, 건수 포함). SES 관련 이벤트는 따로 뽑았습니다.
  2. 사용자(arn)별 건수, IP별 건수
  3. 오류가 난 기록을 사용자·키·IP·오류 코드별로 센 것(많은 순 상위 40줄)
- 특정 구간의 원본 줄이 필요하면 조건을 알려 주세요. 다시 뽑겠습니다.

**계정에 대해 알고 있는 것**
- blue-team-1, blue-team-2는 우리 팀원 계정입니다. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했습니다.
- PatchSignal은 원래 있던 우리 서비스입니다.
- 이 계정은 보안 공방전(연습) 환경입니다.

실행한 명령:
```
echo "== cloudtrail.json 전체 레코드 수 / 시간 범위 =="; jq -r '.Records|length' cloudtrail.json; jq -r '[.Records[].eventTime]|min, max' cloudtrail.json
echo; echo "== 위 3단계 위험 신호 이벤트만: 첫시각 / 마지막시각 / 건수 / eventName / 주체 / IP / 결과 =="
jq -r '.Records[] | [.eventTime, .eventSource, .eventName, (.userIdentity.arn // .userIdentity.type), .userIdentity.accessKeyId, .sourceIPAddress, (.errorCode // "OK")] | @tsv' cloudtrail.json | sort | grep -P '\t(StopLogging|DeleteTrail|UpdateTrail|DeleteDetector|CreateUser|CreateAccessKey|CreateLoginProfile|AttachUserPolicy|PutUserPolicy|UpdateAssumeRolePolicy|RunInstances|RequestSpotInstances|CreateFunction|CreateFunction20150331|RunTask|GetCallerIdentity|ListBuckets|ListUsers|DescribeInstances|GetSecretValue|GetParameter|PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|DeleteBucketPublicAccessBlock|UpdateAccountSendingEnabled|CreateEmailIdentity|ConsoleLogin)\t' | awk -F'\t' '{k=$3"\t"$4"\t"$6"\t"$7; c[k]++; if(!(k in f))f[k]=$1; l[k]=$1} END{for(k in c) print f[k]"\t"l[k]"\t"c[k]"\t"k}' | sort
echo; echo "== SES 관련 이벤트 =="; jq -r '.Records[] | select(.eventSource|test("ses|email")) | [.eventTime,.eventSource,.eventName,(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,(.errorCode // "OK")]|@tsv' cloudtrail.json
```
결과:
```
== cloudtrail.json 전체 레코드 수 / 시간 범위 ==
10223
2026-10-11T04:30:01Z
2026-10-11T07:25:01Z

== 위 3단계 위험 신호 이벤트만: 첫시각 / 마지막시각 / 건수 / eventName / 주체 / IP / 결과 ==
2026-10-11T04:30:02Z	2026-10-11T04:30:02Z	1	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.1.1	OK
2026-10-11T04:30:03Z	2026-10-11T05:52:06Z	61	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.4.1	OK
2026-10-11T04:30:37Z	2026-10-11T06:01:12Z	237	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	OK
2026-10-11T04:30:39Z	2026-10-11T05:10:22Z	8	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	OK
2026-10-11T04:30:40Z	2026-10-11T05:42:10Z	13	DescribeInstances	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	OK
2026-10-11T04:30:44Z	2026-10-11T04:39:59Z	24	DescribeInstances	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	OK
2026-10-11T04:31:05Z	2026-10-11T05:59:39Z	95	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.9.1	OK
2026-10-11T04:31:08Z	2026-10-11T06:01:08Z	13	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	eks.amazonaws.com	OK
2026-10-11T04:31:33Z	2026-10-11T06:01:33Z	10	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	eks-nodegroup.amazonaws.com	OK
2026-10-11T04:31:53Z	2026-10-11T04:31:53Z	1	DescribeInstances	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	OK
2026-10-11T04:32:56Z	2026-10-11T05:58:00Z	18	DescribeInstances	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497	eks.amazonaws.com	OK
2026-10-11T04:33:44Z	2026-10-11T05:58:23Z	13	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.9.1	OK
2026-10-11T04:33:50Z	2026-10-11T05:33:40Z	3	DescribeInstances	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	OK
2026-10-11T04:35:18Z	2026-10-11T06:00:44Z	25	DescribeInstances	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	OK
2026-10-11T04:35:30Z	2026-10-11T04:36:20Z	2	ListBuckets	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	OK
2026-10-11T04:42:48Z	2026-10-11T04:42:48Z	2	GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.0.3	OK
2026-10-11T04:42:50Z	2026-10-11T04:42:50Z	1	GetParameter	arn:aws:iam::111122223333:root	198.18.0.3	OK
2026-10-11T04:42:55Z	2026-10-11T04:42:55Z	1	DescribeInstances	arn:aws:iam::111122223333:root	198.18.0.3	OK
2026-10-11T04:42:59Z	2026-10-11T04:42:59Z	1	GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.14.1	OK
2026-10-11T04:48:40Z	2026-10-11T04:48:41Z	2	GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.18.1	OK
2026-10-11T04:48:42Z	2026-10-11T04:48:42Z	1	GetParameter	arn:aws:iam::111122223333:root	198.18.18.1	OK
2026-10-11T04:48:47Z	2026-10-11T04:48:47Z	1	DescribeInstances	arn:aws:iam::111122223333:root	198.18.18.1	OK
2026-10-11T04:48:51Z	2026-10-11T04:48:51Z	1	GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.18.2	OK
2026-10-11T04:50:33Z	2026-10-11T05:42:00Z	2	DescribeInstances	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling	autoscaling.amazonaws.com	OK
2026-10-11T05:00:03Z	2026-10-11T05:00:03Z	1	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	OK
2026-10-11T05:14:04Z	2026-10-11T05:58:42Z	41	DescribeInstances	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	OK
2026-10-11T05:19:46Z	2026-10-11T05:19:46Z	1	ListBuckets	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	OK
2026-10-11T05:23:34Z	2026-10-11T05:23:34Z	1	ListBuckets	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	OK
2026-10-11T05:24:22Z	2026-10-11T05:59:20Z	18	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	OK
2026-10-11T05:27:38Z	2026-10-11T05:29:49Z	2	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.32.1	OK
2026-10-11T05:29:52Z	2026-10-11T05:44:13Z	3	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	OK
2026-10-11T05:30:54Z	2026-10-11T05:30:54Z	1	DescribeInstances	arn:aws:iam::111122223333:user/blue-team-2	ssm.amazonaws.com	OK
2026-10-11T05:30:58Z	2026-10-11T05:36:49Z	2	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.33.1	OK
2026-10-11T05:31:30Z	2026-10-11T05:31:30Z	1	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	OK
2026-10-11T05:32:08Z	2026-10-11T05:57:03Z	2	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	OK
2026-10-11T05:32:12Z	2026-10-11T05:57:53Z	25	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	apigateway.amazonaws.com	OK
2026-10-11T05:32:13Z	2026-10-11T05:57:54Z	3	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	OK
2026-10-11T05:37:59Z	2026-10-11T05:43:49Z	2	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.36.1	OK
2026-10-11T05:44:58Z	2026-10-11T05:44:58Z	1	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.37.1	OK
2026-10-11T06:00:20Z	2026-10-11T06:00:45Z	10	GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	OK

== SES 관련 이벤트 ==
2026-10-11T05:55:22Z	ses.amazonaws.com	ListDedicatedIpPools	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com	OK
```

실행한 명령:
```
echo "== 주체(arn)별 이벤트 건수 =="; jq -r '.Records[] | (.userIdentity.arn // .userIdentity.type)' cloudtrail.json | sed 's#arn:aws:[a-z]*::111122223333:##' | sort | uniq -c | sort -rn
echo; echo "== sourceIPAddress별 이벤트 건수 =="; jq -r '.Records[].sourceIPAddress' cloudtrail.json | sort | uniq -c | sort -rn
echo; echo "== AccessDenied 등 오류 건수 (주체 / 키 / IP / errorCode) =="; jq -r '.Records[] | select(.errorCode) | [(.userIdentity.arn // .userIdentity.type), .userIdentity.accessKeyId, .sourceIPAddress, .errorCode]|@tsv' cloudtrail.json | sed 's#arn:aws:[a-z]*::111122223333:##' | sort | uniq -c | sort -rn | head -40
```
결과:
```
== 주체(arn)별 이벤트 건수 ==
   4814 user/blue-team-1
   3207 assumed-role/ec2-ssmrole/i-026754fe07a870049
    788 user/blue-team-2
    386 AWSService
    171 assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77
    153 root
    110 assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS
     99 Unknown
     83 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS
     74 assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession
     69 assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2
     62 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1
     48 assumed-role/AWSServiceRoleForAutoScaling/AutoScaling
     34 assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe
     20 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer
     18 assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api
     18 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497
     14 assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe
     13 assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector
     10 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api
      8 assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring
      6 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s
      4 assumed-role/AWSServiceRoleForSecurityHubV2/securityhub
      3 assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession
      2 user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit
      2 user/system:serviceaccount:device-support:portal-api
      2 assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery
      1 user/AWSAccount
      1 assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3
      1 assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession
      1 assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession
      1 assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession

== sourceIPAddress별 이벤트 건수 ==
   3225 198.18.6.1
   2301 198.18.23.1
   1474 198.18.2.1
    854 198.18.0.1
    450 198.18.5.1
    265 198.18.3.1
    176 eks.amazonaws.com
    170 eks-nodegroup.amazonaws.com
    170 config.amazonaws.com
    142 198.18.10.1
    108 198.18.9.1
    103 delivery.logs.amazonaws.com
     87 resource-explorer-2.amazonaws.com
     73 198.18.18.1
     72 198.18.0.3
     68 lambda.amazonaws.com
     61 198.18.4.1
     54 198.18.8.1
     53 autoscaling.amazonaws.com
     30 198.18.7.1
     27 198.18.7.2
     26 states.amazonaws.com
     25 apigateway.amazonaws.com
     19 AWS Internal
     18 observabilityadmin.amazonaws.com
     18 10.81.0.102
     15 cloudtrail.amazonaws.com
     13 198.18.19.1
     10 ec2.amazonaws.com
      9 2001:db8:0:18::1
      8 securityhub.amazonaws.com
      8 guardduty.amazonaws.com
      7 198.18.20.1
      6 2001:db8:0:b::2
      5 198.18.26.1
      4 198.18.50.1
      4 198.18.34.1
      4 198.18.16.1
      4 198.18.0.2
      2 198.18.36.1
      2 198.18.33.1
      2 198.18.32.1
      2 198.18.14.1
      1 ssm.amazonaws.com
      1 ssm-quicksetup.amazonaws.com
      1 198.18.68.1
      1 198.18.67.1
      1 198.18.66.1
      1 198.18.65.1
      1 198.18.64.1
      1 198.18.63.1
      1 198.18.62.1
      1 198.18.61.1
      1 198.18.60.1
      1 198.18.59.1
      1 198.18.58.1
      1 198.18.57.1
      1 198.18.56.1
      1 198.18.55.1
      1 198.18.54.1
      1 198.18.53.1
      1 198.18.52.1
      1 198.18.51.1
      1 198.18.49.1
      1 198.18.48.1
      1 198.18.47.1
      1 198.18.46.1
      1 198.18.45.1
      1 198.18.44.1
      1 198.18.43.1
      1 198.18.42.1
      1 198.18.41.1
      1 198.18.40.1
      1 198.18.39.1
      1 198.18.38.1
      1 198.18.37.1
      1 198.18.35.1
      1 198.18.31.1
      1 198.18.30.1
      1 198.18.29.2
      1 198.18.29.1
      1 198.18.28.1
      1 198.18.27.1
      1 198.18.25.1
      1 198.18.22.1
      1 198.18.21.1
      1 198.18.18.2
      1 198.18.17.1
      1 198.18.15.1
      1 198.18.13.1
      1 198.18.12.1
      1 198.18.1.1

== AccessDenied 등 오류 건수 (주체 / 키 / IP / errorCode) ==
     12 user/blue-team-1	ASIA0E8E…8B55	198.18.23.1	ThrottlingException
      8 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	ASIA6E0C…4099	198.18.8.1	Client.InvalidParameterValue
      6 user/blue-team-1	ASIAE1F9…B210	198.18.0.1	ValidationException
      6 user/blue-team-1	ASIA6F82…737C	198.18.0.1	ThrottlingException
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIAD70B…ECFE	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIACF58…D398	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIABFCA…F0CC	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIAB5E6…F898	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA0861…69A7	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA042B…F588	eks.amazonaws.com	Client.DryRunOperation
      6 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA012A…9304	eks.amazonaws.com	Client.DryRunOperation
      6 Unknown		198.18.7.1	InvalidPasswordException
      5 user/blue-team-1	ASIA6C9C…6CBA	198.18.0.1	ThrottlingException
      4 user/blue-team-1	ASIA137F…F5F7	198.18.5.1	ObjectLockConfigurationNotFoundError
      4 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	ASIA0944…8BFA	198.18.8.1	Client.InvalidParameterValue
      4 assumed-role/ec2-ssmrole/i-026754fe07a870049	ASIAFB04…3F63	198.18.6.1	AccessDenied
      4 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIAF98D…C8C1	eks.amazonaws.com	Client.DryRunOperation
      4 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIACE90…29A5	eks.amazonaws.com	Client.DryRunOperation
      4 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA7E7D…43D6	eks.amazonaws.com	Client.DryRunOperation
      4 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA3783…075F	eks.amazonaws.com	Client.DryRunOperation
      4 assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ASIA16D5…5C40	eks.amazonaws.com	Client.DryRunOperation
      4 Unknown		198.18.7.2	NotAuthorizedException
      4 Unknown		198.18.7.2	InvalidPasswordException
      3 user/blue-team-1	ASIAF579…3FD6	198.18.23.1	InvalidStatusException
      3 user/blue-team-1	ASIA6FF5…1247	198.18.0.1	ValidationException
      3 assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	198.18.7.1	AccessDenied
      3 Unknown		198.18.7.1	NotAuthorizedException
      3 AWSService		delivery.logs.amazonaws.com	ResourceAlreadyExistsException
      2 user/blue-team-2	ASIA2CD4…B3DF	198.18.23.1	InsightNotEnabledException
      2 user/blue-team-1	ASIAE1F9…B210	198.18.0.1	UnauthorizedException
      2 user/blue-team-1	ASIAC741…317A	198.18.0.1	ValidationException
      2 user/blue-team-1	ASIAB9BA…ACBA	198.18.23.1	InvalidLookupAttributesException
      2 user/blue-team-1	ASIA9F13…59D8	198.18.23.1	DashboardNotFoundError
      2 user/blue-team-1	ASIA75B9…13C1	198.18.23.1	ValidationException
      2 user/blue-team-1	ASIA4831…C58D	198.18.23.1	ResourceNotFoundException
      2 user/blue-team-1	ASIA1F13…5AB1	198.18.23.1	InvalidStatusException
      2 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	ASIAAD86…20D7	198.18.8.1	Client.InvalidParameterValue
      2 assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	ASIA1F0C…48DC	resource-explorer-2.amazonaws.com	NotFoundException
      1 user/blue-team-2	ASIAF0CC…6AEE	198.18.23.1	InsightNotEnabledException
      1 user/blue-team-2	ASIAEBE6…24CF	198.18.23.1	DashboardNotFoundError
```

## 채팅 AI

## 요약

이 파일에서 가장 의심스러운 단서는 **198.18.7.1과 198.18.7.2**라는 두 IP입니다. 이 IP는 PatchSignal 포털 서버(인스턴스 `i-05816900800807b77`)에 부여된 역할의 임시 자격 증명을 서버 밖에서 사용한 흔적이 있습니다. 같은 IP에서 로그인 실패도 여러 번 기록됐습니다.

두 번째로 확인할 것은 **root 계정 활동 153건**입니다. 팀원 계정 목록에 root가 없으므로, 누가 사용했는지 밝혀야 합니다.

다만 아직은 **추정**입니다. 원본 기록을 보기 전에는 단정할 수 없습니다.

---

## 1. 가장 의심되는 것: 198.18.7.x와 PatchSignal 포털 역할

```
3  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  ASIA71C2…95CF  198.18.7.1  AccessDenied
6  Unknown  198.18.7.1  InvalidPasswordException
3  Unknown  198.18.7.1  NotAuthorizedException
4  Unknown  198.18.7.2  NotAuthorizedException
4  Unknown  198.18.7.2  InvalidPasswordException
```

의심하는 이유는 세 가지입니다.

- **역할 자격 증명이 다른 곳에서 쓰였습니다.** 포털 역할은 평소 198.18.10.1(142건, 서버 자신의 주소로 보임)에서 호출됩니다. 그런데 같은 역할의 임시 키가 198.18.7.1에서 쓰였고, 결과가 `AccessDenied`였습니다. 이는 EC2 역할 자격 증명이 탈취돼 외부에서 사용될 때 나타나는 전형적인 모습입니다. 흔한 원인은 SSRF로 메타데이터(IMDS)를 읽어 가는 것입니다. GuardDuty에서는 `InstanceCredentialExfiltration` 계열 탐지에 해당합니다.
- **같은 IP에서 인증 시도 실패가 있었습니다.** 주체가 `Unknown`이고 오류가 `NotAuthorizedException`, `InvalidPasswordException`인 기록은 보통 Cognito 같은 사용자 인증 API에서 나옵니다. 앞의 것은 비밀번호가 틀린 경우이고, 뒤의 것은 가입이나 비밀번호 변경 때 비밀번호 정책을 어긴 경우입니다. 같은 사람이 포털에 로그인하거나 가입하려다 서버 자격 증명까지 사용해 본 흐름일 수 있습니다.
- **`AccessDenied`라는 결과의 의미**: 그 키로 시도한 작업이 막혔다는 뜻입니다. 그러나 성공한 호출이 따로 있었는지는 아직 모릅니다. 아래 추가 로그로 확인해야 합니다.

## 2. 확인이 필요한 것: root 계정 사용

```
04:42:48  GetCallerIdentity  root  198.18.0.3
04:42:50  GetParameter       root  198.18.0.3
04:42:55  DescribeInstances  root  198.18.0.3
04:42:59  GetCallerIdentity  root  198.18.14.1   ← 4초 뒤 다른 IP
04:48:40~51  같은 순서 반복 (198.18.18.1 → 198.18.18.2)
```

- 순서가 똑같이 반복되고 간격이 몇 초 단위여서 **사람이 아니라 스크립트**로 보입니다.
- 공방전 환경에서는 **운영 측 점검 봇(checker)**이 root로 이렇게 동작하기도 합니다. 운영진에게 "root로 자동 점검을 돌리느냐"고 먼저 물어보세요.
- 운영 측이 아니라면 심각합니다. 이 경우 root 자격 증명(특히 access key)이 유출된 것입니다.
- root가 `GetParameter`로 **어떤 파라미터를 읽었는지**도 꼭 확인해야 합니다.

## 3. 눈여겨볼 다른 것들 (판단 보류)

| 항목 | 이유 |
|---|---|
| IP마다 1건씩, 약 55개 IP (198.18.12.1~68.1) | 여러 IP로 나눠 시도하는 패턴일 수 있습니다. 무엇을 호출했는지 봐야 합니다. |
| eks-node 역할이 198.18.9.1에서 호출됨 | 이 IP는 blue-team-1도 씁니다. 공용 NAT일 수도 있고, 노드 자격 증명이 다른 곳에서 쓰인 것일 수도 있습니다. |
| ec2-ssmrole 3,207건 | 대부분 SSM 에이전트의 정상 폴링일 가능성이 큽니다. 다만 `AccessDenied` 4건이 무엇이었는지는 봐야 합니다. |
| pagesnap renderer 역할 20건 | URL을 받아 렌더링하는 서비스는 SSRF의 단골 표적입니다. 호출 위치를 확인해야 합니다. |
| `user/AWSAccount` 1건 | 다른 AWS 계정에서 접근한 기록입니다. 어느 계정인지 확인해야 합니다. |
| blue-team-1이 IP 8개 이상에서 사용됨 | 여러 명이 한 계정을 공유하는 것으로 보입니다. 그래서 공격자가 섞여 있어도 구별하기 어렵습니다. 팀원들의 실제 IP를 확인해 두세요. |

`ThrottlingException`, `ValidationException`, EKS의 `Client.DryRunOperation` 같은 오류는 일반적인 잡음이라 신경 쓰지 않아도 됩니다.

## 4. 이 파일에 없던 것 (좋은 소식이지만 한계가 있음)

서울 리전, 이 시간대 기준으로는 아래 이벤트가 **없었습니다.**

- 로그 끄기 (`StopLogging`, `DeleteTrail`)
- IAM 사용자나 키 생성 (`CreateUser`, `CreateAccessKey`)
- 인스턴스 생성 (`RunInstances`)
- 버킷 공개 전환
- SES 악용

다만 이것만으로 "없었다"고 결론 내리면 안 됩니다. 이유는 세 가지입니다.

- **제 처음 목록이 부족했습니다.** `SendCommand`/`StartSession`(SSM으로 서버 명령 실행), `GetParameters`(복수형), `AssumeRole`, `CreateRole`/`PutRolePolicy`, 보안그룹 변경, Cognito 가입·관리 이벤트가 빠져 있었습니다. 아래 명령에 추가했습니다.
- **IAM과 root 로그인 같은 글로벌 이벤트는** 보통 us-east-1에 기록됩니다. 이 파일에 빠져 있을 수 있습니다.
- **다른 리전**은 아직 전혀 확인하지 못했습니다.

---

## 5. 지금 해야 할 일 (콘솔 접근 권한이 있는 팀원이나 운영진에게 요청)

1. **운영진에게 알리기**: 공방전 환경이라면 운영진이 사실상 AWS Support 역할을 합니다. root 사용 여부도 이때 함께 물어보세요.
2. **포털 역할의 기존 세션 무효화**: IAM → Roles → `patchsignal-ewc2enb8-portal-role` → "Revoke active sessions". 이미 발급된 임시 키가 즉시 무효가 됩니다. 정상 서버는 새 키를 다시 받아 오므로 서비스 영향은 작습니다.
3. **포털 인스턴스를 IMDSv2 필수로 변경**: `i-05816900800807b77`에 적용합니다. 다만 근본 원인(앱의 SSRF나 원격 명령 실행 취약점)을 고치지 않으면 다시 털릴 수 있습니다.
4. **root가 운영 측이 아닌 경우**: root 비밀번호를 바꾸고, root access key를 비활성화하고, MFA를 확인합니다.
5. **Cognito 사용자 풀 확인**: 13:30 이후 새로 가입하거나 확인된 사용자, 그룹이 바뀐 사용자가 있는지 봅니다.

---

## 6. 다음에 뽑아 주실 로그

아래 스크립트를 실행해서 `next.txt`를 보내 주세요. Cognito 요청에 들어 있는 사용자 이름이나 이메일은 원하시면 가리셔도 됩니다. 비밀번호는 CloudTrail이 자동으로 가려 둡니다.

```bash
F=cloudtrail.json
S='s#arn:aws:[a-z]*::111122223333:##'
{
echo "== A. 198.18.7.1/7.2 및 포털 키 ASIA71C2…95CF 전체 원본 =="
jq -r '.Records[] | select(.sourceIPAddress=="198.18.7.1" or .sourceIPAddress=="198.18.7.2" or .userIdentity.accessKeyId=="ASIA71C2…95CF")
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn // .userIdentity.type),(.userIdentity.accessKeyId // "-"),(.errorCode // "OK"),((.requestParameters // {})|tojson|.[0:200])]|@tsv' $F | sed "$S" | sort

echo; echo "== B. 포털 역할: IP / 이벤트 / 결과 =="
jq -r '.Records[] | select((.userIdentity.arn // "")|test("patchsignal-ewc2enb8-portal-role")) | [.sourceIPAddress,.eventName,(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn

echo; echo "== C. root 전체: 이벤트 / IP / 키 / userAgent / 결과 =="
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.eventName,.sourceIPAddress,(.userIdentity.accessKeyId // "-"),((.userAgent // "-")|.[0:60]),(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn
echo "-- root GetParameter 대상"
jq -r '.Records[] | select(.userIdentity.type=="Root" and (.eventName|test("GetParameter"))) | [.eventTime,.sourceIPAddress,((.requestParameters // {})|tojson)]|@tsv' $F

echo; echo "== D. Unknown 주체: IP / 서비스 / 이벤트 / 결과 =="
jq -r '.Records[] | select(.userIdentity.type=="Unknown") | [.sourceIPAddress,.eventSource,.eventName,(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn

echo; echo "== E. 1건짜리 IP들의 원본 =="
jq -r '.Records[].sourceIPAddress' $F | sort | uniq -c | awk '$1==1{print $2}' > single_ips.txt
jq -r --rawfile ips single_ips.txt '($ips|split("\n")) as $l | .Records[] | select(.sourceIPAddress | IN($l[]))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn // .userIdentity.type),(.errorCode // "OK")]|@tsv' $F | sed "$S" | sort

echo; echo "== F. 리전 분포 =="
jq -r '.Records[].awsRegion' $F | sort | uniq -c

echo; echo "== G. 추가 위험 이벤트 =="
jq -r '.Records[] | select(.eventName|test("^(SendCommand|StartSession|ResumeSession|GetParameters|GetParametersByPath|AssumeRole|AssumeRoleWithWebIdentity|CreateRole|PutRolePolicy|AttachRolePolicy|UpdateFunctionCode|UpdateFunctionConfiguration|AuthorizeSecurityGroupIngress|ModifyInstanceAttribute|ModifyInstanceMetadataOptions|CreateKeyPair|ImportKeyPair|SignUp|ConfirmSignUp|AdminCreateUser|AdminAddUserToGroup|AdminSetUserPassword|Decrypt|GetObject|PutObject)$"))
  | [.eventName,(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,(.errorCode // "OK")]|@tsv' $F | sed "$S" | sort | uniq -c | sort -rn

echo; echo "== H. 모든 AccessDenied 원본 =="
jq -r '.Records[] | select(.errorCode|tostring|test("AccessDenied|UnauthorizedOperation")) | [.eventTime,(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,.eventSource,.eventName]|@tsv' $F | sed "$S" | sort

echo; echo "== I. 기타 확인 대상: IP / 이벤트 =="
jq -r '.Records[] | select((.userIdentity.arn // .userIdentity.type)|test("ec2-ssmrole|eks-node|pagesnap|serviceaccount|AWSAccount"))
  | [(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,.eventName,(.errorCode // "OK"),(.userIdentity.accountId // "-")]|@tsv' $F | sed "$S" | sort | uniq -c | sort -rn | head -60
} > next.txt 2>&1
wc -l next.txt
```

`next.txt`가 너무 길면 **A, C, D, H**부터 보내 주세요. 이 네 개로 "무엇이 털렸고 공격자가 무엇에 성공했는지"를 판단할 수 있습니다.

그리고 콘솔 접근이 되는 분이 있다면, 같은 시간대의 **us-east-1 로그**(IAM, root 로그인)와 **GuardDuty 탐지 목록**도 함께 받아 주시면 훨씬 정확해집니다.

## 사용자

A부터 I까지 모두 뽑아서 아래에 붙였습니다. 결과가 길어서 next.txt 한 파일로 묶지 않고 네 번(A+B, C+D, E+F+G, H+I)에 나눠 실행했습니다. 그 외에는 보내 주신 jq 명령을 그대로 썼습니다.

**결과를 볼 때 참고할 점**
- 이 파일에는 기록마다 eventTime, eventSource, eventName, sourceIPAddress, userIdentity, errorCode, requestParameters 칸만 있습니다. awsRegion과 userAgent 칸은 없습니다.
  - 그래서 F(리전 분포)는 전부 `null`로 나오고, C의 userAgent 칸은 전부 `-`입니다.
- I의 마지막 칸(accountId)도 전부 `-`로 나옵니다. userIdentity에 accountId 값이 없기 때문인 것 같습니다.
- A의 requestParameters는 대부분 `{}`로 비어 있습니다. Cognito 요청에 사용자 이름이나 이메일이 따로 들어 있지 않아서 가린 것은 없습니다.
- E 단계에서는 현재 디렉터리에 파일을 쓸 수 없어서 single_ips.txt를 /tmp에 만들었습니다.

**확인 못 하는 것**
- us-east-1 로그, 다른 리전 로그, GuardDuty 탐지 목록은 확인 못 함(그 로그는 없어요). 지금은 콘솔과 CLI에도 접속할 수 없습니다.
- 운영 측이 root로 자동 점검을 돌리는지는 저는 모릅니다.
- Cognito 사용자 풀 상태도 지금은 볼 수 없습니다.

실행한 명령:
```
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'
echo "== A. 198.18.7.1/7.2 및 포털 키 ASIA71C2…95CF 전체 원본 =="
jq -r '.Records[] | select(.sourceIPAddress=="198.18.7.1" or .sourceIPAddress=="198.18.7.2" or .userIdentity.accessKeyId=="ASIA71C2…95CF")
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn // .userIdentity.type),(.userIdentity.accessKeyId // "-"),(.errorCode // "OK"),((.requestParameters // {})|tojson|.[0:200])]|@tsv' $F | sed "$S" | sort
echo; echo "== B. 포털 역할: IP / 이벤트 / 결과 =="
jq -r '.Records[] | select((.userIdentity.arn // "")|test("patchsignal-ewc2enb8-portal-role")) | [.sourceIPAddress,.eventName,(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn
```
결과:
```
== A. 198.18.7.1/7.2 및 포털 키 ASIA71C2…95CF 전체 원본 ==
2026-10-11T04:37:35Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:37:54Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:38:05Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:39:18Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:39:34Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:39:48Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	OK	{}
2026-10-11T04:40:14Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:40:26Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	OK	{}
2026-10-11T04:41:32Z	198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	OK	{}
2026-10-11T04:41:54Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:42:01Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:42:04Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:42:04Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T04:42:14Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T04:42:16Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T04:43:47Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:43:47Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T04:43:49Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T04:43:49Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T04:44:03Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:44:12Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:44:22Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:48:18Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException	{}
2026-10-11T04:48:29Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	OK	{}
2026-10-11T04:48:58Z	198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	OK	{}
2026-10-11T04:49:03Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:49:04Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T04:49:06Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:49:07Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T04:50:27Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T05:09:58Z	198.18.7.2	s3.amazonaws.com	GetBucketVersioning	user/AWSAccount	-	AccessDenied	{"bucketName":"pagesnap-final-s1-results-0e666173"}
2026-10-11T05:28:39Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	OK	{}
2026-10-11T05:29:20Z	198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	OK	{}
2026-10-11T05:29:30Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T05:29:30Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T05:45:47Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T05:45:47Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T05:45:49Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T05:45:49Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException	{}
2026-10-11T05:45:57Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	OK	{}
2026-10-11T05:45:58Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	OK	{}
2026-10-11T06:36:22Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{}
2026-10-11T06:39:20Z	198.18.50.1	ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	AccessDenied	{}
2026-10-11T06:40:45Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{"name":"case-redteam-validation-002"}
2026-10-11T06:41:53Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{"name":"case-redteam-validation-003"}
2026-10-11T06:52:08Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{}
2026-10-11T07:02:09Z	198.18.7.1	ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	AccessDenied	{}
2026-10-11T07:02:17Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{}
2026-10-11T07:03:46Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{"name":"test-run-1791702223"}
2026-10-11T07:05:02Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{"name":"test-run-1791702300"}
2026-10-11T07:05:47Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{"name":"test-run-1791702344"}
2026-10-11T07:08:11Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	OK	{}
2026-10-11T07:11:37Z	198.18.7.1	ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	AccessDenied	{}
2026-10-11T07:12:16Z	198.18.7.1	ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ASIA71C2…95CF	AccessDenied	{}

== B. 포털 역할: IP / 이벤트 / 결과 ==
     76 198.18.10.1	StartExecution	OK
     41 198.18.10.1	UpdateInstanceInformation	OK
     18 10.81.0.102	GetFunction20150331v2	OK
     10 198.18.10.1	DescribeExecution	OK
      9 198.18.10.1	ListInstanceAssociations	OK
      6 198.18.7.1	StartExecution	OK
      3 198.18.50.1	StartExecution	OK
      2 198.18.7.1	SendCommand	AccessDenied
      2 198.18.10.1	CreateDataChannel	OK
      1 198.18.7.1	StartSession	AccessDenied
      1 198.18.50.1	StartSession	AccessDenied
      1 198.18.10.1	PutConfigurePackageResult	OK
      1 198.18.10.1	GetCallerIdentity	OK
```

실행한 명령:
```
F=cloudtrail.json
echo "== C. root 전체: 이벤트 / IP / 키 / userAgent / 결과 =="
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.eventName,.sourceIPAddress,(.userIdentity.accessKeyId // "-"),((.userAgent // "-")|.[0:60]),(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn
echo "-- root GetParameter 대상"
jq -r '.Records[] | select(.userIdentity.type=="Root" and (.eventName|test("GetParameter"))) | [.eventTime,.sourceIPAddress,((.requestParameters // {})|tojson)]|@tsv' $F
echo; echo "== D. Unknown 주체: IP / 서비스 / 이벤트 / 결과 =="
jq -r '.Records[] | select(.userIdentity.type=="Unknown") | [.sourceIPAddress,.eventSource,.eventName,(.errorCode // "OK")]|@tsv' $F | sort | uniq -c | sort -rn
```
결과:
```
== C. root 전체: 이벤트 / IP / 키 / userAgent / 결과 ==
      6 DescribeSecurityGroupRules	198.18.18.1	ASIAFA49…29C2	-	OK
      5 DescribeTags	198.18.18.1	ASIAFA49…29C2	-	OK
      5 DescribeTags	198.18.0.3	ASIAFA49…29C2	-	OK
      5 DescribeSecurityGroupRules	198.18.0.3	ASIAFA49…29C2	-	OK
      4 GetApi	198.18.18.1	ASIAFA49…29C2	-	OK
      4 GetApi	198.18.0.3	ASIAFA49…29C2	-	OK
      4 DescribeInstanceAttribute	198.18.18.1	ASIAFA49…29C2	-	OK
      4 DescribeInstanceAttribute	198.18.0.3	ASIAFA49…29C2	-	OK
      3 ListTagsForResource	198.18.18.1	ASIAFA49…29C2	-	OK
      3 ListTagsForResource	198.18.0.3	ASIAFA49…29C2	-	OK
      3 DescribeSecurityGroups	198.18.18.1	ASIAFA49…29C2	-	OK
      3 DescribeSecurityGroups	198.18.0.3	ASIAFA49…29C2	-	OK
      3 DescribeNetworkInterfaces	198.18.18.1	ASIAFA49…29C2	-	OK
      3 DescribeNetworkInterfaces	198.18.0.3	ASIAFA49…29C2	-	OK
      2 ListVersionsByFunction20150331	198.18.18.1	ASIAFA49…29C2	-	OK
      2 ListVersionsByFunction20150331	198.18.0.3	ASIAFA49…29C2	-	OK
      2 GetStage	198.18.18.1	ASIAFA49…29C2	-	OK
      2 GetStage	198.18.0.3	ASIAFA49…29C2	-	OK
      2 GetFunctionCodeSigningConfig	198.18.18.1	ASIAFA49…29C2	-	OK
      2 GetFunctionCodeSigningConfig	198.18.0.3	ASIAFA49…29C2	-	OK
      2 GetFunction20150331v2	198.18.18.1	ASIAFA49…29C2	-	OK
      2 GetFunction20150331v2	198.18.0.3	ASIAFA49…29C2	-	OK
      2 GetCallerIdentity	198.18.18.1	ASIAFA49…29C2	-	OK
      2 GetCallerIdentity	198.18.0.3	ASIAFA49…29C2	-	OK
      2 DescribeTable	198.18.18.1	ASIAFA49…29C2	-	OK
      2 DescribeTable	198.18.0.3	ASIAFA49…29C2	-	OK
      2 DescribeLogGroups	198.18.18.1	ASIAFA49…29C2	-	OK
      2 DescribeLogGroups	198.18.0.3	ASIAFA49…29C2	-	OK
      2 DescribeAddresses	198.18.18.1	ASIAFA49…29C2	-	OK
      2 DescribeAddresses	198.18.0.3	ASIAFA49…29C2	-	OK
      2 Decrypt	lambda.amazonaws.com	ASIA3982…9AC2	-	OK
      1 UpdateStage	198.18.18.1	ASIAFA49…29C2	-	OK
      1 UpdateStage	198.18.0.3	ASIAFA49…29C2	-	OK
      1 ListTagsOfResource	198.18.18.1	ASIAFA49…29C2	-	OK
      1 ListTagsOfResource	198.18.0.3	ASIAFA49…29C2	-	OK
      1 ListStateMachineVersions	198.18.18.1	ASIAFA49…29C2	-	OK
      1 ListStateMachineVersions	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetRoute	198.18.18.1	ASIAFA49…29C2	-	OK
      1 GetRoute	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetPolicy20150331v2	198.18.18.1	ASIAFA49…29C2	-	OK
      1 GetPolicy20150331v2	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetParameter	198.18.18.1	ASIAFA49…29C2	-	OK
      1 GetParameter	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetManagedPrefixListEntries	198.18.18.1	ASIAFA49…29C2	-	OK
      1 GetManagedPrefixListEntries	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetIntegration	198.18.18.1	ASIAFA49…29C2	-	OK
      1 GetIntegration	198.18.0.3	ASIAFA49…29C2	-	OK
      1 GetCallerIdentity	198.18.18.2	ASIAFA49…29C2	-	OK
      1 GetCallerIdentity	198.18.14.1	ASIAFA49…29C2	-	OK
      1 GetApi	198.18.15.1	ASIAFA49…29C2	-	OK
      1 DescribeVpcs	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeVpcs	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeVpcEndpoints	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeVpcEndpoints	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeVolumes	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeVolumes	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeTimeToLive	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeTimeToLive	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeTargetHealth	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeTargetHealth	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeTargetGroups	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeTargetGroups	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeTargetGroupAttributes	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeTargetGroupAttributes	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeStateMachine	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeStateMachine	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeSecurityGroupRules	198.18.14.1	ASIAFA49…29C2	-	OK
      1 DescribeRules	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeRules	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribePrefixLists	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribePrefixLists	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeManagedPrefixLists	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeManagedPrefixLists	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeLoadBalancers	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeLoadBalancers	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeLoadBalancerAttributes	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeLoadBalancerAttributes	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeListeners	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeListeners	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeListenerAttributes	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeListenerAttributes	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeInstances	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeInstances	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeInstanceTypes	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeInstanceTypes	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeInstanceCreditSpecifications	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeInstanceCreditSpecifications	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeContinuousBackups	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeContinuousBackups	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeCapacityReservation	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeCapacityReservation	198.18.0.3	ASIAFA49…29C2	-	OK
      1 DescribeAddressesAttribute	198.18.18.1	ASIAFA49…29C2	-	OK
      1 DescribeAddressesAttribute	198.18.0.3	ASIAFA49…29C2	-	OK
      1 Decrypt	lambda.amazonaws.com	ASIA5117…8689	-	OK
      1 Decrypt	lambda.amazonaws.com	ASIA0C40…D406	-	OK
-- root GetParameter 대상
2026-10-11T04:42:50Z	198.18.0.3	{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}
2026-10-11T04:48:42Z	198.18.18.1	{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}

== D. Unknown 주체: IP / 서비스 / 이벤트 / 결과 ==
     18 198.18.6.1	ssm.amazonaws.com	OpenDataChannel	OK
     17 198.18.23.1	ssm.amazonaws.com	OpenDataChannel	OK
      9 198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	OK
      6 198.18.7.1	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      6 198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	OK
      5 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      4 198.18.7.2	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      4 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      4 198.18.3.1	ssm.amazonaws.com	OpenDataChannel	OK
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      3 198.18.5.1	ssm.amazonaws.com	OpenDataChannel	OK
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	OK
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	OK
      2 198.18.7.2	cognito-idp.amazonaws.com	SignUp	OK
      2 198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	OK
      2 198.18.7.1	cognito-idp.amazonaws.com	SignUp	OK
      2 198.18.2.1	ssm.amazonaws.com	OpenDataChannel	OK
      2 198.18.10.1	ssm.amazonaws.com	OpenDataChannel	OK
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	OK
      1 198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	OK
```

실행한 명령:
```
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'
echo "== E. 1건짜리 IP들의 원본 =="
jq -r '.Records[].sourceIPAddress' $F | sort | uniq -c | awk '$1==1{print $2}' > /tmp/single_ips.txt
jq -r --rawfile ips /tmp/single_ips.txt '($ips|split("\n")) as $l | .Records[] | select(.sourceIPAddress | IN($l[]))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn // .userIdentity.type),(.errorCode // "OK")]|@tsv' $F | sed "$S" | sort
echo; echo "== F. 리전 분포 =="
jq -r '.Records[].awsRegion' $F | sort | uniq -c
echo; echo "== G. 추가 위험 이벤트 =="
jq -r '.Records[] | select(.eventName|test("^(SendCommand|StartSession|ResumeSession|GetParameters|GetParametersByPath|AssumeRole|AssumeRoleWithWebIdentity|CreateRole|PutRolePolicy|AttachRolePolicy|UpdateFunctionCode|UpdateFunctionConfiguration|AuthorizeSecurityGroupIngress|ModifyInstanceAttribute|ModifyInstanceMetadataOptions|CreateKeyPair|ImportKeyPair|SignUp|ConfirmSignUp|AdminCreateUser|AdminAddUserToGroup|AdminSetUserPassword|Decrypt|GetObject|PutObject)$"))
  | [.eventName,(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,(.errorCode // "OK")]|@tsv' $F | sed "$S" | sort | uniq -c | sort -rn
```
결과:
```
== E. 1건짜리 IP들의 원본 ==
2026-10-11T04:30:02Z	198.18.1.1	sts.amazonaws.com	GetCallerIdentity	user/blue-team-1	OK
2026-10-11T04:42:19Z	198.18.12.1	kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T04:42:24Z	198.18.13.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T04:45:23Z	198.18.15.1	apigateway.amazonaws.com	GetApi	root	OK
2026-10-11T04:46:53Z	198.18.17.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	OK
2026-10-11T04:48:51Z	198.18.18.2	sts.amazonaws.com	GetCallerIdentity	root	OK
2026-10-11T05:00:08Z	198.18.21.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T05:00:10Z	198.18.22.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:14:33Z	198.18.25.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T05:14:38Z	198.18.27.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:17:55Z	198.18.28.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	OK
2026-10-11T05:24:09Z	198.18.29.1	kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:24:16Z	198.18.30.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T05:24:18Z	198.18.31.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:30:54Z	ssm.amazonaws.com	ec2.amazonaws.com	DescribeInstances	user/blue-team-2	OK
2026-10-11T05:33:58Z	198.18.35.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	OK
2026-10-11T05:44:58Z	198.18.37.1	sts.amazonaws.com	GetCallerIdentity	user/blue-team-2	OK
2026-10-11T05:45:56Z	ssm-quicksetup.amazonaws.com	cloudformation.amazonaws.com	DescribeStacks	user/blue-team-2	OK
2026-10-11T05:49:49Z	198.18.38.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	OK
2026-10-11T05:52:48Z	198.18.39.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	OK
2026-10-11T05:54:03Z	198.18.40.1	kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:54:07Z	198.18.41.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T05:54:07Z	198.18.42.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T05:56:15Z	198.18.43.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T05:56:15Z	198.18.44.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:08:19Z	198.18.45.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T06:10:28Z	198.18.46.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T06:27:08Z	198.18.47.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T06:34:25Z	198.18.48.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:34:26Z	198.18.49.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T06:39:49Z	198.18.51.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:40:52Z	198.18.52.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:48:44Z	198.18.53.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T06:49:30Z	198.18.54.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T06:49:32Z	198.18.55.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:52:11Z	198.18.56.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T06:52:12Z	198.18.57.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T06:58:48Z	198.18.58.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T06:59:48Z	198.18.59.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T06:59:56Z	198.18.29.2	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T07:04:34Z	198.18.60.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T07:07:34Z	198.18.61.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T07:09:30Z	198.18.62.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T07:13:31Z	198.18.63.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T07:15:14Z	198.18.64.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK
2026-10-11T07:18:39Z	198.18.65.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK
2026-10-11T07:18:43Z	198.18.66.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T07:23:48Z	198.18.67.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK
2026-10-11T07:23:49Z	198.18.68.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK

== F. 리전 분포 ==
  10223 null

== G. 추가 위험 이벤트 ==
    244 SendCommand	user/blue-team-1	198.18.2.1	OK
     60 AssumeRole	AWSService	eks-nodegroup.amazonaws.com	OK
     56 AssumeRole	AWSService	config.amazonaws.com	OK
     55 AssumeRole	AWSService	eks.amazonaws.com	OK
     33 Decrypt	user/blue-team-1	lambda.amazonaws.com	OK
     27 AssumeRole	AWSService	lambda.amazonaws.com	OK
     26 AssumeRole	AWSService	states.amazonaws.com	OK
     18 AssumeRole	AWSService	resource-explorer-2.amazonaws.com	OK
     13 ResumeSession	user/blue-team-2	198.18.23.1	OK
     10 AssumeRole	AWSService	ec2.amazonaws.com	OK
      8 SendCommand	user/blue-team-1	198.18.3.1	OK
      7 AssumeRole	AWSService	AWS Internal	OK
      6 SignUp	Unknown	198.18.7.1	InvalidPasswordException
      5 SendCommand	user/blue-team-1	198.18.5.1	OK
      5 SendCommand	user/blue-team-1	198.18.23.1	OK
      5 AssumeRole	AWSService	autoscaling.amazonaws.com	OK
      4 StartSession	user/blue-team-1	198.18.3.1	OK
      4 SignUp	Unknown	198.18.7.2	InvalidPasswordException
      4 ModifyInstanceAttribute	user/blue-team-1	198.18.2.1	OK
      4 Decrypt	user/blue-team-2	lambda.amazonaws.com	OK
      4 Decrypt	root	lambda.amazonaws.com	OK
      4 Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1	OK
      4 Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1	OK
      4 Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1	OK
      4 Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1	OK
      4 AuthorizeSecurityGroupIngress	user/blue-team-1	198.18.2.1	OK
      4 AssumeRole	AWSService	securityhub.amazonaws.com	OK
      3 StartSession	user/blue-team-1	198.18.5.1	OK
      3 StartSession	user/blue-team-1	198.18.23.1	OK
      2 StartSession	user/blue-team-1	198.18.2.1	OK
      2 StartSession	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
      2 SignUp	Unknown	2001:db8:0:b::2	OK
      2 SignUp	Unknown	198.18.7.2	OK
      2 SignUp	Unknown	198.18.7.1	OK
      2 SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      2 Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1	OK
      2 ConfirmSignUp	Unknown	198.18.7.2	OK
      2 AssumeRoleWithWebIdentity	user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1	OK
      2 AssumeRoleWithWebIdentity	user/system:serviceaccount:device-support:portal-api	198.18.8.1	OK
      1 StartSession	user/blue-team-2	198.18.23.1	OK
      1 StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      1 StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied
      1 ResumeSession	user/blue-team-1	198.18.3.1	OK
      1 Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1	OK
      1 Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1	OK
      1 Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1	OK
      1 Decrypt	assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1	OK
      1 Decrypt	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1	OK
      1 ConfirmSignUp	Unknown	2001:db8:0:b::2	OK
      1 ConfirmSignUp	Unknown	198.18.7.1	OK
      1 AuthorizeSecurityGroupIngress	user/blue-team-1	198.18.2.1	Client.DryRunOperation
      1 AuthorizeSecurityGroupIngress	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	OK
```

실행한 명령:
```
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'
echo "== H. 모든 AccessDenied 원본 =="
jq -r '.Records[] | select(.errorCode|tostring|test("AccessDenied|UnauthorizedOperation")) | [.eventTime,(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,.eventSource,.eventName]|@tsv' $F | sed "$S" | sort
echo; echo "== I. 기타 확인 대상: IP / 이벤트 =="
jq -r '.Records[] | select((.userIdentity.arn // .userIdentity.type)|test("ec2-ssmrole|eks-node|pagesnap|serviceaccount|AWSAccount"))
  | [(.userIdentity.arn // .userIdentity.type),.sourceIPAddress,.eventName,(.errorCode // "OK"),(.userIdentity.accountId // "-")]|@tsv' $F | sed "$S" | sort | uniq -c | sort -rn | head -60
```
결과:
```
== H. 모든 AccessDenied 원본 ==
2026-10-11T04:33:29Z	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	StartSession
2026-10-11T04:33:33Z	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	StartSession
2026-10-11T04:44:35Z	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	logs.amazonaws.com	DescribeLogStreams
2026-10-11T05:00:18Z	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	logs.amazonaws.com	FilterLogEvents
2026-10-11T05:09:58Z	user/AWSAccount	198.18.7.2	s3.amazonaws.com	GetBucketVersioning
2026-10-11T06:39:20Z	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	ssm.amazonaws.com	StartSession
2026-10-11T07:02:09Z	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	ssm.amazonaws.com	StartSession
2026-10-11T07:11:37Z	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	ssm.amazonaws.com	SendCommand
2026-10-11T07:12:16Z	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	ssm.amazonaws.com	SendCommand

== I. 기타 확인 대상: IP / 이벤트 ==
   2255 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	FilterLogEvents	OK	-
    725 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	GetLogEvents	OK	-
    145 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	DescribeLogStreams	OK	-
     41 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	UpdateInstanceInformation	OK	-
     18 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	CreateDataChannel	OK	-
     14 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DeleteNetworkInterface	Client.InvalidParameterValue	-
     13 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.9.1	GetCallerIdentity	OK	-
     10 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ListInstanceAssociations	OK	-
      8 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	GetCallerIdentity	OK	-
      6 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ModifyNetworkInterfaceAttribute	OK	-
      6 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DetachNetworkInterface	OK	-
      6 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	CreateNetworkInterface	OK	-
      6 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	AttachNetworkInterface	OK	-
      5 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DeleteNetworkInterface	OK	-
      4 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1	Decrypt	OK	-
      4 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1	Decrypt	OK	-
      4 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1	Decrypt	OK	-
      4 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1	Decrypt	OK	-
      2 user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1	AssumeRoleWithWebIdentity	OK	-
      2 user/system:serviceaccount:device-support:portal-api	198.18.8.1	AssumeRoleWithWebIdentity	OK	-
      2 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DescribeSubnets	OK	-
      2 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DescribeNetworkInterfaces	OK	-
      2 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	-
      1 user/AWSAccount	198.18.7.2	GetBucketVersioning	AccessDenied	-
      1 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.38.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.35.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.28.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.17.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.39.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1	Decrypt	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.64.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.63.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.61.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.60.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.58.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.53.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.47.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.45.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.13.1	CreateLogStream	OK	-
      1 assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1	Decrypt	OK	-
      1 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DescribeInstances	OK	-
      1 assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DeleteNetworkInterface	Client.InvalidNetworkInterface.InUse	-
      1 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	PutConfigurePackageResult	OK	-
      1 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	FilterLogEvents	AccessDenied	-
      1 assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	DescribeLogStreams	AccessDenied	-
```

## 채팅 AI

# 분석 결과: 공격 경로가 거의 드러났습니다

## 한 줄 요약

공격자(198.18.7.1, 198.18.7.2, 198.18.50.1)는 다음 순서로 움직였습니다.

1. **PatchSignal 포털에 직접 회원가입해서 로그인했습니다.**
2. 약 1시간 반 뒤부터 **포털 서버(`i-05816900800807b77`)의 AWS 임시 키를 외부에서 사용했습니다.**
3. 그 키로 **Step Functions 실행을 9번 성공시켰습니다.**
4. 서버에 원격 명령을 보내려는 시도(SSM `StartSession`/`SendCommand`)는 **4번 모두 막혔습니다.**

로그를 끄거나, 사용자·키를 만들거나, 인스턴스를 생성한 흔적은 이 파일에 없습니다.

---

## 1. 공격 타임라인 (UTC, 한국 시간은 +9)

| 시각 | IP | 행동 | 결과 |
|---|---|---|---|
| 04:37~04:40 | 7.1 | Cognito `SignUp` 8회 (비밀번호 정책 실패 6회) | 계정 2개 생성 |
| 04:41~04:42 | 7.1 | `ConfirmSignUp`, 로그인(`InitiateAuth`/`RespondToAuthChallenge`) | 성공 |
| 04:43~04:50 | 7.2 | 로그인 4회 연속 실패 후 다시 가입 → 확인 → 로그인 | 성공 |
| **05:09** | 7.2 | **다른 AWS 계정**(`user/AWSAccount`)에서 `pagesnap-final-s1-results-0e666173` 버킷 조회 | AccessDenied |
| 05:28~05:45 | 7.1/7.2 | 추가 가입, 로그인 | 성공 |
| **06:36** | **7.1** | **포털 역할 키 `ASIA71C2…95CF`로 `StartExecution`** | **성공** |
| 06:39 | 50.1 | 같은 키로 `ssm:StartSession` | AccessDenied |
| 06:40~07:08 | 7.1, 50.1 | `StartExecution` 8회 추가 (`case-redteam-validation-002/003`, `test-run-*` 등) | **성공** |
| 07:02~07:12 | 7.1 | `StartSession` 1회, `SendCommand` 2회 | AccessDenied |

**판단 근거**
- 포털 역할은 원래 **198.18.10.1**(포털 서버 자신, SSM 에이전트 호출도 여기서 나옴)과 **10.81.0.102**(내부 주소)에서만 쓰입니다. 같은 임시 키가 7.1과 50.1에서 쓰였다는 것은 **서버의 자격 증명이 밖으로 빠져나갔다는 뜻**입니다.
- 공격자가 서버에 있는 키를 꺼내려면 **포털 앱에 SSRF나 원격 코드 실행 취약점**이 있어야 합니다. 가입·로그인을 먼저 한 것을 보면, **로그인한 사용자만 쓸 수 있는 기능**에 취약점이 있을 가능성이 높습니다.
- 05:09의 `user/AWSAccount`는 공격자가 **자기 AWS 계정**으로 우리 버킷을 들여다본 기록입니다. 7.2가 공격자 IP라는 것을 다시 확인해 줍니다.

### 아직 모르는 것 (가장 중요)
1. **9번 성공한 Step Functions 실행이 실제로 무엇을 했는가.** 상태 머신이 Lambda 등을 호출하면, 공격자가 포털 역할보다 넓은 권한으로 간접적으로 작업했을 수 있습니다.
2. **공격자가 포털 서버 안에서 명령을 실행할 수 있는가.** 그렇다면 서버 IP인 198.18.10.1에서 나간 호출도 공격자일 수 있습니다. 로그만 봐서는 정상 호출과 구별되지 않습니다. 10.1에서 나간 `StartExecution` 76건 중에 섞여 있을 수 있습니다.

---

## 2. 지난번 의심했지만 정상으로 보이는 것 (정정)

지난 답변에서 제가 과하게 의심한 부분을 바로잡습니다.

| 항목 | 지난번 판단 | 지금 판단 | 이유 |
|---|---|---|---|
| **root 153건** | 심각할 수 있음 | **배포 도구(Terraform 등)로 추정, 확인은 필요** | 보안그룹·LB·Lambda·DynamoDB(`DescribeContinuousBackups`, `DescribeTimeToLive`)를 빠짐없이 조회하고, 04:42와 04:48에 똑같은 순서로 두 번 반복합니다. 이는 인프라 코드를 plan/apply 할 때 나오는 전형적인 모습입니다. 읽은 파라미터도 비밀값이 아니라 **AWS 공개 AMI 정보**입니다. |
| 1건짜리 IP 약 55개 | 분산 공격 가능성 | **정상** | 전부 Lambda 함수의 `CreateLogStream`/`Decrypt`입니다. Lambda는 실행할 때마다 IP가 바뀝니다. |
| eks-node 역할이 9.1에서 호출됨 | 의심 | **정상으로 추정** | blue-team-1의 `GetCallerIdentity`도 9.1에서 나옵니다. kubectl이나 노드의 EKS 인증 토큰을 EKS가 검증할 때 생기는 기록으로 보입니다. |
| 포털 역할의 Cognito 인증 실패 | 비밀번호 대입 공격 | **공격자가 계정을 직접 만든 것** | 위 타임라인 참고 |

**root에 대해 꼭 확인할 것:** 이 계정에서 누가 root로 인프라 배포를 하는지 운영진에게 물어보세요. 그리고 `UpdateStage`(API Gateway 스테이지 변경) 2건의 내용을 확인해야 합니다. 운영 측이 한 것이 아니라면 판단이 완전히 달라집니다.

---

## 3. 팀 안에서 확인할 것

| 항목 | 질문 |
|---|---|
| `ec2-ssmrole` / `i-026754fe07a870049` (198.18.6.1) | CloudWatch Logs를 3천 번 넘게 읽은 서버입니다. **우리 팀의 모니터링 서버가 맞나요?** 맞다면 정상입니다. 아니라면 누군가 로그를 훔쳐보는 것이고, 로그에 비밀값이 찍혀 있으면 위험합니다. |
| blue-team-1의 `AuthorizeSecurityGroupIngress` 4건, `ModifyInstanceAttribute` 4건 (198.18.2.1) | 팀원이 대응 중에 한 작업이 맞는지, **보안그룹을 0.0.0.0/0으로 열어 둔 것은 없는지** 확인하세요. |
| `2001:db8:0:b::2`의 Cognito 가입·로그인 | 정상 사용자인지 다른 공격자인지 아직 모릅니다. |
| blue-team-1을 여러 명이 함께 쓰는 것 | 공격자가 이 계정을 얻으면 구별할 수 없습니다. 끝나고 나서 사람별 계정으로 나누는 것을 권합니다. |

---

## 4. 지금 해야 할 조치 (콘솔 권한이 있는 팀원이나 운영진에게 전달)

**원칙: 지우기 전에 기록부터 남기세요.** Cognito 사용자 목록과 Step Functions 실행 기록은 화면 캡처나 내보내기로 보존해 두세요.

### ① 포털 역할 세션 무효화 (최우선)
IAM → Roles → `patchsignal-ewc2enb8-portal-role` → **Revoke active sessions**

공격자가 가진 키가 아직 유효해서, 지금도 `StartExecution`을 할 수 있습니다. 정상 서버는 새 키를 자동으로 받아 오므로 서비스는 거의 영향을 받지 않습니다.

### ② 같은 역할에 "서버 밖에서는 사용 금지" 정책 추가
취약점을 고치기 전까지는 키를 다시 훔쳐 갈 수 있으므로, 훔쳐도 밖에서는 못 쓰게 막습니다. 아래 정책을 인라인 정책으로 추가하세요.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUseOutsidePortalHost",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "NotIpAddress": { "aws:SourceIp": "198.18.10.1/32" },
      "Null":         { "aws:SourceIp": "false" },
      "BoolIfExists": { "aws:ViaAWSService": "false" }
    }
  }]
}
```

- `Null` 조건은 VPC 엔드포인트를 거친 내부 호출(10.81.0.102의 `GetFunction`)을 막지 않으려고 넣은 것입니다.
- 198.18.10.1이 포털 서버의 고정 출구 IP(Elastic IP 또는 NAT)인지 먼저 확인하세요. IP가 바뀌면 서비스가 멈춥니다.

### ③ 포털 인스턴스를 IMDSv2 필수, hop limit 1로 변경
```bash
aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
  --http-tokens required --http-put-response-hop-limit 1
```

SSRF로 메타데이터를 읽는 공격은 대부분 이것으로 막힙니다. 원격 코드 실행 취약점이었다면 이것으로는 막을 수 없습니다.

### ④ Step Functions 실행 내용 확인
Step Functions 콘솔에서 06:36~07:08 UTC에 시작된 실행 9건을 찾습니다. 이름은 `case-redteam-validation-002/003`, `test-run-1791702223`, `test-run-1791702300`, `test-run-1791702344`이고, 이름 없는 실행이 4건 더 있습니다. 각 실행의 **Input, 단계별 이벤트, Output**을 확인하세요.
- 공격자가 넣은 입력값을 보면 무엇을 노렸는지 알 수 있습니다.
- 그 결과로 데이터가 바뀌었는지도 확인해야 합니다. 예를 들어 패치 피드나 결과물이 바뀌었을 수 있습니다.

### ⑤ 포털 앱의 취약점 찾기 (백엔드 개발자분이 가장 잘하실 부분)
포털 앱 로그에서 공격자가 만든 Cognito 계정의 요청을 **04:41~06:36 UTC** 사이로 찾아보세요. 특히 아래를 보시면 됩니다.
- URL이나 호스트명을 입력받아 서버가 대신 요청하는 기능: `169.254.169.254`, `localhost`, `file://`, 리다이렉트 URL이 들어간 요청
- 파일 업로드, 템플릿 렌더링, 셸 명령으로 넘어가는 입력값
- `/latest/meta-data/iam/security-credentials/` 문자열

### ⑥ Cognito 정리
- 공격자 계정을 기록한 뒤 비활성화합니다. 가입 시각 04:39:48, 04:40:26, 04:48:29, 05:28:39 UTC를 기준으로 찾으세요.
- 셀프 가입이 서비스에 꼭 필요한 기능인지 검토합니다.

### ⑦ 이미 잘 막힌 것 (유지)
포털 역할에 SSM 권한이 없어서 공격자가 서버 셸을 얻지 못했습니다. pagesnap 결과 버킷도 다른 계정의 접근을 막았습니다. 이 설정들은 바꾸지 마세요.

---

## 5. 다음에 뽑아 주실 로그

```bash
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'

echo "== J. 공격자 StartExecution 원본 1건 (전체 필드) =="
jq '[.Records[] | select(.userIdentity.accessKeyId=="ASIA71C2…95CF" and .eventName=="StartExecution")][0]' $F

echo; echo "== K. 포털 역할 StartExecution 전체 (정상 76건 포함, 이름·시각 비교용) =="
jq -r '.Records[] | select((.userIdentity.arn//"")|test("portal-role")) | select(.eventName=="StartExecution")
  | [.eventTime,.sourceIPAddress,((.requestParameters//{})|tojson)]|@tsv' $F | sort

echo; echo "== L. 06:30 이후 서비스 역할, Step Functions, Lambda 활동 =="
jq -r '.Records[] | select(.eventTime>="2026-10-11T06:30:00Z")
  | select(((.userIdentity.arn//"")|test("patchsignal|pagesnap")) or ((.sourceIPAddress//"")|test("states|lambda")))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),(.errorCode//"OK"),((.requestParameters//{})|tojson|.[0:150])]|@tsv' $F | sed "$S" | sort

echo; echo "== M. IPv6 주소의 활동 =="
jq -r '.Records[] | select((.sourceIPAddress//"")|test(":"))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),(.errorCode//"OK")]|@tsv' $F | sed "$S" | sort

echo; echo "== N. ec2-ssmrole이 읽은 로그 그룹 =="
jq -r '.Records[] | select((.userIdentity.arn//"")|test("ec2-ssmrole")) | select(.eventName|test("FilterLogEvents|GetLogEvents|DescribeLogStreams"))
  | (.requestParameters.logGroupName // .requestParameters.logGroupIdentifier // "-")' $F | sort | uniq -c | sort -rn

echo; echo "== O. root UpdateStage, 팀원의 보안그룹·인스턴스 변경 원본 =="
jq -r '.Records[] | select(.eventName|test("^(UpdateStage|AuthorizeSecurityGroupIngress|ModifyInstanceAttribute)$"))
  | [.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.errorCode//"OK"),((.requestParameters//{})|tojson|.[0:300])]|@tsv' $F | sed "$S" | sort
```

이 파일은 requestParameters가 많이 비어 있어서 J와 K로 얻을 수 있는 정보가 적을 수 있습니다. 그 경우 **④ Step Functions 콘솔의 실행 기록**이 훨씬 정확합니다.

우선순위는 다음과 같습니다.
1. ①②③을 바로 적용합니다. 공격자가 지금도 움직일 수 있습니다.
2. ④ 실행 내용을 확인합니다. 피해 범위를 판단하는 데 필요합니다.
3. ⑤ 앱 취약점을 찾습니다. 재발을 막는 근본 조치입니다.
4. 운영진에게 root 배포 여부를 확인하고, 팀 안에서 모니터링 서버를 확인합니다.

## 사용자

J부터 O까지 보내 주신 명령 그대로 실행했고, 결과는 아래에 붙였습니다. 결과가 길어서 세 번(J+K, L, M+N+O)에 나눠 실행했습니다.

**결과를 볼 때 참고할 점**
- J: 이 파일의 원본 기록에는 붙인 내용(eventTime, eventSource, eventName, sourceIPAddress, userIdentity)이 전부입니다. 이 1건에는 requestParameters와 errorCode 칸이 아예 없습니다.
- N: 로그 그룹 이름이 기록에 없어서 3127건이 모두 `-`로 나옵니다.
- O: 보안그룹 변경과 UpdateStage는 requestParameters가 `{}`로 비어 있어서 무엇을 바꿨는지 이 파일로는 알 수 없습니다.

**물어보신 것**
- `ec2-ssmrole` / `i-026754fe07a870049`가 우리 팀 모니터링 서버인지는 저는 모릅니다.
- root로 배포를 누가 하는지, 운영 측이 root를 쓰는지도 저는 모릅니다.
- blue-team-1의 보안그룹·인스턴스 변경:
  - 사고 뒤 대응 작업(조회, 설정 변경)은 팀원이 했다는 것까지만 압니다.
  - 각 변경이 정확히 무엇이었는지, 0.0.0.0/0으로 연 것이 있는지는 저는 모릅니다.
- `2001:db8:0:b::2`가 누구인지 저는 모릅니다.

**못 하는 것**
- 조치 ①~⑥(세션 무효화, 정책 추가, IMDSv2 변경, Step Functions 실행 내용 확인, Cognito 사용자 정리)은 진행하지 못했습니다. 지금 콘솔과 CLI에 접속할 수 없습니다.
- Step Functions 실행 기록과 Cognito 사용자 목록은 확인 못 함(그 로그는 없어요).
- ⑤에서 말씀하신 포털 앱 로그(애플리케이션 로그)도 확인 못 함(그 로그는 없어요).

실행한 명령:
```
F=cloudtrail.json
echo "== J. 공격자 StartExecution 원본 1건 (전체 필드) =="
jq '[.Records[] | select(.userIdentity.accessKeyId=="ASIA71C2…95CF" and .eventName=="StartExecution")][0]' $F
echo; echo "== K. 포털 역할 StartExecution 전체 (정상 76건 포함, 이름·시각 비교용) =="
jq -r '.Records[] | select((.userIdentity.arn//"")|test("portal-role")) | select(.eventName=="StartExecution")
  | [.eventTime,.sourceIPAddress,((.requestParameters//{})|tojson)]|@tsv' $F | sort
```
결과:
```
== J. 공격자 StartExecution 원본 1건 (전체 필드) ==
{
  "eventTime": "2026-10-11T06:36:22Z",
  "eventSource": "states.amazonaws.com",
  "eventName": "StartExecution",
  "sourceIPAddress": "198.18.7.1",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77",
    "accessKeyId": "ASIA71C2…95CF"
  }
}

== K. 포털 역할 StartExecution 전체 (정상 76건 포함, 이름·시각 비교용) ==
2026-10-11T05:00:03Z	198.18.10.1	{"name":"case-ec4331c54acf42f3a59e7132efe11b0f"}
2026-10-11T05:14:32Z	198.18.10.1	{"name":"case-eb91f8b2e2b04896a882c27133e28461"}
2026-10-11T05:24:08Z	198.18.10.1	{"name":"case-f4b1237d8e5c4f3783b6044947f151dd"}
2026-10-11T05:27:26Z	198.18.10.1	{"name":"case-4220d74b91684fd4851f292c7266fd0c"}
2026-10-11T05:27:37Z	198.18.10.1	{"name":"case-bb4c5667790542719e2ee83f062fd919"}
2026-10-11T05:28:26Z	198.18.10.1	{"name":"case-b4d3e90ede9841ddb46913fbaf2d089c"}
2026-10-11T05:28:37Z	198.18.10.1	{"name":"case-fa0d1770f10a411fa41828583ed12629"}
2026-10-11T05:28:44Z	198.18.10.1	{"name":"case-a6ee907fb65742e8a63a41aa431f9a85"}
2026-10-11T05:30:19Z	198.18.10.1	{"name":"case-cb72d8aee366407d893a24225873062f"}
2026-10-11T05:30:40Z	198.18.10.1	{"name":"case-d5f1222f52fe42e8b92425303221593c"}
2026-10-11T05:31:35Z	198.18.10.1	{"name":"case-b84950bc61a944ffae0fa25712edb685"}
2026-10-11T05:31:44Z	198.18.10.1	{"name":"case-54cf79d907514c33b7ddbd5f69ab5490"}
2026-10-11T05:34:04Z	198.18.10.1	{"name":"case-b22c6e2168874834b2bd0f33771fddfb"}
2026-10-11T05:34:17Z	198.18.10.1	{"name":"case-fbb05947e56c499e96d1d16d2c892dc0"}
2026-10-11T05:38:09Z	198.18.10.1	{"name":"case-578eefa07daf4478b50f6d3c6948fa28"}
2026-10-11T05:40:53Z	198.18.10.1	{"name":"case-872925e26fe14d5081d3d31708b8ee31"}
2026-10-11T05:41:49Z	198.18.10.1	{"name":"case-991521209e1e4cb6b73d4e72e93240c8"}
2026-10-11T05:41:54Z	198.18.10.1	{"name":"case-5b9a97abada54c929975b280e7f79dc7"}
2026-10-11T05:43:00Z	198.18.10.1	{"name":"case-a5580f6c439849f592c64ffdd12b2524"}
2026-10-11T05:43:06Z	198.18.10.1	{"name":"case-560ab29b419d4fd6857f12a96b0c9339"}
2026-10-11T05:43:34Z	198.18.10.1	{"name":"case-c19372bae32149bdbc205a80516afaf1"}
2026-10-11T05:44:26Z	198.18.10.1	{"name":"case-17d2b4cf3d3c427b8280756aa59dcda8"}
2026-10-11T05:45:08Z	198.18.10.1	{"name":"case-e916046f53354298993ded760794f74b"}
2026-10-11T05:48:14Z	198.18.10.1	{"name":"case-34fdf7faf8e447f6b86865480a9414ba"}
2026-10-11T05:54:02Z	198.18.10.1	{"name":"case-0471810233df4c408149a45e82a4870a"}
2026-10-11T05:54:33Z	198.18.10.1	{"name":"case-0e49e9d53e854399b746229fb6064a35"}
2026-10-11T05:56:07Z	198.18.10.1	{"name":"case-a4202545a011401389be9b97eb47ee9e"}
2026-10-11T05:58:54Z	198.18.10.1	{"name":"case-0284eab122bd4d41a708da6a81cafc6c"}
2026-10-11T05:59:57Z	198.18.10.1	{"name":"case-a8e4cd31749f44e69e83e632c003e44b"}
2026-10-11T06:00:39Z	198.18.10.1	{"name":"case-76124a0dad8f4187b03c04eaf3b45940"}
2026-10-11T06:00:43Z	198.18.10.1	{"name":"case-536113bf81ee42e88b160ecc8d6ea3cc"}
2026-10-11T06:00:45Z	198.18.10.1	{"name":"case-469d6faa796c4c52b95b01b2c6e2a418"}
2026-10-11T06:03:15Z	198.18.10.1	{"name":"case-1d973696c12246fdbb7e872793de1f42"}
2026-10-11T06:08:01Z	198.18.10.1	{"name":"case-55ae4197ed9c42d19eb6d1e12fa4240a"}
2026-10-11T06:08:06Z	198.18.10.1	{"name":"case-8919cca21f05494487d4b868d6029921"}
2026-10-11T06:08:16Z	198.18.10.1	{"name":"case-3d760f72c0da458f922642252a5254b6"}
2026-10-11T06:08:51Z	198.18.10.1	{"name":"case-ce9a3813730946a589abe7594a1333d7"}
2026-10-11T06:09:02Z	198.18.10.1	{"name":"case-46e7e80716864a6c97b4a5b7557afbdb"}
2026-10-11T06:09:07Z	198.18.10.1	{"name":"case-61578bcb434a4dd8aa9ff5420f0ecf26"}
2026-10-11T06:09:24Z	198.18.10.1	{"name":"case-93bea42739fa4138918068ed138e6c42"}
2026-10-11T06:09:34Z	198.18.10.1	{"name":"case-eb71ed0b742a427a95a43510221f7b09"}
2026-10-11T06:09:39Z	198.18.10.1	{"name":"case-cf9e53c9db264165bdf9c0c2c9e68eae"}
2026-10-11T06:09:42Z	198.18.10.1	{"name":"case-c36bdc34305b443590da6326c1654059"}
2026-10-11T06:09:47Z	198.18.10.1	{"name":"case-80c425dae7044b85a0b8851ad4e209ee"}
2026-10-11T06:10:01Z	198.18.10.1	{"name":"case-5102fac6957a4fd889c56947d670d00c"}
2026-10-11T06:10:07Z	198.18.10.1	{"name":"case-ca2cc76cc42945f496c9765225aab09b"}
2026-10-11T06:10:58Z	198.18.10.1	{"name":"case-b1a40ea5454c414f9f1f8ecfe6ed1187"}
2026-10-11T06:11:00Z	198.18.10.1	{"name":"case-cb02cccacd70467596f974a47a96587b"}
2026-10-11T06:11:06Z	198.18.10.1	{"name":"case-4a6e7d5d8c1f4d389c662dd4700abf27"}
2026-10-11T06:11:17Z	198.18.10.1	{"name":"case-9c5f0ced9a8f40dca63cc1d2fee0847c"}
2026-10-11T06:11:36Z	198.18.10.1	{"name":"case-9d42843c59b34949a7abe721618cce8f"}
2026-10-11T06:11:38Z	198.18.10.1	{"name":"case-938d4738cd374b98be678f5bfda9a983"}
2026-10-11T06:13:23Z	198.18.10.1	{"name":"case-01847f5d9bef4b21b1279a787990f575"}
2026-10-11T06:13:27Z	198.18.10.1	{"name":"case-9339665a7b8c4d74926d4bbcb5d4f4a0"}
2026-10-11T06:14:02Z	198.18.10.1	{"name":"case-3cbd0f0899b14af5900e19b947a3f548"}
2026-10-11T06:14:14Z	198.18.10.1	{"name":"case-d6f2d75697cf4d08a93b33f732041ca2"}
2026-10-11T06:14:54Z	198.18.10.1	{"name":"case-7a12923a50e2475491968cd7e4236c40"}
2026-10-11T06:15:36Z	198.18.10.1	{"name":"case-b4e1f4a4843e4e778d71dde9e86bbe61"}
2026-10-11T06:16:01Z	198.18.10.1	{"name":"case-e8750b17c50c4ca1a969c651378e30d1"}
2026-10-11T06:16:24Z	198.18.10.1	{"name":"case-63096791d5354d03a127d9942433627b"}
2026-10-11T06:16:33Z	198.18.10.1	{"name":"case-3d6beffade09439383d13b1332e53e3c"}
2026-10-11T06:16:37Z	198.18.10.1	{"name":"case-d6eedaf93586449181c041640420353f"}
2026-10-11T06:17:09Z	198.18.10.1	{"name":"case-6957139478d34a6998057315d61b2f92"}
2026-10-11T06:18:31Z	198.18.10.1	{"name":"case-f0a5af86a3e44a9ebaff1b4bebcd08f8"}
2026-10-11T06:18:55Z	198.18.10.1	{"name":"case-c0c4b96befa94fa188b722778b75aa0f"}
2026-10-11T06:34:24Z	198.18.10.1	{"name":"case-85f359ca6cd44366af38ca65888bf9e5"}
2026-10-11T06:34:32Z	198.18.10.1	{"name":"case-d29e27d29f7248aab5a84a408e412a67"}
2026-10-11T06:35:02Z	198.18.10.1	{"name":"case-27234d5bb55e4f6eadb510aa4201afd3"}
2026-10-11T06:35:10Z	198.18.10.1	{"name":"case-a7c0409ec5fc420cab3441d5e8588f3e"}
2026-10-11T06:36:22Z	198.18.7.1	{}
2026-10-11T06:40:45Z	198.18.7.1	{"name":"case-redteam-validation-002"}
2026-10-11T06:41:53Z	198.18.7.1	{"name":"case-redteam-validation-003"}
2026-10-11T06:49:24Z	198.18.10.1	{"name":"case-bb38364049494742898ed45450660962"}
2026-10-11T06:49:29Z	198.18.10.1	{"name":"case-0eb18af607204850a7043b9377a77821"}
2026-10-11T06:52:08Z	198.18.50.1	{}
2026-10-11T06:59:46Z	198.18.10.1	{"name":"case-ed703c00f8d244078c7556ffb60e51fe"}
2026-10-11T07:00:30Z	198.18.10.1	{"name":"case-432772485c824a46ba2a4e50606182bf"}
2026-10-11T07:02:17Z	198.18.50.1	{}
2026-10-11T07:03:16Z	198.18.10.1	{"name":"case-f6c5d9a230de4a01801f741390f2e3b2"}
2026-10-11T07:03:46Z	198.18.7.1	{"name":"test-run-1791702223"}
2026-10-11T07:05:02Z	198.18.7.1	{"name":"test-run-1791702300"}
2026-10-11T07:05:47Z	198.18.7.1	{"name":"test-run-1791702344"}
2026-10-11T07:08:11Z	198.18.50.1	{}
2026-10-11T07:18:35Z	198.18.10.1	{"name":"case-26a3b3e40ded4ffa8fa538f5f0672ba5"}
2026-10-11T07:23:44Z	198.18.10.1	{"name":"case-7fe6fd5484b245a0b0559b9d0cdbee15"}
```

실행한 명령:
```
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'
echo "== L. 06:30 이후 서비스 역할, Step Functions, Lambda 활동 =="
jq -r '.Records[] | select(.eventTime>="2026-10-11T06:30:00Z")
  | select(((.userIdentity.arn//"")|test("patchsignal|pagesnap")) or ((.sourceIPAddress//"")|test("states|lambda")))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),(.errorCode//"OK"),((.requestParameters//{})|tojson|.[0:150])]|@tsv' $F | sed "$S" | sort
```
결과:
```
== L. 06:30 이후 서비스 역할, Step Functions, Lambda 활동 ==
2026-10-11T06:32:11Z	198.18.10.1	ssm.amazonaws.com	CreateDataChannel	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T06:33:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:34:24Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-85f359ca6cd44366af38ca65888bf9e5"}
2026-10-11T06:34:25Z	198.18.48.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T06:34:26Z	198.18.49.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T06:34:32Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-d29e27d29f7248aab5a84a408e412a67"}
2026-10-11T06:35:02Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-27234d5bb55e4f6eadb510aa4201afd3"}
2026-10-11T06:35:10Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-a7c0409ec5fc420cab3441d5e8588f3e"}
2026-10-11T06:36:22Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T06:38:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:39:20Z	198.18.50.1	ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied	{}
2026-10-11T06:39:49Z	198.18.51.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T06:40:45Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-redteam-validation-002"}
2026-10-11T06:40:52Z	198.18.52.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T06:41:53Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-redteam-validation-003"}
2026-10-11T06:42:18Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:43:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:48:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:48:44Z	198.18.53.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T06:49:24Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-bb38364049494742898ed45450660962"}
2026-10-11T06:49:29Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-0eb18af607204850a7043b9377a77821"}
2026-10-11T06:49:30Z	198.18.54.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T06:49:32Z	198.18.55.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T06:52:08Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T06:52:11Z	198.18.56.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T06:52:12Z	198.18.57.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T06:53:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:58:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T06:58:48Z	198.18.58.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T06:59:46Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-ed703c00f8d244078c7556ffb60e51fe"}
2026-10-11T06:59:48Z	198.18.59.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T06:59:56Z	198.18.29.2	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T07:00:30Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-432772485c824a46ba2a4e50606182bf"}
2026-10-11T07:02:09Z	198.18.7.1	ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied	{}
2026-10-11T07:02:17Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T07:03:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:03:16Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-f6c5d9a230de4a01801f741390f2e3b2"}
2026-10-11T07:03:46Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"test-run-1791702223"}
2026-10-11T07:04:34Z	198.18.60.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T07:05:02Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"test-run-1791702300"}
2026-10-11T07:05:47Z	198.18.7.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"test-run-1791702344"}
2026-10-11T07:07:34Z	198.18.61.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T07:08:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:08:11Z	198.18.50.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T07:09:30Z	198.18.62.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T07:11:37Z	198.18.7.1	ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied	{}
2026-10-11T07:12:16Z	198.18.7.1	ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied	{}
2026-10-11T07:12:18Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:13:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:13:31Z	198.18.63.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T07:15:14Z	198.18.64.1	logs.amazonaws.com	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	OK	{}
2026-10-11T07:18:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:18:35Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-26a3b3e40ded4ffa8fa538f5f0672ba5"}
2026-10-11T07:18:39Z	198.18.65.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
2026-10-11T07:18:43Z	198.18.66.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T07:19:43Z	198.18.10.1	ssm.amazonaws.com	PutConfigurePackageResult	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{}
2026-10-11T07:23:01Z	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"instanceId":"i-05816900800807b77"}
2026-10-11T07:23:44Z	198.18.10.1	states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	OK	{"name":"case-7fe6fd5484b245a0b0559b9d0cdbee15"}
2026-10-11T07:23:48Z	198.18.67.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	OK	{}
2026-10-11T07:23:49Z	198.18.68.1	logs.amazonaws.com	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	OK	{}
```

실행한 명령:
```
F=cloudtrail.json; S='s#arn:aws:[a-z]*::111122223333:##'
echo "== M. IPv6 주소의 활동 =="
jq -r '.Records[] | select((.sourceIPAddress//"")|test(":"))
  | [.eventTime,.sourceIPAddress,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),(.errorCode//"OK")]|@tsv' $F | sed "$S" | sort
echo; echo "== N. ec2-ssmrole이 읽은 로그 그룹 =="
jq -r '.Records[] | select((.userIdentity.arn//"")|test("ec2-ssmrole")) | select(.eventName|test("FilterLogEvents|GetLogEvents|DescribeLogStreams"))
  | (.requestParameters.logGroupName // .requestParameters.logGroupIdentifier // "-")' $F | sort | uniq -c | sort -rn
echo; echo "== O. root UpdateStage, 팀원의 보안그룹·인스턴스 변경 원본 =="
jq -r '.Records[] | select(.eventName|test("^(UpdateStage|AuthorizeSecurityGroupIngress|ModifyInstanceAttribute)$"))
  | [.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.errorCode//"OK"),((.requestParameters//{})|tojson|.[0:300])]|@tsv' $F | sed "$S" | sort
```
결과:
```
== M. IPv6 주소의 활동 ==
2026-10-11T05:09:19Z	2001:db8:0:18::1	cognito-identity.amazonaws.com	ListIdentityPools	user/blue-team-1	OK
2026-10-11T05:09:19Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPools	user/blue-team-1	OK
2026-10-11T05:10:45Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPool	user/blue-team-1	OK
2026-10-11T05:10:45Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPoolClient	user/blue-team-1	OK
2026-10-11T05:10:45Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPoolClients	user/blue-team-1	OK
2026-10-11T05:10:45Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPoolReplicas	user/blue-team-1	OK
2026-10-11T05:11:17Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPool	user/blue-team-1	OK
2026-10-11T05:11:17Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPoolClient	user/blue-team-1	OK
2026-10-11T05:11:17Z	2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPoolReplicas	user/blue-team-1	OK
2026-10-11T05:16:40Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	Unknown	OK
2026-10-11T05:17:08Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	Unknown	OK
2026-10-11T05:17:22Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	OK
2026-10-11T05:17:31Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	OK
2026-10-11T05:17:32Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	OK
2026-10-11T06:26:59Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	OK

== N. ec2-ssmrole이 읽은 로그 그룹 ==
   3127 -

== O. root UpdateStage, 팀원의 보안그룹·인스턴스 변경 원본 ==
2026-10-11T04:39:33Z	user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	OK	{}
2026-10-11T04:43:00Z	root	198.18.0.3	UpdateStage	OK	{}
2026-10-11T04:48:52Z	root	198.18.18.1	UpdateStage	OK	{}
2026-10-11T05:09:28Z	user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	OK	{}
2026-10-11T05:09:29Z	user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	OK	{}
2026-10-11T05:27:36Z	user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	Client.DryRunOperation	{}
2026-10-11T05:27:37Z	user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	OK	{}
2026-10-11T05:30:13Z	user/blue-team-1	198.18.2.1	ModifyInstanceAttribute	OK	{"instanceId":"i-026754fe07a870049"}
2026-10-11T05:30:39Z	user/blue-team-1	198.18.2.1	ModifyInstanceAttribute	OK	{"instanceId":"i-026754fe07a870049"}
2026-10-11T05:31:44Z	user/blue-team-1	198.18.2.1	ModifyInstanceAttribute	OK	{"instanceId":"i-026754fe07a870049"}
2026-10-11T05:33:02Z	user/blue-team-1	198.18.2.1	ModifyInstanceAttribute	OK	{"instanceId":"i-026754fe07a870049"}
2026-10-11T07:18:34Z	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	AuthorizeSecurityGroupIngress	OK	{}
```

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# 최종 사고 보고서: PatchSignal 포털 침해 의심 건

- **대상 계정**: 111122223333 (보안 공방전 연습 환경)
- **분석 범위**: 서울 리전 CloudTrail 파일 1개, 2026-10-11 04:30:01Z ~ 07:25:01Z (한국 시간 13:30 ~ 16:25), 10,223건
- **분석 방법**: 로그 분석만 수행했습니다. 콘솔·CLI·앱 로그는 확인하지 못했고, 조치도 아직 적용하지 않았습니다.

판단마다 확신 정도를 표시했습니다.
- **[확인]**: 로그에 직접 드러난 사실
- **[추정]**: 근거는 있으나 다른 해석도 가능
- **[미확인]**: 이 자료로는 알 수 없음

---

## 1. 결론 요약

1. **[확인]** 외부 공격자가 PatchSignal 포털 서버(`i-05816900800807b77`)의 AWS 임시 자격 증명을 탈취했습니다. 공격자는 이 키를 서버 밖(198.18.7.1, 198.18.50.1)에서 사용했습니다.
2. **[확인]** 공격자는 그 키로 Step Functions 실행 **9건을 성공**시켰습니다. 서버 원격 접속(SSM `StartSession`)과 원격 명령(`SendCommand`) 시도 **4건은 모두 거부**됐습니다.
3. **[추정]** 공격자의 Step Functions 실행 중 일부는 실제로 하위 Lambda(`provider-api`, `feed-connector`)를 동작시킨 것으로 보입니다. 이 실행들이 무엇을 바꿨는지는 **미확인**이며, 피해 범위를 판단하는 데 가장 중요한 빈칸입니다.
4. **[추정]** 탈취 경로는 포털 앱의 취약점일 가능성이 높습니다. 공격자는 먼저 포털에 회원가입해 로그인했고, 약 2시간 뒤 서버 키를 썼습니다. 서버 셸을 얻으려 SSM을 시도한 점으로 보아, 서버에서 명령을 실행하는 능력(RCE)은 없었던 것 같습니다. 그보다는 SSRF 등으로 메타데이터의 자격 증명만 읽어 간 형태로 보입니다.
5. **[확인]** 로그 파일 끝(07:25Z)까지 공격자의 키를 무효화한 기록이 없습니다. **공격자는 지금도 이 키를 쓸 수 있다고 가정해야 합니다.**
6. 이 파일 범위에서는 로그 끄기, IAM 사용자·키 생성, 인스턴스 생성, 버킷 공개 전환, SES 악용 흔적이 없습니다. 다만 IAM 변경과 전역 STS 호출은 보통 **us-east-1에 기록**되므로, "백도어가 없다"는 결론은 **내릴 수 없습니다.**

---

## 2. 공격 타임라인

| UTC (한국 시간) | 출처 IP | 행동 | 결과 | 근거 |
|---|---|---|---|---|
| 04:37~04:40 (13:37~) | 198.18.7.1 | Cognito `SignUp` 8회 (비밀번호 정책 위반 6회) | 계정 2개 생성 | [확인] |
| 04:41~04:42 | 198.18.7.1 | `ConfirmSignUp`, 로그인 | 성공 | [확인] |
| 04:43~04:50 | 198.18.7.2 | 로그인 4회 실패 → 다시 가입 → 확인 → 로그인 | 성공 | [확인] |
| 05:09:58 | 198.18.7.2 | **공격자 자신의 AWS 계정**으로 `pagesnap-final-s1-results-0e666173` 버킷 조회 | 거부 | [확인] |
| 05:28~05:45 | 198.18.7.1/7.2 | 추가 가입, 로그인 | 성공 | [확인] |
| **06:36:22 (15:36)** | **198.18.7.1** | **포털 역할 키 `ASIA71C2…95CF`로 첫 `StartExecution`** | **성공** | [확인] |
| 06:39:20 | 198.18.50.1 | 같은 키로 `ssm:StartSession` | 거부 | [확인] |
| 06:40~07:08 | 7.1 / 50.1 | `StartExecution` 8회 추가 | **성공** | [확인] |
| 07:02~07:12 (~16:12) | 198.18.7.1 | `StartSession` 1회, `SendCommand` 2회 | 거부 | [확인] |
| 07:25 | | 로그 파일 끝. 이후 활동은 알 수 없음 | | [미확인] |

### 공격자 실행과 정상 실행의 구별

포털 앱이 정상적으로 만든 실행 79건은 이름이 **모두 `case-` 뒤에 32자리 16진수**가 붙은 형식이고, 출처는 198.18.10.1입니다. 공격자의 실행 9건은 이 형식과 다릅니다.

| 시각 | IP | 실행 이름 |
|---|---|---|
| 06:36:22 | 7.1 | (이름 없음, AWS 자동 생성) |
| 06:40:45 | 7.1 | `case-redteam-validation-002` |
| 06:41:53 | 7.1 | `case-redteam-validation-003` |
| 06:52:08 | 50.1 | (이름 없음) |
| 07:02:17 | 50.1 | (이름 없음) |
| 07:03:46 | 7.1 | `test-run-1791702223` |
| 07:05:02 | 7.1 | `test-run-1791702300` |
| 07:05:47 | 7.1 | `test-run-1791702344` |
| 07:08:11 | 50.1 | (이름 없음) |

- `test-run-` 뒤의 숫자는 유닉스 시각입니다. 각각 07:03:43, 07:05:00, 07:05:44로 변환되며, 실제 호출보다 2~3초 앞섭니다. **공격자가 스크립트로 실행했다**는 뜻입니다.
- `case-` 접두어를 흉내 낸 것을 보면, 공격자는 정상 실행의 이름 규칙을 알고 있었습니다.
- `-001`이 없는 이유는 알 수 없습니다. 06:36의 이름 없는 실행이었거나, 이 파일 밖(다른 리전 등)에서 시도했을 수 있습니다.
- **[추정]** 198.18.10.1에서 나온 실행은 모두 정상 형식이었습니다. 따라서 공격자가 포털 서버 안에서 직접 실행했다는 흔적은 없습니다.

### 공격자 실행이 실제로 무언가를 동작시켰다는 근거 [추정]

정상 실행 직후에는 수 초 안에 `provider-api`와 `feed-connector` Lambda의 `CreateLogStream`이 반복해서 나타납니다. 예를 들어 06:34:24 실행 다음에 06:34:25와 06:34:26 기록이 있습니다. 공격자 실행 뒤에도 같은 모습이 보입니다.

- 06:40:45 공격자 실행 → 06:40:52 `provider-api`
- 06:52:08 공격자 실행 → 06:52:11 `provider-api`, 06:52:12 `feed-connector`

`CreateLogStream`은 Lambda가 새 실행 환경을 띄울 때만 남습니다. 그래서 기록이 없는 다른 실행들도 Lambda를 호출했을 수 있습니다. 결국 **공격자는 포털 역할을 거쳐 PatchSignal 처리 흐름 전체를 마음대로 돌릴 수 있었습니다.**

---

## 3. 조사 후 정상 또는 낮은 위험으로 판단한 것

| 항목 | 판단 | 근거 |
|---|---|---|
| 1건짜리 IP 약 55개 | 정상 | 모두 Lambda의 `CreateLogStream`/`Decrypt`입니다. Lambda는 실행마다 IP가 바뀝니다. |
| root 153건 | 배포 도구로 추정, **확인 필요** | 04:42와 04:48에 똑같은 순서의 전수 조회와 `UpdateStage`가 반복됩니다. Terraform 같은 도구의 plan/apply 모습입니다. 읽은 파라미터도 공개 AMI 정보뿐입니다. 하지만 root를 일상적으로 쓰는 것 자체가 위험합니다. |
| eks-node 역할의 198.18.9.1 호출 | 정상으로 추정 | EKS 인증 토큰 검증 과정의 `GetCallerIdentity`입니다. |
| GuardDuty의 `AuthorizeSecurityGroupIngress` (07:18) | 정상 | GuardDuty Runtime Monitoring이 자체 엔드포인트용 보안그룹을 설정한 것입니다. |
| `2001:db8:0:18::1` | 팀원 | blue-team-1이 05:09~05:11에 Cognito 설정을 조회했습니다. |

---

## 4. 판단하지 못한 것 (누군가 확인해야 함)

| 항목 | 상태 | 왜 중요한가 |
|---|---|---|
| 공격자 Step Functions 실행 9건의 입력과 결과 | 미확인 | 데이터나 패치 피드 변조 여부를 판단하는 핵심입니다. |
| 자격 증명 탈취 방법 | 미확인 (앱 로그 없음) | 근본 원인입니다. 고치지 않으면 키를 바꿔도 다시 털립니다. |
| 07:25 이후 활동 | 미확인 | 키가 아직 유효합니다. |
| us-east-1과 다른 리전 | 미확인 | IAM 백도어, 전역 STS 정찰, 다른 리전 자원 생성 여부를 알 수 없습니다. 공격자가 이 파일에서 첫 호출부터 `StartExecution`을 정확히 겨냥했으므로, **사전 정찰은 다른 곳에 기록됐을 가능성이 큽니다.** |
| `2001:db8:0:b::2` | 미확인 | 05:16~05:17에 계정 2개를 가입하고 06:26에 다시 로그인했습니다. 공격자와 비슷한 모습이라 확인이 필요합니다. |
| `ec2-ssmrole` / `i-026754fe07a870049` | 미확인 | CloudWatch Logs를 3천 번 넘게 읽었는데, 어떤 로그 그룹인지는 기록에 없습니다. blue-team-1이 05:30~05:33에 이 인스턴스를 4번 수정한 것을 보면 팀이 관리하는 서버일 가능성이 있습니다. |
| blue-team-1의 보안그룹 변경 4건 | 미확인 | 0.0.0.0/0으로 열린 규칙이 생겼는지 확인해야 합니다. |
| root의 `UpdateStage` 2건 | 미확인 | API Gateway 설정이 바뀌었습니다. 운영 측 작업인지 확인해야 합니다. |
| 공격자가 pagesnap도 노렸는지 | 일부 확인 | 버킷 조회는 거부됐습니다. pagesnap 쪽 다른 공격은 이 파일에서 보이지 않습니다. |

**자료의 한계**: 이 파일에는 `awsRegion`, `userAgent`, `responseElements`가 없고 `requestParameters`도 대부분 비어 있습니다. 가공된 사본으로 보이므로, 가능하면 S3에 있는 CloudTrail 원본으로 다시 확인하는 것이 좋습니다.

---

## 5. 고쳐야 할 것 (우선순위순)

콘솔 권한이 있는 팀원이나 운영진에게 그대로 전달하시면 됩니다. **바꾸거나 지우기 전에 반드시 화면 캡처나 내보내기로 기록부터 남기세요.**

### 즉시 (공격 차단)

1. **포털 역할 세션 무효화**: IAM → Roles → `patchsignal-ewc2enb8-portal-role` → **Revoke active sessions**. 공격자가 가진 `ASIA71C2…95CF`가 즉시 무효가 됩니다. 정상 서버는 새 키를 자동으로 받습니다.
2. **서버 밖에서 역할 사용 금지**: 지난 답변의 `DenyUseOutsidePortalHost` 정책을 이 역할에 추가합니다. 원인을 고치기 전까지는 키를 다시 훔쳐 가도 밖에서 못 쓰게 하는 장치입니다. 먼저 198.18.10.1이 포털 서버의 고정 출구 IP인지 확인하세요.
3. **포털 인스턴스를 IMDSv2 필수, hop limit 1로 변경**:
   ```bash
   aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
     --http-tokens required --http-put-response-hop-limit 1
   ```
4. **공격자 Cognito 계정 비활성화**: 가입 시각 04:39:48, 04:40:26, 04:48:29, 05:28:39 UTC 기준으로 찾습니다. `2001:db8:0:b::2`가 만든 계정(05:16~05:17)은 확인한 뒤 결정하세요.

### 오늘 안에 (피해 범위 파악)

5. **Step Functions 실행 9건 확인**: 위 표의 이름과 시각으로 찾아서 Input, 단계별 이벤트, Output을 보존하고 검토합니다. 하위 Lambda(`provider-api`, `feed-connector`)가 그 시각에 무엇을 쓰고 바꿨는지 CloudWatch Logs에서 대조하세요.
6. **us-east-1 CloudTrail 확인**: 같은 시간대에 `ASIA71C2…95CF`, 198.18.7.1, 198.18.7.2, 198.18.50.1이 남긴 기록을 찾습니다. 특히 IAM 변경(`Create*`, `Attach*`, `Put*Policy`)과 `GetCallerIdentity`를 봐야 합니다.
7. **GuardDuty 탐지 목록 확인**: `InstanceCredentialExfiltration` 계열 탐지가 있는지 봅니다. 이번 사건의 독립적인 확인 근거가 됩니다.
8. **팀원 변경 점검**: blue-team-1의 보안그룹 변경 4건과 `i-026754fe07a870049` 수정 4건의 내용을 확인하고, 불필요하게 열린 규칙을 되돌립니다.

### 근본 원인 수정 (백엔드 담당)

9. **포털 앱 취약점 찾기**: 앱 로그에서 공격자 계정의 요청을 04:41~06:36 UTC 범위로 추적합니다. 우선 의심할 곳은 다음과 같습니다.
   - URL이나 호스트를 받아 서버가 대신 요청하는 기능 (`169.254.169.254`, `localhost`, 리다이렉트 이용)
   - 파일 경로를 받는 기능 (`/proc/self/environ` 등을 읽는 경로 조작)
   - 디버그나 상태 확인용 엔드포인트, 오류 메시지에 환경 정보가 그대로 노출되는 곳
10. **Step Functions 입력을 신뢰하지 않기**: 공격자가 실행을 직접 시작할 수 있었다면, 상태 머신과 Lambda가 입력값을 검증하지 않는 한 무엇이든 처리했을 것입니다. 케이스 ID 형식, 소유자, 허용 값을 하위 단계에서 다시 검증하세요.
11. **포털 역할 최소 권한화**: `states:StartExecution`을 필요한 상태 머신 ARN 하나로만 제한하세요. 이번에 SSM 권한이 없었던 것이 셸 탈취를 막았으니, 이 상태는 유지합니다.

### 이후 개선

12. **root 사용 중단**: 배포는 IAM 역할로 하고, root access key는 삭제하고, MFA를 켭니다. 운영 측 확인이 먼저입니다.
13. **blue-team-1 공유 사용 중단**: 사람별 계정으로 나눠야 공격자가 섞여도 구별할 수 있습니다.
14. **탐지 규칙 추가**: 포털 역할이 198.18.10.1이 아닌 곳에서 호출되면 알림이 오게 하세요(EventBridge나 GuardDuty). 또 셀프 회원가입이 꼭 필요한 기능인지 검토하세요.
15. **CloudTrail 전체 필드 보존**: `userAgent`, `requestParameters`, `awsRegion`이 남아 있어야 다음 조사가 가능합니다.

---

## 6. 운영진과 팀에 물어볼 것

1. root로 Terraform 같은 배포를 하나요? 04:43과 04:48의 `UpdateStage`는 운영 측 작업인가요?
2. `i-026754fe07a870049`(ec2-ssmrole)는 팀의 모니터링 서버인가요? 어떤 로그 그룹을 읽나요?
3. blue-team-1의 보안그룹 변경 4건은 무엇을 연 것인가요?
4. `2001:db8:0:b::2`는 누구인가요?
5. 공방전 규칙상 레드팀의 공격 대상과 범위가 정해져 있나요? 실행 이름의 `redteam`은 이번 공격이 연습의 레드팀 활동이라는 단서일 수 있습니다. 그렇더라도 위 조치는 그대로 필요합니다.

---

## 7. 침해 지표 (IOC)

| 종류 | 값 |
|---|---|
| 공격자 IP | 198.18.7.1, 198.18.7.2, 198.18.50.1 |
| 확인 필요 IP | 2001:db8:0:b::2 |
| 탈취된 키 | `ASIA71C2…95CF` (`patchsignal-ewc2enb8-portal-role`, `i-05816900800807b77`) |
| 공격자 실행 이름 | `case-redteam-validation-002`, `case-redteam-validation-003`, `test-run-1791702223`, `test-run-1791702300`, `test-run-1791702344`, 이름 없는 실행 4건 (06:36:22, 06:52:08, 07:02:17, 07:08:11 UTC) |
| 공격자 가입 시각 | 04:39:48, 04:40:26, 04:48:29, 05:28:39 UTC |
| 공격자가 조회한 자원 | `pagesnap-final-s1-results-0e666173` (거부됨) |

---

**가장 먼저 할 일 하나만 꼽으면 5-1번(포털 역할 세션 무효화)입니다.** 콘솔 권한이 있는 분께 이것부터 요청하세요. 이어서 2·3번으로 재탈취를 막은 뒤, 5번(Step Functions 실행 내용)으로 실제 피해를 확인하시면 됩니다.

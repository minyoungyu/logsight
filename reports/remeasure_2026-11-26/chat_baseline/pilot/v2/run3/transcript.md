## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

# AWS 계정 침해 의심 대응

**누가 어떤 내용으로 연락했는지**도 알려 주세요. AWS 메일인지, GuardDuty 알림인지, 사내 보안팀인지에 따라 우선순위가 달라집니다.

---

## 1단계: 지금 바로 (10~20분)

1. **혼자 처리하지 마세요.** 팀장, 사내 보안 담당자, 인프라 담당자에게 지금 상황을 공유하세요. 결제 권한이 있는 사람도 알고 있어야 합니다.
2. **루트 계정 보호**
   - 루트 비밀번호를 변경하고 MFA를 확인하세요. MFA가 없다면 지금 설정하세요.
   - 루트 계정에 Access Key가 있으면 **비활성화(Deactivate)** 하세요.
3. **의심되는 Access Key는 삭제하지 말고 비활성화하세요.** 삭제하면 조사 단서가 사라집니다. 비활성화는 되돌릴 수 있습니다.
4. **리소스를 함부로 삭제하지 마세요.** 이상한 EC2가 있으면 삭제 대신 **중지(Stop)** 하세요. 비용은 멈추고 증거는 남습니다.
5. **결제 확인**: Billing → Bills / Cost Explorer에서 오늘 비용이 튀었는지 보세요. 공격자는 보통 **평소 안 쓰는 리전**에 대형 EC2나 GPU를 띄워 채굴합니다.

---

## 2단계: 로그 수집

⚠️ **시간대 주의**: AWS 로그는 UTC 기준입니다. **한국시간 13:30 = UTC 04:30**입니다. 넉넉하게 오늘 UTC 00:00부터 보는 걸 권장합니다.

아래 명령은 **관리자 권한이 있는 안전한 자격증명**으로 실행하세요. 의심되는 키로 실행하면 안 됩니다. 날짜(`2025-01-01`)는 오늘 날짜로 바꾸세요.

### ① CloudTrail: 누가 무엇을 했는지 (가장 중요)
```bash
# 전체 리전 순회하며 오늘 이벤트 수집
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r =="
  aws cloudtrail lookup-events --region $r \
    --start-time 2025-01-01T00:00:00Z \
    --query "Events[].{Time:EventTime,Name:EventName,User:Username,Source:EventSource}" \
    --output table
done > cloudtrail_today.txt
```

### ② IAM 사용자/키 현황
```bash
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > credential_report.csv
aws iam list-users --output table > iam_users.txt
aws iam list-roles --query "Roles[].{Name:RoleName,Created:CreateDate}" --output table > iam_roles.txt
```

### ③ 전 리전 EC2 인스턴스
```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r =="
  aws ec2 describe-instances --region $r \
    --query "Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name,Launch:LaunchTime}" \
    --output table
done > ec2_all_regions.txt
```

### ④ GuardDuty (켜져 있다면)
```bash
aws guardduty list-detectors
# 결과의 DetectorId로:
aws guardduty list-findings --detector-id <ID>
```

---

## 공유할 때 주의

- **Secret Access Key, 비밀번호, 세션 토큰은 절대 붙여 넣지 마세요.**
- 계정 ID나 Access Key ID(`AKIA...`)는 앞 4자리 정도만 남기고 가려도 분석에는 충분합니다.

---

## 로그를 받으면 제가 확인할 것들

| 확인 항목 | 의미 |
|---|---|
| `ConsoleLogin` (낯선 IP/시간) | 콘솔 로그인 탈취 |
| `CreateUser`, `CreateAccessKey`, `CreateLoginProfile` | 공격자가 백도어 계정을 생성 |
| `AttachUserPolicy`, `PutUserPolicy` (AdministratorAccess 등) | 권한 상승 |
| `RunInstances` (낯선 리전, 대형 타입) | 채굴 |
| `GetCallerIdentity`, `ListBuckets` 연속 호출 | 정찰 단계 |
| `StopLogging`, `DeleteTrail` | 흔적 지우기 시도 |
| S3 `PutBucketPolicy`, `GetObject` 대량 호출 | 데이터 유출 |

---

## 함께 알려 주시면 좋은 정보

1. 연락 온 곳과 메시지 내용
2. 최근에 Access Key를 GitHub, 프론트엔드 코드, `.env` 파일 등에 올린 적이 있는지 (가장 흔한 원인입니다)
3. 회사에서 AWS Organizations를 쓰는지, 계정이 하나인지

피해가 확실해 보이면 **AWS Support에 케이스를 여세요** (Account and billing → 보안 관련). 기본 플랜으로도 가능하며, 침해로 발생한 비용을 조정받을 수 있는 경우도 있습니다.

로그를 뽑아 주시면 이어서 분석해 드리겠습니다.

## 사용자

메시지 받았어요. 질문부터 답하고, 뽑은 방법은 아래에 적었어요.

**질문 답변**
- 누가 어떤 내용으로 연락했는지: "계정이 공격받았을 수 있다"는 연락만 받았고, AWS 메일인지 GuardDuty 알림인지 보안팀인지, 정확한 내용은 몰라요.
- 이 계정은 보안 공방전(연습) 환경이에요.
- blue-team-1, blue-team-2는 우리 팀원 계정이에요. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했어요.
- PatchSignal은 원래 있던 우리 서비스예요.
- Access Key를 GitHub, 프론트엔드 코드, .env 등에 올린 적이 있는지, AWS Organizations를 쓰는지는 몰라요.

**1단계 조치**
지금은 AWS 콘솔과 CLI에 접속할 수 없어서 루트 비밀번호 변경, MFA, 키 비활성화, EC2 중지, 결제 확인은 하지 못했어요.

**2단계 로그 수집**
① CloudTrail: 제가 가진 건 내려받아 둔 CloudTrail 파일 하나뿐이고, 그 안의 기록만 jq로 뽑았어요.
- **범위:** ap-northeast-2 기록만 있어요. 다른 리전은 확인 못 해요(그 로그는 없어요).
- **기간과 개수:** 2026-10-11T04:30:01Z ~ 07:25:01Z, 모두 10,223건이에요.
- **항목:** 각 기록에는 eventTime, eventSource, eventName, sourceIPAddress, userIdentity만 있어요.
- **사용자 표시:** User는 userIdentity.arn으로 표시했어요. arn이 없으면 invokedBy, 그것도 없으면 type을 넣었어요.

이벤트를 한 줄씩 표로 뽑으면 너무 길어서 두 가지로 묶어서 뽑았어요.
1. **첫 번째 결과(사용자별 요약):** 처음 시각, 마지막 시각, 건수, 사용자 순서예요.
2. **두 번째~다섯 번째 결과(사용자+이벤트+서비스별 요약):** 처음 시각, 건수, 사용자, EventName, EventSource 순서예요.
   - 글자 수를 줄이려고 arn 앞부분(`arn:aws:iam::111122223333:`, `arn:aws:sts::111122223333:`)과 `.amazonaws.com`은 지웠어요.
   - 모두 529줄이라 네 번에 나눠 보냈어요. 두 번째 결과는 1~138줄 정도에서 글자 수 제한으로 잘렸어요.
   - 그래서 세 번째는 139~270줄(앞 결과와 한두 줄 겹침), 네 번째는 271~400줄, 다섯 번째는 401~529줄이에요. 이걸로 전체가 다 들어갔어요.

② IAM 사용자/키 현황(credential report, list-users, list-roles), ③ 전 리전 EC2 인스턴스 목록, ④ GuardDuty 탐지 결과는 확인 못 했어요(그 로그는 없어요).

실행한 명령:
```
jq -r '.Records|map(. + {u:(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)})|group_by(.u)|map({u:.[0].u,c:length,f:(map(.eventTime)|min),l:(map(.eventTime)|max)})|sort_by(.f)[]|"\(.f)  \(.l)  \(.c)  \(.u)"' cloudtrail.json
```
결과:
```
2026-10-11T04:30:01Z  2026-10-11T07:23:36Z  4814  arn:aws:iam::111122223333:user/blue-team-1
2026-10-11T04:30:07Z  2026-10-11T07:23:37Z  3207  arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049
2026-10-11T04:30:13Z  2026-10-11T07:24:06Z  103  delivery.logs.amazonaws.com
2026-10-11T04:30:25Z  2026-10-11T05:55:23Z  56  config.amazonaws.com
2026-10-11T04:30:31Z  2026-10-11T05:55:48Z  69  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2
2026-10-11T04:30:31Z  2026-10-11T05:55:48Z  18  resource-explorer-2.amazonaws.com
2026-10-11T04:30:41Z  2026-10-11T05:30:35Z  2  arn:aws:iam::111122223333:user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit
2026-10-11T04:30:45Z  2026-10-11T04:30:45Z  1  arn:aws:sts::111122223333:assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3
2026-10-11T04:30:49Z  2026-10-11T06:00:49Z  7  AWS Internal
2026-10-11T04:30:49Z  2026-10-11T07:15:50Z  83  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS
2026-10-11T04:31:06Z  2026-10-11T06:00:42Z  4  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSecurityHubV2/securityhub
2026-10-11T04:31:06Z  2026-10-11T06:00:42Z  4  securityhub.amazonaws.com
2026-10-11T04:31:08Z  2026-10-11T06:01:08Z  14  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe
2026-10-11T04:31:08Z  2026-10-11T06:01:08Z  55  eks.amazonaws.com
2026-10-11T04:31:12Z  2026-10-11T06:00:46Z  48  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling
2026-10-11T04:31:33Z  2026-10-11T06:01:34Z  110  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS
2026-10-11T04:31:33Z  2026-10-11T06:01:34Z  60  eks-nodegroup.amazonaws.com
2026-10-11T04:31:52Z  2026-10-11T07:25:01Z  62  arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1
2026-10-11T04:32:31Z  2026-10-11T07:23:44Z  171  arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77
2026-10-11T04:32:38Z  2026-10-11T06:46:25Z  99  Unknown
2026-10-11T04:32:56Z  2026-10-11T05:58:00Z  18  arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497
2026-10-11T04:33:50Z  2026-10-11T05:55:21Z  34  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe
2026-10-11T04:39:57Z  2026-10-11T06:01:03Z  15  cloudtrail.amazonaws.com
2026-10-11T04:42:19Z  2026-10-11T07:15:14Z  10  arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api
2026-10-11T04:42:19Z  2026-10-11T05:56:07Z  27  lambda.amazonaws.com
2026-10-11T04:42:48Z  2026-10-11T04:48:52Z  153  arn:aws:iam::111122223333:root
2026-10-11T04:43:09Z  2026-10-11T05:48:49Z  2  arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api
2026-10-11T04:46:49Z  2026-10-11T05:49:49Z  20  arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer
2026-10-11T04:47:07Z  2026-10-11T05:42:00Z  5  autoscaling.amazonaws.com
2026-10-11T04:49:21Z  2026-10-11T05:53:30Z  10  ec2.amazonaws.com
2026-10-11T04:54:22Z  2026-10-11T06:22:58Z  788  arn:aws:iam::111122223333:user/blue-team-2
2026-10-11T04:55:21Z  2026-10-11T04:55:21Z  1  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession
2026-10-11T04:55:21Z  2026-10-11T05:55:23Z  74  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession
2026-10-11T04:58:00Z  2026-10-11T05:58:01Z  6  arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s
2026-10-11T05:00:03Z  2026-10-11T06:00:43Z  26  states.amazonaws.com
2026-10-11T05:00:04Z  2026-10-11T07:23:48Z  18  arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api
2026-10-11T05:00:08Z  2026-10-11T07:23:49Z  13  arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector
2026-10-11T05:09:58Z  2026-10-11T05:09:58Z  1  arn:aws:iam::111122223333:user/AWSAccount
2026-10-11T05:27:49Z  2026-10-11T05:29:59Z  3  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession
2026-10-11T05:52:46Z  2026-10-11T05:52:48Z  2  arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery
2026-10-11T05:55:21Z  2026-10-11T05:55:21Z  1  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession
2026-10-11T05:55:21Z  2026-10-11T05:55:21Z  1  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession
2026-10-11T07:10:20Z  2026-10-11T07:19:22Z  8  arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring
```

실행한 명령:
```
jq -r '.Records|map(. + {u:(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)})|group_by([.u,.eventName,.eventSource])|map({u:.[0].u, n:.[0].eventName, s:.[0].eventSource, c:length, f:(map(.eventTime)|min)})|sort_by(.f)[]|"\(.f)  \(.c)  \(.u)  \(.n)  \(.s)"' cloudtrail.json | sed -e 's#arn:aws:[a-z]*::111122223333:##' -e 's#\.amazonaws\.com##'
```
결과:
```
2026-10-11T04:30:01Z  1  user/blue-team-1  GetEnvironmentStatus  cloudshell
2026-10-11T04:30:02Z  404  user/blue-team-1  GetCallerIdentity  sts
2026-10-11T04:30:02Z  342  user/blue-team-1  GetCommandInvocation  ssm
2026-10-11T04:30:02Z  18  user/blue-team-1  PutCredentials  cloudshell
2026-10-11T04:30:02Z  112  user/blue-team-1  Search  resource-explorer-2
2026-10-11T04:30:07Z  10  assumed-role/ec2-ssmrole/i-026754fe07a870049  ListInstanceAssociations  ssm
2026-10-11T04:30:09Z  254  user/blue-team-1  FilterLogEvents  logs
2026-10-11T04:30:11Z  9  user/blue-team-1  GetFunction20150331v2  lambda
2026-10-11T04:30:12Z  2256  assumed-role/ec2-ssmrole/i-026754fe07a870049  FilterLogEvents  logs
2026-10-11T04:30:13Z  103  delivery.logs  CreateLogStream  logs.amazonaws.com
2026-10-11T04:30:14Z  9  user/blue-team-1  DescribeLogStreams  logs
2026-10-11T04:30:15Z  1  user/blue-team-1  GetBucketEncryption  s3
2026-10-11T04:30:25Z  56  config  AssumeRole  sts.amazonaws.com
2026-10-11T04:30:31Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListDataSets  dataexchange
2026-10-11T04:30:31Z  18  resource-explorer-2  AssumeRole  sts.amazonaws.com
2026-10-11T04:30:38Z  44  user/blue-team-1  DescribeTrails  cloudtrail
2026-10-11T04:30:38Z  20  user/blue-team-1  ListEventDataStores  cloudtrail
2026-10-11T04:30:38Z  41  user/blue-team-1  ListNotificationHubs  notifications
2026-10-11T04:30:38Z  14  user/blue-team-1  ListTrails  cloudtrail
2026-10-11T04:30:38Z  671  user/blue-team-1  LookupEvents  cloudtrail
2026-10-11T04:30:38Z  262  user/blue-team-1  SendCommand  ssm
2026-10-11T04:30:39Z  420  user/blue-team-1  DescribeAlarms  monitoring
2026-10-11T04:30:39Z  7  user/blue-team-1  DescribeAutoScalingGroups  autoscaling
2026-10-11T04:30:39Z  7  user/blue-team-1  DescribeAvailabilityZones  ec2
2026-10-11T04:30:39Z  34  user/blue-team-1  DescribeInstanceStatus  ec2
2026-10-11T04:30:39Z  17  user/blue-team-1  DescribeLoadBalancers  elasticloadbalancing
2026-10-11T04:30:39Z  33  user/blue-team-1  DescribeRegions  ec2
2026-10-11T04:30:39Z  11  user/blue-team-1  DescribeVolumeStatus  ec2
2026-10-11T04:30:39Z  47  user/blue-team-1  GetTrailStatus  cloudtrail
2026-10-11T04:30:39Z  8  assumed-role/ec2-ssmrole/i-026754fe07a870049  GetCallerIdentity  sts
2026-10-11T04:30:40Z  17  user/blue-team-1  DescribeAccountAttributes  ec2
2026-10-11T04:30:40Z  13  user/blue-team-1  DescribeAddresses  ec2
2026-10-11T04:30:40Z  7  user/blue-team-1  DescribeCapacityReservations  ec2
2026-10-11T04:30:40Z  7  user/blue-team-1  DescribeHosts  ec2
2026-10-11T04:30:40Z  62  user/blue-team-1  DescribeInstances  ec2
2026-10-11T04:30:40Z  7  user/blue-team-1  DescribeKeyPairs  ec2
2026-10-11T04:30:40Z  7  user/blue-team-1  DescribeLaunchTemplates  ec2
2026-10-11T04:30:40Z  7  user/blue-team-1  DescribePlacementGroups  ec2
2026-10-11T04:30:40Z  15  user/blue-team-1  DescribeSecurityGroups  ec2
2026-10-11T04:30:40Z  61  user/blue-team-1  DescribeSnapshots  ec2
2026-10-11T04:30:40Z  15  user/blue-team-1  DescribeTags  ec2
2026-10-11T04:30:40Z  14  user/blue-team-1  DescribeVolumes  ec2
2026-10-11T04:30:41Z  2  user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit  AssumeRoleWithWebIdentity  sts
2026-10-11T04:30:45Z  1  assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3  CreateLogStream  logs
2026-10-11T04:30:47Z  9  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeIndexPolicies  logs
2026-10-11T04:30:47Z  9  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeLogGroups  logs
2026-10-11T04:30:47Z  9  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeResourcePolicies  logs
2026-10-11T04:30:47Z  10  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  GetResource  cloudcontrolapi
2026-10-11T04:30:47Z  9  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListTagsForResource  logs
2026-10-11T04:30:49Z  7  AWS Internal  AssumeRole  sts
2026-10-11T04:30:49Z  24  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  CreateNetworkInterface  ec2
2026-10-11T04:30:49Z  24  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  CreateNetworkInterfacePermission  ec2
2026-10-11T04:30:49Z  14  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  DescribeNetworkInterfaces  ec2
2026-10-11T04:30:49Z  7  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  DescribeSecurityGroups  ec2
2026-10-11T04:30:49Z  7  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  DescribeSubnets  ec2
2026-10-11T04:30:49Z  7  assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS  DescribeVpcs  ec2
2026-10-11T04:30:50Z  5  user/blue-team-1  DescribeApplicationStatus  ec2
2026-10-11T04:30:50Z  28  user/blue-team-1  DescribeInstanceAttribute  ec2
2026-10-11T04:30:50Z  6  user/blue-team-1  DescribeInstanceCreditSpecifications  ec2
2026-10-11T04:30:50Z  5  user/blue-team-1  DescribeInstanceImageMetadata  ec2
2026-10-11T04:30:50Z  13  user/blue-team-1  DescribeInstanceInformation  ssm
2026-10-11T04:30:50Z  15  user/blue-team-1  DescribeNetworkInterfaces  ec2
2026-10-11T04:30:50Z  6  user/blue-team-1  DescribeReplaceRootVolumeTasks  ec2
2026-10-11T04:30:50Z  6  user/blue-team-1  GetEnrollmentStatus  compute-optimizer
2026-10-11T04:30:50Z  17  user/blue-team-1  GetEventSelectors  cloudtrail
2026-10-11T04:30:50Z  2  user/blue-team-1  GetInsightSelectors  cloudtrail
2026-10-11T04:30:50Z  2  user/blue-team-1  ListTags  cloudtrail
2026-10-11T04:30:51Z  5  user/blue-team-1  DescribeImages  ec2
2026-10-11T04:30:51Z  6  user/blue-team-1  DescribeSubnets  ec2
2026-10-11T04:30:51Z  11  user/blue-team-1  DescribeVpcs  ec2
2026-10-11T04:30:53Z  95  user/blue-team-1  DescribeMetricFilters  logs
2026-10-11T04:31:06Z  4  assumed-role/AWSServiceRoleForSecurityHubV2/securityhub  GetResources  tagging
2026-10-11T04:31:06Z  4  securityhub  AssumeRole  sts.amazonaws.com
2026-10-11T04:31:08Z  13  assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe  GetCallerIdentity  sts
2026-10-11T04:31:08Z  55  eks  AssumeRole  sts.amazonaws.com
2026-10-11T04:31:12Z  28  user/blue-team-1  CreateOAuth2Token  signin
2026-10-11T04:31:12Z  46  assumed-role/AWSServiceRoleForAutoScaling/AutoScaling  DescribeInstanceStatus  ec2
2026-10-11T04:31:30Z  1  user/blue-team-1  CancelCommand  ssm
2026-10-11T04:31:33Z  30  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeAutoScalingGroups  autoscaling
2026-10-11T04:31:33Z  20  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeLaunchTemplateVersions  ec2
2026-10-11T04:31:33Z  10  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeSecurityGroups  ec2
2026-10-11T04:31:33Z  10  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeSubnets  ec2
2026-10-11T04:31:33Z  10  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  GetCallerIdentity  sts
2026-10-11T04:31:33Z  60  eks-nodegroup  AssumeRole  sts.amazonaws.com
2026-10-11T04:31:34Z  20  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeRouteTables  ec2
2026-10-11T04:31:34Z  10  assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS  DescribeWarmPool  autoscaling
2026-10-11T04:31:52Z  2  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  DescribeSubnets  ec2
2026-10-11T04:31:53Z  6  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  CreateNetworkInterface  ec2
2026-10-11T04:31:53Z  1  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  DescribeInstances  ec2
2026-10-11T04:31:54Z  6  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  AttachNetworkInterface  ec2
2026-10-11T04:31:54Z  6  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  ModifyNetworkInterfaceAttribute  ec2
2026-10-11T04:32:31Z  9  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  ListInstanceAssociations  ssm
2026-10-11T04:32:38Z  46  Unknown  OpenDataChannel  ssm
2026-10-11T04:32:38Z  12  user/blue-team-1  StartSession  ssm
2026-10-11T04:32:38Z  18  assumed-role/ec2-ssmrole/i-026754fe07a870049  CreateDataChannel  ssm
2026-10-11T04:32:51Z  22  user/blue-team-1  DescribeConfigurationRecorderStatus  config
2026-10-11T04:32:51Z  22  user/blue-team-1  DescribeConfigurationRecorders  config
2026-10-11T04:32:51Z  18  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  GetFunction20150331v2  lambda
2026-10-11T04:32:54Z  4  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  GetStage  apigateway
2026-10-11T04:32:56Z  18  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497  DescribeInstances  ec2
2026-10-11T04:33:01Z  41  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  UpdateInstanceInformation  ssm
2026-10-11T04:33:20Z  16  user/blue-team-1  DescribeSecurityGroupRules  ec2
2026-10-11T04:33:29Z  2  assumed-role/ec2-ssmrole/i-026754fe07a870049  StartSession  ssm
2026-10-11T04:33:31Z  12  user/blue-team-1  DescribeManagedPrefixLists  ec2
2026-10-11T04:33:37Z  41  assumed-role/ec2-ssmrole/i-026754fe07a870049  UpdateInstanceInformation  ssm
2026-10-11T04:33:44Z  13  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  GetCallerIdentity  sts
2026-10-11T04:33:50Z  3  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeInstances  ec2
2026-10-11T04:33:50Z  2  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeNetworkInterfaces  ec2
2026-10-11T04:33:55Z  7  user/blue-team-1  ListDiscoveredResources  config
2026-10-11T04:33:56Z  2  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  DescribeNetworkInterfaces  ec2
2026-10-11T04:33:56Z  6  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  DetachNetworkInterface  ec2
2026-10-11T04:33:58Z  23  user/blue-team-1  DescribeLogGroups  logs
2026-10-11T04:33:58Z  20  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1  DeleteNetworkInterface  ec2
2026-10-11T04:33:59Z  3  user/blue-team-1  GetStage  apigateway
2026-10-11T04:35:07Z  27  user/blue-team-1  ListIndexes  resource-explorer-2
2026-10-11T04:35:12Z  1  user/blue-team-1  DescribeIamInstanceProfileAssociations  ec2
2026-10-11T04:35:30Z  3  user/blue-team-1  ListBuckets  s3
2026-10-11T04:35:47Z  9  user/blue-team-1  GetOTelEnrichmentConfiguration  monitoring
2026-10-11T04:35:47Z  14  user/blue-team-1  ListSinks  oam
2026-10-11T04:35:48Z  15  user/blue-team-1  GetBucketVersioning  s3
2026-10-11T04:35:49Z  5  user/blue-team-1  GetBucketOwnershipControls  s3
2026-10-11T04:35:49Z  33  user/blue-team-1  ListProblems  application-insights
2026-10-11T04:35:50Z  6  user/blue-team-1  GetDashboard  monitoring
2026-10-11T04:35:50Z  12  user/blue-team-1  ListGroups  resource-groups
2026-10-11T04:36:03Z  1  user/blue-team-1  DescribePolicies  autoscaling
2026-10-11T04:36:03Z  1  user/blue-team-1  DescribeScalingPolicies  autoscaling
2026-10-11T04:36:03Z  2  user/blue-team-1  ListSubscriptions  sns
2026-10-11T04:36:03Z  1  user/blue-team-1  ListTopics  sns
2026-10-11T04:36:04Z  15  user/blue-team-1  ListDashboards  monitoring
2026-10-11T04:36:08Z  39  user/blue-team-1  GetTelemetryEvaluationStatus  observabilityadmin
2026-10-11T04:36:08Z  31  user/blue-team-1  GetTelemetryEvaluationStatusForOrganization  observabilityadmin
2026-10-11T04:36:11Z  15  user/blue-team-1  ListTelemetryPipelines  observabilityadmin
2026-10-11T04:36:11Z  15  user/blue-team-1  ListTelemetryRules  observabilityadmin
2026-10-11T04:36:19Z  4  user/blue-team-1  GetBucketObjectLockConfiguration  s3
2026-10-11T04:37:35Z  16  Unknown  SignUp  cognito-idp
2026-10-11T04:38:54Z  3  user/blue-team-1  TerminateSession  ssm
2026-10-11T04:39:07Z  10  user/blue-team-1  DescribeInsightRules  monitoring
2026-10-11T04:39:07Z  7  user/blue-team-1  ListLogAnomalyDetectors  logs
2026-10-11T04:39:07Z  5  user/blue-team-1  ListSyslogConfigurations  logs
2026-10-11T04:39:08Z  27  user/blue-team-
[... 출력 44,733자 중 앞 12,000자만]
```

실행한 명령:
```
jq -r '.Records|map(. + {u:(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)})|group_by([.u,.eventName,.eventSource])|map({u:.[0].u, n:.[0].eventName, s:.[0].eventSource, c:length, f:(map(.eventTime)|min)})|sort_by(.f)[]|"\(.f)  \(.c)  \(.u)  \(.n)  \(.s)"' cloudtrail.json | sed -e 's#arn:aws:[a-z]*::111122223333:##' -e 's#\.amazonaws\.com##' | sed -n '139,270p'
```
결과:
```
2026-10-11T04:39:07Z  5  user/blue-team-1  ListSyslogConfigurations  logs
2026-10-11T04:39:08Z  27  user/blue-team-1  DescribeAccountPolicies  logs
2026-10-11T04:39:08Z  10  user/blue-team-1  ListS3TableIntegrations  observabilityadmin
2026-10-11T04:39:11Z  5  user/blue-team-1  ListAnomalies  logs
2026-10-11T04:39:33Z  5  user/blue-team-1  AuthorizeSecurityGroupIngress  ec2
2026-10-11T04:39:57Z  15  cloudtrail  GetBucketAcl  s3.amazonaws.com
2026-10-11T04:40:13Z  4  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeSecurityGroups  ec2
2026-10-11T04:40:37Z  1  assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe  ListAssociatedAccessPolicies  eks
2026-10-11T04:41:08Z  7  user/blue-team-1  DescribeLookupTables  logs
2026-10-11T04:41:08Z  4  user/blue-team-1  DescribeQueryDefinitions  logs
2026-10-11T04:41:08Z  28  user/blue-team-1  ListAggregateLogGroupSummaries  logs
2026-10-11T04:41:08Z  23  user/blue-team-1  ListLogGroups  logs
2026-10-11T04:41:08Z  91  user/blue-team-1  StartQuery  logs
2026-10-11T04:41:09Z  3  user/blue-team-1  DescribeFieldIndexes  logs
2026-10-11T04:41:09Z  21  user/blue-team-1  GetLogGroupFields  logs
2026-10-11T04:41:09Z  154  user/blue-team-1  GetQueryResults  logs
2026-10-11T04:41:09Z  6  user/blue-team-1  GetResources  tagging
2026-10-11T04:41:32Z  4  Unknown  ConfirmSignUp  cognito-idp
2026-10-11T04:41:54Z  17  Unknown  InitiateAuth  cognito-idp
2026-10-11T04:42:04Z  16  Unknown  RespondToAuthChallenge  cognito-idp
2026-10-11T04:42:19Z  1  assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api  Decrypt  kms
2026-10-11T04:42:19Z  27  lambda  AssumeRole  sts.amazonaws.com
2026-10-11T04:42:24Z  9  assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api  CreateLogStream  logs
2026-10-11T04:42:48Z  6  root  GetCallerIdentity  sts
2026-10-11T04:42:49Z  4  root  DescribeAddresses  ec2
2026-10-11T04:42:49Z  2  root  DescribeAddressesAttribute  ec2
2026-10-11T04:42:49Z  2  root  DescribeContinuousBackups  dynamodb
2026-10-11T04:42:49Z  4  root  DescribeLogGroups  logs
2026-10-11T04:42:49Z  2  root  DescribeManagedPrefixLists  ec2
2026-10-11T04:42:49Z  12  root  DescribeSecurityGroupRules  ec2
2026-10-11T04:42:49Z  6  root  DescribeSecurityGroups  ec2
2026-10-11T04:42:49Z  4  root  DescribeTable  dynamodb
2026-10-11T04:42:49Z  8  root  DescribeTags  elasticloadbalancing
2026-10-11T04:42:49Z  2  root  DescribeTargetGroupAttributes  elasticloadbalancing
2026-10-11T04:42:49Z  2  root  DescribeTargetGroups  elasticloadbalancing
2026-10-11T04:42:49Z  2  root  DescribeTimeToLive  dynamodb
2026-10-11T04:42:49Z  9  root  GetApi  apigateway
2026-10-11T04:42:49Z  2  root  GetManagedPrefixListEntries  ec2
2026-10-11T04:42:49Z  4  root  ListTagsForResource  logs
2026-10-11T04:42:49Z  2  root  ListTagsOfResource  dynamodb
2026-10-11T04:42:50Z  2  root  DescribeCapacityReservation  elasticloadbalancing
2026-10-11T04:42:50Z  2  root  DescribeLoadBalancerAttributes  elasticloadbalancing
2026-10-11T04:42:50Z  2  root  DescribeLoadBalancers  elasticloadbalancing
2026-10-11T04:42:50Z  6  root  DescribeNetworkInterfaces  ec2
2026-10-11T04:42:50Z  2  root  DescribePrefixLists  ec2
2026-10-11T04:42:50Z  2  root  DescribeVpcEndpoints  ec2
2026-10-11T04:42:50Z  2  root  GetParameter  ssm
2026-10-11T04:42:50Z  4  root  GetStage  apigateway
2026-10-11T04:42:51Z  2  root  DescribeListenerAttributes  elasticloadbalancing
2026-10-11T04:42:51Z  2  root  DescribeListeners  elasticloadbalancing
2026-10-11T04:42:52Z  4  root  Decrypt  kms
2026-10-11T04:42:52Z  2  root  DescribeRules  elasticloadbalancing
2026-10-11T04:42:52Z  4  root  GetFunction20150331v2  lambda
2026-10-11T04:42:52Z  4  root  GetFunctionCodeSigningConfig  lambda
2026-10-11T04:42:52Z  2  root  GetIntegration  apigateway
2026-10-11T04:42:52Z  2  root  GetPolicy20150331v2  lambda
2026-10-11T04:42:52Z  4  root  ListVersionsByFunction20150331  lambda
2026-10-11T04:42:53Z  2  root  DescribeStateMachine  states
2026-10-11T04:42:53Z  2  root  GetRoute  apigateway
2026-10-11T04:42:53Z  2  root  ListStateMachineVersions  states
2026-10-11T04:42:53Z  2  root  ListTagsForResource  states
2026-10-11T04:42:55Z  2  root  DescribeInstanceTypes  ec2
2026-10-11T04:42:55Z  2  root  DescribeInstances  ec2
2026-10-11T04:42:55Z  2  root  DescribeTags  ec2
2026-10-11T04:42:55Z  2  root  DescribeVpcs  ec2
2026-10-11T04:42:56Z  8  root  DescribeInstanceAttribute  ec2
2026-10-11T04:42:56Z  2  root  DescribeVolumes  ec2
2026-10-11T04:42:57Z  2  root  DescribeInstanceCreditSpecifications  ec2
2026-10-11T04:42:57Z  2  root  DescribeTargetHealth  elasticloadbalancing
2026-10-11T04:43:00Z  2  root  UpdateStage  apigateway
2026-10-11T04:43:09Z  2  user/system:serviceaccount:device-support:portal-api  AssumeRoleWithWebIdentity  sts
2026-10-11T04:44:35Z  146  assumed-role/ec2-ssmrole/i-026754fe07a870049  DescribeLogStreams  logs
2026-10-11T04:45:11Z  725  assumed-role/ec2-ssmrole/i-026754fe07a870049  GetLogEvents  logs
2026-10-11T04:45:32Z  16  user/blue-team-1  ListCommands  ssm
2026-10-11T04:45:52Z  12  user/blue-team-1  GetDocument  ssm
2026-10-11T04:45:52Z  12  user/blue-team-1  ListCommandInvocations  ssm
2026-10-11T04:46:49Z  16  assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer  Decrypt  kms
2026-10-11T04:46:53Z  4  assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer  CreateLogStream  logs
2026-10-11T04:47:07Z  5  autoscaling  AssumeRole  sts.amazonaws.com
2026-10-11T04:48:47Z  8  user/blue-team-1  DescribeFlowLogs  ec2
2026-10-11T04:48:50Z  7  user/blue-team-1  DescribeCluster  eks
2026-10-11T04:49:02Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListCertificates  iot
2026-10-11T04:49:02Z  3  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListResources  cloudcontrolapi
2026-10-11T04:49:05Z  33  user/blue-team-1  Decrypt  kms
2026-10-11T04:49:05Z  5  user/blue-team-1  ListFunctions20150331  lambda
2026-10-11T04:49:21Z  10  ec2  AssumeRole  sts.amazonaws.com
2026-10-11T04:49:39Z  7  user/blue-team-1  GetWebACL  wafv2
2026-10-11T04:50:16Z  1  user/blue-team-1  GetDashboard  cloudtrail
2026-10-11T04:50:33Z  2  assumed-role/AWSServiceRoleForAutoScaling/AutoScaling  DescribeInstances  ec2
2026-10-11T04:51:55Z  1  user/blue-team-1  ListAccessEntries  eks
2026-10-11T04:52:26Z  2  user/blue-team-1  ListAssociatedAccessPolicies  eks
2026-10-11T04:52:29Z  1  user/blue-team-1  DescribeStacks  cloudformation
2026-10-11T04:52:31Z  8  user/blue-team-1  ListDetectors  guardduty
2026-10-11T04:53:14Z  4  user/blue-team-1  DescribeQueries  logs
2026-10-11T04:53:14Z  3  user/blue-team-1  ListCentralizationRulesForOrganization  observabilityadmin
2026-10-11T04:53:15Z  3  user/blue-team-1  ListTelemetryRulesForOrganization  observabilityadmin
2026-10-11T04:54:06Z  1  user/blue-team-1  GetBucketPublicAccessBlock  s3
2026-10-11T04:54:22Z  11  user/blue-team-2  DescribeRegions  ec2
2026-10-11T04:54:22Z  14  user/blue-team-2  DescribeTrails  cloudtrail
2026-10-11T04:54:22Z  3  user/blue-team-2  ListTrails  cloudtrail
2026-10-11T04:54:23Z  13  user/blue-team-2  GetTrailStatus  cloudtrail
2026-10-11T04:54:24Z  12  user/blue-team-2  GetEventSelectors  cloudtrail
2026-10-11T04:54:24Z  6  user/blue-team-2  GetInsightSelectors  cloudtrail
2026-10-11T04:54:24Z  13  user/blue-team-2  ListNotificationHubs  notifications
2026-10-11T04:54:24Z  6  user/blue-team-2  ListTags  cloudtrail
2026-10-11T04:54:34Z  12  user/blue-team-2  ListIndexes  resource-explorer-2
2026-10-11T04:54:34Z  29  user/blue-team-2  Search  resource-explorer-2
2026-10-11T04:55:21Z  3  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeLoadBalancerAttributes  elasticloadbalancing
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeLoadBalancers  elasticloadbalancing
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeTags  elasticloadbalancing
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession  DescribePolicies  autoscaling
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeEventSubscriptions  dms
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeRule  events
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListAuthorizers  iot
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListBrokers  amazonmq
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListCrls  rolesanywhere
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListDirectoryRegistrations  pca-connector-ad
2026-10-11T04:55:21Z  2  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListEventBuses  events
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListFlows  mediaconnect
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListModelBiasJobDefinitions  sagemaker
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListProfiles  transfer
2026-10-11T04:55:21Z  14  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListResources  cloudcontrolapi
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListRules  events
2026-10-11T04:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListTargetsByRule  events
2026-10-11T04:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListScripts  gamelift
2026-10-11T04:57:19Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListTrails  cloudtrail
2026-10-11T04:58:00Z  6  assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s  DescribeNetworkInterfaces  ec2
2026-10-11T04:58:32Z  2  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeTrails  cloudtrail
2026-10-11T04:58:32Z  2  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  GetTrailStatus  cloudtrail
2026-10-11T05:00:03Z  1  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  GetCallerIdentity  sts
2026-10-11T05:00:03Z  85  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  StartExecution  states
2026-10-11T05:00:03Z  26  states  AssumeRole  sts.amazonaws.com
```

실행한 명령:
```
jq -r '.Records|map(. + {u:(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)})|group_by([.u,.eventName,.eventSource])|map({u:.[0].u, n:.[0].eventName, s:.[0].eventSource, c:length, f:(map(.eventTime)|min)})|sort_by(.f)[]|"\(.f)  \(.c)  \(.u)  \(.n)  \(.s)"' cloudtrail.json | sed -e 's#arn:aws:[a-z]*::111122223333:##' -e 's#\.amazonaws\.com##' | sed -n '271,400p'
```
결과:
```
2026-10-11T05:00:04Z  5  assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api  Decrypt  kms
2026-10-11T05:00:08Z  13  assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector  CreateLogStream  logs
2026-10-11T05:00:10Z  13  assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api  CreateLogStream  logs
2026-10-11T05:01:17Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListMalwareProtectionPlans  guardduty
2026-10-11T05:04:14Z  10  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  DescribeExecution  states
2026-10-11T05:09:19Z  7  user/blue-team-1  ListIdentityPools  cognito-identity
2026-10-11T05:09:19Z  10  user/blue-team-1  ListUserPools  cognito-idp
2026-10-11T05:09:55Z  1  user/blue-team-1  ResumeSession  ssm
2026-10-11T05:09:58Z  1  user/AWSAccount  GetBucketVersioning  s3
2026-10-11T05:10:45Z  56  user/blue-team-1  DescribeUserPool  cognito-idp
2026-10-11T05:10:45Z  12  user/blue-team-1  DescribeUserPoolClient  cognito-idp
2026-10-11T05:10:45Z  8  user/blue-team-1  ListUserPoolClients  cognito-idp
2026-10-11T05:10:45Z  52  user/blue-team-1  ListUserPoolReplicas  cognito-idp
2026-10-11T05:10:48Z  1  user/blue-team-2  DescribeConfigurationRecorderStatus  config
2026-10-11T05:10:48Z  1  user/blue-team-2  DescribeConfigurationRecorders  config
2026-10-11T05:10:48Z  6  user/blue-team-2  LookupEvents  cloudtrail
2026-10-11T05:10:52Z  1  user/blue-team-2  GetDashboard  cloudtrail
2026-10-11T05:10:52Z  3  user/blue-team-2  ListEventDataStores  cloudtrail
2026-10-11T05:11:23Z  1  user/blue-team-1  ListStateMachines  states
2026-10-11T05:11:24Z  2  user/blue-team-1  ListRules  events
2026-10-11T05:14:04Z  14  user/blue-team-2  DescribeAddresses  ec2
2026-10-11T05:14:04Z  36  user/blue-team-2  DescribeAlarms  monitoring
2026-10-11T05:14:04Z  6  user/blue-team-2  DescribeAutoScalingGroups  autoscaling
2026-10-11T05:14:04Z  6  user/blue-team-2  DescribeHosts  ec2
2026-10-11T05:14:04Z  42  user/blue-team-2  DescribeInstances  ec2
2026-10-11T05:14:04Z  6  user/blue-team-2  DescribeKeyPairs  ec2
2026-10-11T05:14:04Z  12  user/blue-team-2  DescribeLoadBalancers  elasticloadbalancing
2026-10-11T05:14:04Z  6  user/blue-team-2  DescribePlacementGroups  ec2
2026-10-11T05:14:04Z  9  user/blue-team-2  DescribeSecurityGroups  ec2
2026-10-11T05:14:04Z  6  user/blue-team-2  DescribeSnapshots  ec2
2026-10-11T05:14:04Z  12  user/blue-team-2  DescribeVolumes  ec2
2026-10-11T05:14:05Z  11  user/blue-team-2  DescribeAccountAttributes  ec2
2026-10-11T05:14:05Z  6  user/blue-team-2  DescribeAvailabilityZones  ec2
2026-10-11T05:14:05Z  6  user/blue-team-2  DescribeCapacityReservations  ec2
2026-10-11T05:14:05Z  36  user/blue-team-2  DescribeInstanceStatus  ec2
2026-10-11T05:14:05Z  6  user/blue-team-2  DescribeLaunchTemplates  ec2
2026-10-11T05:14:05Z  10  user/blue-team-2  DescribeVolumeStatus  ec2
2026-10-11T05:16:19Z  63  user/blue-team-1  CheckCapacity  wafv2
2026-10-11T05:16:19Z  31  user/blue-team-1  ListWebACLs  wafv2
2026-10-11T05:16:54Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListDataQualityRulesets  glue
2026-10-11T05:17:02Z  8  user/blue-team-1  GetLoggingConfiguration  wafv2
2026-10-11T05:19:01Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeVerifiedAccessInstances  ec2
2026-10-11T05:21:07Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListFirewallPolicies  network-firewall
2026-10-11T05:21:39Z  2  user/blue-team-1  GetProvisionedLimit  cognito-idp
2026-10-11T05:21:40Z  2  user/blue-team-1  GetServiceQuota  servicequotas
2026-10-11T05:21:45Z  24  user/blue-team-2  DescribeInstanceTypes  ec2
2026-10-11T05:21:45Z  11  user/blue-team-2  DescribeTags  ec2
2026-10-11T05:21:50Z  6  user/blue-team-2  DescribeApplicationStatus  ec2
2026-10-11T05:21:50Z  12  user/blue-team-2  DescribeInstanceAttribute  ec2
2026-10-11T05:21:50Z  6  user/blue-team-2  DescribeInstanceCreditSpecifications  ec2
2026-10-11T05:21:50Z  6  user/blue-team-2  DescribeInstanceImageMetadata  ec2
2026-10-11T05:21:50Z  7  user/blue-team-2  DescribeInstanceInformation  ssm
2026-10-11T05:21:50Z  12  user/blue-team-2  DescribeNetworkInterfaces  ec2
2026-10-11T05:21:50Z  6  user/blue-team-2  DescribeReplaceRootVolumeTasks  ec2
2026-10-11T05:21:50Z  6  user/blue-team-2  GetEnrollmentStatus  compute-optimizer
2026-10-11T05:21:51Z  8  user/blue-team-2  DescribeImages  ec2
2026-10-11T05:21:51Z  8  user/blue-team-2  DescribeSubnets  ec2
2026-10-11T05:21:51Z  6  user/blue-team-2  DescribeVpcs  ec2
2026-10-11T05:21:55Z  65  user/blue-team-2  DescribeMetricFilters  logs
2026-10-11T05:22:33Z  1  user/blue-team-1  DescribeTargetGroups  elasticloadbalancing
2026-10-11T05:22:36Z  1  user/blue-team-2  GetOTelEnrichmentConfiguration  monitoring
2026-10-11T05:22:36Z  1  user/blue-team-2  ListSinks  oam
2026-10-11T05:22:37Z  4  user/blue-team-2  ListProblems  application-insights
2026-10-11T05:22:38Z  1  user/blue-team-2  GetDashboard  monitoring
2026-10-11T05:22:38Z  2  user/blue-team-2  ListGroups  resource-groups
2026-10-11T05:22:40Z  2  user/blue-team-2  ListDashboards  monitoring
2026-10-11T05:22:43Z  6  user/blue-team-1  PutRetentionPolicy  logs
2026-10-11T05:22:45Z  1  user/blue-team-2  GetBucketVersioning  s3
2026-10-11T05:22:46Z  1  user/blue-team-2  GetBucketOwnershipControls  s3
2026-10-11T05:22:53Z  1  user/blue-team-1  PutBucketVersioning  s3
2026-10-11T05:22:56Z  3  user/blue-team-1  GetBucketLocation  s3
2026-10-11T05:23:00Z  1  user/blue-team-1  PutEventSelectors  cloudtrail
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetAccelerateConfiguration  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketAbac  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketAcl  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketCors  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketEncryption  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketLifecycle  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketLogging  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketNotification  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketObjectLockConfiguration  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketPolicy  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketPublicAccessBlock  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketReplication  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketRequestPayment  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketTagging  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketVersioning  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetBucketWebsite  s3
2026-10-11T05:23:34Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  ListBuckets  s3
2026-10-11T05:24:06Z  1  user/blue-team-1  DescribeIndexPolicies  logs
2026-10-11T05:24:06Z  1  user/blue-team-1  GetTransformer  logs
2026-10-11T05:24:08Z  17  user/blue-team-1  GetLogEvents  logs
2026-10-11T05:24:22Z  41  user/blue-team-1  ListUserImportJobs  cognito-idp
2026-10-11T05:24:22Z  22  user/blue-team-1  ListUsers  cognito-idp
2026-10-11T05:24:23Z  40  user/blue-team-1  GetCSVHeader  cognito-idp
2026-10-11T05:24:33Z  2  user/blue-team-1  DescribeTargetHealth  elasticloadbalancing
2026-10-11T05:24:36Z  36  user/blue-team-1  AdminGetUser  cognito-idp
2026-10-11T05:24:36Z  15  user/blue-team-1  AdminListGroupsForUser  cognito-idp
2026-10-11T05:24:51Z  1  user/blue-team-2  ListPlatformApplications  sns
2026-10-11T05:24:51Z  3  user/blue-team-2  ListSubscriptions  sns
2026-10-11T05:24:51Z  4  user/blue-team-2  ListTopics  sns
2026-10-11T05:24:59Z  1  user/blue-team-2  DescribeKey  kms
2026-10-11T05:24:59Z  1  user/blue-team-2  ListAliases  kms
2026-10-11T05:25:23Z  1  user/blue-team-2  CreateTopic  sns
2026-10-11T05:25:24Z  2  user/blue-team-2  GetTopicAttributes  sns
2026-10-11T05:25:24Z  1  user/blue-team-2  ListSubscriptionsByTopic  sns
2026-10-11T05:25:24Z  1  user/blue-team-2  ListTagsForResource  sns
2026-10-11T05:26:06Z  4  user/blue-team-2  Decrypt  kms
2026-10-11T05:26:06Z  1  user/blue-team-2  ListFunctions20150331  lambda
2026-10-11T05:27:36Z  1  user/blue-team-2  CreateEnvironment  cloudshell
2026-10-11T05:27:36Z  3  user/blue-team-2  DescribeEnvironments  cloudshell
2026-10-11T05:27:36Z  19  user/blue-team-2  GetEnvironmentStatus  cloudshell
2026-10-11T05:27:38Z  8  user/blue-team-2  CreateSession  cloudshell
2026-10-11T05:27:38Z  34  user/blue-team-2  GetCallerIdentity  sts
2026-10-11T05:27:38Z  7  user/blue-team-2  PutCredentials  cloudshell
2026-10-11T05:27:38Z  3  user/blue-team-2  RedeemCode  cloudshell
2026-10-11T05:27:49Z  2  assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession  GetTopicAttributes  sns
2026-10-11T05:27:49Z  1  assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession  ListTagsForResource  sns
2026-10-11T05:28:45Z  1  user/blue-team-2  DeleteTopic  sns
2026-10-11T05:28:59Z  1  user/blue-team-2  SendHeartBeat  cloudshell
2026-10-11T05:29:12Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  GetTopicAttributes  sns
2026-10-11T05:29:47Z  10  user/blue-team-2  DeleteSession  cloudshell
2026-10-11T05:30:04Z  5  user/blue-team-1  ListGroups  cognito-idp
2026-10-11T05:30:06Z  1  user/blue-team-1  GetUserPoolMfaConfig  cognito-idp
2026-10-11T05:30:13Z  4  user/blue-team-1  ModifyInstanceAttribute  ec2
2026-10-11T05:30:42Z  2  user/blue-team-2  DescribeRouteTables  ec2
2026-10-11T05:30:45Z  1  user/blue-team-2  GetConnectionStatus  ssm
2026-10-11T05:30:45Z  1  user/blue-team-2  GetDocument  ssm
2026-10-11T05:30:45Z  1  user/blue-team-2  GetServiceSetting  ssm
2026-10-11T05:30:54Z  1  user/blue-team-2  DescribeInstanceProperties  ssm
```

실행한 명령:
```
jq -r '.Records|map(. + {u:(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)})|group_by([.u,.eventName,.eventSource])|map({u:.[0].u, n:.[0].eventName, s:.[0].eventSource, c:length, f:(map(.eventTime)|min)})|sort_by(.f)[]|"\(.f)  \(.c)  \(.u)  \(.n)  \(.s)"' cloudtrail.json | sed -e 's#arn:aws:[a-z]*::111122223333:##' -e 's#\.amazonaws\.com##' | sed -n '401,529p'
```
결과:
```
2026-10-11T05:30:54Z  3  user/blue-team-2  DescribeSessions  ssm
2026-10-11T05:30:54Z  1  user/blue-team-2  StartSession  ssm
2026-10-11T05:31:47Z  3  user/blue-team-1  CreateSnapshot  ec2
2026-10-11T05:31:55Z  1  user/blue-team-2  GetEventConfiguration  cloudtrail
2026-10-11T05:31:58Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeFlowLogs  ec2
2026-10-11T05:32:08Z  4  user/blue-team-2  ListClusters  eks
2026-10-11T05:32:09Z  3  user/blue-team-2  DescribeCluster  eks
2026-10-11T05:32:09Z  2  user/blue-team-2  DescribeClusterVersions  eks
2026-10-11T05:32:09Z  2  user/blue-team-2  ListCertificateAuthorities  eks
2026-10-11T05:32:12Z  31  user/blue-team-2  AccessKubernetesApi  eks
2026-10-11T05:32:12Z  6  user/blue-team-2  DescribeAddon  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  DescribeAddonVersions  eks
2026-10-11T05:32:12Z  3  user/blue-team-2  DescribeNodegroup  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  ListAccessEntries  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  ListAddons  eks
2026-10-11T05:32:12Z  3  user/blue-team-2  ListCapabilities  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  ListFargateProfiles  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  ListIdentityProviderConfigs  eks
2026-10-11T05:32:12Z  8  user/blue-team-2  ListInsights  eks
2026-10-11T05:32:12Z  3  user/blue-team-2  ListNodegroups  eks
2026-10-11T05:32:12Z  2  user/blue-team-2  ListPodIdentityAssociations  eks
2026-10-11T05:32:13Z  1  user/blue-team-1  AdminListUserAuthEvents  cognito-idp
2026-10-11T05:32:13Z  3  user/blue-team-2  DescribeLaunchTemplateVersions  ec2
2026-10-11T05:32:13Z  3  user/blue-team-2  GetParameter  ssm
2026-10-11T05:32:13Z  2  user/blue-team-2  ListMonitors  networkflowmonitor
2026-10-11T05:32:13Z  2  user/blue-team-2  ListScrapers  aps
2026-10-11T05:32:16Z  4  user/blue-team-2  DescribeAccessEntry  eks
2026-10-11T05:32:16Z  4  user/blue-team-2  ListAssociatedAccessPolicies  eks
2026-10-11T05:36:38Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListIdentityPools  cognito-identity
2026-10-11T05:38:14Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  DescribeTransitGatewayAttachments  ec2
2026-10-11T05:38:38Z  1  user/blue-team-1  RevokeSecurityGroupIngress  ec2
2026-10-11T05:41:52Z  3  user/blue-team-1  GetAuthorizers  apigateway
2026-10-11T05:45:56Z  1  user/blue-team-2  DescribeStacks  cloudformation
2026-10-11T05:45:56Z  1  user/blue-team-2  ListConfigurationManagers  ssm-quicksetup
2026-10-11T05:45:56Z  1  user/blue-team-2  ListConfigurations  ssm-quicksetup
2026-10-11T05:45:58Z  13  user/blue-team-2  ResumeSession  ssm
2026-10-11T05:50:26Z  30  user/blue-team-1  GetSampledRequests  wafv2
2026-10-11T05:52:03Z  5  user/blue-team-1  GetStages  apigateway
2026-10-11T05:52:28Z  1  user/blue-team-1  ListIPSets  wafv2
2026-10-11T05:52:29Z  1  user/blue-team-1  ListRegexPatternSets  wafv2
2026-10-11T05:52:30Z  1  user/blue-team-1  ListRuleGroups  wafv2
2026-10-11T05:52:46Z  1  assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery  Decrypt  kms
2026-10-11T05:52:48Z  1  assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery  CreateLogStream  logs
2026-10-11T05:54:32Z  7  user/blue-team-1  GetApis  apigateway
2026-10-11T05:54:32Z  7  user/blue-team-1  GetRestApis  apigateway
2026-10-11T05:54:41Z  4  user/blue-team-1  GetApi  apigateway
2026-10-11T05:54:41Z  5  user/blue-team-1  GetRoutes  apigateway
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  DescribeTrails  cloudtrail
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  GetTrailStatus  cloudtrail
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe  ListTags  cloudtrail
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession  ListPipelines  codepipeline
2026-10-11T05:55:21Z  2  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeCluster  eks
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeIntegrations  rds
2026-10-11T05:55:21Z  6  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeListeners  elasticloadbalancing
2026-10-11T05:55:21Z  4  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeLoadBalancers  elasticloadbalancing
2026-10-11T05:55:21Z  6  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeTags  elasticloadbalancing
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  GetUsagePlans  apigateway
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListBillingGroups  iot
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListBuilds  gamelift
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListClusters  eks
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListMonitoringSchedules  sagemaker
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListServers  transfer
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListTasks  datasync
2026-10-11T05:55:21Z  1  assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession  DescribeVpcEndpointServiceConfigurations  ec2
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeNetworkInsightsAnalyses  ec2
2026-10-11T05:55:22Z  3  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeTargetGroupAttributes  elasticloadbalancing
2026-10-11T05:55:22Z  4  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeTargetGroups  elasticloadbalancing
2026-10-11T05:55:22Z  3  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  DescribeTargetHealth  elasticloadbalancing
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  GetDataCatalog  athena
2026-10-11T05:55:22Z  3  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  GetResource  cloudcontrolapi
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListDataCatalogs  athena
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListDedicatedIpPools  ses
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListEventDataStores  cloudtrail
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListLocations  datasync
2026-10-11T05:55:22Z  1  assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession  ListPipelines  osis
2026-10-11T05:55:48Z  1  assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2  ListStackSets  cloudformation
2026-10-11T05:56:44Z  1  user/blue-team-1  DescribeNatGateways  ec2
2026-10-11T05:56:59Z  1  user/blue-team-1  DescribeRouteTables  ec2
2026-10-11T05:56:59Z  3  user/blue-team-1  GetApiKeys  apigateway
2026-10-11T05:57:05Z  1  user/blue-team-1  GetClientCertificates  apigateway
2026-10-11T05:57:06Z  1  user/blue-team-1  GetUsagePlans  apigateway
2026-10-11T05:57:08Z  1  user/blue-team-1  GetAccount  apigateway
2026-10-11T05:57:12Z  2  user/blue-team-1  ListPortalProducts  apigateway
2026-10-11T05:57:16Z  1  user/blue-team-1  ListPortals  apigateway
2026-10-11T05:57:20Z  6  user/blue-team-1  GetVpcLinks  apigateway
2026-10-11T05:57:27Z  1  user/blue-team-1  GetDomainNameAccessAssociations  apigateway
2026-10-11T05:57:29Z  1  user/blue-team-1  GetDomainNames  apigateway
2026-10-11T05:57:29Z  1  user/blue-team-2  DescribeInsightsRefresh  eks
2026-10-11T05:57:53Z  2  user/blue-team-1  ListLogGroupsForQuery  logs
2026-10-11T05:58:00Z  3  user/blue-team-1  GetLogRecord  logs
2026-10-11T05:58:46Z  1  user/blue-team-2  DescribeSecurityGroupRules  ec2
2026-10-11T06:00:20Z  7  user/blue-team-1  GetAccountSettings20160819  lambda
2026-10-11T06:00:39Z  1  user/blue-team-1  GetFunctionConcurrency  lambda
2026-10-11T06:00:39Z  2  user/blue-team-1  GetFunctionConfiguration20150331v2  lambda
2026-10-11T06:00:39Z  2  user/blue-team-1  GetFunctionEventInvokeConfig  lambda
2026-10-11T06:00:39Z  1  user/blue-team-1  GetRuntimeManagementConfig  lambda
2026-10-11T06:00:39Z  1  user/blue-team-1  ListAliases20150331  lambda
2026-10-11T06:00:39Z  3  user/blue-team-1  ListEventSourceMappings20150331  lambda
2026-10-11T06:00:39Z  1  user/blue-team-1  ListFunctionUrlConfigs  lambda
2026-10-11T06:00:39Z  1  user/blue-team-1  ListProvisionedConcurrencyConfigs  lambda
2026-10-11T06:00:39Z  2  user/blue-team-1  ListVersionsByFunction20150331  lambda
2026-10-11T06:00:40Z  1  user/blue-team-1  DescribeStackResources  cloudformation
2026-10-11T06:00:40Z  1  user/blue-team-1  GetFunctionCodeSigningConfig  lambda
2026-10-11T06:00:40Z  1  user/blue-team-1  GetIntegrations  apigateway
2026-10-11T06:00:40Z  1  user/blue-team-1  GetPolicy20150331  lambda
2026-10-11T06:00:40Z  1  user/blue-team-1  GetRestApi  apigateway
2026-10-11T06:00:40Z  2  user/blue-team-1  ListSchedulesByTarget  scheduler
2026-10-11T06:00:41Z  1  user/blue-team-1  DescribeSchema  schemas
2026-10-11T06:00:41Z  1  user/blue-team-1  ListTags20170331  lambda
2026-10-11T06:01:41Z  1  user/blue-team-1  GetView  resource-explorer-2
2026-10-11T06:01:41Z  1  user/blue-team-1  ListResources  resource-explorer-2
2026-10-11T06:01:41Z  2  user/blue-team-1  ListViews  resource-explorer-2
2026-10-11T06:07:52Z  3  user/blue-team-1  StartEnvironment  cloudshell
2026-10-11T06:07:59Z  21  user/blue-team-1  CreateSession  cloudshell
2026-10-11T06:07:59Z  27  user/blue-team-1  DeleteSession  cloudshell
2026-10-11T06:08:06Z  8  user/blue-team-1  SendHeartBeat  cloudshell
2026-10-11T06:09:40Z  2  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  CreateDataChannel  ssm
2026-10-11T06:14:37Z  1  user/blue-team-1  CreateIPSet  wafv2
2026-10-11T06:18:22Z  4  user/blue-team-1  UpdateWebACL  wafv2
2026-10-11T06:19:31Z  5  user/blue-team-1  UpdateIPSet  wafv2
2026-10-11T06:39:20Z  2  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  StartSession  ssm
2026-10-11T06:43:19Z  3  user/blue-team-1  CreateBackup  dynamodb
2026-10-11T07:09:19Z  1  user/blue-team-1  CreateDetector  guardduty
2026-10-11T07:10:20Z  2  assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring  PutAccountSettingDefault  ecs
2026-10-11T07:10:31Z  2  user/blue-team-1  UpdateDetector  guardduty
2026-10-11T07:11:37Z  2  assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77  SendCommand  ssm
2026-10-11T07:18:33Z  1  assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring  CreateAddon  eks
2026-10-11T07:18:34Z  1  assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring  AuthorizeSecurityGroupIngress  ec2
2026-10-11T07:18:34Z  1  assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring  CreateSecurityGroup  ec2
```

## 채팅 AI

# CloudTrail 1차 분석 결과

## 요약

**이 로그만으로는 침해를 확정할 수 없습니다.** 다만 확인이 필요한 의심 지점이 3곳 있습니다.

1. **patchsignal portal EC2(i-05816900800807b77)의 역할이 SSM 세션 시작과 명령 실행을 했습니다.** 가장 의심스럽습니다.
2. **root 계정이 6분 동안 153건을 호출했고, 그중 설정 변경(UpdateStage)도 있습니다.**
3. **인증 없는 Cognito 회원가입과 로그인이 16건 있습니다.**

나머지 대부분은 AWS 서비스의 자동 동작이거나 블루팀의 조사 작업으로 보입니다. 각 항목을 확정하려면 **sourceIPAddress**를 봐야 합니다. 아래에 추가 jq 명령을 정리했습니다.

---

## 먼저 알아야 할 이 로그의 한계

| 빠진 것 | 이유 | 영향 |
|---|---|---|
| IAM 변경(CreateUser, CreateAccessKey, AttachPolicy 등) | IAM은 글로벌 서비스라 **us-east-1**에 기록됨 | 백도어 계정을 만들었어도 이 파일에는 **안 보일 수 있음** |
| 콘솔 로그인(ConsoleLogin) | 대부분 us-east-1에 기록됨 | root가 콘솔로 들어왔는지 확인 불가 |
| S3 GetObject, Lambda Invoke | 데이터 이벤트라 별도 설정 필요 | 데이터 유출 여부 확인 불가 |
| 04:30 UTC(13:30 KST) 이전 | 파일 범위 밖 | **최초 침투는 그 이전일 수 있음** |
| GuardDuty | **07:09 UTC에 처음 켜짐**(blue-team-1 CreateDetector) | 사고 시간대의 GuardDuty 탐지 기록은 없음 |
| requestParameters, userAgent | 추출하지 않음 | "무엇을" 바꿨는지는 원본 로그가 있어야 확인 가능 |

이 파일에 IAM 이벤트가 하나도 없는 건 정상입니다. 그렇다고 "IAM 변경이 없었다"는 뜻은 아닙니다.

---

## 정상으로 보이는 것 (제외해도 됨)

- **AWSServiceRoleFor…** (Config, ResourceExplorer, EKS, AutoScaling, SecurityHub, GuardDuty): AWS가 자동으로 수행하는 조회
- **midnight-…-eks-node**의 네트워크 인터페이스 생성·연결·삭제: EKS 네트워크 플러그인(VPC CNI)의 일반 동작
- **Unknown OpenDataChannel 46건**: SSM 세션을 열 때 

## 사용자

메시지가 중간에 끊겨서 왔어요. "정상으로 보이는 것" 목록의 "Unknown OpenDataChannel 46건: SSM 세션을 열 때"에서 끝났어요. 그래서 "아래에 추가 jq 명령을 정리했습니다"라고 하신 jq 명령을 하나도 못 받았어요. 이번에는 아무것도 뽑지 않았어요. 끊긴 뒷부분과 jq 명령을 다시 보내 주시면 그대로 실행해서 결과를 붙일게요.

'로그의 한계' 표에서 파일 내용과 다른 부분이 있어서 알려 드려요.
- **requestParameters, userAgent:** 제가 뽑지 않은 게 아니라, 제 CloudTrail 파일에 처음부터 없어요. 각 기록에는 eventTime, eventSource, eventName, sourceIPAddress, userIdentity만 있어요. userIdentity 안에는 type, arn, accessKeyId, accountId, invokedBy 중 일부만 들어 있어요. 그래서 "무엇을 바꿨는지"를 보여 줄 원본 내용은 저한테 없어요.
- **sourceIPAddress:** 이 항목은 파일에 있어서 뽑을 수 있어요.
- **기간:** 파일은 2026-10-11T04:30:01Z부터 시작해요. 그 이전 기록은 없어요.
- **us-east-1 등 다른 리전 CloudTrail:** 확인 못 해요(그 로그는 없어요).

## 채팅 AI



## 사용자

이번 메시지는 내용 없이 빈 채로 왔어요. 그래서 아무것도 뽑지 않았어요. 지난번에 말씀하신 끊긴 분석 뒷부분과 추가 jq 명령(sourceIPAddress 확인용)도 아직 못 받았어요. 다시 보내 주시면 그대로 실행해서 결과를 붙일게요.

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# AWS 계정 침해 의심 최종 보고서 (CloudTrail 1개 파일 기준)

앞선 답변이 두 번 끊기고 비어서 혼란을 드려 죄송합니다. 지적해 주신 '로그의 한계' 표의 오류도 아래에 반영했습니다. **requestParameters와 userAgent는 파일에 처음부터 없는 항목**이고, **sourceIPAddress는 파일에 있지만 이번 분석에서는 뽑지 않은 상태**입니다.

---

## 1. 결론 요약

**이 파일만으로는 침해를 확정할 수 없습니다.** 다만 **침해가 진행 중일 가능성이 높은 지점이 하나** 있고, 확인이 필요한 지점이 몇 개 더 있습니다.

| 우선순위 | 대상 | 판단 |
|---|---|---|
| 🔴 높음 | **patchsignal portal EC2 역할** (i-05816900800807b77) | EC2 역할이 할 일이 아닌 호출(신원 확인, Lambda 코드 조회, SSM 세션 시작, 원격 명령)을 함. **자격증명 탈취 후 내부 이동 패턴과 일치** |
| 🔴 높음 | **root 계정** | 6분간 153건을 API로 호출했고, API Gateway 설정을 변경(UpdateStage)함 |
| 🟠 중간 | **user/AWSAccount** | 정체를 알 수 없는 주체가 S3 버전 관리 설정을 조회함 |
| 🟠 중간 | **인증 없는 Cognito 가입/로그인** | 가입 16건, 로그인 17건. 외부 공격자가 앱 계정을 만들었을 가능성 |
| 🟡 확인 | **블루팀이 바꾼 설정** | 보안그룹 인바운드 허용 5건 대비 회수 1건, CloudTrail 이벤트 선택기 변경 등 |

이 리전(ap-northeast-2)의 관리 이벤트에서는 **보이지 않은 것**도 있습니다. EC2 대량 생성(채굴), CloudTrail 중지·삭제, S3 버킷 정책 변경, Cognito Identity Pool을 통한 AWS 자격증명 발급이 없었습니다. 다른 리전과 IAM은 확인하지 못했습니다.

---

## 2. 이 분석의 한계 (수정본)

| 한계 | 영향 |
|---|---|
| 파일에는 eventTime, eventSource, eventName, sourceIPAddress, userIdentity만 있음 (requestParameters, userAgent 없음) | **무엇을 바꿨는지**(어떤 포트를 열었는지, 어떤 명령을 보냈는지 등)는 알 수 없음 |
| sourceIPAddress는 있지만 분석하지 못함

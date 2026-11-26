## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

# AWS 계정 침해 의심 대응 가이드

보안 전문가가 아니어도 순서대로 따라 하시면 됩니다. **(1) 피해 확산 막기 → (2) 로그 수집 → (3) 분석 → (4) 복구** 순서로 진행합니다.

---

## 0. 먼저 확인할 것

어디서 연락을 받으셨나요?
- **AWS에서 온 메일/Support 케이스** (예: "Your AWS account may be compromised", "Exposed access key")라면 **어떤 액세스 키가 노출됐는지 메일에 적혀 있는 경우가 많습니다.** 메일 원문을 보내 주세요(계정 ID는 가려도 됩니다).
- **GuardDuty, 외부 제보, 비용 급증** 등 다른 경로라면 그 내용을 알려 주세요.

회사에 보안 담당자나 보안팀이 있다면 지금 바로 공유하세요.

---

## 1. 지금 바로 할 일 (피해 확산 차단)

⚠️ **아직 리소스를 삭제하지 마세요.** 증거가 사라집니다. 대신 **비활성화·차단**만 합니다.

### 1-1. 루트 계정 보호
- 루트 비밀번호를 변경하세요.
- 루트 MFA가 켜져 있는지 확인하세요.
- 루트 계정에 액세스 키가 있다면 **비활성화**하세요.

### 1-2. 노출된 액세스 키 비활성화
노출된 키를 알고 있다면 삭제하지 말고 **Inactive로 변경**합니다.
```bash
aws iam update-access-key --user-name <사용자명> --access-key-id <AKIA...> --status Inactive
```
> 이 키를 운영 서비스에서 쓰고 있다면 해당 서비스가 멈출 수 있습니다. 공격자가 계속 쓰는 것보다는 낫지만, 팀에 미리 알리세요.

### 1-3. 비용 확인
**Billing → Bills / Cost Explorer**에서 오늘 비용이 튀었는지 보세요. 침해 사고에서 가장 흔한 형태는 **모든 리전에 EC2를 대량으로 띄워 코인 채굴을 하는 것**입니다.

---

## 2. 로그 뽑기

### 시간대 주의
CloudTrail은 **UTC 기준**입니다. 한국시간 13:30은 **UTC 04:30**입니다.

### 2-1. CloudTrail 설정 확인
```bash
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail 이름>   # IsLogging이 true인지 확인
```
Trail이 없어도 최근 90일의 관리 이벤트는 **Event history**로 조회할 수 있습니다.

### 2-2. 모든 리전의 13:30 이후 이벤트 추출
공격자는 평소 안 쓰는 리전을 노리는 경우가 많아서 **전 리전**을 봐야 합니다. 날짜는 오늘 날짜로 바꿔서 실행하세요.

```bash
START="2025-01-15T04:30:00Z"   # ← 오늘 날짜로 수정 (UTC 04:30 = KST 13:30)
mkdir -p ct_logs

for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r =="
  aws cloudtrail lookup-events --region "$r" --start-time "$START" \
    --output json > "ct_logs/$r.json"
done
```

### 2-3. 보기 좋게 요약 (jq 필요)
```bash
for f in ct_logs/*.json; do
  jq -r '.Events[].CloudTrailEvent | fromjson |
    [.eventTime, .awsRegion, .eventName, (.userIdentity.arn // .userIdentity.type),
     .sourceIPAddress, (.userAgent|tostring)[0:60], (.errorCode // "-")] | @tsv' "$f"
done | sort > summary.tsv
```

### 2-4. IAM 현황 스냅샷
```bash
aws iam generate-credential-report && sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > credential_report.csv
aws iam list-users --output json > users.json
```

**보내 주실 것:** `summary.tsv`, `credential_report.csv`, 받으신 알림 원문.
> 공유 전에 **비밀번호나 시크릿 값, 액세스 키 전체 문자열**이 들어 있으면 가려 주세요. 키 ID 앞뒤 몇 글자만 남기면 충분합니다.

---

## 3. 로그에서 먼저 볼 위험 신호

직접 훑어보실 때 아래 이벤트 이름을 검색해 보세요.

| 분류 | 이벤트 이름 | 의미 |
|---|---|---|
| **지속성 확보** | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` | 공격자가 자기 계정·키를 만든 흔적 |
| **권한 상승** | `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `UpdateAssumeRolePolicy` | AdministratorAccess를 붙이는 경우가 많음 |
| **흔적 지우기** | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `DeleteDetector` | 매우 위험한 신호 |
| **자원 남용** | `RunInstances`, `CreateKeyPair`, `ImportKeyPair`, `RequestSpotInstances` | 코인 채굴 |
| **데이터 유출** | `GetSecretValue`, `GetParameter`, `PutBucketPolicy`, `PutBucketAcl`, `PutPublicAccessBlock` | 시크릿 탈취, S3 공개 전환 |
| **네트워크 개방** | `AuthorizeSecurityGroupIngress` | 0.0.0.0/0 개방 |
| **정찰** | `GetCallerIdentity`, `ListBuckets`, `ListUsers` 등이 짧은 시간에 몰림 | 탈취한 키를 시험해 본 흔적 |

추가로 확인할 점:
- **sourceIPAddress**가 회사나 서비스에서 쓰는 IP가 아닌 곳
- **userAgent**가 평소와 다른 것 (예: 평소엔 SDK인데 갑자기 `python-requests`, `curl`, 낯선 도구 이름)
- **errorCode = AccessDenied**가 연달아 나오는 것 (공격자가 권한을 이것저것 시도해 본 흔적)

---

## 4. 흔한 침입 원인

나중에 원인을 고칠 때 참고하세요.
1. **액세스 키가 GitHub에 커밋됨.** 가장 흔하고, public repo는 몇 분 안에 털립니다. 과거 커밋 히스토리도 확인해야 합니다.
2. `.env` 파일이나 설정 파일이 웹에서 노출됨
3. **EC2 앱의 SSRF 취약점**으로 인스턴스 메타데이터(IMDS)에서 임시 자격 증명이 탈취됨. IMDSv2를 강제하면 막을 수 있습니다.
4. 퇴사자나 외주 업체의 키가 방치됨
5. 콘솔 사용자 비밀번호가 약하거나 MFA가 없음

---

## 5. 정리·복구 (분석 후 진행)

로그를 같이 보고 범위를 확정한 뒤에 진행하는 것을 권합니다.
- 공격자가 만든 IAM 사용자, 키, 정책, 역할 제거
- 공격자가 띄운 인스턴스와 Lambda 종료 (**전 리전** 확인)
- 영향받은 키와 시크릿 전부 교체 (DB 비밀번호, API 키 등 Secrets Manager나 Parameter Store에 있던 것 포함)
- GuardDuty 활성화, CloudTrail 전 리전 Trail 구성
- AWS Support에 케이스 열기: 침해로 인한 요금은 조정해 주는 경우가 있습니다.

---

**다음 단계:** 2번의 결과물(`summary.tsv`, `credential_report.csv`)과 알림 원문을 보내 주시면 어떤 키로 들어왔는지, 무엇을 했는지, 무엇을 지워야 하는지 같이 분석해 드리겠습니다. 명령어 실행 중 에러가 나면 에러 메시지를 그대로 붙여 주세요.

## 사용자

요청하신 내용을 뽑아서 아래에 붙입니다.

**연락받은 경로:** 계정이 공격받았을 수 있다는 연락만 받았습니다. 알림 원문은 저한테 없어서 보내 드릴 수 없습니다. 이 계정은 보안 공방전 연습 환경입니다.

**1번(루트 보호, 키 비활성화, 비용 확인):** 지금 AWS 콘솔과 CLI에 접속할 수 없어서 하지 못했습니다. 비용도 확인 못 함(그 로그는 없어요).

**2번 로그:** 제가 가진 건 미리 내려받아 둔 CloudTrail 기록 파일(`cloudtrail.json`) 하나뿐입니다. 그래서 명령을 그대로 실행하지 않고 이 파일에서 jq로 뽑았습니다.
- **2-1 Trail 설정과 상태(describe-trails, get-trail-status):** 확인 못 함(그 로그는 없어요).
- **2-2 전 리전 lookup-events:** 다른 리전은 확인 못 함(그 로그는 없어요). 파일은 ap-northeast-2 기록이고, 기간은 UTC 2026-10-11 04:30:01 ~ 07:25:01(KST 13:30~16:25)입니다.
- **2-3 summary.tsv:** 레코드에 `awsRegion`, `userAgent` 필드가 없어서 이 두 칸은 뽑을 수 없습니다. 있는 필드는 eventTime, eventSource, eventName, sourceIPAddress, userIdentity, errorCode(204건), requestParameters(1173건)입니다.
  - 전체가 10,223건이라 한 줄씩 다 붙이면 잘립니다. 그래서 다음 3가지로 나눠 뽑았습니다.
  - ① 사용자(arn)별 이벤트 수, IP 개수, 처음·마지막 시각, 에러 수
  - ② 3번 표의 위험 이벤트 이름(정찰 줄 제외) 중 파일에 있는 것 전부: 11건
  - ③ errorCode가 있는 이벤트를 arn, IP, eventName, errorCode별로 센 것
  - 특정 사용자나 IP, 시간대의 전체 줄이 필요하시면 말씀해 주세요. 그 조건으로 다시 뽑겠습니다.
- **2-4 credential_report.csv, users.json:** 확인 못 함(그 로그는 없어요).

**계정 참고:** 결과에 나오는 blue-team-1, blue-team-2는 우리 팀원 계정입니다. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했습니다. PatchSignal은 원래 있던 우리 서비스입니다.

실행한 명령:
```
echo "# 전체 이벤트 수: $(jq '.Records|length' cloudtrail.json), 기간: $(jq -r '.Records|map(.eventTime)|min' cloudtrail.json) ~ $(jq -r '.Records|map(.eventTime)|max' cloudtrail.json)"; echo -e "# arn\t이벤트수\tIP개수\t처음\t마지막\t에러수"; jq -r '.Records|group_by(.userIdentity.arn // .userIdentity.type)[]|[(.[0].userIdentity.arn // .[0].userIdentity.type), length, (map(.sourceIPAddress)|unique|length), (map(.eventTime)|min), (map(.eventTime)|max), (map(select(.errorCode))|length)]|@tsv' cloudtrail.json | sort -t$'\t' -k4
```
결과:
```
# 전체 이벤트 수: 10223, 기간: 2026-10-11T04:30:01Z ~ 2026-10-11T07:25:01Z
# arn	이벤트수	IP개수	처음	마지막	에러수
arn:aws:iam::111122223333:user/blue-team-1	4814	13	2026-10-11T04:30:01Z	2026-10-11T07:23:36Z	73
arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	3207	1	2026-10-11T04:30:07Z	2026-10-11T07:23:37Z	4
AWSService	386	12	2026-10-11T04:30:13Z	2026-10-11T07:24:06Z	3
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	69	1	2026-10-11T04:30:31Z	2026-10-11T05:55:48Z	6
arn:aws:iam::111122223333:user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	2	1	2026-10-11T04:30:41Z	2026-10-11T05:30:35Z	0
arn:aws:sts::111122223333:assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3	1	1	2026-10-11T04:30:45Z	2026-10-11T04:30:45Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	83	1	2026-10-11T04:30:49Z	2026-10-11T07:15:50Z	62
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSecurityHubV2/securityhub	4	1	2026-10-11T04:31:06Z	2026-10-11T06:00:42Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	14	1	2026-10-11T04:31:08Z	2026-10-11T06:01:08Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling	48	1	2026-10-11T04:31:12Z	2026-10-11T06:00:46Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	110	1	2026-10-11T04:31:33Z	2026-10-11T06:01:34Z	0
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	62	2	2026-10-11T04:31:52Z	2026-10-11T07:25:01Z	15
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	171	4	2026-10-11T04:32:31Z	2026-10-11T07:23:44Z	4
Unknown	99	9	2026-10-11T04:32:38Z	2026-10-11T06:46:25Z	17
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497	18	1	2026-10-11T04:32:56Z	2026-10-11T05:58:00Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	34	1	2026-10-11T04:33:50Z	2026-10-11T05:55:21Z	7
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	10	10	2026-10-11T04:42:19Z	2026-10-11T07:15:14Z	0
arn:aws:iam::111122223333:root	153	6	2026-10-11T04:42:48Z	2026-10-11T04:48:52Z	0
arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	2	1	2026-10-11T04:43:09Z	2026-10-11T05:48:49Z	0
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	20	8	2026-10-11T04:46:49Z	2026-10-11T05:49:49Z	0
arn:aws:iam::111122223333:user/blue-team-2	788	10	2026-10-11T04:54:22Z	2026-10-11T06:22:58Z	10
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession	1	1	2026-10-11T04:55:21Z	2026-10-11T04:55:21Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	74	1	2026-10-11T04:55:21Z	2026-10-11T05:55:23Z	1
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s	6	1	2026-10-11T04:58:00Z	2026-10-11T05:58:01Z	0
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	18	17	2026-10-11T05:00:04Z	2026-10-11T07:23:48Z	0
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	13	13	2026-10-11T05:00:08Z	2026-10-11T07:23:49Z	0
arn:aws:iam::111122223333:user/AWSAccount	1	1	2026-10-11T05:09:58Z	2026-10-11T05:09:58Z	1
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	3	1	2026-10-11T05:27:49Z	2026-10-11T05:29:59Z	1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	2	2	2026-10-11T05:52:46Z	2026-10-11T05:52:48Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession	1	1	2026-10-11T05:55:21Z	2026-10-11T05:55:21Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession	1	1	2026-10-11T05:55:21Z	2026-10-11T05:55:21Z	0
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	8	1	2026-10-11T07:10:20Z	2026-10-11T07:19:22Z	0
```

실행한 명령:
```
jq -r '.Records[]|select(.eventName|IN("CreateUser","CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","PutUserPolicy","AttachRolePolicy","UpdateAssumeRolePolicy","StopLogging","DeleteTrail","UpdateTrail","DeleteDetector","RunInstances","CreateKeyPair","ImportKeyPair","RequestSpotInstances","GetSecretValue","GetParameter","PutBucketPolicy","PutBucketAcl","PutPublicAccessBlock","AuthorizeSecurityGroupIngress"))|[.eventTime, .eventName, (.userIdentity.arn // .userIdentity.type), .userIdentity.accessKeyId, .sourceIPAddress, (.errorCode // "-"), (.requestParameters|tojson)]|@tsv' cloudtrail.json
```
결과:
```
2026-10-11T04:39:33Z	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	ASIAA35E…DE4A	198.18.2.1	-	null
2026-10-11T04:42:50Z	GetParameter	arn:aws:iam::111122223333:root	ASIAFA49…29C2	198.18.0.3	-	{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}
2026-10-11T04:48:42Z	GetParameter	arn:aws:iam::111122223333:root	ASIAFA49…29C2	198.18.18.1	-	{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}
2026-10-11T05:09:28Z	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	ASIA8AA2…CB09	198.18.2.1	-	null
2026-10-11T05:09:29Z	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	ASIA8AA2…CB09	198.18.2.1	-	null
2026-10-11T05:27:36Z	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	ASIAF61C…0505	198.18.2.1	Client.DryRunOperation	null
2026-10-11T05:27:37Z	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	ASIAF61C…0505	198.18.2.1	-	null
2026-10-11T05:32:13Z	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	ASIAD175…1196	198.18.23.1	-	{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}
2026-10-11T05:57:21Z	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	ASIA241B…E78E	198.18.23.1	-	{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}
2026-10-11T05:57:54Z	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	ASIAA809…AE75	198.18.23.1	-	{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}
2026-10-11T07:18:34Z	AuthorizeSecurityGroupIngress	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	ASIA3CF9…09AC	guardduty.amazonaws.com	-	null
```

실행한 명령:
```
echo -e "# 에러 발생 이벤트 (arn, eventName, errorCode별 건수)"; jq -r '.Records[]|select(.errorCode)|[(.userIdentity.arn // .userIdentity.type), .sourceIPAddress, .eventName, .errorCode]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
# 에러 발생 이벤트 (arn, eventName, errorCode별 건수)
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	CreateNetworkInterfacePermission	Client.DryRunOperation
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	CreateNetworkInterface	Client.DryRunOperation
     14 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DeleteNetworkInterface	Client.InvalidParameterValue
     14 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	DescribeNetworkInterfaces	Client.DryRunOperation
     12 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	LookupEvents	ThrottlingException
     11 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	LookupEvents	ThrottlingException
     10 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	ListTelemetryRules	ValidationException
      6 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	DeleteSession	InvalidStatusException
      6 Unknown	198.18.7.1	SignUp	InvalidPasswordException
      5 arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	GetInsightSelectors	InsightNotEnabledException
      5 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	ListTelemetryRules	ValidationException
      4 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	GetStage	NotFoundException
      4 arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	GetBucketObjectLockConfiguration	ObjectLockConfigurationNotFoundError
      4 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	GetDashboard	DashboardNotFoundError
      4 Unknown	198.18.7.2	SignUp	InvalidPasswordException
      4 Unknown	198.18.7.2	RespondToAuthChallenge	NotAuthorizedException
      3 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	ListTelemetryRulesForOrganization	ValidationException
      3 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	ListCentralizationRulesForOrganization	UnauthorizedException
      3 Unknown	198.18.7.1	RespondToAuthChallenge	NotAuthorizedException
      3 AWSService	delivery.logs.amazonaws.com	CreateLogStream	ResourceAlreadyExistsException
      2 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	SendCommand	AccessDenied
      2 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied
      2 arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	GetInsightSelectors	InsightNotEnabledException
      2 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	LookupEvents	InvalidLookupAttributesException
      2 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	GetFunctionEventInvokeConfig	ResourceNotFoundException
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	StartSession	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	StartSession	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	DeleteNetworkInterface	Client.InvalidNetworkInterface.InUse
      1 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	FilterLogEvents	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	DescribeLogStreams	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	GetTopicAttributes	NotFoundException
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	GetResource	ResourceNotFoundException
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	config.amazonaws.com	GetTopicAttributes	NotFoundException
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com	GetDataCatalog	InvalidRequestException
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketWebsite	NoSuchWebsiteConfiguration
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketTagging	NoSuchTagSet
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketReplication	ReplicationConfigurationNotFoundError
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketObjectLockConfiguration	ObjectLockConfigurationNotFoundError
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketLifecycle	NoSuchLifecycleConfiguration
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	GetBucketCors	NoSuchCORSConfiguration
      1 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	DescribeNetworkInterfaces	Client.InvalidNetworkInterfaceID.NotFound
      1 arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	GetDocument	InvalidDocument
      1 arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	GetDashboard	ResourceNotFoundException
      1 arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	GetDashboard	DashboardNotFoundError
      1 arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	DescribeInsightsRefresh	ResourceNotFoundException
      1 arn:aws:iam::111122223333:user/blue-team-2	198.18.19.1	GetInsightSelectors	InsightNotEnabledException
      1 arn:aws:iam::111122223333:user/blue-team-1	AWS Internal	GetRestApi	NotFoundException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	GetDashboard	ResourceNotFoundException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	GetDashboard	DashboardNotFoundError
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	UpdateIPSet	WAFOptimisticLockException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	DescribeStackResources	ValidationException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	DescribeSchema	NotFoundException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	AdminListUserAuthEvents	UserPoolAddOnNotEnabledException
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress	Client.DryRunOperation
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	GetDashboard	DashboardNotFoundError
      1 arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2	GetBucketVersioning	AccessDenied
```

## 채팅 AI

# 1차 분석 결과

## 요약

이 파일만으로 확정할 수 있는 것은 없지만, **외부 IP(198.18.7.x)가 회원가입·로그인을 시도하고, 같은 IP가 PatchSignal 포털 서버의 EC2 역할 자격 증명으로 다른 서버 접속을 시도한 흔적**이 있습니다. 포털 서버에서 자격 증명이 탈취됐을 가능성이 가장 높습니다. 확인된 시도들은 `AccessDenied`로 실패했지만, **성공한 호출은 아직 보지 않았기 때문에** 피해 범위는 추가 조회가 필요합니다.

> 참고: 로그의 IP가 전부 198.18.0.0/15(테스트용 예약 대역)입니다. 연습 환경이라 IP가 가명 처리된 것으로 보입니다. 위치 추적은 할 수 없고, **파일 안에서 같은 IP끼리 연결 짓는 것만** 의미가 있습니다.

---

## 의심 지점 (위험도 순)

### 🔴 1. PatchSignal 포털 서버의 역할 자격 증명 탈취 의심
`patchsignal-ewc2enb8-portal-role/i-05816900800807b77`

- **EC2 인스턴스 역할인데 IP가 4개입니다.** 인스턴스 역할은 보통 그 서버 하나의 IP에서만 호출됩니다. IP가 여러 개라면 **자격 증명이 서버 밖으로 빠져나가 다른 곳에서 쓰였을** 가능성이 큽니다.
- 웹 포털 역할이 `SendCommand`(2회)와 `StartSession`(2회)을 호출했다가 거부됐습니다. 둘 다 **다른 서버에 명령을 실행하거나 접속하려는 시도**이고, 포털 앱이 정상적으로 할 일이 아닙니다.
- 이 호출의 출처는 **198.18.7.1**과 **198.18.50.1**입니다.

전형적인 시나리오는 이렇습니다. 포털 앱의 **SSRF 취약점**이나 원격 코드 실행으로 인스턴스 메타데이터(IMDS)에서 임시 자격 증명을 빼낸 뒤, 그 자격 증명으로 권한 확대나 내부 이동을 시도한 것입니다.

### 🔴 2. 198.18.7.1 / 198.18.7.2: 공격자 IP 후보
| IP | 한 일 |
|---|---|
| 198.18.7.1 | Cognito `SignUp` 실패 6회, `RespondToAuthChallenge` 실패 3회, **포털 역할로 `SendCommand`·`StartSession` 시도** |
| 198.18.7.2 | Cognito `SignUp` 실패 4회, `RespondToAuthChallenge` 실패 4회, 정체가 불분명한 `user/AWSAccount`로 S3 `GetBucketVersioning` 시도(거부) |

같은 IP가 **앱 회원가입 시도**와 **탈취한 것으로 보이는 AWS 자격 증명 사용**에 모두 등장합니다. 하나의 공격자로 볼 근거가 됩니다. 실패만 집계한 것이므로 **성공한 SignUp이나 로그인이 있었는지** 반드시 확인해야 합니다.

### 🟠 3. `ec2-ssmrole/i-026754fe07a870049`: 두 번째 서버 의심
- 인스턴스 역할로 `StartSession`(다른 서버 접속)을 2회, `FilterLogEvents`와 `DescribeLogStreams`(CloudWatch 로그 열람)를 시도했다가 거부됐습니다.
- IP는 1개(198.18.6.1)라서 자격 증명이 외부로 빠졌다기보다는 **누군가 이 서버 안에서 셸을 잡고 역할 권한을 시험해 본** 모양새입니다.
- 이벤트 3,207건 중 대부분은 SSM 에이전트의 주기적 호출일 수 있습니다. 내역을 봐야 판단할 수 있습니다.

### 🟠 4. 루트 계정 사용: 팀에 확인 필요
- 04:42:48~04:48:52, 약 6분 동안 이벤트 153건, IP 6개.
- AL2023 AMI 파라미터 조회는 보통 **콘솔에서 EC2 시작 화면을 열 때** 발생합니다. 이 파일에는 `RunInstances`가 없습니다.
- **팀원이나 운영 측에서 이 시간에 루트로 로그인한 사람이 있는지 꼭 확인하세요.** 아무도 없다면 가장 심각한 항목이 됩니다.

### 🟡 5. 그 외 확인 항목
- **pagesnap renderer 역할**(이벤트 20건, IP 8개): Lambda라면 IP가 여러 개인 것은 정상입니다. 다만 "페이지 렌더러"는 임의의 URL을 여는 기능이라 **SSRF의 단골 대상**입니다. 이벤트 내역을 봐야 합니다. `recovery` 역할(05:52)을 팀에서 실행했는지도 알려 주세요.
- **blue-team-1의 `AuthorizeSecurityGroupIngress` 4건**: `requestParameters`가 null이라 어떤 포트를 열었는지 보이지 않습니다. 팀원이 연 것이라도 **0.0.0.0/0으로 열려 있지 않은지** 현재 규칙을 확인해야 합니다.

### 정상으로 보이는 것
- GuardDuty의 `AuthorizeSecurityGroupIngress`(07:18): Runtime Monitoring을 켜면 AWS가 자동으로 만드는 보안 그룹입니다.
- EKS·VPC CNI의 `DryRunOperation`, `DeleteNetworkInterface` 에러: EKS가 평소에 내는 에러입니다.
- PatchSignal provider·feed 역할: 약 10분 간격으로 매번 다른 IP에서 호출됩니다. 예약 실행되는 Lambda의 정상 패턴으로 보입니다.

---

## 이 파일의 한계

- **IAM 이벤트는 보통 us-east-1에 기록됩니다.** 사용자 생성, 키 발급, 정책 부착 같은 지속성 흔적이 이 파일에 없다고 해서 **없었다는 뜻은 아닙니다**(아래 H번 명령으로 확인).
- 파일이 KST 13:30부터 시작합니다. 포털 역할은 13:32에 이미 활동하고 있어서 **침입은 그 전에 시작됐을 수 있습니다.**
- 지난번 위험 이벤트 목록은 기본 항목이었습니다. 이번 상황에 맞춰 범위를 넓혀야 합니다(아래 G번).

---

## 지금 해야 할 조치 (접속 가능한 팀원이 진행)

⚠️ 인스턴스를 **종료하거나 삭제하지 마세요.** 필요하면 EBS 스냅샷부터 떠 두세요.

**① 포털 인스턴스: IMDSv2 강제 및 탈취된 세션 무효화**
```bash
aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
  --http-tokens required --http-put-response-hop-limit 1
```
역할 이전에 발급된 임시 자격 증명을 무효화합니다. 콘솔에서는 **IAM → 역할 → patchsignal-ewc2enb8-portal-role → "활성 세션 취소"**를 누르면 되고, CLI로는 다음과 같습니다.
```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name patchsignal-ewc2enb8-portal-role \
  --policy-name RevokeOldSessions --policy-document "{
  \"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",
  \"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"$NOW\"}}}]}"
```
> 액세스 키를 비활성화하는 방법은 임시 자격 증명(ASIA...)에는 통하지 않습니다. 위처럼 세션을 취소해야 합니다. 취소하는 순간 포털 앱도 새 자격 증명을 받을 때까지 AWS 호출이 실패할 수 있습니다.
> 또 이 조치는 **이미 빼간 자격 증명만** 막습니다. 포털 앱의 취약점(SSRF나 원격 코드 실행)을 고치지 않으면 다시 털립니다. 백엔드 개발자시니 **포털 코드에서 사용자가 준 URL로 서버가 요청을 보내는 부분**이 있는지 먼저 봐 주세요.

**② `i-026754fe07a870049`:** ec2-ssmrole도 같은 방식으로 세션을 취소하고 IMDSv2를 강제합니다. 서버 안에 낯선 프로세스나 접속 흔적이 있는지도 확인합니다.

**③ 루트:** 팀에서 사용한 사람이 없다면 즉시 비밀번호를 변경하고 MFA를 확인합니다.

**④ Cognito:** 해당 사용자 풀에 오늘 새로 생긴 사용자가 있는지 확인합니다. 셀프 회원가입이 필요 없다면 끕니다.

**⑤ 보안 그룹:** blue-team-1이 수정한 그룹의 현재 규칙을 확인합니다.

---

## 다음으로 뽑아 주실 것

결과가 길면 앞부분만 붙여 주셔도 됩니다.

```bash
# A. 공격자 후보 IP의 전체 타임라인
jq -r '.Records[]|select(.sourceIPAddress|IN("198.18.7.1","198.18.7.2","198.18.50.1"))|[.eventTime,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,(.errorCode//"-"),(.requestParameters|tojson|.[0:200])]|@tsv' cloudtrail.json | sort

# B. 포털 역할의 이벤트 이름·IP별 집계 (성공 포함)
jq -r '.Records[]|select((.userIdentity.arn//"")|test("portal-role"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn

# C. ec2-ssmrole 집계
jq -r '.Records[]|select((.userIdentity.arn//"")|test("ec2-ssmrole"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn

# D. 루트 집계
jq -r '.Records[]|select((.userIdentity.arn//"")|test(":root$"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn

# E. Unknown(비인증 호출) 집계: 성공한 SignUp/로그인 확인용
jq -r '.Records[]|select(.userIdentity.arn==null and .userIdentity.type=="Unknown")|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn

# F. pagesnap 역할 전체 (32줄)
jq -r '.Records[]|select((.userIdentity.arn//"")|test("pagesnap"))|[.eventTime,.eventSource,.eventName,(.userIdentity.arn|split("/")[1]),.sourceIPAddress,(.errorCode//"-")]|@tsv' cloudtrail.json | sort

# G. 팀원·AWS 서비스를 뺀 나머지의 "변경" 이벤트 집계 (조회성 호출 제외)
jq -r '.Records[]|select((.userIdentity.arn//.userIdentity.type)|test("AWSServiceRole|blue-team|^AWSService$")|not)|select(.eventName|test("^(Describe|Get|List|Lookup|Head|Search|Filter)")|not)|[(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn

# H. 이 파일에 IAM/STS 이벤트가 들어 있는지 (0이면 us-east-1 로그가 별도로 필요)
jq -r '.Records[]|select(.eventSource|IN("iam.amazonaws.com","sts.amazonaws.com","signin.amazonaws.com"))|.eventSource+" "+.eventName' cloudtrail.json | sort | uniq -c
```

**팀에 확인해 주실 것:**
1. 13:42~13:48(KST)에 루트로 로그인한 사람이 있나요?
2. 팀원들이 쓴 IP는 무엇인가요? blue-team-1의 IP 13개가 모두 팀원 것인지 확인이 필요합니다.
3. pagesnap `recovery` 역할 실행과 보안 그룹 변경 4건은 팀에서 한 작업인가요?
4. PatchSignal 포털은 어떤 기능을 하나요? 특히 URL을 입력받아 서버가 가져오는 기능이 있는지 알려 주세요.

이 결과를 보면 **어떻게 들어왔는지**와 **들어와서 성공한 일이 있는지**를 판단할 수 있습니다.

## 사용자

A~H 8개를 모두 그대로 실행해서 결과를 붙였습니다.

**뽑은 방식**
- **G:** 결과가 길어서 첫 실행에서는 앞부분(1~87줄)만 붙었습니다. 그래서 같은 명령 뒤에 `tail -n +88`을 붙여 나머지 88~96줄을 따로 한 번 더 실행했습니다. 결과에 G가 두 번 나오는데, 두 개를 이으면 전체 96줄입니다.
- **H:** 이 파일에 IAM 이벤트는 없고 STS와 signin 이벤트만 있습니다. us-east-1 같은 다른 리전 로그는 확인 못 함(그 로그는 없어요).

**지금 해야 할 조치 ①~⑤:** 지금 AWS 콘솔과 CLI에 접속할 수 없어서 하지 못했습니다. 인스턴스 설정, Cognito 사용자 목록, 보안 그룹의 현재 규칙도 확인 못 함(그 로그는 없어요).

**팀에 확인할 것**
1. **13:42~13:48(KST) 루트 로그인:** 누가 했는지 모릅니다.
2. **팀원 IP:** 팀원이 쓴 IP 목록은 모릅니다. blue-team-1과 blue-team-2가 우리 팀원 계정이라는 것만 압니다.
3. **pagesnap recovery 실행, 보안 그룹 변경 4건:**
   - recovery 역할을 팀에서 실행했는지는 모릅니다.
   - 보안 그룹 변경 4건은 blue-team-1 계정이 했고, 이 계정은 팀원 계정입니다. 사고 뒤 대응 작업(조회, 설정 변경)을 팀원이 한 것도 맞습니다. 다만 이 4건이 각각 어떤 작업이었는지는 모릅니다.
4. **PatchSignal 포털 기능:** 원래 있던 우리 서비스라는 것만 압니다. URL을 입력받아 서버가 가져오는 기능이 있는지는 모릅니다.

실행한 명령:
```
jq -r '.Records[]|select(.sourceIPAddress|IN("198.18.7.1","198.18.7.2","198.18.50.1"))|[.eventTime,.eventSource,.eventName,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,(.errorCode//"-"),(.requestParameters|tojson|.[0:200])]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:37:35Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:37:54Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:38:05Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:39:18Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:39:34Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:39:48Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	-	null
2026-10-11T04:40:14Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	null
2026-10-11T04:40:26Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	-	null
2026-10-11T04:41:32Z	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	198.18.7.1	-	null
2026-10-11T04:41:54Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T04:42:01Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T04:42:04Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T04:42:04Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	null
2026-10-11T04:42:14Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	-	null
2026-10-11T04:42:16Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	-	null
2026-10-11T04:43:47Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:43:47Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	null
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	null
2026-10-11T04:43:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	null
2026-10-11T04:43:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	null
2026-10-11T04:44:03Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	null
2026-10-11T04:44:12Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	null
2026-10-11T04:44:22Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	null
2026-10-11T04:48:18Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	null
2026-10-11T04:48:29Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	-	null
2026-10-11T04:48:58Z	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	198.18.7.2	-	null
2026-10-11T04:49:03Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:49:04Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-	null
2026-10-11T04:49:06Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:49:07Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-	null
2026-10-11T04:50:27Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:50:28Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T04:50:28Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-	null
2026-10-11T04:50:28Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-	null
2026-10-11T05:09:58Z	s3.amazonaws.com	GetBucketVersioning	arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2	AccessDenied	{"bucketName":"pagesnap-final-s1-results-0e666173"}
2026-10-11T05:28:39Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	-	null
2026-10-11T05:29:20Z	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	198.18.7.2	-	null
2026-10-11T05:29:30Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-	null
2026-10-11T05:29:30Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-	null
2026-10-11T05:45:47Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T05:45:47Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T05:45:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	null
2026-10-11T05:45:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	null
2026-10-11T05:45:57Z	cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-	null
2026-10-11T05:45:58Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	-	null
2026-10-11T06:36:22Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	null
2026-10-11T06:39:20Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied	null
2026-10-11T06:40:45Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	{"name":"case-redteam-validation-002"}
2026-10-11T06:41:53Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	{"name":"case-redteam-validation-003"}
2026-10-11T06:52:08Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	-	null
2026-10-11T07:02:09Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	null
2026-10-11T07:02:17Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	-	null
2026-10-11T07:03:46Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	{"name":"test-run-1791702223"}
2026-10-11T07:05:02Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	{"name":"test-run-1791702300"}
2026-10-11T07:05:47Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-	{"name":"test-run-1791702344"}
2026-10-11T07:08:11Z	states.amazonaws.com	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	-	null
2026-10-11T07:11:37Z	ssm.amazonaws.com	SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	null
2026-10-11T07:12:16Z	ssm.amazonaws.com	SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	null
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//"")|test("portal-role"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
     76 198.18.10.1	states.amazonaws.com	StartExecution	-
     41 198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	-
     18 10.81.0.102	lambda.amazonaws.com	GetFunction20150331v2	-
     10 198.18.10.1	states.amazonaws.com	DescribeExecution	-
      9 198.18.10.1	ssm.amazonaws.com	ListInstanceAssociations	-
      6 198.18.7.1	states.amazonaws.com	StartExecution	-
      3 198.18.50.1	states.amazonaws.com	StartExecution	-
      2 198.18.7.1	ssm.amazonaws.com	SendCommand	AccessDenied
      2 198.18.10.1	ssm.amazonaws.com	CreateDataChannel	-
      1 198.18.7.1	ssm.amazonaws.com	StartSession	AccessDenied
      1 198.18.50.1	ssm.amazonaws.com	StartSession	AccessDenied
      1 198.18.10.1	sts.amazonaws.com	GetCallerIdentity	-
      1 198.18.10.1	ssm.amazonaws.com	PutConfigurePackageResult	-
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//"")|test("ec2-ssmrole"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
   2255 198.18.6.1	logs.amazonaws.com	FilterLogEvents	-
    725 198.18.6.1	logs.amazonaws.com	GetLogEvents	-
    145 198.18.6.1	logs.amazonaws.com	DescribeLogStreams	-
     41 198.18.6.1	ssm.amazonaws.com	UpdateInstanceInformation	-
     18 198.18.6.1	ssm.amazonaws.com	CreateDataChannel	-
     10 198.18.6.1	ssm.amazonaws.com	ListInstanceAssociations	-
      8 198.18.6.1	sts.amazonaws.com	GetCallerIdentity	-
      2 198.18.6.1	ssm.amazonaws.com	StartSession	AccessDenied
      1 198.18.6.1	ssm.amazonaws.com	PutConfigurePackageResult	-
      1 198.18.6.1	logs.amazonaws.com	FilterLogEvents	AccessDenied
      1 198.18.6.1	logs.amazonaws.com	DescribeLogStreams	AccessDenied
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//"")|test(":root$"))|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
      6 198.18.18.1	ec2.amazonaws.com	DescribeSecurityGroupRules	-
      5 198.18.0.3	ec2.amazonaws.com	DescribeSecurityGroupRules	-
      4 lambda.amazonaws.com	kms.amazonaws.com	Decrypt	-
      4 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeTags	-
      4 198.18.18.1	ec2.amazonaws.com	DescribeInstanceAttribute	-
      4 198.18.18.1	apigateway.amazonaws.com	GetApi	-
      4 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeTags	-
      4 198.18.0.3	ec2.amazonaws.com	DescribeInstanceAttribute	-
      4 198.18.0.3	apigateway.amazonaws.com	GetApi	-
      3 198.18.18.1	ec2.amazonaws.com	DescribeSecurityGroups	-
      3 198.18.18.1	ec2.amazonaws.com	DescribeNetworkInterfaces	-
      3 198.18.0.3	ec2.amazonaws.com	DescribeSecurityGroups	-
      3 198.18.0.3	ec2.amazonaws.com	DescribeNetworkInterfaces	-
      2 198.18.18.1	sts.amazonaws.com	GetCallerIdentity	-
      2 198.18.18.1	logs.amazonaws.com	ListTagsForResource	-
      2 198.18.18.1	logs.amazonaws.com	DescribeLogGroups	-
      2 198.18.18.1	lambda.amazonaws.com	ListVersionsByFunction20150331	-
      2 198.18.18.1	lambda.amazonaws.com	GetFunctionCodeSigningConfig	-
      2 198.18.18.1	lambda.amazonaws.com	GetFunction20150331v2	-
      2 198.18.18.1	ec2.amazonaws.com	DescribeAddresses	-
      2 198.18.18.1	dynamodb.amazonaws.com	DescribeTable	-
      2 198.18.18.1	apigateway.amazonaws.com	GetStage	-
      2 198.18.0.3	sts.amazonaws.com	GetCallerIdentity	-
      2 198.18.0.3	logs.amazonaws.com	ListTagsForResource	-
      2 198.18.0.3	logs.amazonaws.com	DescribeLogGroups	-
      2 198.18.0.3	lambda.amazonaws.com	ListVersionsByFunction20150331	-
      2 198.18.0.3	lambda.amazonaws.com	GetFunctionCodeSigningConfig	-
      2 198.18.0.3	lambda.amazonaws.com	GetFunction20150331v2	-
      2 198.18.0.3	ec2.amazonaws.com	DescribeAddresses	-
      2 198.18.0.3	dynamodb.amazonaws.com	DescribeTable	-
      2 198.18.0.3	apigateway.amazonaws.com	GetStage	-
      1 198.18.18.2	sts.amazonaws.com	GetCallerIdentity	-
      1 198.18.18.1	states.amazonaws.com	ListTagsForResource	-
      1 198.18.18.1	states.amazonaws.com	ListStateMachineVersions	-
      1 198.18.18.1	states.amazonaws.com	DescribeStateMachine	-
      1 198.18.18.1	ssm.amazonaws.com	GetParameter	-
      1 198.18.18.1	lambda.amazonaws.com	GetPolicy20150331v2	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeTargetHealth	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeTargetGroups	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeTargetGroupAttributes	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeRules	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeLoadBalancers	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeLoadBalancerAttributes	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeListeners	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeListenerAttributes	-
      1 198.18.18.1	elasticloadbalancing.amazonaws.com	DescribeCapacityReservation	-
      1 198.18.18.1	ec2.amazonaws.com	GetManagedPrefixListEntries	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeVpcs	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeVpcEndpoints	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeVolumes	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeTags	-
      1 198.18.18.1	ec2.amazonaws.com	DescribePrefixLists	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeManagedPrefixLists	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeInstances	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeInstanceTypes	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeInstanceCreditSpecifications	-
      1 198.18.18.1	ec2.amazonaws.com	DescribeAddressesAttribute	-
      1 198.18.18.1	dynamodb.amazonaws.com	ListTagsOfResource	-
      1 198.18.18.1	dynamodb.amazonaws.com	DescribeTimeToLive	-
      1 198.18.18.1	dynamodb.amazonaws.com	DescribeContinuousBackups	-
      1 198.18.18.1	apigateway.amazonaws.com	UpdateStage	-
      1 198.18.18.1	apigateway.amazonaws.com	GetRoute	-
      1 198.18.18.1	apigateway.amazonaws.com	GetIntegration	-
      1 198.18.15.1	apigateway.amazonaws.com	GetApi	-
      1 198.18.14.1	sts.amazonaws.com	GetCallerIdentity	-
      1 198.18.14.1	ec2.amazonaws.com	DescribeSecurityGroupRules	-
      1 198.18.0.3	states.amazonaws.com	ListTagsForResource	-
      1 198.18.0.3	states.amazonaws.com	ListStateMachineVersions	-
      1 198.18.0.3	states.amazonaws.com	DescribeStateMachine	-
      1 198.18.0.3	ssm.amazonaws.com	GetParameter	-
      1 198.18.0.3	lambda.amazonaws.com	GetPolicy20150331v2	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeTargetHealth	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeTargetGroups	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeTargetGroupAttributes	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeRules	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeLoadBalancers	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeLoadBalancerAttributes	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeListeners	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeListenerAttributes	-
      1 198.18.0.3	elasticloadbalancing.amazonaws.com	DescribeCapacityReservation	-
      1 198.18.0.3	ec2.amazonaws.com	GetManagedPrefixListEntries	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeVpcs	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeVpcEndpoints	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeVolumes	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeTags	-
      1 198.18.0.3	ec2.amazonaws.com	DescribePrefixLists	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeManagedPrefixLists	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeInstances	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeInstanceTypes	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeInstanceCreditSpecifications	-
      1 198.18.0.3	ec2.amazonaws.com	DescribeAddressesAttribute	-
      1 198.18.0.3	dynamodb.amazonaws.com	ListTagsOfResource	-
      1 198.18.0.3	dynamodb.amazonaws.com	DescribeTimeToLive	-
      1 198.18.0.3	dynamodb.amazonaws.com	DescribeContinuousBackups	-
      1 198.18.0.3	apigateway.amazonaws.com	UpdateStage	-
      1 198.18.0.3	apigateway.amazonaws.com	GetRoute	-
      1 198.18.0.3	apigateway.amazonaws.com	GetIntegration	-
```

실행한 명령:
```
jq -r '.Records[]|select(.userIdentity.arn==null and .userIdentity.type=="Unknown")|[.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
     18 198.18.6.1	ssm.amazonaws.com	OpenDataChannel	-
     17 198.18.23.1	ssm.amazonaws.com	OpenDataChannel	-
      9 198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	-
      6 198.18.7.1	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      6 198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	-
      5 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      4 198.18.7.2	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      4 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      4 198.18.3.1	ssm.amazonaws.com	OpenDataChannel	-
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      3 198.18.5.1	ssm.amazonaws.com	OpenDataChannel	-
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	-
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	-
      2 198.18.7.2	cognito-idp.amazonaws.com	SignUp	-
      2 198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	-
      2 198.18.7.1	cognito-idp.amazonaws.com	SignUp	-
      2 198.18.2.1	ssm.amazonaws.com	OpenDataChannel	-
      2 198.18.10.1	ssm.amazonaws.com	OpenDataChannel	-
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	-
      1 198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	-
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//"")|test("pagesnap"))|[.eventTime,.eventSource,.eventName,(.userIdentity.arn|split("/")[1]),.sourceIPAddress,(.errorCode//"-")]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:42:19Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-api-role	198.18.12.1	-
2026-10-11T04:42:24Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.13.1	-
2026-10-11T04:46:49Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.16.1	-
2026-10-11T04:46:49Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.16.1	-
2026-10-11T04:46:49Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.16.1	-
2026-10-11T04:46:49Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.16.1	-
2026-10-11T04:46:53Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-renderer-role	198.18.17.1	-
2026-10-11T05:17:51Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.20.1	-
2026-10-11T05:17:51Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.20.1	-
2026-10-11T05:17:51Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.20.1	-
2026-10-11T05:17:51Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.20.1	-
2026-10-11T05:17:55Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-renderer-role	198.18.28.1	-
2026-10-11T05:33:56Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.34.1	-
2026-10-11T05:33:56Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.34.1	-
2026-10-11T05:33:56Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.34.1	-
2026-10-11T05:33:56Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.34.1	-
2026-10-11T05:33:58Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-renderer-role	198.18.35.1	-
2026-10-11T05:49:45Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.26.1	-
2026-10-11T05:49:45Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.26.1	-
2026-10-11T05:49:45Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.26.1	-
2026-10-11T05:49:45Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-renderer-role	198.18.26.1	-
2026-10-11T05:49:49Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-renderer-role	198.18.38.1	-
2026-10-11T05:52:46Z	kms.amazonaws.com	Decrypt	pagesnap-final-s1-recovery-role	198.18.20.1	-
2026-10-11T05:52:48Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-recovery-role	198.18.39.1	-
2026-10-11T06:08:19Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.45.1	-
2026-10-11T06:27:08Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.47.1	-
2026-10-11T06:48:44Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.53.1	-
2026-10-11T06:58:48Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.58.1	-
2026-10-11T07:04:34Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.60.1	-
2026-10-11T07:07:34Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.61.1	-
2026-10-11T07:13:31Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.63.1	-
2026-10-11T07:15:14Z	logs.amazonaws.com	CreateLogStream	pagesnap-final-s1-api-role	198.18.64.1	-
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//.userIdentity.type)|test("AWSServiceRole|blue-team|^AWSService$")|not)|select(.eventName|test("^(Describe|Get|List|Lookup|Head|Search|Filter)")|not)|[(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
     76 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	states.amazonaws.com	StartExecution	-
     41 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	ssm.amazonaws.com	UpdateInstanceInformation	-
     41 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	UpdateInstanceInformation	-
     18 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	CreateDataChannel	-
     18 Unknown	198.18.6.1	ssm.amazonaws.com	OpenDataChannel	-
     17 Unknown	198.18.23.1	ssm.amazonaws.com	OpenDataChannel	-
     14 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	DeleteNetworkInterface	Client.InvalidParameterValue
      9 Unknown	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	-
      6 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	states.amazonaws.com	StartExecution	-
      6 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	ModifyNetworkInterfaceAttribute	-
      6 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	DetachNetworkInterface	-
      6 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	CreateNetworkInterface	-
      6 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	AttachNetworkInterface	-
      6 Unknown	198.18.7.1	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      6 Unknown	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	-
      5 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	DeleteNetworkInterface	-
      5 Unknown	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      4 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1	kms.amazonaws.com	Decrypt	-
      4 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1	kms.amazonaws.com	Decrypt	-
      4 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1	kms.amazonaws.com	Decrypt	-
      4 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1	kms.amazonaws.com	Decrypt	-
      4 arn:aws:iam::111122223333:root	lambda.amazonaws.com	kms.amazonaws.com	Decrypt	-
      4 Unknown	198.18.7.2	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      4 Unknown	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      4 Unknown	198.18.3.1	ssm.amazonaws.com	OpenDataChannel	-
      3 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	states.amazonaws.com	StartExecution	-
      3 Unknown	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      3 Unknown	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      3 Unknown	198.18.5.1	ssm.amazonaws.com	OpenDataChannel	-
      2 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1	kms.amazonaws.com	Decrypt	-
      2 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	ssm.amazonaws.com	SendCommand	AccessDenied
      2 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	ssm.amazonaws.com	CreateDataChannel	-
      2 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	StartSession	AccessDenied
      2 arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	198.18.8.1	sts.amazonaws.com	AssumeRoleWithWebIdentity	-
      2 Unknown	2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	-
      2 Unknown	2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	-
      2 Unknown	198.18.7.2	cognito-idp.amazonaws.com	SignUp	-
      2 Unknown	198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	-
      2 Unknown	198.18.7.1	cognito-idp.amazonaws.com	SignUp	-
      2 Unknown	198.18.2.1	ssm.amazonaws.com	OpenDataChannel	-
      2 Unknown	198.18.10.1	ssm.amazonaws.com	OpenDataChannel	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.67.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.66.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.56.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.55.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.52.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.51.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.48.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.44.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.41.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1	kms.amazonaws.com	Decrypt	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.31.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.2	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1	kms.amazonaws.com	Decrypt	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.27.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1	kms.amazonaws.com	Decrypt	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.22.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	ssm.amazonaws.com	StartSession	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	ssm.amazonaws.com	StartSession	AccessDenied
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	ssm.amazonaws.com	PutConfigurePackageResult	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.68.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.65.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.62.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.59.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.57.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.54.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.49.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.46.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.43.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.42.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.30.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.25.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.21.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.38.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.35.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.28.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.17.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.39.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1	kms.amazonaws.com	Decrypt	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.64.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.63.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.61.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.60.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.58.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.53.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.47.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.45.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api
[... 출력 12,949자 중 앞 12,000자만]
```

실행한 명령:
```
jq -r '.Records[]|select(.eventSource|IN("iam.amazonaws.com","sts.amazonaws.com","signin.amazonaws.com"))|.eventSource+" "+.eventName' cloudtrail.json | sort | uniq -c
```
결과:
```
     28 signin.amazonaws.com CreateOAuth2Token
    268 sts.amazonaws.com AssumeRole
      4 sts.amazonaws.com AssumeRoleWithWebIdentity
    489 sts.amazonaws.com GetCallerIdentity
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//.userIdentity.type)|test("AWSServiceRole|blue-team|^AWSService$")|not)|select(.eventName|test("^(Describe|Get|List|Lookup|Head|Search|Filter)")|not)|[(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventSource,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn | tail -n +88
```
결과:
```
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.13.1	logs.amazonaws.com	CreateLogStream	-
      1 arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1	kms.amazonaws.com	Decrypt	-
      1 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	ec2.amazonaws.com	DeleteNetworkInterface	Client.InvalidNetworkInterface.InUse
      1 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ssm.amazonaws.com	PutConfigurePackageResult	-
      1 arn:aws:iam::111122223333:root	198.18.18.1	apigateway.amazonaws.com	UpdateStage	-
      1 arn:aws:iam::111122223333:root	198.18.0.3	apigateway.amazonaws.com	UpdateStage	-
      1 Unknown	2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	-
      1 Unknown	2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	-
      1 Unknown	198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	-
```

## 채팅 AI

# 2차 분석 결과

## 요약

이번 로그로 **공격 흐름의 윤곽이 잡혔습니다.**

1. 공격자(198.18.7.1, 198.18.7.2)가 **앱 회원가입(Cognito)에 성공해 로그인했습니다.**
2. 약 2시간 뒤 **PatchSignal 포털 서버(EC2)의 역할 자격 증명이 공격자 IP에서 사용됐습니다.** 서버 밖으로 자격 증명이 빠져나간 것이 사실상 확정입니다.
3. 그 자격 증명으로 **Step Functions 실행을 9번 성공**시켰고, 다른 서버 접속과 명령 실행(SSM)은 거부됐습니다.

포털 앱에 **로그인한 사용자라면 누구나 악용할 수 있는 취약점**이 있고, 이를 통해 서버 자격 증명(또는 서버 자체)이 탈취됐을 가능성이 가장 높습니다.

---

## 타임라인 (UTC / KST)

| UTC | KST | 출처 IP | 내용 | 결과 |
|---|---|---|---|---|
| 04:37~04:40 | 13:37 | 7.1 | 회원가입 시도. 비밀번호 정책 위반 5회 뒤 **가입 2건 성공** | ✅ |
| 04:41~04:42 | 13:41 | 7.1 | 가입 확인(ConfirmSignUp), **로그인 성공** | ✅ |
| 04:43:47~49 | 13:43 | 7.2 | 2초 안에 로그인 4회 시도, 모두 실패 (스크립트로 보임) | ❌ |
| 04:48~04:50 | 13:48 | 7.2 | **가입, 확인, 로그인 성공** | ✅ |
| 05:09:58 | 14:09 | 7.2 | **외부 AWS 신원**으로 `pagesnap-final-s1-results-…` 버킷 조회 | ❌ 거부 |
| 05:28~05:29 | 14:28 | 7.2 | **가입, 확인, 로그인 추가 성공** | ✅ |
| 05:45 | 14:45 | 7.1 | 로그인 2회 실패 후 성공 | ✅ |
| ? | ? | | **자격 증명 탈취 (시점은 로그에 없음)** | |
| **06:36:22** | **15:36** | **7.1** | **포털 역할로 Step Functions `StartExecution`. 외부에서 처음 사용** | ✅ |
| 06:39 | 15:39 | 50.1 | 포털 역할로 SSM `StartSession` | ❌ |
| 06:40~07:08 | 15:40 | 7.1, 50.1 | `StartExecution` 8건 추가 (이름 `case-redteam-validation-002/003`, `test-run-<시각>` 등) | ✅ |
| 07:02 | 16:02 | 7.1 | `StartSession` | ❌ |
| 07:11~07:12 | 16:11 | 7.1 | SSM `SendCommand` 2회 | ❌ |
| 07:10~07:19 | 16:10 | | GuardDuty Runtime Monitoring 활성화 (팀 대응으로 추정) | |
| 07:25 | 16:25 | | 파일 끝. **외부 사용이 멈췄는지는 알 수 없음** | |

**자격 증명 탈취로 판단한 근거:** 포털 역할의 평소 호출 IP는 198.18.10.1(서버의 공인 IP 또는 NAT)과 10.81.0.102(VPC 내부)입니다. 그런데 **회원가입을 했던 바로 그 IP(7.1)**와 새 IP(50.1)에서 같은 역할이 쓰였습니다. 서버 역할 자격 증명이 서버 밖에서 쓰이는 것은 정상 동작으로는 일어나지 않습니다.

---

## 확정 / 추정 / 모름

**확정 (이 파일 근거)**
- 공격자 IP로 Cognito 계정이 **최소 3개 가입·확인**됐고 로그인에 성공했습니다. 가입 확인 코드를 받았다는 뜻이므로, **공격자가 실제로 받아 볼 수 있는 이메일이나 전화번호가 Cognito 사용자 정보에 남아 있습니다.**
- 포털 역할 자격 증명이 외부에서 사용됐습니다.
- Step Functions 실행 9건은 성공했고, SSM 시도 4건은 실패했습니다.
- 이 리전에서 공격자가 리소스를 생성·변경·삭제한 흔적은 없습니다(G 결과 기준).

**추정**
- 침입 경로는 로그인 사용자가 쓸 수 있는 포털 기능의 취약점으로 보입니다. SSRF로 메타데이터(IMDS)를 읽었거나 서버에서 원격 코드를 실행했을 가능성이 있습니다.
- 공격자는 PageSnap(결과 버킷)도 노렸습니다.

**모름 (이 파일로 알 수 없음)**
- **Step Functions 9건이 실제로 무엇을 했는지.** 실행 입력값과 결과는 CloudTrail에 없고 Step Functions 실행 기록에만 있습니다.
- 공격자가 포털 서버에서 **명령 실행까지 했는지**, 아니면 자격 증명만 빼갔는지.
- IAM 변경(us-east-1), 다른 리전, S3 객체 읽기(데이터 이벤트).

---

## 이전 분석 정정

- **루트 계정:** 지난번에 "콘솔에서 EC2 시작 화면"이라고 추정했는데, 이번 결과를 보면 **Terraform 같은 인프라 코드 도구의 실행 패턴**에 더 가깝습니다. EC2, ELB, API Gateway, Lambda, DynamoDB, Step Functions를 똑같은 순서로 조회하는 묶음이 두 IP에서 한 번씩, 총 2회 나왔습니다. 변경 작업은 **API Gateway `UpdateStage` 2건**뿐입니다. 운영진의 환경 배포일 가능성이 높지만, **UpdateStage 내용과 실행자는 확인해야 합니다**(아래 L).
- **`ec2-ssmrole` 서버:** 위험도를 낮춥니다. 이 서버로 Session Manager 접속이 18회 열렸고, CloudWatch 로그를 3시간 동안 약 3,100번 읽었습니다. **팀이 쓰는 모니터링 또는 작업용 서버**의 패턴으로 보입니다. 거부된 4건은 이 서버에 접속한 사람이 시도한 것이므로, 누가 접속했는지만 확인하면 됩니다(아래 K).
- **새로 눈에 띈 점:** 포털 서버 자신(198.18.10.1)이 `GetCallerIdentity`("나는 누구인가")를 **딱 1번** 호출했습니다. 웹 앱이 평소에 하는 호출이 아니고, **서버에 침입한 사람이 가장 먼저 치는 명령**이기도 합니다. 이 호출의 시각에 따라 "자격 증명만 탈취"인지 "서버 장악"인지가 갈립니다(아래 J).

---

## 고쳐야 할 것

콘솔 접속이 가능한 팀원이나 운영진에게 그대로 전달하세요.

### 🔴 즉시

**1. 포털 역할 세션 취소 + IMDSv2 강제**
지난번 ①번 조치입니다. 이제는 근거가 확정됐으므로 최우선입니다.

**2. 포털 역할을 서버 밖에서 쓸 수 없게 막기**
세션을 취소해도 취약점이 남아 있으면 다시 빼갈 수 있습니다. 포털 서버의 실제 공인(NAT) IP를 확인한 뒤 역할에 아래 정책을 추가합니다. 로그의 IP는 가명이므로 그대로 쓰면 안 됩니다.
```json
{"Version":"2012-10-17","Statement":[{
  "Effect":"Deny","Action":"*","Resource":"*",
  "Condition":{
    "NotIpAddress":{"aws:SourceIp":["<포털 NAT 공인 IP>/32"]},
    "Bool":{"aws:ViaAWSService":"false"},
    "Null":{"aws:SourceVpc":"true"}}}]}
```
> VPC 엔드포인트를 거치는 호출(10.81.0.102)은 제외되도록 작성했습니다. 적용 직후 포털 기능이 정상인지 꼭 확인하세요.

**3. Step Functions 확인**
포털 역할이 실행할 수 있는 상태 머신에서 06:36 이후 실행 9건의 **입력값과 실행 기록**을 확인하고, 아직 실행 중이면 중지합니다.
```bash
aws stepfunctions list-executions --state-machine-arn <ARN> --max-results 100
aws stepfunctions get-execution-history --execution-arn <실행 ARN>
```
그 상태 머신이 무엇을 할 수 있는지(Lambda 호출, DB 쓰기 등)가 곧 **실제 피해 범위**입니다.

**4. Cognito 공격자 계정 처리**
오늘 생성된 사용자를 조회해 이메일 등 정보를 **먼저 기록**한 뒤, 비활성화하고 강제 로그아웃합니다.
```bash
aws cognito-idp list-users --user-pool-id <풀 ID> \
  --query "Users[?UserCreateDate>='2026-10-11T04:30:00'].[Username,UserCreateDate,Attributes]"
aws cognito-idp admin-disable-user --user-pool-id <풀 ID> --username <사용자>
aws cognito-idp admin-user-global-sign-out --user-pool-id <풀 ID> --username <사용자>
```
셀프 회원가입이 필요 없는 서비스라면 끕니다.

**5. 포털 서버 증거 보존**
EBS 스냅샷을 떠 둡니다. 서버를 장악당했을 수 있으므로 낯선 프로세스, 웹셸, cron, `~/.ssh/authorized_keys` 변경 여부를 확인합니다. 분석이 끝나면 **새 인스턴스로 교체**하는 것이 안전합니다.

### 🟠 근본 원인 (개발자 몫)

**6. 포털 앱 취약점 찾기**
공격자는 **일반 회원으로 로그인한 뒤** 공격했습니다. 로그인 후 쓸 수 있는 기능 중 아래 항목을 우선 보세요.
- 사용자가 입력한 **URL로 서버가 요청을 보내는 기능** (피드 URL 등록, 웹훅, 미리보기, 가져오기 등). SSRF로 `169.254.169.254`에 접근할 수 있습니다.
- 파일 업로드, 사용자 입력이 셸 명령, 템플릿, 역직렬화에 들어가는 부분.

포털의 웹 접근 로그(nginx, 앱 로그)가 있다면 이렇게 찾아 보세요.
```bash
grep -E "169\.254\.169\.254|latest/meta-data|security-credentials|latest/api/token" <로그파일>
```
04:42~06:36(UTC) 사이 공격자 계정의 요청을 시간순으로 보면 **어떤 기능을 썼는지** 나옵니다.

**7. 포털 역할 권한 최소화**
SSM 시도가 거부된 것은 다행입니다. 이 밖에 `states:StartExecution`을 필요한 상태 머신 하나로만 제한하고, `lambda:GetFunction`처럼 함수 코드와 환경 변수를 노출하는 권한이 정말 필요한지 확인하세요.

### 🟡 그 밖에 확인할 것
- `pagesnap-final-s1-results-…` 버킷의 정책과 퍼블릭 액세스 설정.
- GuardDuty 발견 사항. 특히 **`InstanceCredentialExfiltration`** 계열이 있으면 자격 증명 유출을 AWS가 직접 확인해 준 것입니다.
- us-east-1 CloudTrail에서 IAM 변경(`CreateUser`, `CreateAccessKey`, `Attach*Policy` 등). 이 파일에는 IAM 이벤트가 하나도 없어서 판단할 수 없습니다.

---

## 다음으로 뽑아 주실 것 (이 파일에서)

```bash
# I. 포털 역할: 액세스 키·IP별 사용 기간 (공격자가 서버와 같은 키를 썼는지 확인)
jq -r '.Records|map(select((.userIdentity.arn//"")|test("portal-role")))|group_by([.userIdentity.accessKeyId,.sourceIPAddress])[]|[.[0].userIdentity.accessKeyId,.[0].sourceIPAddress,length,(map(.eventTime)|min),(map(.eventTime)|max)]|@tsv' cloudtrail.json | sort -t$'\t' -k4

# J. 포털 역할 타임라인 (SSM 에이전트 정기 호출 제외, 약 110줄)
jq -r '.Records[]|select((.userIdentity.arn//"")|test("portal-role"))|select(.eventName|IN("UpdateInstanceInformation","ListInstanceAssociations")|not)|[.eventTime,.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort

# K. Session Manager 접속 기록 (누가 어느 서버로 접속했는지)
jq -r '.Records[]|select(.eventName|IN("StartSession","TerminateSession","ResumeSession","SendCommand"))|[.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort

# L. 루트의 UpdateStage 내용과 CreateOAuth2Token 사용자
jq -r '.Records[]|select(.eventName|IN("UpdateStage","CreateOAuth2Token"))|[.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.requestParameters|tojson|.[0:300])]|@tsv' cloudtrail.json | sort

# M. IPv6 주소(2001:db8:0:b::2)로 가입·로그인한 사용자의 타임라인
jq -r '.Records[]|select(.sourceIPAddress=="2001:db8:0:b::2")|[.eventTime,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort

# N. 공격자 StartExecution 원본 레코드 1건 (어느 상태 머신인지 확인)
jq '[.Records[]|select(.eventName=="StartExecution" and .sourceIPAddress=="198.18.7.1")][0]' cloudtrail.json
```

## 이 파일 밖에서 필요한 것 (운영진이나 접속 가능한 사람에게 요청)

1. Step Functions 실행 기록 (위 3번)
2. 포털 웹/앱 접근 로그 (위 6번)
3. Cognito 사용자 목록 (위 4번)
4. us-east-1 CloudTrail, GuardDuty 발견 사항
5. 루트 계정을 누가 쓰는지, IPv6 주소로 가입한 사용자가 팀원인지 여부

J와 I 결과가 나오면 **언제, 어떻게 탈취됐는지**(자격 증명만인지, 서버 장악인지)를 판단할 수 있습니다. N 결과로는 **어느 상태 머신이 피해를 입었는지**를 특정할 수 있습니다.

## 사용자

I~N 6개를 모두 뽑아서 결과를 붙였습니다.

**뽑은 방식**
- **I, J, L, M, N:** 주신 명령을 그대로 실행했습니다.
- **K:** 그대로 실행하니 결과가 39,155자라서 앞 12,000자만 붙었습니다. 대부분이 blue-team-1의 SendCommand 줄이어서, 같은 조건으로 두 부분으로 나눠 다시 뽑았습니다. 첫 번째로 붙은 잘린 K 결과는 무시하고 아래 두 개를 봐 주세요.
  - **K-1:** blue-team-1의 SendCommand만 모은 집계입니다. arn, IP, 대상 인스턴스별 건수와 처음·마지막 시각이 있습니다.
  - **K-2:** 나머지 전부를 시간순으로 한 줄씩 뽑았습니다. StartSession, TerminateSession, ResumeSession 전체와 blue-team-1이 아닌 사용자의 SendCommand입니다.
- **N:** 원본 레코드에 요청 파라미터 필드가 없어서, 어느 상태 머신인지는 이 파일에 나오지 않습니다.

**파일 밖에서 필요한 것**
- Step Functions 실행 기록, 포털 웹/앱 접근 로그, Cognito 사용자 목록, us-east-1 CloudTrail, GuardDuty 발견 사항은 확인 못 함(그 로그는 없어요).
- 지금 AWS 콘솔과 CLI에 접속할 수 없어서, 말씀하신 조치(1~7번)는 제가 직접 하지 못했습니다.

**팀에 확인할 것**
- **루트 계정:** 누가 썼는지 모릅니다.
- **IPv6 주소(2001:db8:0:b::2)로 가입한 사용자:** 팀원인지 모릅니다.

실행한 명령:
```
jq -r '.Records|map(select((.userIdentity.arn//"")|test("portal-role")))|group_by([.userIdentity.accessKeyId,.sourceIPAddress])[]|[.[0].userIdentity.accessKeyId,.[0].sourceIPAddress,length,(map(.eventTime)|min),(map(.eventTime)|max)]|@tsv' cloudtrail.json | sort -t$'\t' -k4
```
결과:
```
ASIAE89B…4DE2	198.18.10.1	14	2026-10-11T04:32:31Z	2026-10-11T05:12:23Z
ASIA0822…2E7A	10.81.0.102	18	2026-10-11T04:32:51Z	2026-10-11T05:57:54Z
ASIA9EFD…2435	198.18.10.1	99	2026-10-11T05:00:03Z	2026-10-11T07:23:44Z
ASIA9DC4…35DA	198.18.10.1	18	2026-10-11T05:48:01Z	2026-10-11T06:48:01Z
ASIA71C2…95CF	198.18.7.1	9	2026-10-11T06:36:22Z	2026-10-11T07:12:16Z
ASIA71C2…95CF	198.18.50.1	4	2026-10-11T06:39:20Z	2026-10-11T07:08:11Z
ASIA0F7E…0AE1	198.18.10.1	9	2026-10-11T06:53:01Z	2026-10-11T07:23:01Z
```

실행한 명령:
```
jq -r '.Records[]|select((.userIdentity.arn//"")|test("portal-role"))|select(.eventName|IN("UpdateInstanceInformation","ListInstanceAssociations")|not)|[.eventTime,.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:32:51Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T04:37:51Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T04:42:51Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T04:47:51Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T04:52:52Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T04:57:52Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:00:03Z	198.18.10.1	GetCallerIdentity	-	null
2026-10-11T05:00:03Z	198.18.10.1	StartExecution	-	{"name":"case-ec4331c54acf42f3a59e7132efe11b0f"}
2026-10-11T05:02:52Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:04:14Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:04:19Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:07:52Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:12:52Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:14:32Z	198.18.10.1	StartExecution	-	{"name":"case-eb91f8b2e2b04896a882c27133e28461"}
2026-10-11T05:17:53Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:22:53Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:24:08Z	198.18.10.1	StartExecution	-	{"name":"case-f4b1237d8e5c4f3783b6044947f151dd"}
2026-10-11T05:27:26Z	198.18.10.1	StartExecution	-	{"name":"case-4220d74b91684fd4851f292c7266fd0c"}
2026-10-11T05:27:37Z	198.18.10.1	StartExecution	-	{"name":"case-bb4c5667790542719e2ee83f062fd919"}
2026-10-11T05:27:53Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:28:26Z	198.18.10.1	StartExecution	-	{"name":"case-b4d3e90ede9841ddb46913fbaf2d089c"}
2026-10-11T05:28:37Z	198.18.10.1	StartExecution	-	{"name":"case-fa0d1770f10a411fa41828583ed12629"}
2026-10-11T05:28:44Z	198.18.10.1	StartExecution	-	{"name":"case-a6ee907fb65742e8a63a41aa431f9a85"}
2026-10-11T05:28:59Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:30:19Z	198.18.10.1	StartExecution	-	{"name":"case-cb72d8aee366407d893a24225873062f"}
2026-10-11T05:30:40Z	198.18.10.1	StartExecution	-	{"name":"case-d5f1222f52fe42e8b92425303221593c"}
2026-10-11T05:31:35Z	198.18.10.1	StartExecution	-	{"name":"case-b84950bc61a944ffae0fa25712edb685"}
2026-10-11T05:31:44Z	198.18.10.1	StartExecution	-	{"name":"case-54cf79d907514c33b7ddbd5f69ab5490"}
2026-10-11T05:32:53Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:34:04Z	198.18.10.1	StartExecution	-	{"name":"case-b22c6e2168874834b2bd0f33771fddfb"}
2026-10-11T05:34:08Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:34:09Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:34:17Z	198.18.10.1	StartExecution	-	{"name":"case-fbb05947e56c499e96d1d16d2c892dc0"}
2026-10-11T05:37:53Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:38:09Z	198.18.10.1	StartExecution	-	{"name":"case-578eefa07daf4478b50f6d3c6948fa28"}
2026-10-11T05:40:53Z	198.18.10.1	StartExecution	-	{"name":"case-872925e26fe14d5081d3d31708b8ee31"}
2026-10-11T05:41:49Z	198.18.10.1	StartExecution	-	{"name":"case-991521209e1e4cb6b73d4e72e93240c8"}
2026-10-11T05:41:54Z	198.18.10.1	StartExecution	-	{"name":"case-5b9a97abada54c929975b280e7f79dc7"}
2026-10-11T05:42:54Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:43:00Z	198.18.10.1	StartExecution	-	{"name":"case-a5580f6c439849f592c64ffdd12b2524"}
2026-10-11T05:43:06Z	198.18.10.1	StartExecution	-	{"name":"case-560ab29b419d4fd6857f12a96b0c9339"}
2026-10-11T05:43:34Z	198.18.10.1	StartExecution	-	{"name":"case-c19372bae32149bdbc205a80516afaf1"}
2026-10-11T05:44:26Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:44:26Z	198.18.10.1	StartExecution	-	{"name":"case-17d2b4cf3d3c427b8280756aa59dcda8"}
2026-10-11T05:45:08Z	198.18.10.1	StartExecution	-	{"name":"case-e916046f53354298993ded760794f74b"}
2026-10-11T05:47:54Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:48:14Z	198.18.10.1	StartExecution	-	{"name":"case-34fdf7faf8e447f6b86865480a9414ba"}
2026-10-11T05:50:40Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:50:53Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:51:44Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:52:54Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:54:02Z	198.18.10.1	StartExecution	-	{"name":"case-0471810233df4c408149a45e82a4870a"}
2026-10-11T05:54:33Z	198.18.10.1	DescribeExecution	-	null
2026-10-11T05:54:33Z	198.18.10.1	StartExecution	-	{"name":"case-0e49e9d53e854399b746229fb6064a35"}
2026-10-11T05:56:07Z	198.18.10.1	StartExecution	-	{"name":"case-a4202545a011401389be9b97eb47ee9e"}
2026-10-11T05:57:54Z	10.81.0.102	GetFunction20150331v2	-	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
2026-10-11T05:58:54Z	198.18.10.1	StartExecution	-	{"name":"case-0284eab122bd4d41a708da6a81cafc6c"}
2026-10-11T05:59:57Z	198.18.10.1	StartExecution	-	{"name":"case-a8e4cd31749f44e69e83e632c003e44b"}
2026-10-11T06:00:39Z	198.18.10.1	StartExecution	-	{"name":"case-76124a0dad8f4187b03c04eaf3b45940"}
2026-10-11T06:00:43Z	198.18.10.1	StartExecution	-	{"name":"case-536113bf81ee42e88b160ecc8d6ea3cc"}
2026-10-11T06:00:45Z	198.18.10.1	StartExecution	-	{"name":"case-469d6faa796c4c52b95b01b2c6e2a418"}
2026-10-11T06:03:15Z	198.18.10.1	StartExecution	-	{"name":"case-1d973696c12246fdbb7e872793de1f42"}
2026-10-11T06:08:01Z	198.18.10.1	StartExecution	-	{"name":"case-55ae4197ed9c42d19eb6d1e12fa4240a"}
2026-10-11T06:08:06Z	198.18.10.1	StartExecution	-	{"name":"case-8919cca21f05494487d4b868d6029921"}
2026-10-11T06:08:16Z	198.18.10.1	StartExecution	-	{"name":"case-3d760f72c0da458f922642252a5254b6"}
2026-10-11T06:08:51Z	198.18.10.1	StartExecution	-	{"name":"case-ce9a3813730946a589abe7594a1333d7"}
2026-10-11T06:09:02Z	198.18.10.1	StartExecution	-	{"name":"case-46e7e80716864a6c97b4a5b7557afbdb"}
2026-10-11T06:09:07Z	198.18.10.1	StartExecution	-	{"name":"case-61578bcb434a4dd8aa9ff5420f0ecf26"}
2026-10-11T06:09:24Z	198.18.10.1	StartExecution	-	{"name":"case-93bea42739fa4138918068ed138e6c42"}
2026-10-11T06:09:34Z	198.18.10.1	StartExecution	-	{"name":"case-eb71ed0b742a427a95a43510221f7b09"}
2026-10-11T06:09:39Z	198.18.10.1	StartExecution	-	{"name":"case-cf9e53c9db264165bdf9c0c2c9e68eae"}
2026-10-11T06:09:40Z	198.18.10.1	CreateDataChannel	-	null
2026-10-11T06:09:42Z	198.18.10.1	StartExecution	-	{"name":"case-c36bdc34305b443590da6326c1654059"}
2026-10-11T06:09:47Z	198.18.10.1	StartExecution	-	{"name":"case-80c425dae7044b85a0b8851ad4e209ee"}
2026-10-11T06:10:01Z	198.18.10.1	StartExecution	-	{"name":"case-5102fac6957a4fd889c56947d670d00c"}
2026-10-11T06:10:07Z	198.18.10.1	StartExecution	-	{"name":"case-ca2cc76cc42945f496c9765225aab09b"}
2026-10-11T06:10:58Z	198.18.10.1	StartExecution	-	{"name":"case-b1a40ea5454c414f9f1f8ecfe6ed1187"}
2026-10-11T06:11:00Z	198.18.10.1	StartExecution	-	{"name":"case-cb02cccacd70467596f974a47a96587b"}
2026-10-11T06:11:06Z	198.18.10.1	StartExecution	-	{"name":"case-4a6e7d5d8c1f4d389c662dd4700abf27"}
2026-10-11T06:11:17Z	198.18.10.1	StartExecution	-	{"name":"case-9c5f0ced9a8f40dca63cc1d2fee0847c"}
2026-10-11T06:11:36Z	198.18.10.1	StartExecution	-	{"name":"case-9d42843c59b34949a7abe721618cce8f"}
2026-10-11T06:11:38Z	198.18.10.1	StartExecution	-	{"name":"case-938d4738cd374b98be678f5bfda9a983"}
2026-10-11T06:13:23Z	198.18.10.1	StartExecution	-	{"name":"case-01847f5d9bef4b21b1279a787990f575"}
2026-10-11T06:13:27Z	198.18.10.1	StartExecution	-	{"name":"case-9339665a7b8c4d74926d4bbcb5d4f4a0"}
2026-10-11T06:14:02Z	198.18.10.1	StartExecution	-	{"name":"case-3cbd0f0899b14af5900e19b947a3f548"}
2026-10-11T06:14:14Z	198.18.10.1	StartExecution	-	{"name":"case-d6f2d75697cf4d08a93b33f732041ca2"}
2026-10-11T06:14:54Z	198.18.10.1	StartExecution	-	{"name":"case-7a12923a50e2475491968cd7e4236c40"}
2026-10-11T06:15:36Z	198.18.10.1	StartExecution	-	{"name":"case-b4e1f4a4843e4e778d71dde9e86bbe61"}
2026-10-11T06:16:01Z	198.18.10.1	StartExecution	-	{"name":"case-e8750b17c50c4ca1a969c651378e30d1"}
2026-10-11T06:16:24Z	198.18.10.1	StartExecution	-	{"name":"case-63096791d5354d03a127d9942433627b"}
2026-10-11T06:16:33Z	198.18.10.1	StartExecution	-	{"name":"case-3d6beffade09439383d13b1332e53e3c"}
2026-10-11T06:16:37Z	198.18.10.1	StartExecution	-	{"name":"case-d6eedaf93586449181c041640420353f"}
2026-10-11T06:17:09Z	198.18.10.1	StartExecution	-	{"name":"case-6957139478d34a6998057315d61b2f92"}
2026-10-11T06:18:31Z	198.18.10.1	StartExecution	-	{"name":"case-f0a5af86a3e44a9ebaff1b4bebcd08f8"}
2026-10-11T06:18:55Z	198.18.10.1	StartExecution	-	{"name":"case-c0c4b96befa94fa188b722778b75aa0f"}
2026-10-11T06:32:11Z	198.18.10.1	CreateDataChannel	-	null
2026-10-11T06:34:24Z	198.18.10.1	StartExecution	-	{"name":"case-85f359ca6cd44366af38ca65888bf9e5"}
2026-10-11T06:34:32Z	198.18.10.1	StartExecution	-	{"name":"case-d29e27d29f7248aab5a84a408e412a67"}
2026-10-11T06:35:02Z	198.18.10.1	StartExecution	-	{"name":"case-27234d5bb55e4f6eadb510aa4201afd3"}
2026-10-11T06:35:10Z	198.18.10.1	StartExecution	-	{"name":"case-a7c0409ec5fc420cab3441d5e8588f3e"}
2026-10-11T06:36:22Z	198.18.7.1	StartExecution	-	null
2026-10-11T06:39:20Z	198.18.50.1	StartSession	AccessDenied	null
2026-10-11T06:40:45Z	198.18.7.1	StartExecution	-	{"name":"case-redteam-validation-002"}
2026-10-11T06:41:53Z	198.18.7.1	StartExecution	-	{"name":"case-redteam-validation-003"}
2026-10-11T06:49:24Z	198.18.10.1	StartExecution	-	{"name":"case-bb38364049494742898ed45450660962"}
2026-10-11T06:49:29Z	198.18.10.1	StartExecution	-	{"name":"case-0eb18af607204850a7043b9377a77821"}
2026-10-11T06:52:08Z	198.18.50.1	StartExecution	-	null
2026-10-11T06:59:46Z	198.18.10.1	StartExecution	-	{"name":"case-ed703c00f8d244078c7556ffb60e51fe"}
2026-10-11T07:00:30Z	198.18.10.1	StartExecution	-	{"name":"case-432772485c824a46ba2a4e50606182bf"}
2026-10-11T07:02:09Z	198.18.7.1	StartSession	AccessDenied	null
2026-10-11T07:02:17Z	198.18.50.1	StartExecution	-	null
2026-10-11T07:03:16Z	198.18.10.1	StartExecution	-	{"name":"case-f6c5d9a230de4a01801f741390f2e3b2"}
2026-10-11T07:03:46Z	198.18.7.1	StartExecution	-	{"name":"test-run-1791702223"}
2026-10-11T07:05:02Z	198.18.7.1	StartExecution	-	{"name":"test-run-1791702300"}
2026-10-11T07:05:47Z	198.18.7.1	StartExecution	-	{"name":"test-run-1791702344"}
2026-10-11T07:08:11Z	198.18.50.1	StartExecution	-	null
2026-10-11T07:11:37Z	198.18.7.1	SendCommand	AccessDenied	null
2026-10-11T07:12:16Z	198.18.7.1	SendCommand	AccessDenied	null
2026-10-11T07:18:35Z	198.18.10.1	StartExecution	-	{"name":"case-26a3b3e40ded4ffa8fa538f5f0672ba5"}
2026-10-11T07:19:43Z	198.18.10.1	PutConfigurePackageResult	-	null
2026-10-11T07:23:44Z	198.18.10.1	StartExecution	-	{"name":"case-7fe6fd5484b245a0b0559b9d0cdbee15"}
```

실행한 명령:
```
jq -r '.Records[]|select(.eventName|IN("StartSession","TerminateSession","ResumeSession","SendCommand"))|[.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:30:38Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:30:39Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:30:43Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:30:56Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:31:04Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:31:35Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:31:52Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:31:52Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:31:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:02Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:07Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:15Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:17Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:17Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:20Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:20Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:31Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:35Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:38Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:32:43Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:45Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:32:57Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:00Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:08Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:19Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:19Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:29Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	null
2026-10-11T04:33:33Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:33Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	null
2026-10-11T04:33:35Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:53Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:33:57Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:33:58Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:34:11Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:34:25Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:34:44Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:34:53Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:35:13Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:35:16Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:35:40Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:36:05Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:36:07Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:36:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	StartSession	-	null
2026-10-11T04:36:27Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:36:30Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:36:56Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:37:21Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:37:47Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:37:57Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:38:09Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:38:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:38:30Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:38:31Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:38:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:38:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	TerminateSession	-	null
2026-10-11T04:39:01Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:39:26Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:39:35Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:39:51Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:40:16Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:40:48Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:40:51Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:41:04Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:41:15Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:41:51Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:42:08Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:42:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:42:22Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:42:47Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:01Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:04Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:25Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:38Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:43:50Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:53Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:43:56Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:44:11Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:44:23Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:44:34Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:44:34Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:44:57Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:45:10Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:45:18Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:45:44Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:46:01Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:46:02Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:46:05Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	TerminateSession	-	null
2026-10-11T04:47:17Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:47:40Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:47:56Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:48:04Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
2026-10-11T04:48:48Z	arn:aws:iam::111122223333:user/blue-team-1	198.1
[... 출력 39,155자 중 앞 12,000자만]
```

실행한 명령:
```
jq -r '.Records[]|select(.eventName|IN("UpdateStage","CreateOAuth2Token"))|[.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.requestParameters|tojson|.[0:300])]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:31:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	CreateOAuth2Token	null
2026-10-11T04:34:18Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T04:34:18Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T04:37:56Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T04:38:29Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	CreateOAuth2Token	null
2026-10-11T04:43:00Z	arn:aws:iam::111122223333:root	198.18.0.3	UpdateStage	null
2026-10-11T04:44:22Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T04:48:52Z	arn:aws:iam::111122223333:root	198.18.18.1	UpdateStage	null
2026-10-11T04:52:19Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	CreateOAuth2Token	null
2026-10-11T04:52:29Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T04:52:34Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	CreateOAuth2Token	null
2026-10-11T04:54:22Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:04:24Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:04:24Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:06:14Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
2026-10-11T05:08:37Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
2026-10-11T05:09:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T05:16:48Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:17:51Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
2026-10-11T05:21:13Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T05:27:01Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:31:48Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T05:31:58Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
2026-10-11T05:37:02Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:37:02Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:41:49Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	CreateOAuth2Token	null
2026-10-11T05:47:04Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:52:02Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
2026-10-11T05:57:15Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	CreateOAuth2Token	null
2026-10-11T05:57:32Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	CreateOAuth2Token	null
```

실행한 명령:
```
jq -r '.Records[]|select(.sourceIPAddress=="2001:db8:0:b::2")|[.eventTime,.eventName,(.errorCode//"-")]|@tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T05:16:40Z	SignUp	-
2026-10-11T05:17:08Z	SignUp	-
2026-10-11T05:17:22Z	ConfirmSignUp	-
2026-10-11T05:17:31Z	InitiateAuth	-
2026-10-11T05:17:32Z	RespondToAuthChallenge	-
2026-10-11T06:26:59Z	InitiateAuth	-
```

실행한 명령:
```
jq '[.Records[]|select(.eventName=="StartExecution" and .sourceIPAddress=="198.18.7.1")][0]' cloudtrail.json
```
결과:
```
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
```

실행한 명령:
```
echo "# K-1. blue-team-1의 SendCommand 집계 (건수, arn, IP, 이벤트, 에러, 파라미터 / 처음~마지막 시각)"; jq -r '.Records[]|select(.eventName=="SendCommand" and ((.userIdentity.arn//"")|test("blue-team-1")))|[(.userIdentity.arn),.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort | uniq -c; jq -r '[.Records[]|select(.eventName=="SendCommand" and ((.userIdentity.arn//"")|test("blue-team-1")))|.eventTime]|"처음 \(min) / 마지막 \(max)"' cloudtrail.json; echo; echo "# K-2. 나머지 전부 (StartSession/TerminateSession/ResumeSession 전체 + blue-team-1 외 SendCommand)"; jq -r '.Records[]|select(.eventName|IN("StartSession","TerminateSession","ResumeSession","SendCommand"))|select((.eventName=="SendCommand" and ((.userIdentity.arn//"")|test("blue-team-1")))|not)|[.eventTime,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,.eventName,(.errorCode//"-"),(.requestParameters|tojson|.[0:150])]|@tsv' cloudtrail.json | sort
```
결과:
```
# K-1. blue-team-1의 SendCommand 집계 (건수, arn, IP, 이벤트, 에러, 파라미터 / 처음~마지막 시각)
    219 arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
     25 arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	SendCommand	-	{"instanceIds":"[\\"i-05816900800807b77\\"]"}
      5 arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
      8 arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
      5 arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	SendCommand	-	{"instanceIds":"[\\"i-026754fe07a870049\\"]"}
처음 2026-10-11T04:30:38Z / 마지막 2026-10-11T07:23:36Z

# K-2. 나머지 전부 (StartSession/TerminateSession/ResumeSession 전체 + blue-team-1 외 SendCommand)
2026-10-11T04:32:38Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:33:29Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	null
2026-10-11T04:33:33Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	null
2026-10-11T04:33:57Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:36:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	StartSession	-	null
2026-10-11T04:38:30Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	StartSession	-	null
2026-10-11T04:38:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:38:54Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	TerminateSession	-	null
2026-10-11T04:42:12Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:43:38Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T04:46:05Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	TerminateSession	-	null
2026-10-11T05:06:14Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	StartSession	-	null
2026-10-11T05:09:01Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	StartSession	-	null
2026-10-11T05:09:55Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	ResumeSession	-	null
2026-10-11T05:13:06Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	StartSession	-	null
2026-10-11T05:30:54Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	StartSession	-	null
2026-10-11T05:45:58Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:09:40Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	StartSession	-	null
2026-10-11T06:12:35Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:13:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:14:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:15:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:16:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:17:17Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:18:35Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:19:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:20:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:21:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:22:34Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:22:58Z	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	ResumeSession	-	null
2026-10-11T06:26:14Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	StartSession	-	null
2026-10-11T06:26:21Z	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	TerminateSession	-	null
2026-10-11T06:39:20Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	StartSession	AccessDenied	null
2026-10-11T07:02:09Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	StartSession	AccessDenied	null
2026-10-11T07:11:37Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	SendCommand	AccessDenied	null
2026-10-11T07:12:16Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	SendCommand	AccessDenied	null
```

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# 최종 보고서: AWS 계정 침해 의심 건 (2026-10-11, ap-northeast-2)

> **분석 범위:** `cloudtrail.json` 한 파일(ap-northeast-2, UTC 04:30~07:25 / KST 13:30~16:25, 10,223건)만 사용했습니다. 콘솔과 CLI에 접속할 수 없어서 **조치는 아직 아무것도 실행되지 않았습니다.** 아래 "고쳐야 할 것"은 접속 권한이 있는 팀원이나 운영진에게 그대로 넘기시면 됩니다.

---

## 1. 결론

**PatchSignal 포털 서버(EC2 `i-05816900800807b77`)의 IAM 역할 자격 증명이 외부로 유출되었습니다.** 공격자는 이 자격 증명으로 **Step Functions 워크플로를 9번 실행하는 데 성공**했습니다. 다른 서버에 접속하거나 명령을 실행하려던 시도 4번은 권한이 없어 **모두 거부**됐습니다.

공격자는 유출 전에 서비스에 **일반 회원으로 가입하고 로그인**했습니다. 따라서 **로그인한 사용자가 쓸 수 있는 포털 기능의 취약점**으로 서버 자격 증명을 빼냈을 가능성이 가장 높습니다. 정확한 침입 방법과 실행된 워크플로의 내용은 이 파일로는 알 수 없습니다.

---

## 2. 무슨 일이 있었나 (최종 타임라인)

| UTC | KST | 출처 | 내용 | 결과 |
|---|---|---|---|---|
| 04:30~ | 13:30~ | 팀(blue-team-1) | 작업 서버(`i-026754…`)에 명령을 계속 실행하며 대응 시작 | 정상 |
| 04:37~04:42 | 13:37 | **198.18.7.1** | 회원가입 시도. 비밀번호 정책 위반 5회 뒤 **가입 2건 성공**, 확인 1건, **로그인 성공** | ✅ |
| 04:42~04:48 | 13:42 | 루트 (다른 IP) | 인프라 전체 조회 2회, API Gateway `UpdateStage` 2건 | 확인 필요 |
| 04:43~04:50 | 13:43 | **198.18.7.2** | 2초 안에 로그인 4회 실패(스크립트), 그 뒤 **가입, 확인, 로그인 성공** | ✅ |
| 05:00 | 14:00 | 포털 서버 | 앱이 정상 워크플로 실행 시작 (`case-<UUID>` 형식, 이후 76건) | 정상 |
| 05:09 | 14:09 | **7.2** | 정체불명 신원(`AWSAccount`)으로 PageSnap 결과 버킷 조회 | ❌ 거부 |
| 05:28~05:29 | 14:28 | **7.2** | 계정 **추가 가입, 확인, 로그인** | ✅ |
| 05:45 | 14:45 | **7.1** | 로그인 실패 2회 뒤 성공 | ✅ |
| 06:32:11 | 15:32 | 포털 서버 | 서버에 원격 세션 채널이 열림. **이 시각의 세션 시작 기록이 없음** | ⚠️ 미확인 |
| **06:36:22** | **15:36** | **7.1** | **포털 역할 자격 증명이 외부에서 처음 사용됨.** `StartExecution` | ✅ |
| 06:39~07:08 | 15:39 | 7.1, **198.18.50.1** | 같은 키로 `StartExecution` 8건 추가, `StartSession` 2회 | 실행 ✅ / 세션 ❌ |
| 07:11~07:12 | 16:11 | 7.1 | `SendCommand` 2회 | ❌ 거부 |
| 07:10~07:19 | 16:10 | 팀 추정 | GuardDuty Runtime Monitoring 활성화, 포털 서버에 에이전트 설치 | 대응 |
| 07:25 | 16:25 | | 파일 끝. 마지막 공격자 호출은 07:12. **이후 상황은 알 수 없음** | |

---

## 3. 판단 근거

### 확정 (파일에서 직접 확인)

- **유출된 키는 `ASIA71C2…95CF`입니다.** 세션 이름이 포털 인스턴스 ID라서 EC2 인스턴스 역할에서 나온 자격 증명입니다. 이 키는 **198.18.7.1과 198.18.50.1에서만** 사용됐고, 서버 자신의 IP(198.18.10.1, 10.81.0.102)에서는 한 번도 쓰이지 않았습니다.
- **같은 IP가 앱 가입과 키 사용에 모두 등장합니다.** 198.18.7.1은 Cognito 가입·로그인을 한 IP이고, 동시에 탈취 키를 쓴 IP입니다. 한 공격자로 연결됩니다.
- **이 키의 활동은 13건이 전부입니다.**

  | 호출 | 건수 | 결과 |
  |---|---|---|
  | `StartExecution` | 9 | 성공 |
  | `StartSession` | 2 | 거부 |
  | `SendCommand` | 2 | 거부 |

  조회나 정찰 호출이 하나도 없습니다. 공격자가 **이 역할로 무엇을 할 수 있는지 미리 알고 있었다**는 뜻입니다.
- **공격자는 앱의 실행 이름 규칙을 흉내 냈습니다.**
  - 앱은 `case-<32자리 UUID>` 형식을 씁니다.
  - 공격자는 `case-redteam-validation-002`, `case-redteam-validation-003`, `test-run-<유닉스 시각>`을 썼고, 일부는 이름 없이 실행했습니다.
  - 예를 들어 `test-run-1791702223`은 07:03:43에 해당하고, 실제 호출은 3초 뒤입니다. **스크립트로 자동 실행**한 것입니다.
- **공격자 IP에서 가입에 성공한 Cognito 계정은 4개이고, 그중 3개가 확인 완료됐습니다.**

  | 출처 | 가입 시각(UTC) |
  |---|---|
  | 7.1 | 04:39:48, 04:40:26 |
  | 7.2 | 04:48:29, 05:28:39 |

  가입 확인 코드를 받았다는 것은 **공격자가 실제로 받아 볼 수 있는 이메일이나 전화번호가 Cognito에 남아 있다**는 뜻입니다.
- **이 리전에서는 공격자가 리소스를 생성, 변경, 삭제한 흔적이 없습니다.**

### 추정

- **침입 경로**는 포털 앱의 SSRF나 원격 코드 실행으로 인스턴스 메타데이터(IMDS)를 읽은 것일 가능성이 큽니다. 공격자가 가입·로그인을 먼저 했다는 점이 근거입니다.
- **"redteam"이라는 실행 이름**으로 볼 때 연습의 레드팀 공격으로 보입니다.
- **PageSnap도 노렸을 수 있습니다.**
  - 결과 버킷 조회 시도가 있었습니다(거부).
  - 렌더러 Lambda가 콜드 스타트한 시각 중 두 번(05:33, 05:49)이 공격자 로그인 약 4분 뒤입니다.
  - 다만 콜드 스타트만 기록에 남기 때문에 **근거는 약합니다.**

### 모름

- **Step Functions 9건이 실제로 한 일.** 이것이 곧 실제 피해 범위인데, 이 파일에는 어떤 상태 머신인지조차 나오지 않습니다.
- **자격 증명이 유출된 정확한 시각과 방법.** 자격 증명만 빼갔는지, 서버를 장악했는지도 알 수 없습니다.
- **06:32:11 포털 서버 세션 채널의 주인.** 직전 팀원 세션(06:26:14)은 7초 만에 종료됐고, 06:32에는 세션을 시작하거나 재개한 기록이 없습니다. 공격자 첫 사용 4분 전이므로 **꼭 확인해야 할 항목**입니다.
- **다른 리전과 글로벌 이벤트.** 특히 us-east-1에 기록되는 IAM 변경(사용자 생성, 키 발급, 정책 부착)과 S3 객체 읽기, Lambda 호출 같은 데이터 이벤트입니다.
- **07:25 이후 상황.** 인스턴스 역할 자격 증명은 보통 몇 시간 동안 유효하므로, **누군가 취소하지 않았다면 지금도 유효할 수 있습니다.**

---

## 4. 이전 분석 정정

| 항목 | 이전 판단 | 최종 판단 |
|---|---|---|
| 포털 서버의 `GetCallerIdentity` 1건 (05:00:03) | 서버 침입의 신호일 수 있음 | **앱 시작 시 호출로 보임.** 새 키의 첫 사용이고, 같은 초에 정상 `case-<UUID>` 실행이 함께 시작됨. 위험도 낮음 |
| `ec2-ssmrole` 서버 (`i-026754…`) | 두 번째 침해 서버 의심 | **팀 작업 서버.** blue-team-1이 이 서버에 명령 237건을 보냈고, 거부된 `StartSession`(04:33:29, 04:33:33)은 팀 명령(04:33:19, 04:33:33) 직후임. 정상 |
| 루트 사용 | 콘솔 사용 → 인프라 도구로 정정 | 공격자 IP와 겹치지 않음. 조회 위주이고 변경은 `UpdateStage` 2건. **환경 운영 측 작업으로 보이지만 누가 했는지는 확인 필요** |
| 원격 접속·명령 이벤트(`StartSession`/`SendCommand`) | | 팀원이 아닌 사용자는 **공격자(포털 역할)와 작업 서버(ec2-ssmrole)뿐**이고 모두 거부됨. 나머지는 팀원 작업. 팀원이 포털 서버에도 명령 25건을 보냄 |

---

## 5. 고쳐야 할 것

### 🔴 즉시 (접속 가능한 사람이 진행)

**1. 탈취된 자격 증명 무효화**

포털 역할(`patchsignal-ewc2enb8-portal-role`)의 기존 세션을 전부 취소합니다. 콘솔에서는 **IAM → 역할 → 활성 세션 취소**, CLI로는 2차 답변의 `TokenIssueTime` 정책을 쓰면 됩니다. 공격자 키 `ASIA71C2…`는 서버가 쓰는 키와 다르므로, 취소해도 서버는 새 자격 증명을 다시 받습니다.

**2. 메타데이터 탈취 차단 (IMDSv2 강제)**

```bash
aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
  --http-tokens required --http-put-response-hop-limit 1
```

**3. 포털 역할을 서버 밖에서 쓸 수 없게 막기**

포털 서버의 실제 NAT 공인 IP나 VPC 조건을 넣은 Deny 정책을 추가합니다(2차 답변 2번).

**4. Step Functions 피해 확인**

포털 역할이 실행할 수 있는 상태 머신에서 06:36~07:08(UTC) 실행 9건의 **입력값, 실행 기록, 결과**를 확인합니다. 아직 실행 중이면 중지하고, 그 워크플로가 바꾼 데이터나 리소스를 되돌립니다. 찾을 실행 이름은 다음과 같습니다.
- `case-redteam-validation-002`, `case-redteam-validation-003`
- `test-run-1791702223`, `test-run-1791702300`, `test-run-1791702344`
- 이름 없이 실행된 4건 (06:36:22, 06:52:08, 07:02:17, 07:08:11)

**5. Cognito 공격자 계정 처리**

위 가입 시각(04:39~05:29 UTC)의 계정을 찾아 **이메일이나 전화번호를 먼저 기록**합니다. 그 뒤 비활성화하고 `admin-user-global-sign-out`을 실행합니다. IPv6 주소(05:16~05:17)로 가입한 계정도 누구인지 확인합니다.

**6. 포털 서버 증거 보존 후 교체**

EBS 스냅샷을 떠 두고, SSM 명령·세션 기록(`list-commands`, 세션 기록)에서 **팀원 작업과 06:32 세션을 구분**합니다. 웹셸, 낯선 프로세스, cron, SSH 키 변경 여부를 확인한 뒤 **새 인스턴스로 교체**합니다.

### 🟠 근본 원인 (개발자 몫)

**7. 포털 앱 취약점 수정**

로그인한 사용자가 쓸 수 있는 기능 중 다음을 우선 점검하세요.
- 사용자가 준 **URL로 서버가 요청을 보내는 기능** (SSRF)
- 사용자 입력이 셸 명령, 템플릿, 파일 경로, 역직렬화에 들어가는 부분 (원격 코드 실행)

웹·앱 로그에서 공격자 계정의 04:42~06:36(UTC) 요청과 `169.254.169.254` 문자열을 찾으면 **어떤 기능으로 들어왔는지** 특정할 수 있습니다.

**8. 포털 역할 권한 최소화**
- `states:StartExecution`은 필요한 상태 머신 하나로만 제한하세요.
- 앱이 5분마다 `lambda:GetFunction`을 호출하는데, 이 권한은 **함수 코드 다운로드 URL과 환경 변수**까지 노출합니다. 상태 확인만 필요하다면 `GetFunctionConfiguration` 등으로 줄이세요.
- SSM 권한이 없어서 이번에 피해가 막혔습니다. 이 상태를 유지하세요.

**9. 워크플로 입력 검증**

공격자가 앱의 실행 이름 규칙을 그대로 흉내 낼 수 있었습니다. 상태 머신 **안에서도** 입력값을 검증하고, 실행 요청이 실제 앱 요청인지 확인할 수 있는 구조(서명된 케이스 ID 등)를 검토하세요.

### 🟡 그 밖에 확인할 것

- **GuardDuty 발견 사항.** `InstanceCredentialExfiltration.OutsideAWS`가 있으면 유출이 공식 확인된 것입니다. 07:19에 포털 서버에 런타임 에이전트도 설치됐으니 런타임 발견 사항도 봐야 합니다.
- **us-east-1 CloudTrail**에서 IAM 변경 여부, 그리고 다른 리전의 활동.
- **PageSnap:** 결과 버킷 정책과 퍼블릭 액세스 설정, 렌더러의 SSRF 가능성.
- **루트 계정:** 사용자를 확인하고, MFA와 루트 액세스 키 상태를 점검합니다. `UpdateStage` 2건이 어떤 변경이었는지도 확인합니다.
- **보안 그룹:** blue-team-1이 수정한 4건이 0.0.0.0/0으로 열려 있지 않은지 확인합니다.

---

## 6. 운영진·팀에 넘길 질문

1. Step Functions 실행 9건의 입력과 결과는 무엇이었나요? (**피해 범위를 정하는 핵심 질문**)
2. 06:32:11(UTC)에 포털 서버로 세션을 연 사람은 누구인가요?
3. 포털 앱에 URL을 받아 서버가 가져오는 기능이 있나요? IMDSv1이 켜져 있었나요?
4. 04:42~04:48(UTC)에 루트를 사용한 사람은 누구인가요?
5. IPv6 주소(`2001:db8:0:b::2`)로 가입한 계정은 누구인가요?
6. us-east-1에 IAM 변경 기록이 있나요? GuardDuty 발견 사항은 무엇인가요?

---

### 공유용 세 줄 요약

> 앱에 회원가입한 공격자가 PatchSignal 포털 서버의 IAM 역할 자격 증명(`ASIA71C2…`)을 빼내 외부 IP 2곳에서 Step Functions를 9회 실행했습니다(성공). 서버 접속과 명령 실행은 권한 부족으로 실패했습니다.
> 즉시 조치는 포털 역할 세션 취소, IMDSv2 강제, 공격자 Cognito 계정 차단, 실행 9건의 영향 확인입니다.
> 근본 원인은 포털 앱의 SSRF 또는 원격 코드 실행 취약점으로 추정되며, 코드 점검과 역할 권한 축소가 필요합니다.

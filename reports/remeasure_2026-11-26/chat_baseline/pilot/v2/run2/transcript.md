## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

먼저 상황을 확인하고 피해 확산을 막은 다음, 로그를 분석하는 순서로 진행하겠습니다. 로그를 주시면 함께 분석해 드릴게요.

---

## 0단계: 연락이 진짜인지 확인 (5분)

"계정이 공격받았다"는 연락 자체가 피싱일 수 있습니다.

- **누가, 어떤 경로로** 연락했나요? (AWS 이메일, AWS Support 케이스, GuardDuty 알림, 사내 보안팀, 외부인 등)
- 메일에 있는 링크는 클릭하지 마세요. 브라우저에 직접 `console.aws.amazon.com`을 입력해서 접속하세요.
- 콘솔 우측 상단 **Support → Support Center**에 AWS가 연 케이스가 있는지 확인하세요. 진짜 AWS 알림이면 보통 여기에도 케이스가 있습니다.

회사 계정이라면 **지금 바로 팀장과 보안 담당자에게 알리세요.** 혼자 처리할 일이 아닙니다.

---

## 1단계: 즉시 조치 (30분 이내)

**원칙: 지우지 말고 비활성화하세요.** 삭제하면 증거가 사라집니다.

1. **루트 계정 보호**
   - 루트 비밀번호를 변경하세요.
   - MFA가 켜져 있는지 확인하고, 없으면 등록하세요.
   - 루트 계정에 Access Key가 있으면 비활성화하세요.

2. **IAM 사용자와 키 점검** (IAM 콘솔 → Users)
   - 모르는 사용자가 있나요?
   - 오늘 생성된 Access Key가 있나요?
   - 의심스러운 키는 **Deactivate**만 하세요. Delete는 하지 마세요.
   - 단, 운영 중인 서비스가 쓰는 키를 끄면 서비스가 멈출 수 있습니다. 어떤 키를 끌지는 로그를 보고 함께 판단하는 게 안전합니다.

3. **요금 확인** (Billing → Bills, Cost Explorer)
   - 오늘 비용이 급증했는지 확인하세요. 가장 흔한 공격은 **EC2로 암호화폐 채굴**하는 것입니다.

4. **CloudTrail이 꺼지지 않았는지 확인**
   - CloudTrail → Trails에서 로깅 상태를 확인하세요. 공격자가 흔적을 지우려고 끄는 경우가 많습니다.

---

## 2단계: 로그 추출

**주의: CloudTrail 시간은 UTC 기준입니다.** 한국시간 13:30은 **UTC 04:30**입니다.

먼저 올바른 계정에 연결됐는지 확인하세요.
```bash
aws sts get-caller-identity
```

### (1) CloudTrail 이벤트, 전체 리전 (가장 중요)
공격자는 평소 쓰지 않는 리전에 리소스를 만드는 경우가 많아서 모든 리전을 봐야 합니다. `YYYY-MM-DD`는 오늘 날짜로 바꾸세요.
```bash
START="YYYY-MM-DDT04:30:00Z"
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r"
  aws cloudtrail lookup-events --region "$r" --start-time "$START" \
    --output json > "cloudtrail_${r}.json"
done
```
IAM이나 로그인 같은 글로벌 이벤트는 주로 `us-east-1` 파일에 기록됩니다.

### (2) IAM 자격증명 리포트
```bash
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > credential_report.csv
```

### (3) 전체 리전의 실행 중인 EC2
```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r"
  aws ec2 describe-instances --region "$r" \
    --query "Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,State.Name,KeyName]" \
    --output table
done > ec2_all_regions.txt
```

---

## 3단계: 로그에서 볼 것 (미리 보기)

파일이 크면 아래 이벤트만 먼저 걸러서 주셔도 됩니다.

| 의심 이벤트 | 의미 |
|---|---|
| `ConsoleLogin` | 누가, 어떤 IP에서 로그인했는지 |
| `CreateUser`, `CreateAccessKey`, `CreateLoginProfile` | 공격자가 뒷문용 계정을 만듦 |
| `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy` | 권한 상승 |
| `RunInstances`, `ImportKeyPair`, `CreateKeyPair` | 채굴용 서버 생성 |
| `StopLogging`, `DeleteTrail`, `DeleteDetector` | 흔적 지우기 |
| `GetSecretValue`, `GetParameter` | 비밀값 탈취 |
| `PutBucketPolicy`, `PutBucketAcl` | S3 데이터 공개나 유출 |
| `AuthorizeSecurityGroupIngress` | 방화벽 개방 |

간단히 거르는 방법:
```bash
cat cloudtrail_*.json | jq -r '.Events[] | [.EventTime, .EventName, .Username, (.CloudTrailEvent|fromjson|.sourceIPAddress)] | @tsv' \
  | grep -E "ConsoleLogin|Create|Attach|Put.*Policy|RunInstances|KeyPair|StopLogging|Delete|GetSecretValue|Authorize" \
  > suspicious.tsv
```

---

## 로그를 공유할 때 주의할 점

- **Secret Access Key, 비밀번호, DB 접속 정보는 절대 붙여넣지 마세요.** CloudTrail에는 보통 포함되지 않지만, 한 번 훑어보고 주세요.
- Access Key ID(`AKIA...`)는 분석에 필요하니 그대로 두셔도 됩니다. 걱정되면 뒤 몇 자리만 남기고 가리셔도 됩니다.
- 고객 개인정보가 보이면 가려 주세요.

---

## 참고: 흔한 침입 원인

로그를 보면서 이런 가능성도 떠올려 보세요.
- GitHub 등에 Access Key나 `.env` 파일이 커밋됨 (가장 흔함)
- 개발자 PC나 CI/CD에서 키 유출
- EC2 앱의 SSRF 취약점으로 인스턴스 메타데이터(IMDSv1)에서 임시 자격증명이 탈취됨
- MFA 없는 콘솔 계정의 비밀번호 유출

---

**다음 순서:** 0단계 확인 결과(누가 연락했는지)와 `suspicious.tsv`, `credential_report.csv`, `ec2_all_regions.txt`를 주시면 무슨 일이 있었는지 분석하고 구체적인 복구 방법을 알려 드리겠습니다. 요금 폭탄이 있다면 AWS Support에 케이스를 열어 두세요. 침해로 인한 요금은 조정해 주는 경우가 있습니다.

## 사용자

요청하신 것 중 뽑을 수 있는 것만 아래 붙였습니다.

**0단계 (누가 연락했는지):** 누가 어떤 경로로 연락했는지는 저도 몰라요. 지금은 AWS 콘솔과 CLI에 접속할 수 없어서 Support Center 케이스는 확인하지 못했습니다. 참고로 이 계정은 보안 공방전(연습) 환경입니다.

**1단계 (즉시 조치):** 콘솔에 접속할 수 없어서 아무것도 하지 못했습니다. 루트 계정, IAM 사용자와 키, 요금, CloudTrail 로깅 상태 모두 확인하지 못했어요.

**2단계, 3단계 (로그 추출):**
- `aws sts get-caller-identity`: CLI를 쓸 수 없어서 실행하지 못했습니다.
- (1) CloudTrail 전체 리전: 제게 있는 건 ap-northeast-2 리전의 `cloudtrail.json` 하나뿐입니다. 한국 시간 13:30~16:25 무렵이 담겨 있어요. 다른 리전과 us-east-1은 확인하지 못했습니다(그 로그는 없어요).
- `suspicious.tsv`: 주신 jq와 grep 조건 그대로 `cloudtrail.json`에서 뽑았는데, 두 가지를 바꿨습니다.
  - 이 파일은 lookup-events 결과가 아니라 `{"Records":[...]}` 형식이에요. 그래서 `.Events[]` 대신 `.Records[]`를 읽었습니다. 각 필드는 `eventTime`, `eventName`, `sourceIPAddress`이고, 사용자는 `userIdentity.userName`(없으면 `arn`, 그것도 없으면 `type`)을 썼어요.
  - 걸러진 줄이 383줄(약 4만 자)이라 다 붙일 수가 없었습니다. 그래서 '이벤트 이름 + 사용자 + 출발지 IP'가 같은 줄끼리 묶어 첫 시각, 마지막 시각, 횟수만 보여 드려요(79줄). 사용자 ARN 앞부분 `arn:aws:iam::111122223333:`와 `arn:aws:sts::111122223333:`도 빼서 짧게 했습니다. 이 파일의 계정 ID는 모두 111122223333이에요. 묶기 전 원래 줄이 필요하시면 말씀해 주세요.
- (2) `credential_report.csv`: 확인하지 못했습니다(그 로그는 없어요).
- (3) `ec2_all_regions.txt`: 확인하지 못했습니다(그 로그는 없어요).

실행한 명령:
```
echo -e "first_time\tlast_time\tcount\teventName\tuser\tsourceIP"; jq -r '.Records[] | [.eventTime, .eventName, ((.userIdentity.userName // .userIdentity.arn // .userIdentity.type) | sub("^arn:aws:(iam|sts)::[0-9]+:";"")), .sourceIPAddress] | @tsv' cloudtrail.json | grep -E "ConsoleLogin|Create|Attach|Put.*Policy|RunInstances|KeyPair|StopLogging|Delete|GetSecretValue|Authorize" | awk -F'\t' '{k=$2"\t"$3"\t"$4; c[k]++; if(!(k in f))f[k]=$1; l[k]=$1} END{for(k in c) print f[k]"\t"l[k]"\t"c[k]"\t"k}' | sort
```
결과:
```
first_time	last_time	count	eventName	user	sourceIP
2026-10-11T04:30:13Z	2026-10-11T07:24:06Z	103	CreateLogStream	AWSService	delivery.logs.amazonaws.com
2026-10-11T04:30:40Z	2026-10-11T05:41:29Z	2	DescribeKeyPairs	user/blue-team-1	198.18.3.1
2026-10-11T04:30:44Z	2026-10-11T04:39:58Z	4	DescribeKeyPairs	user/blue-team-1	198.18.5.1
2026-10-11T04:30:45Z	2026-10-11T04:30:45Z	1	CreateLogStream	assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3	198.18.8.1
2026-10-11T04:30:49Z	2026-10-11T07:15:49Z	24	CreateNetworkInterfacePermission	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com
2026-10-11T04:30:49Z	2026-10-11T07:15:50Z	24	CreateNetworkInterface	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com
2026-10-11T04:31:12Z	2026-10-11T04:52:34Z	4	CreateOAuth2Token	user/blue-team-1	198.18.5.1
2026-10-11T04:31:53Z	2026-10-11T07:23:54Z	6	CreateNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1
2026-10-11T04:31:54Z	2026-10-11T07:23:55Z	6	AttachNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1
2026-10-11T04:32:38Z	2026-10-11T06:46:25Z	18	CreateDataChannel	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1
2026-10-11T04:33:58Z	2026-10-11T07:25:01Z	20	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1
2026-10-11T04:34:18Z	2026-10-11T05:57:15Z	12	CreateOAuth2Token	user/blue-team-1	198.18.2.1
2026-10-11T04:37:56Z	2026-10-11T05:41:49Z	6	CreateOAuth2Token	user/blue-team-1	198.18.3.1
2026-10-11T04:39:33Z	2026-10-11T05:27:37Z	5	AuthorizeSecurityGroupIngress	user/blue-team-1	198.18.2.1
2026-10-11T04:39:53Z	2026-10-11T04:39:53Z	1	DescribeKeyPairs	user/blue-team-1	198.18.2.1
2026-10-11T04:42:24Z	2026-10-11T04:42:24Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.13.1
2026-10-11T04:46:53Z	2026-10-11T04:46:53Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.17.1
2026-10-11T04:55:21Z	2026-10-11T04:55:21Z	1	ListAuthorizers	assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com
2026-10-11T05:00:08Z	2026-10-11T05:00:08Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.21.1
2026-10-11T05:00:10Z	2026-10-11T05:00:10Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.22.1
2026-10-11T05:06:14Z	2026-10-11T05:57:32Z	6	CreateOAuth2Token	user/blue-team-1	198.18.23.1
2026-10-11T05:14:04Z	2026-10-11T05:58:38Z	6	DescribeKeyPairs	user/blue-team-2	198.18.23.1
2026-10-11T05:14:33Z	2026-10-11T05:14:33Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.25.1
2026-10-11T05:14:38Z	2026-10-11T05:14:38Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.27.1
2026-10-11T05:17:55Z	2026-10-11T05:17:55Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.28.1
2026-10-11T05:22:43Z	2026-10-11T05:22:49Z	6	PutRetentionPolicy	user/blue-team-1	198.18.2.1
2026-10-11T05:24:16Z	2026-10-11T05:24:16Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.30.1
2026-10-11T05:24:18Z	2026-10-11T05:24:18Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.31.1
2026-10-11T05:25:23Z	2026-10-11T05:25:23Z	1	CreateTopic	user/blue-team-2	198.18.23.1
2026-10-11T05:27:36Z	2026-10-11T05:27:36Z	1	CreateEnvironment	user/blue-team-2	198.18.23.1
2026-10-11T05:27:38Z	2026-10-11T05:31:36Z	8	CreateSession	user/blue-team-2	198.18.23.1
2026-10-11T05:28:45Z	2026-10-11T05:28:45Z	1	DeleteTopic	user/blue-team-2	198.18.23.1
2026-10-11T05:29:47Z	2026-10-11T05:31:38Z	10	DeleteSession	user/blue-team-2	198.18.23.1
2026-10-11T05:31:47Z	2026-10-11T06:35:21Z	3	CreateSnapshot	user/blue-team-1	198.18.2.1
2026-10-11T05:33:58Z	2026-10-11T05:33:58Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.35.1
2026-10-11T05:38:14Z	2026-10-11T05:38:14Z	1	DescribeTransitGatewayAttachments	assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com
2026-10-11T05:41:52Z	2026-10-11T05:41:53Z	2	GetAuthorizers	user/blue-team-1	198.18.3.1
2026-10-11T05:49:49Z	2026-10-11T05:49:49Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.38.1
2026-10-11T05:52:48Z	2026-10-11T05:52:48Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.39.1
2026-10-11T05:54:07Z	2026-10-11T05:54:07Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.42.1
2026-10-11T05:54:07Z	2026-10-11T05:54:07Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.41.1
2026-10-11T05:56:15Z	2026-10-11T05:56:15Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.43.1
2026-10-11T05:56:15Z	2026-10-11T05:56:15Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.44.1
2026-10-11T06:00:40Z	2026-10-11T06:00:40Z	1	GetAuthorizers	user/blue-team-1	AWS Internal
2026-10-11T06:07:59Z	2026-10-11T07:00:08Z	21	CreateSession	user/blue-team-1	198.18.23.1
2026-10-11T06:07:59Z	2026-10-11T07:19:00Z	27	DeleteSession	user/blue-team-1	198.18.23.1
2026-10-11T06:08:19Z	2026-10-11T06:08:19Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.45.1
2026-10-11T06:09:40Z	2026-10-11T06:32:11Z	2	CreateDataChannel	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1
2026-10-11T06:10:28Z	2026-10-11T06:10:28Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.46.1
2026-10-11T06:14:37Z	2026-10-11T06:14:37Z	1	CreateIPSet	user/blue-team-1	198.18.23.1
2026-10-11T06:27:08Z	2026-10-11T06:27:08Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.47.1
2026-10-11T06:34:25Z	2026-10-11T06:34:25Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.48.1
2026-10-11T06:34:26Z	2026-10-11T06:34:26Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.49.1
2026-10-11T06:39:49Z	2026-10-11T06:39:49Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.51.1
2026-10-11T06:40:52Z	2026-10-11T06:40:52Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.52.1
2026-10-11T06:43:19Z	2026-10-11T06:43:29Z	3	CreateBackup	user/blue-team-1	198.18.2.1
2026-10-11T06:48:44Z	2026-10-11T06:48:44Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.53.1
2026-10-11T06:49:30Z	2026-10-11T06:49:30Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.54.1
2026-10-11T06:49:32Z	2026-10-11T06:49:32Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.55.1
2026-10-11T06:52:11Z	2026-10-11T06:52:11Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.56.1
2026-10-11T06:52:12Z	2026-10-11T06:52:12Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.57.1
2026-10-11T06:58:48Z	2026-10-11T06:58:48Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.58.1
2026-10-11T06:59:48Z	2026-10-11T06:59:48Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.59.1
2026-10-11T06:59:56Z	2026-10-11T06:59:56Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.2
2026-10-11T07:04:34Z	2026-10-11T07:04:34Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.60.1
2026-10-11T07:07:34Z	2026-10-11T07:07:34Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.61.1
2026-10-11T07:09:19Z	2026-10-11T07:09:19Z	1	CreateDetector	user/blue-team-1	198.18.23.1
2026-10-11T07:09:30Z	2026-10-11T07:09:30Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.62.1
2026-10-11T07:13:31Z	2026-10-11T07:13:31Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.63.1
2026-10-11T07:15:14Z	2026-10-11T07:15:14Z	1	CreateLogStream	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.64.1
2026-10-11T07:18:33Z	2026-10-11T07:18:33Z	1	CreateAddon	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
2026-10-11T07:18:34Z	2026-10-11T07:18:34Z	1	AuthorizeSecurityGroupIngress	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
2026-10-11T07:18:34Z	2026-10-11T07:18:34Z	1	CreateSecurityGroup	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
2026-10-11T07:18:37Z	2026-10-11T07:18:37Z	1	CreateVpcEndpoint	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
2026-10-11T07:18:39Z	2026-10-11T07:18:39Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.65.1
2026-10-11T07:18:43Z	2026-10-11T07:18:43Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.66.1
2026-10-11T07:19:22Z	2026-10-11T07:19:22Z	1	CreateAssociation	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
2026-10-11T07:23:48Z	2026-10-11T07:23:48Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.67.1
2026-10-11T07:23:49Z	2026-10-11T07:23:49Z	1	CreateLogStream	assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.68.1
```

## 채팅 AI

## 요약

**공유해 주신 범위에서는 공격이라고 단정할 만한 이벤트가 보이지 않습니다.** 하지만 그렇다고 공격이 없었다는 뜻은 아닙니다. 이 데이터로는 판단할 수 없는 부분이 많아서, 지금 결론은 "아직 모름"입니다.

참고로 로그 시작 시각 04:30:13Z는 한국시간 13:30이니, 13:30부터 잘라 낸 로그입니다. 13:30에 특별한 일이 있었다는 의미는 아닙니다.

---

## 1. 정상 동작으로 보이는 것 (대부분)

| 이벤트 | 주체 | 해석 |
|---|---|---|
| `CreateLogStream` (Lambda 역할들, delivery.logs) | pagesnap/patchsignal 함수, AWS 서비스 | Lambda가 새로 뜰 때마다 로그 스트림을 만드는 정상 동작입니다. 실행할 때마다 IP가 달라지는 것도 정상입니다. |
| `Create/Attach/DeleteNetworkInterface` | EKS 서비스 역할, EKS 노드 | EKS의 Pod 네트워킹(VPC CNI) 정상 동작입니다. |
| `CreateAddon`, `CreateSecurityGroup`, `CreateVpcEndpoint`, `CreateAssociation` (07:18~07:19) | GuardDuty 서비스 역할 | 07:09에 blue-team-1이 `CreateDetector`로 GuardDuty를 켠 직후 런타임 모니터링이 자동 설치된 것입니다. 정상입니다. |
| `ListAuthorizers`, `DescribeTransitGatewayAttachments` | AWS Config, Resource Explorer | 서비스 자동 수집입니다. |
| fluent-bit `CreateLogStream` | tetragon 역할 | 보안 모니터링 도구의 로그 전송입니다. |

---

## 2. 확인이 필요한 것 (우선순위 순)

공격처럼 보이는 행동은 모두 **blue-team-1, blue-team-2 IAM 사용자**가 했습니다. 방어팀 본인들의 정상 작업일 가능성이 높지만, 그 사용자 키가 탈취됐다면 같은 모습으로 보입니다. **팀원에게 "이거 본인이 한 거 맞냐"고 확인하는 게 가장 빠릅니다.**

1. **`AuthorizeSecurityGroupIngress` 5회** (blue-team-1, 198.18.2.1, 04:39~05:27)
   방화벽 규칙이 열렸습니다. 어떤 포트가 어디(`0.0.0.0/0`인지)에 열렸는지 꼭 봐야 합니다.

2. **`CreateSnapshot` 3회, `CreateBackup` 3회** (blue-team-1, 198.18.2.1)
   방어팀이 증거 보존용으로 만든 것일 수도 있습니다. 반대로 데이터 유출의 첫 단계(스냅샷을 만든 뒤 외부 계정에 공유)일 수도 있습니다. 공유하는 이벤트(`ModifySnapshotAttribute`)는 이번 필터에 걸리지 않으니 따로 확인해야 합니다.

3. **SSM 세션 접속 흔적 `CreateDataChannel`**
   - `ec2-ssmrole/i-026754fe07a870049`: 18회
   - `patchsignal-...-portal-role/i-05816900800807b77`: 06:09, 06:32 두 번
   - 누군가 이 인스턴스에 셸로 들어갔다는 뜻입니다. **누가 들어갔는지**는 `StartSession` 이벤트에 있는데, 이것도 필터에 걸리지 않았습니다.

4. **blue-team-1이 여러 IP에서 사용됨**: 198.18.2.1, .3.1, .5.1, .23.1
   팀원 여럿이 한 계정을 같이 쓰면 자연스러운 모습입니다. 그렇지 않다면 의심스럽습니다. 198.18.23.1은 blue-team-2도 쓰고 있어서 팀 공용 네트워크로 보입니다.

5. **`CreateOAuth2Token`, `CreateEnvironment`/`CreateSession`/`DeleteSession`**
   CloudShell이나 콘솔 로그인 관련 이벤트로 추정되지만, `eventSource`를 봐야 확정할 수 있습니다.

---

## 3. 이 로그로는 알 수 없는 것

- **IP 정보를 쓸 수 없습니다.** 모든 IP가 `198.18.x.x`(테스트용 예약 대역)입니다. 연습 환경 운영 측에서 마스킹한 것으로 보입니다. 그래서 국가나 AWS 소유 여부 같은 판단은 불가능하고, IP끼리 비교만 할 수 있습니다.
- **IAM, 로그인 이벤트가 없습니다.** `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `ConsoleLogin` 등은 us-east-1에 기록됩니다. 그래서 이 파일에 없는 게 정상이고, "뒷문 계정이 안 만들어졌다"는 증거가 되지 않습니다.
- **다른 리전**도 확인하지 못했습니다.
- **제가 드린 grep 필터에 구멍이 많았습니다.** 정정합니다.
  - 표에는 `GetParameter`를 적어 놓고 grep 조건에서는 빠뜨렸습니다.
  - `AssumeRole`, `StartSession`, `ModifySnapshotAttribute`, `UpdateFunctionCode`, `GetObject`도 잡히지 않습니다.
  - 반대로 `Authorize`가 `GetAuthorizers`에, `KeyPair`가 `DescribeKeyPairs`에 걸리는 등 불필요한 것도 섞였습니다.
- **실패한 시도(`errorCode`)가 묶음 과정에서 빠졌습니다.** 공격자는 권한 없는 API를 이것저것 시도하다가 `AccessDenied`를 많이 남기는 경우가 많아서 중요한 단서입니다.
- **애플리케이션 내부 공격은 CloudTrail에 남지 않습니다.** 공방전이라면 공격팀은 pagesnap, patchsignal 같은 앱을 직접 노릴 가능성이 큽니다. 특히 "페이지를 렌더링하는" 서비스는 SSRF로 내부 자격증명을 훔치는 전형적인 표적입니다. 이 경우 훔친 역할 자격증명이 `CreateLogStream` 외의 API 호출에 쓰였는지가 핵심 단서입니다.

---

## 4. 지금 하실 일

콘솔과 CLI 권한이 없으시니, 1단계 즉시 조치는 **권한이 있는 사람(팀장이나 연습 운영진)에게 넘기셔야 합니다.** "연락이 왔다"는 것도 연습 시나리오일 수 있으니 **운영진 공식 채널로 진위를 확인**하시고, 연습 규칙상 허용된 조치 범위도 함께 물어보세요.

그동안 가진 `cloudtrail.json`으로 아래 명령을 돌려 주세요. 이번에는 grep 대신 CloudTrail의 `readOnly` 필드와 서비스 이름(eventSource)을 써서 빠짐없이 봅니다.

**(A) 변경 작업 전체 요약** (가장 중요)
```bash
jq -r '.Records[] | select(.readOnly == false and .eventName != "CreateLogStream")
  | [.eventSource, .eventName,
     ((.userIdentity.arn // .userIdentity.type // "-") | sub("^arn:aws:(iam|sts)::[0-9]+:";"")),
     .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json \
  | sort | uniq -c | sort -rn > write_summary.tsv
```

**(B) 실패한 호출 전부**
```bash
jq -r '.Records[] | select(.errorCode != null)
  | [.eventTime, .eventSource, .eventName,
     ((.userIdentity.arn // .userIdentity.type // "-") | sub("^arn:aws:(iam|sts)::[0-9]+:";"")),
     .sourceIPAddress, .errorCode] | @tsv' cloudtrail.json | sort > errors.tsv
```

**(C) 의심 이벤트의 상세 내용** (어떤 포트를 열었는지, 누가 세션에 접속했는지 등)
```bash
jq -c '.Records[] | select(.eventName | IN("AuthorizeSecurityGroupIngress","CreateSnapshot",
  "CreateBackup","ModifySnapshotAttribute","StartSession","CreateIPSet","CreateOAuth2Token",
  "CreateEnvironment"))
  | {t:.eventTime, src:.eventSource, n:.eventName, u:.userIdentity.arn,
     ip:.sourceIPAddress, ua:.userAgent, err:.errorCode, req:.requestParameters}' \
  clo

## 사용자

(A), (B), (C) 세 개 다 `cloudtrail.json`에서 뽑아 아래 붙였어요. 이 파일에는 `readOnly` 필드가 없어서 (A)는 그대로 실행하면 결과가 0건이라, 조건을 바꿔서 다시 뽑았습니다.

**물어보신 것:**
- blue-team-1, blue-team-2는 둘 다 우리 팀원 계정이에요. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했습니다. 각 이벤트를 누가 직접 했는지는 팀원별로 따로 확인하지 못했어요.
- 누가 어떤 경로로 연락했는지는 여전히 모릅니다. 운영진 쪽 확인이나 콘솔 조치도 제가 할 수 없는 상태예요.

**첫 번째 결과:** 이 파일의 레코드에 들어 있는 필드와 건수입니다. 이것 때문에 명령 몇 개를 고쳤어요.
- `readOnly`와 `userAgent` 필드는 없습니다.
- `requestParameters`는 전체 10,223건 중 1,173건에만 있어요.

**(A) 변경 작업 요약:**
- `readOnly == false`가 맞는 레코드가 없어서, 그 조건 대신 이벤트 이름이 `Get`, `List`, `Describe`, `Head`, `Lookup`, `Search`, `BatchGet`, `BatchDelete`, `Check`, `Verify`, `Filter`, `Query`, `Scan`, `Select`, `Test`, `View`로 시작하는 것을 뺐습니다.
- 이름만 보고 뺀 거라 실제 `readOnly` 값과 다를 수 있어요. 예를 들어 `BatchDelete`는 변경 작업인데 빠졌습니다.
- 나머지(`CreateLogStream` 제외, 묶는 기준, 정렬)는 주신 그대로입니다.
- 결과가 134줄이라 앞 122줄만 붙였어요. 빠진 12줄은 모두 1회짜리 줄입니다.

**(B) 실패한 호출 전부:**
- 원래 명령대로 하면 204줄(약 2만 8천 자)이라 다 붙일 수 없었어요.
- 그래서 `eventTime`을 빼고 같은 줄끼리 묶어 횟수를 셌습니다(`uniq -c`). 나머지 열은 주신 그대로예요.
- 시각이 있는 원래 줄이 필요하면 범위를 좁혀서 다시 뽑아 드릴게요.

**(C) 의심 이벤트 상세:**
- 메시지가 `clo`에서 끊겨 있어서 파일 이름을 `cloudtrail.json`으로 보고 그대로 실행했어요.
- 이 이벤트들은 `requestParameters`가 거의 비어 있어서, 어떤 포트를 열었는지 같은 내용은 이 파일에 없습니다. `CreateIPSet` 한 건에만 들어 있어요.
- `userAgent`도 필드가 없어서 전부 null로 나옵니다.

실행한 명령:
```
echo "# cloudtrail.json 레코드에 있는 필드와 개수 (전체 10223건)"; jq -r '[.Records[] | keys[]] | group_by(.) | map("\(length)\t\(.[0])") | .[]' cloudtrail.json
```
결과:
```
# cloudtrail.json 레코드에 있는 필드와 개수 (전체 10223건)
204	errorCode
10223	eventName
10223	eventSource
10223	eventTime
1173	requestParameters
10223	sourceIPAddress
10223	userIdentity
```

실행한 명령:
```
jq -r '.Records[] | select(.eventName != "CreateLogStream") | select(.eventName|test("^(Get|List|Describe|Head|Lookup|Search|Batch[GD]et|Check|Verify|Filter|Query|Scan|Select|Test|View)")|not) | [.eventSource, .eventName, ((.userIdentity.arn // .userIdentity.type // "-") | sub("^arn:aws:(iam|sts)::[0-9]+:";"")), .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn | head -n 122
```
결과:
```
    244 ssm.amazonaws.com	SendCommand	user/blue-team-1	198.18.2.1	-
     89 logs.amazonaws.com	StartQuery	user/blue-team-1	198.18.23.1	-
     76 states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
     60 sts.amazonaws.com	AssumeRole	AWSService	eks-nodegroup.amazonaws.com	-
     56 sts.amazonaws.com	AssumeRole	AWSService	config.amazonaws.com	-
     55 sts.amazonaws.com	AssumeRole	AWSService	eks.amazonaws.com	-
     41 ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
     41 ssm.amazonaws.com	UpdateInstanceInformation	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	-
     33 kms.amazonaws.com	Decrypt	user/blue-team-1	lambda.amazonaws.com	-
     31 eks.amazonaws.com	AccessKubernetesApi	user/blue-team-2	198.18.23.1	-
     27 sts.amazonaws.com	AssumeRole	AWSService	lambda.amazonaws.com	-
     26 sts.amazonaws.com	AssumeRole	AWSService	states.amazonaws.com	-
     24 ec2.amazonaws.com	CreateNetworkInterfacePermission	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	Client.DryRunOperation
     24 ec2.amazonaws.com	CreateNetworkInterface	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	Client.DryRunOperation
     24 cognito-idp.amazonaws.com	AdminGetUser	user/blue-team-1	198.18.23.1	-
     21 cloudshell.amazonaws.com	DeleteSession	user/blue-team-1	198.18.23.1	-
     21 cloudshell.amazonaws.com	CreateSession	user/blue-team-1	198.18.23.1	-
     18 sts.amazonaws.com	AssumeRole	AWSService	resource-explorer-2.amazonaws.com	-
     18 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.6.1	-
     18 ssm.amazonaws.com	CreateDataChannel	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	-
     17 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.23.1	-
     17 cloudshell.amazonaws.com	PutCredentials	user/blue-team-1	198.18.23.1	-
     14 ec2.amazonaws.com	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	Client.InvalidParameterValue
     13 ssm.amazonaws.com	ResumeSession	user/blue-team-2	198.18.23.1	-
     12 signin.amazonaws.com	CreateOAuth2Token	user/blue-team-1	198.18.2.1	-
     12 cognito-idp.amazonaws.com	AdminGetUser	user/blue-team-1	198.18.3.1	-
     10 sts.amazonaws.com	AssumeRole	AWSService	ec2.amazonaws.com	-
     10 cloudshell.amazonaws.com	DeleteSession	user/blue-team-2	198.18.23.1	-
      9 cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.2	-
      9 cognito-idp.amazonaws.com	AdminListGroupsForUser	user/blue-team-1	198.18.23.1	-
      8 ssm.amazonaws.com	SendCommand	user/blue-team-1	198.18.3.1	-
      8 cloudshell.amazonaws.com	SendHeartBeat	user/blue-team-1	198.18.23.1	-
      8 cloudshell.amazonaws.com	CreateSession	user/blue-team-2	198.18.23.1	-
      7 sts.amazonaws.com	AssumeRole	AWSService	AWS Internal	-
      7 cloudshell.amazonaws.com	PutCredentials	user/blue-team-2	198.18.23.1	-
      6 states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-
      6 signin.amazonaws.com	CreateOAuth2Token	user/blue-team-1	198.18.3.1	-
      6 signin.amazonaws.com	CreateOAuth2Token	user/blue-team-1	198.18.23.1	-
      6 logs.amazonaws.com	PutRetentionPolicy	user/blue-team-1	198.18.2.1	-
      6 ec2.amazonaws.com	ModifyNetworkInterfaceAttribute	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	-
      6 ec2.amazonaws.com	DetachNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	-
      6 ec2.amazonaws.com	CreateNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	-
      6 ec2.amazonaws.com	AttachNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	-
      6 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException
      6 cognito-idp.amazonaws.com	InitiateAuth	Unknown	198.18.7.1	-
      6 cognito-idp.amazonaws.com	AdminListGroupsForUser	user/blue-team-1	198.18.3.1	-
      6 cloudshell.amazonaws.com	DeleteSession	user/blue-team-1	198.18.23.1	InvalidStatusException
      5 sts.amazonaws.com	AssumeRole	AWSService	autoscaling.amazonaws.com	-
      5 ssm.amazonaws.com	SendCommand	user/blue-team-1	198.18.5.1	-
      5 ssm.amazonaws.com	SendCommand	user/blue-team-1	198.18.23.1	-
      5 ec2.amazonaws.com	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	-
      5 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	-
      4 wafv2.amazonaws.com	UpdateWebACL	user/blue-team-1	198.18.23.1	-
      4 wafv2.amazonaws.com	UpdateIPSet	user/blue-team-1	198.18.23.1	-
      4 sts.amazonaws.com	AssumeRole	AWSService	securityhub.amazonaws.com	-
      4 ssm.amazonaws.com	StartSession	user/blue-team-1	198.18.3.1	-
      4 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.3.1	-
      4 signin.amazonaws.com	CreateOAuth2Token	user/blue-team-1	198.18.5.1	-
      4 kms.amazonaws.com	Decrypt	user/blue-team-2	lambda.amazonaws.com	-
      4 kms.amazonaws.com	Decrypt	root	lambda.amazonaws.com	-
      4 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1	-
      4 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1	-
      4 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1	-
      4 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1	-
      4 ec2.amazonaws.com	ModifyInstanceAttribute	user/blue-team-1	198.18.2.1	-
      4 ec2.amazonaws.com	AuthorizeSecurityGroupIngress	user/blue-team-1	198.18.2.1	-
      4 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException
      4 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException
      3 states.amazonaws.com	StartExecution	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	-
      3 ssm.amazonaws.com	StartSession	user/blue-team-1	198.18.5.1	-
      3 ssm.amazonaws.com	StartSession	user/blue-team-1	198.18.23.1	-
      3 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.5.1	-
      3 ec2.amazonaws.com	CreateSnapshot	user/blue-team-1	198.18.2.1	-
      3 dynamodb.amazonaws.com	CreateBackup	user/blue-team-1	198.18.2.1	-
      3 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException
      3 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	-
      3 cloudshell.amazonaws.com	StartEnvironment	user/blue-team-1	198.18.23.1	-
      3 cloudshell.amazonaws.com	RedeemCode	user/blue-team-2	198.18.23.1	-
      2 sts.amazonaws.com	AssumeRoleWithWebIdentity	user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1	-
      2 sts.amazonaws.com	AssumeRoleWithWebIdentity	user/system:serviceaccount:device-support:portal-api	198.18.8.1	-
      2 ssm.amazonaws.com	TerminateSession	user/blue-team-1	198.18.2.1	-
      2 ssm.amazonaws.com	StartSession	user/blue-team-1	198.18.2.1	-
      2 ssm.amazonaws.com	StartSession	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
      2 ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      2 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.2.1	-
      2 ssm.amazonaws.com	OpenDataChannel	Unknown	198.18.10.1	-
      2 ssm.amazonaws.com	CreateDataChannel	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
      2 logs.amazonaws.com	StartQuery	user/blue-team-1	198.18.0.1	-
      2 kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1	-
      2 guardduty.amazonaws.com	UpdateDetector	user/blue-team-1	198.18.23.1	-
      2 ecs.amazonaws.com	PutAccountSettingDefault	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
      2 cognito-idp.amazonaws.com	SignUp	Unknown	2001:db8:0:b::2	-
      2 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	-
      2 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	-
      2 cognito-idp.amazonaws.com	InitiateAuth	Unknown	2001:db8:0:b::2	-
      2 cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	198.18.7.2	-
      1 wafv2.amazonaws.com	UpdateIPSet	user/blue-team-1	198.18.23.1	WAFOptimisticLockException
      1 wafv2.amazonaws.com	CreateIPSet	user/blue-team-1	198.18.23.1	-
      1 ssm.amazonaws.com	TerminateSession	user/blue-team-1	198.18.3.1	-
      1 ssm.amazonaws.com	StartSession	user/blue-team-2	198.18.23.1	-
      1 ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      1 ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied
      1 ssm.amazonaws.com	ResumeSession	user/blue-team-1	198.18.3.1	-
      1 ssm.amazonaws.com	PutConfigurePackageResult	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
      1 ssm.amazonaws.com	PutConfigurePackageResult	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	-
      1 ssm.amazonaws.com	CreateAssociation	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
      1 ssm.amazonaws.com	CancelCommand	user/blue-team-1	198.18.3.1	-
      1 sns.amazonaws.com	DeleteTopic	user/blue-team-2	198.18.23.1	-
      1 sns.amazonaws.com	CreateTopic	user/blue-team-2	198.18.23.1	-
      1 s3.amazonaws.com	PutBucketVersioning	user/blue-team-1	198.18.2.1	-
      1 kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1	-
      1 kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1	-
      1 kms.amazonaws.com	Decrypt	assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1	-
      1 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1	-
      1 kms.amazonaws.com	Decrypt	assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1	-
      1 guardduty.amazonaws.com	CreateDetector	user/blue-team-1	198.18.23.1	-
      1 eks.amazonaws.com	CreateAddon	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
      1 ec2.amazonaws.com	RevokeSecurityGroupIngress	user/blue-team-1	198.18.2.1	-
      1 ec2.amazonaws.com	RevokeSecurityGroupEgress	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
      1 ec2.amazonaws.com	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	Client.InvalidNetworkInterface.InUse
      1 ec2.amazonaws.com	CreateVpcEndpoint	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
      1 ec2.amazonaws.com	CreateSecurityGroup	assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
```

실행한 명령:
```
jq -r '.Records[] | select(.errorCode != null) | [.eventSource, .eventName, ((.userIdentity.arn // .userIdentity.type // "-") | sub("^arn:aws:(iam|sts)::[0-9]+:";"")), .sourceIPAddress, .errorCode] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
     24 ec2.amazonaws.com	CreateNetworkInterfacePermission	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	Client.DryRunOperation
     24 ec2.amazonaws.com	CreateNetworkInterface	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	Client.DryRunOperation
     14 ec2.amazonaws.com	DescribeNetworkInterfaces	assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	Client.DryRunOperation
     14 ec2.amazonaws.com	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	Client.InvalidParameterValue
     12 cloudtrail.amazonaws.com	LookupEvents	user/blue-team-1	198.18.23.1	ThrottlingException
     11 cloudtrail.amazonaws.com	LookupEvents	user/blue-team-1	198.18.0.1	ThrottlingException
     10 observabilityadmin.amazonaws.com	ListTelemetryRules	user/blue-team-1	198.18.0.1	ValidationException
      6 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException
      6 cloudshell.amazonaws.com	DeleteSession	user/blue-team-1	198.18.23.1	InvalidStatusException
      5 observabilityadmin.amazonaws.com	ListTelemetryRules	user/blue-team-1	198.18.23.1	ValidationException
      5 cloudtrail.amazonaws.com	GetInsightSelectors	user/blue-team-2	198.18.23.1	InsightNotEnabledException
      4 s3.amazonaws.com	GetBucketObjectLockConfiguration	user/blue-team-1	198.18.5.1	ObjectLockConfigurationNotFoundError
      4 monitoring.amazonaws.com	GetDashboard	user/blue-team-1	198.18.23.1	DashboardNotFoundError
      4 cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException
      4 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException
      4 apigateway.amazonaws.com	GetStage	assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	NotFoundException
      3 observabilityadmin.amazonaws.com	ListTelemetryRulesForOrganization	user/blue-team-1	198.18.0.1	ValidationException
      3 observabilityadmin.amazonaws.com	ListCentralizationRulesForOrganization	user/blue-team-1	198.18.0.1	UnauthorizedException
      3 logs.amazonaws.com	CreateLogStream	AWSService	delivery.logs.amazonaws.com	ResourceAlreadyExistsException
      3 cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException
      2 ssm.amazonaws.com	StartSession	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
      2 ssm.amazonaws.com	SendCommand	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      2 lambda.amazonaws.com	GetFunctionEventInvokeConfig	user/blue-team-1	198.18.23.1	ResourceNotFoundException
      2 cloudtrail.amazonaws.com	LookupEvents	user/blue-team-1	198.18.23.1	InvalidLookupAttributesException
      2 cloudtrail.amazonaws.com	GetInsightSelectors	user/blue-team-1	198.18.5.1	InsightNotEnabledException
      1 wafv2.amazonaws.com	UpdateIPSet	user/blue-team-1	198.18.23.1	WAFOptimisticLockException
      1 ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
      1 ssm.amazonaws.com	StartSession	assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied
      1 ssm.amazonaws.com	GetDocument	user/blue-team-2	198.18.23.1	InvalidDocument
      1 sns.amazonaws.com	GetTopicAttributes	assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	NotFoundException
      1 sns.amazonaws.com	GetTopicAttributes	assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	config.amazonaws.com	NotFoundException
      1 schemas.amazonaws.com	DescribeSchema	user/blue-team-1	198.18.23.1	NotFoundException
      1 s3.amazonaws.com	GetBucketWebsite	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	NoSuchWebsiteConfiguration
      1 s3.amazonaws.com	GetBucketVersioning	user/AWSAccount	198.18.7.2	AccessDenied
      1 s3.amazonaws.com	GetBucketTagging	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	NoSuchTagSet
      1 s3.amazonaws.com	GetBucketReplication	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	ReplicationConfigurationNotFoundError
      1 s3.amazonaws.com	GetBucketObjectLockConfiguration	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	ObjectLockConfigurationNotFoundError
      1 s3.amazonaws.com	GetBucketLifecycle	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	NoSuchLifecycleConfiguration
      1 s3.amazonaws.com	GetBucketCors	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	NoSuchCORSConfiguration
      1 monitoring.amazonaws.com	GetDashboard	user/blue-team-2	198.18.23.1	DashboardNotFoundError
      1 monitoring.amazonaws.com	GetDashboard	user/blue-team-1	198.18.5.1	DashboardNotFoundError
      1 monitoring.amazonaws.com	GetDashboard	user/blue-team-1	198.18.0.1	DashboardNotFoundError
      1 logs.amazonaws.com	FilterLogEvents	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
      1 logs.amazonaws.com	DescribeLogStreams	assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
      1 eks.amazonaws.com	DescribeInsightsRefresh	user/blue-team-2	198.18.23.1	ResourceNotFoundException
      1 ec2.amazonaws.com	DescribeNetworkInterfaces	assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	Client.InvalidNetworkInterfaceID.NotFound
      1 ec2.amazonaws.com	DeleteNetworkInterface	assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1	Client.InvalidNetworkInterface.InUse
      1 ec2.amazonaws.com	AuthorizeSecurityGroupIngress	user/blue-team-1	198.18.2.1	Client.DryRunOperation
      1 cognito-idp.amazonaws.com	AdminListUserAuthEvents	user/blue-team-1	198.18.23.1	UserPoolAddOnNotEnabledException
      1 cloudtrail.amazonaws.com	GetInsightSelectors	user/blue-team-2	198.18.19.1	InsightNotEnabledException
      1 cloudtrail.amazonaws.com	GetDashboard	user/blue-team-2	198.18.23.1	ResourceNotFoundException
      1 cloudtrail.amazonaws.com	GetDashboard	user/blue-team-1	198.18.5.1	ResourceNotFoundException
      1 cloudformation.amazonaws.com	DescribeStackResources	user/blue-team-1	198.18.23.1	ValidationException
      1 cloudcontrolapi.amazonaws.com	GetResource	assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com	ResourceNotFoundException
      1 athena.amazonaws.com	GetDataCatalog	assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com	InvalidRequestException
      1 apigateway.amazonaws.com	GetRestApi	user/blue-team-1	AWS Internal	NotFoundException
```

실행한 명령:
```
jq -c '.Records[] | select(.eventName | IN("AuthorizeSecurityGroupIngress","CreateSnapshot","CreateBackup","ModifySnapshotAttribute","StartSession","CreateIPSet","CreateOAuth2Token","CreateEnvironment")) | {t:.eventTime, src:.eventSource, n:.eventName, u:.userIdentity.arn, ip:.sourceIPAddress, ua:.userAgent, err:.errorCode, req:.requestParameters}' cloudtrail.json
```
결과:
```
{"t":"2026-10-11T04:31:12Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:32:38Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:33:29Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049","ip":"198.18.6.1","ua":null,"err":"AccessDenied","req":null}
{"t":"2026-10-11T04:33:33Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049","ip":"198.18.6.1","ua":null,"err":"AccessDenied","req":null}
{"t":"2026-10-11T04:33:57Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:34:18Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:34:18Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:36:12Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:37:56Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:38:29Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:38:30Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:38:54Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:39:33Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:42:12Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:43:38Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:44:22Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:52:19Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:52:29Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:52:34Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.5.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T04:54:22Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:04:24Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:04:24Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:06:14Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:06:14Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:08:37Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:09:01Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:09:28Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:09:29Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:09:54Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:13:06Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:16:48Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:17:51Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:21:13Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:27:01Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:27:36Z","src":"cloudshell.amazonaws.com","n":"CreateEnvironment","u":"arn:aws:iam::111122223333:user/blue-team-2","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:27:36Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":"Client.DryRunOperation","req":null}
{"t":"2026-10-11T05:27:37Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:30:54Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-2","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:31:47Z","src":"ec2.amazonaws.com","n":"CreateSnapshot","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:31:48Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:31:58Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:37:02Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:37:02Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:41:49Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.3.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:47:04Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:52:02Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:57:15Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T05:57:32Z","src":"signin.amazonaws.com","n":"CreateOAuth2Token","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:09:40Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:14:37Z","src":"wafv2.amazonaws.com","n":"CreateIPSet","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.23.1","ua":null,"err":null,"req":{"name":"block-ip"}}
{"t":"2026-10-11T06:26:14Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:35:18Z","src":"ec2.amazonaws.com","n":"CreateSnapshot","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:35:21Z","src":"ec2.amazonaws.com","n":"CreateSnapshot","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:39:20Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77","ip":"198.18.50.1","ua":null,"err":"AccessDenied","req":null}
{"t":"2026-10-11T06:43:19Z","src":"dynamodb.amazonaws.com","n":"CreateBackup","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:43:24Z","src":"dynamodb.amazonaws.com","n":"CreateBackup","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T06:43:29Z","src":"dynamodb.amazonaws.com","n":"CreateBackup","u":"arn:aws:iam::111122223333:user/blue-team-1","ip":"198.18.2.1","ua":null,"err":null,"req":null}
{"t":"2026-10-11T07:02:09Z","src":"ssm.amazonaws.com","n":"StartSession","u":"arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77","ip":"198.18.7.1","ua":null,"err":"AccessDenied","req":null}
{"t":"2026-10-11T07:18:34Z","src":"ec2.amazonaws.com","n":"AuthorizeSecurityGroupIngress","u":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","ip":"guardduty.amazonaws.com","ua":null,"err":null,"req":null}
```

## 채팅 AI

## 결론

**이번 로그에서는 공격 흔적으로 보이는 단서가 나왔습니다.** 핵심은 **patchsignal portal EC2 인스턴스의 역할 자격증명이 인스턴스 밖에서 사용됐다**는 점입니다. 같은 출발지(198.18.7.x)가 Cognito 가입 시도와 다른 AWS 계정에서의 S3 조회에도 등장합니다.

전제가 하나 있습니다. IP가 마스킹되어 있어서, **같은 실제 IP는 늘 같은 가짜 IP로 바뀐다고 가정하고** 분석했습니다. 운영진이 IP를 무작위로 섞었다면 아래 해석은 약해집니다.

---

## 발견 1: portal 인스턴스 역할 자격증명이 외부에서 사용됨 (가장 중요)

EC2 인스턴스의 역할 자격증명은 원래 **그 인스턴스 안에서만** 쓰여야 합니다. 이 인스턴스의 실제 출발지는 198.18.10.1입니다. SSM 에이전트의 `UpdateInstanceInformation` 41건이 모두 이 IP에서 왔기 때문입니다.

그런데 같은 자격증명(`patchsignal-ewc2enb8-portal-role/i-05816900800807b77`)이 다른 IP에서도 쓰였습니다.

| 출발지 | 이벤트 | 결과 | 의미 |
|---|---|---|---|
| 198.18.7.1 | `StartExecution` 6회 | **성공** | Step Functions 워크플로를 실행함 |
| 198.18.50.1 | `StartExecution` 3회 | **성공** | 위와 같음 |
| 198.18.7.1 | `SendCommand` 2회 | 거부 | 다른 서버에 명령을 실행하려 함 |
| 198.18.7.1 | `StartSession` (16:02:09 KST) | 거부 | 다른 서버에 셸로 접속하려 함 |
| 198.18.50.1 | `StartSession` (15:39:20 KST) | 거부 | 위와 같음 |

이는 **자격증명 탈취 후 외부 사용**의 전형적인 모습입니다. GuardDuty에서는 `InstanceCredentialExfiltration.OutsideAWS`로 분류되는 유형입니다. 흔한 경로는 portal 웹앱의 SSRF나 원격 코드 실행 취약점을 통해 인스턴스 메타데이터(IMDS)에서 자격증명을 빼내는 것입니다.

- 다행히 서버 장악 시도(`SendCommand`, `StartSession`)는 권한 부족으로 실패했습니다.
- 하지만 **Step Functions 실행 9회는 성공했습니다.** 그 워크플로가 무엇을 하는지(데이터 조회, Lambda 호출 등)가 피해 범위를 결정합니다.
- 198.18.10.1에서 나온 `StartExecution` 76회는 앱의 정상 동작일 수도 있고, 공격자가 인스턴스 안에서 실행했을 수도 있습니다. 평소 패턴과 비교해야 판단할 수 있습니다.

## 발견 2: 같은 출발지 198.18.7.x가 다른 곳에서도 활동함

- **Cognito**: `SignUp`(비밀번호 규칙 실패 10회 후 성공), `ConfirmSignUp` 성공, `InitiateAuth`와 `RespondToAuthChallenge`(일부 실패, 일부 성공)가 기록됐습니다. 198.18.7.1, 198.18.7.2, `2001:db8:0:b::2`에서 왔습니다. 앱 사용자 풀에 **계정을 만들고 로그인까지 한 것**으로 보입니다.
- **S3**: `GetBucketVersioning`, 사용자 유형 `AWSAccount`, 198.18.7.2, `AccessDenied`.
  `AWSAccount`는 **다른 AWS 계정의 자격증명**으로 우리 버킷에 접근했다는 뜻입니다. 공격자가 자기 계정에서 우리 버킷을 탐색한 것으로 보입니다.

Cognito 가입 자체는 일반 사용자도 하는 일입니다. 하지만 **탈취된 역할 자격증명을 쓴 IP와 같은 IP**라는 점 때문에 공격자의 활동으로 판단합니다.

## 발견 3: root 계정이 사용됨

`kms Decrypt / root / lambda.amazonaws.com` 4건이 있습니다. 누군가 **root 계정으로 Lambda 콘솔을 열어 환경변수를 봤을 때** 생기는 기록입니다. 팀이 root를 쓰지 않는다면 심각한 신호입니다. 쓴다면 누가 썼는지 확인해야 합니다. 시각은 아래 (F) 명령으로 확인할 수 있습니다.

## 팀 대응 작업이나 정상 동작으로 보이는 것

- **blue-team-1, 2의 작업**: `SendCommand` 대량 실행, WAF `block-ip` 생성, GuardDuty 활성화, 로그 보존 기간 설정, 스냅샷과 DynamoDB 백업(증거 보존), S3 버전 관리, 보안그룹 변경. 대응 작업 흐름과 맞습니다.
  - `ModifySnapshotAttribute`(스냅샷 외부 공유)는 **없었습니다.**
  - `AuthorizeSecurityGroupIngress` 4회는 어떤 포트를 열었는지 이 파일로는 알 수 없으니, 팀원에게 확인하세요.
- **ec2-ssmrole의 `StartSession`과 로그 조회 거부(13:33 KST)**: blue-team-1이 13:32에 그 인스턴스에 SSM으로 접속한 직후입니다. 팀원이 인스턴스 안에서 aws 명령을 시도한 것으로 보입니다. 의심도는 낮지만 확인은 해 주세요.
- Lambda의 KMS Decrypt(IP가 매번 다름), EKS 네트워크 인터페이스 오류, `CreateOAuth2Token`(콘솔 로그인 토큰), CloudShell 활동: 정상입니다.

## 추정 공격 흐름 (가설)

1. 공격자(198.18.7.x)가 patchsignal portal 웹앱을 공격합니다. Cognito에 가입하고 로그인합니다.
2. 앱 취약점으로 인스턴스 역할 자격증명을 탈취합니다.
3. 그 자격증명으로 외부에서 AWS API를 호출합니다. Step Functions 실행은 성공했고, SSM 장악 시도는 실패했습니다.
4. 별도로 자기 AWS 계정에서 우리 S3 버킷을 탐색합니다.

참고로 로그는 13:30부터라서 **최초 침입은 그 이전일 수 있습니다.**

---

## 고쳐야 할 것 (권한 있는 사람에게 그대로 전달하세요)

**즉시**
1. **portal 역할의 기존 세션 무효화**: IAM → Roles → `patchsignal-ewc2enb8-portal-role` → "Revoke active sessions". 이미 탈취된 임시 자격증명이 바로 무효가 됩니다. 인스턴스는 새 자격증명을 자동으로 받지만 잠깐 오류가 날 수 있습니다.
2. **WAF로는 막을 수 없다는 점에 유의하세요.** 지금 만든 `block-ip`는 웹앱 트래픽만 막습니다. 탈취한 자격증명으로 AWS API를 직접 호출하는 것은 WAF를 거치지 않습니다. 1번이 필요한 이유입니다.
3. **root 사용 확인**: 누가 썼는지 확인하고, 비밀번호 변경과 MFA 설정을 점검하세요.

**재발 방지**
4. 해당 인스턴스에 **IMDSv2를 강제**하세요(`HttpTokens=required`, hop limit 1). SSRF로 자격증명을 빼내기 어려워집니다.
5. **portal 앱의 취약점을 수정**하세요. URL을 받아 서버가 요청하는 기능, 파일 업로드, 명령 실행 부분을 우선 점검해야 합니다.
6. **역할 권한 최소화**: portal에 `states:StartExecution`, `ssm:SendCommand`, `ssm:StartSession` 권한이 정말 필요한지 검토하세요. 또한 `aws:EC2InstanceSourceVPC` 조건을 걸면 인스턴스 밖에서 자격증명을 써도 거부됩니다.
7. **Cognito 정리**: 공격자가 만든 계정을 비활성화하세요. 셀프 가입이 꼭 필요한지, 가입자가 그룹이나 속성을 바꿀 수 있는지 점검하세요.
8. **S3 버킷 정책**: 다른 

## 사용자

이번에는 아무것도 뽑지 않았어요. 실행할 명령을 받지 못했습니다. 메시지가 "8. S3 버킷 정책: 다른"에서 끊겨서 그 뒷부분이 안 왔어요. 본문에서 root 사용 시각을 확인하는 데 쓰라고 한 "(F) 명령"도 안 보입니다. (F)를 포함해서 실행할 명령을 다시 보내 주시면 이 파일에서 뽑아 드릴게요.

물어보신 것:
- **root 계정**: 우리 팀이 root를 쓰는지, 썼다면 누가 썼는지는 제가 모릅니다.
- **ec2-ssmrole의 `StartSession`과 로그 조회 거부(13:33 KST)**: 팀원이 인스턴스 안에서 실행한 것인지는 모릅니다. 제가 아는 건 사고 뒤 대응 작업(조회, 설정 변경)을 팀원이 했다는 것까지예요.
- **보안그룹 변경**: blue-team-1이 `AuthorizeSecurityGroupIngress`로 어떤 포트를 열었는지는 이 파일에 없어서 확인하지 못했습니다(그 로그는 없어요).
- **IP 마스킹**: 같은 실제 IP가 늘 같은 가짜 IP로 바뀌는지는 모릅니다.
- **patchsignal**: PatchSignal은 원래 있던 우리 서비스예요. 평소에 `StartExecution`이 얼마나 일어나는지는 그 기간 로그가 없어서 비교할 수 없습니다(그 로그는 없어요).

조치 쪽:
- 지금은 콘솔과 CLI에 접속할 수 없어서 "고쳐야 할 것" 목록은 하나도 실행하지 못했습니다. 세션 무효화, IMDSv2 강제, 역할 권한 수정, Cognito 계정 비활성화가 다 해당돼요.
- 역할 권한, 인스턴스의 IMDS 설정, Cognito 사용자 풀 설정, S3 버킷 정책도 볼 수 없습니다(그 로그는 없어요).

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# 최종 보고서: AWS 계정 침해 의심 건 (2026-10-11)

앞선 메시지가 중간에 끊겨 "8번 항목"과 "(F) 명령"이 전달되지 않았습니다. 둘 다 이 보고서에 포함했습니다. (F)는 권한 있는 분이 나중에 쓸 수 있도록 부록에 넣었습니다.

---

## 1. 요약

- **공격이 있었을 가능성이 높습니다.** PatchSignal portal EC2 인스턴스의 **IAM 역할 자격증명이 인스턴스 밖에서 사용된 정황**이 있습니다.
- 공격자로 보이는 출발지는 198.18.7.x와 198.18.50.1입니다. 이 출발지에서 **Step Functions 워크플로 실행 9회가 성공**했습니다. 다른 서버를 장악하려는 시도(SSM 명령, 셸 접속)는 **권한 부족으로 실패**했습니다.
- 같은 출발지에서 **Cognito 계정 생성과 로그인**, 그리고 **다른 AWS 계정을 통한 S3 조회 시도(거부됨)**도 있었습니다.
- **공격 활동은 로그 끝(16:25 KST) 직전인 16:02에도 이어졌습니다.** 탈취된 자격증명이 **아직 유효할 수 있으므로** 세션 무효화가 가장 시급합니다.
- 로그 범위가 좁아서 **최초 침입 경로, IAM 변경 여부, 다른 리전의 피해는 확인하지 못했습니다.**

---

## 2. 조사 범위와 한계

| 항목 | 상태 |
|---|---|
| 분석한 로그 | ap-northeast-2 CloudTrail 1개 파일, 13:30~16:25 KST, 10,223건 |
| 확인하지 못한 것 | us-east-1(IAM, 로그인 이벤트), 다른 리전, 13:30 이전 기록, 자격증명 리포트, EC2 목록 |
| 로그에 빠진 필드 | `requestParameters`가 대부분 없음(어떤 포트를 열었는지, 어떤 워크플로인지 알 수 없음), `userAgent`와 `readOnly` 없음 |
| 분석에서 빠진 부분 | 공격자 출발지의 **성공한 조회성 호출**(Get, List, Describe)은 따로 보지 못함 |
| IP | 모두 마스킹됨(198.18.x.x). **같은 실제 IP가 늘 같은 가짜 IP로 바뀐다고 가정**하고 분석함 |
| 연락의 출처 | 확인하지 못함 |

결론의 신뢰도는 마지막 IP 가정에 크게 기대고 있습니다. 운영진에게 마스킹 방식을 꼭 확인하세요.

---

## 3. 무슨 일이 있었나

### 발견 1: portal 인스턴스 자격증명이 외부에서 사용됨 (신뢰도: 중간~높음)

- 역할: `patchsignal-ewc2enb8-portal-role`
- 인스턴스: `i-05816900800807b77`
- 인스턴스의 원래 출발지는 198.18.10.1입니다. SSM 에이전트의 정기 보고 41건이 모두 이 IP에서 왔습니다.
- 같은 자격증명이 아래 출발지에서도 사용됐습니다.

| 출발지 | 호출 | 결과 |
|---|---|---|
| 198.18.7.1 | `states:StartExecution` 6회 | 성공 |
| 198.18.50.1 | `states:StartExecution` 3회 | 성공 |
| 198.18.7.1 | `ssm:SendCommand` 2회 | 거부 |
| 198.18.50.1 | `ssm:StartSession` (15:39 KST) | 거부 |
| 198.18.7.1 | `ssm:StartSession` (16:02 KST) | 거부 |

- **해석:** 앱 취약점(SSRF, 원격 코드 실행 등)으로 인스턴스 메타데이터에서 자격증명을 빼낸 뒤 외부에서 쓴 전형적인 패턴입니다.
- **정상일 가능성:** 인스턴스가 NAT, 프록시, VPC 엔드포인트 등 여러 경로로 나가는 구조라면 출발지가 달라질 수 있습니다. 다만 7.x는 Cognito 가입 시도와 다른 계정의 S3 접근에도 등장하므로 정상일 가능성은 낮다고 봅니다.
- **확인하지 못한 것:** 198.18.10.1에서 나온 `StartExecution` 76회가 정상 동작인지 판단하지 못했습니다. 평소 로그가 없어서 비교할 수 없습니다. 공격자가 인스턴스 안에서 실행했을 가능성도 배제할 수 없습니다.

### 발견 2: 같은 출발지의 Cognito 계정 생성과 로그인 (신뢰도: 중간)

- 출발지는 198.18.7.1, 198.18.7.2, `2001:db8:0:b::2`입니다.
- `SignUp`은 비밀번호 규칙 위반으로 10회 실패한 뒤 6회 성공했습니다.
- `ConfirmSignUp` 2회, `InitiateAuth` 17회가 있었습니다.
- `RespondToAuthChallenge`는 8회 성공하고 7회 실패(`NotAuthorizedException`)했습니다.
- **해석:** 앱에 계정을 만들어 로그인한 뒤 portal 기능에 접근했을 것으로 보입니다. 팀원이 `AdminGetUser`와 `AdminListGroupsForUser`를 수십 번 호출한 것도 Cognito를 조사한 흔적으로 보입니다.

### 발견 3: 다른 AWS 계정에서 우리 S3 조회 시도 (신뢰도: 중간)

- 198.18.7.2에서 `GetBucketVersioning`을 시도했고 `AccessDenied`로 거부됐습니다.
- 사용자 유형 `AWSAccount`는 **외부 계정의 자격증명**이라는 뜻입니다.
- 접근이 막혔으니 현재 버킷 정책은 이 시도를 차단한 것입니다.

### 발견 4: root 계정 사용 (신뢰도: 사실 확인됨, 의도는 알 수 없음)

- `kms:Decrypt` 4건이 root 사용자로, Lambda를 통해 기록됐습니다.
- 누군가 **root로 Lambda 환경변수를 열람**했을 때 생기는 기록입니다.
- 연습 운영진의 작업일 수도 있고 침해일 수도 있습니다. 시각과 사용자를 반드시 확인해야 합니다.

### 침해 흔적이 없었던 것 (이 리전, 이 시간대 한정)

`RunInstances`, `StopLogging`, `DeleteTrail`, `ModifySnapshotAttribute`(스냅샷 외부 공유), `PutBucketPolicy`, `PutBucketAcl`은 없었습니다. 다만 **IAM 관련 이벤트는 us-east-1에 기록되므로 확인되지 않은 상태**입니다.

### 팀 대응 작업으로 보이는 것

`SendCommand` 260여 회, 보안그룹 변경(어떤 포트인지 모름), `ModifyInstanceAttribute` 4회, 스냅샷과 DynamoDB 백업, S3 버전 관리, 로그 보존 설정, WAF `block-ip`, GuardDuty 활성화(16:09 KST)가 여기에 해당합니다.

ec2-ssmrole 인스턴스 안에서 거부된 호출들(13:33 KST)도 있습니다. 이는 팀원이 SSM으로 접속한 직후이고 인스턴스 자신의 IP에서 나왔으므로 **외부 유출 정황은 아닙니다.** 다만 누가 했는지는 확인되지 않았습니다.

---

## 4. 타임라인 (KST, 시각이 확인된 것만)

| 시각 | 사건 |
|---|---|
| 13:30 이전 | 최초 침입이 있었을 수 있음(로그 없음) |
| 13:30 | 로그 시작 |
| 13:32~13:33 | 팀원이 ec2-ssmrole 인스턴스에 SSM 접속, 내부 호출 일부 거부 |
| 13:39~14:27 | blue-team-1이 보안그룹 인바운드 규칙 추가(5회) |
| 14:31 | 첫 EBS 스냅샷(증거 보존 추정) |
| 15:14 | WAF IPSet `block-ip` 생성 |
| 15:35 | EBS 스냅샷 추가 |
| **15:39** | **198.18.50.1이 portal 자격증명으로 SSM 접속 시도(거부)** |
| 15:43 | DynamoDB 백업 3건 |
| **16:02** | **198.18.7.1이 portal 자격증명으로 SSM 접속 시도(거부)** |
| 16:09 | GuardDuty 활성화(그 전까지는 꺼져 있었음) |
| 16:18 | GuardDuty 런타임 모니터링 자동 설치 |
| 16:25 | 로그 끝 |

**WAF 차단(15:14) 이후에도 자격증명 악용이 이어졌습니다.** WAF는 웹 트래픽만 막고, 탈취한 자격증명으로 AWS API를 직접 호출하는 것은 막지 못합니다.

---

## 5. 고쳐야 할 것 (권한 있는 분에게 전달하세요)

### 긴급 (지금 바로)

1. **portal 역할의 기존 세션 무효화**
   IAM → Roles → `patchsignal-ewc2enb8-portal-role` → Revoke active sessions.
   이미 탈취된 임시 자격증명이 무효가 됩니다. 인스턴스는 새 자격증명을 자동으로 받지만 잠깐 오류가 날 수 있습니다.
2. **IMDSv2 강제**
   `i-05816900800807b77`에 `HttpTokens=required`, hop limit 1을 설정하세요. 1번만 하고 이것을 하지 않으면 공격자가 새 자격증명을 다시 빼낼 수 있습니다.
3. **Step Functions 실행 내역 확인**
   portal 역할이 실행할 수 있는 상태 머신의 실행 이력에서 198.18.7.x와 50.1이 실행한 9건의 입력과 결과를 확인하세요. **피해 범위는 이 워크플로가 무엇을 했는지에 달려 있습니다.**
4. **root 사용 확인**
   누가 썼는지 확인하세요. 본인이 아니면 비밀번호를 변경하고, MFA와 root Access Key 유무를 점검하세요.
5. **연락의 진위와 조치 범위를 운영진에게 확인**
   연습 환경이므로 허용된 조치인지도 함께 확인하세요.

### 단기 (오늘~내일)

6. **portal 앱 취약점 수정**
   URL을 받아 서버가 요청하는 기능, 파일 업로드, 명령 실행 부분을 우선 점검하세요. 같은 이유로 pagesnap renderer(페이지 렌더링 서비스)도 점검하세요.
7. **역할 권한 최소화**
   portal 역할에 `states:StartExecution`, `ssm:SendCommand`, `ssm:StartSession`이 정말 필요한지 검토하세요. `aws:EC2InstanceSourceVPC` 같은 조건을 걸면 인스턴스 밖에서 쓴 자격증명은 거부됩니다.
8. **S3 버킷 정책 점검**
   다른 계정의 접근은 이번에 거부됐지만, 모든 버킷의 정책과 ACL에 외부 계정이나 `"Principal": "*"` 허용이 없는지 확인하세요. 계정 수준의 S3 Block Public Access를 켜고, 필요하면 `aws:PrincipalAccount` 조건으로 우리 계정만 허용하세요.
9. **Cognito 정리**
   198.18.7.x에서 가입한 계정을 찾아 비활성화하세요. 셀프 가입이 꼭 필요한지, 가입자가 스스로 그룹이나 속성을 바꿀 수 있는지 점검하세요. 고급 보안 기능을 켜면 로그인 이벤트 조회가 가능해집니다(이번에 `UserPoolAddOnNotEnabledException`으로 실패함).
10. **팀 변경사항 검토**
    보안그룹에 추가한 규칙 5건과 `ModifyInstanceAttribute` 4건이 의도한 것인지, `0.0.0.0/0` 개방이 남아 있지 않은지 확인하세요.

### 재발 방지

11. GuardDuty를 상시로 켜 두세요(이번에는 사고 중에 켜졌습니다). CloudTrail을 전체 리전, 다중 리전 트레일로 설정하고 S3 데이터 이벤트도 기록하세요.
12. us-east-1과 다른 리전에서 IAM 사용자, Access Key, 정책 변경, 의심 

## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

# AWS 계정 침해 의심 대응 가이드

## 0단계: 연락이 진짜인지 먼저 확인하세요

"계정이 공격받았다"는 연락 자체가 피싱인 경우가 많습니다.

- 메일이나 메시지의 링크를 누르지 말고, 브라우저에 직접 주소를 입력해 AWS 콘솔에 로그인하세요.
- 콘솔 오른쪽 위 종 아이콘(**AWS Health Dashboard**)과 **Support Center**에 AWS가 연 케이스가 있는지 확인하세요.
- 누가, 어떤 경로로 연락했는지 알려 주시면 함께 판단해 드리겠습니다.

## 1단계: 지금 바로 할 일 (증거는 보존하면서 차단)

**주의: 의심스러운 리소스(EC2, IAM 사용자 등)를 바로 삭제하지 마세요.** 삭제하면 무슨 일이 있었는지 추적하기 어려워집니다. 차단과 비활성화까지만 하세요.

1. **루트 계정**: 비밀번호를 변경하고 MFA가 켜져 있는지 확인합니다.
2. **본인 IAM 사용자**: 비밀번호를 변경하고 MFA를 확인합니다.
3. **결제 확인**: Billing 콘솔에서 오늘 비용이 급증했는지 봅니다. 공격자가 채굴용 EC2를 대량으로 띄우는 경우가 흔합니다.
4. **사내 보고**: 보안 담당자나 팀장에게 지금 바로 알리세요. 혼자 처리할 일이 아닙니다.

## 2단계: 로그 뽑기

### 시간대 주의
CloudTrail은 **UTC** 기준입니다. 한국 시간 13:30은 **UTC 04:30**입니다.

### CloudTrail 이벤트 (모든 리전)
공격자는 평소 쓰지 않는 리전을 노리는 경우가 많아서 **전 리전**을 봐야 합니다. 아래 명령의 `YYYY-MM-DD`를 오늘 날짜로 바꿔서 실행하세요.

```bash
START="YYYY-MM-DDT04:30:00Z"
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r"
  aws cloudtrail lookup-events --region "$r" --start-time "$START" --output json > "ct_$r.json"
done
```

### 보기 좋게 요약 (jq 필요)
```bash
for f in ct_*.json; do
  jq -r '.Events[] | .CloudTrailEvent | fromjson |
    [.eventTime, .awsRegion, .eventName, .userIdentity.arn,
     .sourceIPAddress, (.errorCode // "-")] | @tsv' "$f"
done | sort > summary.tsv
```

### IAM 자격 증명 보고서
누가 언제 로그인했고, 어떤 액세스 키를 언제 썼는지 보여 줍니다.
```bash
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv
```

### GuardDuty (켜져 있다면)
콘솔에서 GuardDuty의 Findings 화면을 열고 오늘 날짜 항목을 확인하세요.

## 3단계: 로그에서 볼 것

`summary.tsv`에서 아래 이벤트가 있는지 검색해 보세요.

| 의심 이벤트 | 의미 |
|---|---|
| `ConsoleLogin` (낯선 IP나 국가) | 콘솔 무단 로그인 |
| `CreateUser`, `CreateAccessKey`, `CreateLoginProfile` | 공격자가 백도어 계정이나 키를 만듦 |
| `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy` | 권한 상승 |
| `UpdateAssumeRolePolicy`, `CreateRole` | 외부 계정이 들어올 통로 생성 |
| `RunInstances` (특히 GPU 타입, 낯선 리전) | 암호화폐 채굴 |
| `StopLogging`, `DeleteTrail`, `DeleteDetector` | 흔적 지우기 시도 (매우 위험 신호) |
| `GetSecretValue`, `GetParameter` | 비밀값 탈취 |
| `PutBucketPolicy`, `PutBucketAcl` | S3 버킷 공개 설정 |
| `AuthorizeSecurityGroupIngress` | 방화벽 개방 |
| 대량의 `AccessDenied` 에러 | 공격자가 권한을 탐색한 흔적 |

## 4단계: 저에게 보내 주실 것

- `summary.tsv` 내용 (길면 의심 이벤트 위주로)
- 평소 회사에서 쓰는 IP 대역이나 지역 (정상 활동과 구분하기 위해)
- 평소 사용하는 리전
- 결제 화면에서 이상한 점이 있었는지
- 연락이 온 경로

**보내기 전에 가려 주세요:** 액세스 키의 **Secret** 값, 비밀번호, 고객 개인정보. 액세스 키 ID(`AKIA...`)는 앞 몇 자리만 남기고 가리셔도 됩니다.

## 함께 알아 두실 것

- **AWS Support**에 "Account compromised" 케이스를 열 수 있습니다. 무료 플랜도 계정 및 결제 관련 문의는 가능하고, 침해로 인한 요금은 감면받는 경우도 있습니다.
- 고객 **개인정보가 유출됐을 가능성**이 있으면 법적 신고 의무(개인정보보호위원회, 72시간 이내)가 생길 수 있습니다. 이 부분은 회사 법무나 개인정보 담당자에게 꼭 알리세요.

로그를 주시면 실제로 무슨 일이 있었는지, 무엇을 막고 고쳐야 하는지 구체적으로 정리해 드리겠습니다.

## 사용자

요청하신 로그를 뽑았습니다. 지금 AWS 콘솔과 CLI에 들어갈 수 없어서, 미리 내려받아 둔 CloudTrail 로그 파일(cloudtrail.json)에서 jq로 같은 내용을 뽑았습니다.

**summary.tsv 관련**
- 이 파일에는 ap-northeast-2 리전, 한국 시간 13:30~16:25 무렵 기록만 있습니다. 다른 리전 로그는 없어서 전 리전 조회는 못 했습니다.
- 기록에 `awsRegion` 필드가 없어서 리전 열은 모두 `-`로 나옵니다.
- 전체 10,223건이라 너무 길어서, 3단계 표에 있는 이벤트만 골랐습니다. 열 순서는 요청하신 대로 시각, 리전, 이벤트명, ARN, IP, 에러코드입니다.
- 대량 AccessDenied를 보시려고 에러코드별 건수와 AccessDenied·Unauthorized 계열 건수(주체/IP별)도 함께 뽑았습니다.
- 표에 있는 이벤트 가운데 결과에 안 나온 것(ConsoleLogin, CreateUser, RunInstances 등)은 이 파일에 기록이 없습니다.

**확인하지 못한 것**
- IAM 자격 증명 보고서: 확인 못 함(그 자료는 없어요)
- GuardDuty Findings 화면: 확인 못 함(그 자료는 없어요)
- 결제 화면, Health Dashboard, Support Center: 지금 콘솔에 들어갈 수 없어서 확인 못 했습니다.
- 1단계 조치(비밀번호 변경, MFA 확인 등): 콘솔에 들어갈 수 없어서 저는 아직 못 했습니다.

**질문에 대한 답**
- 평소 회사에서 쓰는 IP 대역과 지역은 모릅니다.
- 평소 쓰는 리전은 확실히는 모르고, 받은 로그는 ap-northeast-2 것입니다.
- 연락이 어떤 경로로 왔는지는 저도 모릅니다.

**참고로 알려 드릴 것**
- 이 계정은 보안 공방전(연습) 환경입니다.
- blue-team-1과 blue-team-2는 우리 팀원 계정입니다. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했습니다.
- PatchSignal은 원래 있던 우리 서비스입니다.

실행한 명령:
```
jq -r '.Records[] | select(.eventName | test("^(ConsoleLogin|CreateUser|CreateAccessKey|CreateLoginProfile|AttachUserPolicy|PutUserPolicy|AttachRolePolicy|UpdateAssumeRolePolicy|CreateRole|RunInstances|StopLogging|DeleteTrail|DeleteDetector|GetSecretValue|GetParameter|PutBucketPolicy|PutBucketAcl|AuthorizeSecurityGroupIngress)$")) | [.eventTime, (.awsRegion // "-"), .eventName, .userIdentity.arn, .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:39:33Z	-	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T04:42:50Z	-	GetParameter	arn:aws:iam::111122223333:root	198.18.0.3	-
2026-10-11T04:48:42Z	-	GetParameter	arn:aws:iam::111122223333:root	198.18.18.1	-
2026-10-11T05:09:28Z	-	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:09:29Z	-	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:27:36Z	-	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	Client.DryRunOperation
2026-10-11T05:27:37Z	-	AuthorizeSecurityGroupIngress	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:32:13Z	-	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-
2026-10-11T05:57:21Z	-	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-
2026-10-11T05:57:54Z	-	GetParameter	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-
2026-10-11T07:18:34Z	-	AuthorizeSecurityGroupIngress	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com	-
```

실행한 명령:
```
echo "== errorCode별 건수"; jq -r '.Records[] | select(.errorCode) | .errorCode' cloudtrail.json | sort | uniq -c | sort -rn; echo "== AccessDenied 계열: 주체/IP별 건수"; jq -r '.Records[] | select((.errorCode // "") | test("AccessDenied|Unauthorized")) | [.userIdentity.arn, .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
== errorCode별 건수
     63 Client.DryRunOperation
     23 ThrottlingException
     19 ValidationException
     14 Client.InvalidParameterValue
     10 InvalidPasswordException
      9 AccessDenied
      8 NotFoundException
      8 InsightNotEnabledException
      7 NotAuthorizedException
      7 DashboardNotFoundError
      6 ResourceNotFoundException
      6 InvalidStatusException
      5 ObjectLockConfigurationNotFoundError
      3 UnauthorizedException
      3 ResourceAlreadyExistsException
      2 InvalidLookupAttributesException
      1 WAFOptimisticLockException
      1 UserPoolAddOnNotEnabledException
      1 ReplicationConfigurationNotFoundError
      1 NoSuchWebsiteConfiguration
      1 NoSuchTagSet
      1 NoSuchLifecycleConfiguration
      1 NoSuchCORSConfiguration
      1 InvalidRequestException
      1 InvalidDocument
      1 Client.InvalidNetworkInterfaceID.NotFound
      1 Client.InvalidNetworkInterface.InUse
== AccessDenied 계열: 주체/IP별 건수
      4 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1
      3 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1
      3 arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1
      1 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1
      1 arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2
```

## 채팅 AI

# CloudTrail 1차 분석 결과

## 요약

로그를 보면 **공격 가능성이 있는 신호가 세 가지** 있습니다. 다만 아직 확정할 수는 없습니다. 받은 자료가 3단계 표에 해당하는 이벤트만 골라낸 것이고, 다른 리전과 전역(IAM·로그인) 기록이 빠져 있을 가능성이 크기 때문입니다.

| 우선순위 | 발견 | 의심되는 상황 |
|---|---|---|
| 🔴 높음 | **루트 계정**이 SSM 파라미터를 읽음 (6분 사이 두 개의 다른 IP) | 루트 계정 탈취, 비밀값 유출 |
| 🔴 높음 | 팀 목록에 없는 **`user/AWSAccount`** 라는 IAM 사용자의 활동 | 공격자가 만든 백도어 계정 |
| 🟠 중간 | PatchSignal 포털 **EC2 역할 자격 증명이 두 IP에서 사용됨** + 권한 오류 | 인스턴스 자격 증명 탈취(SSRF 등) 후 권한 탐색 |

정상 활동으로 보이는 것도 있습니다.
- **07:18 GuardDuty의 `AuthorizeSecurityGroupIngress`**: GuardDuty Runtime Monitoring이 자동으로 하는 정상 동작입니다. GuardDuty가 켜져 있다는 뜻이기도 하니 Findings를 꼭 확인해야 합니다.
- **blue-team-1, blue-team-2 활동**: 말씀하신 대로 대응 작업으로 보입니다. 단, 아래 "확인할 점"에 적은 두 가지는 짚어 봐야 합니다.

## 발견 상세

### 1. 루트 계정 사용 (가장 심각)
```
04:42:50  GetParameter  root  198.18.0.3
04:48:42  GetParameter  root  198.18.18.1
```
- 루트 계정은 평소에 쓰면 안 되는 계정입니다. 그런데 사고 시간대에 쓰였고, 6분 사이에 IP가 바뀌었습니다.
- 사고 신고 시각(04:30 UTC) 직후의 활동입니다.
- 지금 콘솔에 들어갈 수 없는 상황과 연결될 수도 있습니다. 공격자가 루트 비밀번호를 바꿨을 가능성이 있습니다.
- **어떤 파라미터를 읽었는지** 확인해야 합니다. 거기 들어 있던 비밀값은 유출됐다고 보는 것이 안전합니다.

### 2. `user/AWSAccount` 사용자
```
1  arn:aws:iam::111122223333:user/AWSAccount  198.18.7.2  (AccessDenied)
```
- AWS 공식 계정처럼 보이게 지은 이름은 공격자가 백도어 계정에 흔히 붙입니다.
- IP `198.18.7.2`가 포털 인스턴스 역할이 쓴 `198.18.7.1`과 바로 붙어 있습니다.
- `CreateUser`가 결과에 없는 이유는 아래 "로그의 한계"를 참고하세요. 생성 기록은 이 파일에 원래 안 들어 있었을 수 있습니다.
- **팀에 이 사용자를 아는 사람이 있는지 바로 물어보세요.**

### 3. 인스턴스 역할 자격 증명
```
3  patchsignal-...-portal-role/i-05816900800807b77  198.18.7.1
1  patchsignal-...-portal-role/i-05816900800807b77  198.18.50.1
4  ec2-ssmrole/i-026754fe07a870049                   198.18.6.1
```
- 같은 인스턴스 세션이 서로 다른 두 IP에서 쓰였습니다. 웹 앱(포털)의 취약점(SSRF 등)으로 인스턴스 메타데이터(IMDS)에서 자격 증명을 빼 가서 외부에서 쓰면 이런 패턴이 나옵니다.
- 정상적인 이유(NAT, VPC 엔드포인트 경로 차이)일 수도 있어서 실제로 무엇을 호출했는지 봐야 판단할 수 있습니다.
- AccessDenied가 났다는 것은 누군가 이 역할로 **할 수 있는 일을 탐색했다**는 신호일 수 있습니다.

### 확인할 점
- **blue-team-1의 04:39 보안 그룹 개방**: 사고 9분 뒤입니다. 대응 작업이 맞는지, 그리고 `0.0.0.0/0`에 SSH(22)나 RDP 같은 포트를 연 건 아닌지 확인해야 합니다.
- **blue-team-1이 다른 IP(198.18.0.1)에서 AccessDenied를 받음**: 평소 IP는 198.18.2.1입니다. 그리고 루트를 쓴 IP 198.18.0.3과 같은 대역입니다. 본인에게 확인하세요.
- **DryRunOperation 63건**: 실제 실행 없이 "권한이 있는지만" 확인하는 호출이라 권한 탐색 도구가 자주 남깁니다. 누가 했는지 봐야 합니다.
- **InvalidPasswordException 10건, NotAuthorizedException 7건**: Cognito(포털 로그인 등)에 대한 비밀번호 대입 공격일 수 있습니다.

참고로 IP가 모두 `198.18.x.x`(테스트용 예약 대역)이라 국가나 위치로는 판단할 수 없습니다. 연습 환경이라 그런 것으로 보입니다.

## 로그의 한계 (중요)

결과에 이벤트가 없다고 해서 그 일이 없었다는 뜻은 아닙니다.
- **IAM(`CreateUser`, `CreateAccessKey` 등)과 콘솔 로그인 기록은 보통 `us-east-1`에 남습니다.** ap-northeast-2 로그만으로는 백도어 계정 생성이나 루트 로그인을 볼 수 없을 수 있습니다.
- 정상적인 CloudTrail 기록에는 `awsRegion`이 항상 있습니다. 필드가 없다면 이 파일은 누군가 가공했거나 걸러 낸 것일 수 있습니다. 출처를 확인해 주세요.
- 3단계 표가 모든 공격 유형을 담지는 않습니다. SSM 원격 명령(`SendCommand`), 비밀번호 변경 같은 이벤트는 빠져 있었습니다.

## 지금 바로 할 일 (권한 있는 팀원·운영자에게 요청)

본인은 콘솔에 들어갈 수 없으니, **팀장이나 연습 운영자, 또는 blue-team 팀원**에게 아래를 요청하세요. 여기서도 **삭제하지 말고 비활성화까지만** 하세요.

1. **루트 계정**: 비밀번호 변경, MFA 확인, 루트 액세스 키가 있으면 비활성화
2. **`AWSAccount` 사용자**(아는 사람이 없을 때): 액세스 키 비활성화, 콘솔 비밀번호 제거, `AWSDenyAll` 정책 연결
3. **두 인스턴스 역할**(`patchsignal-...-portal-role`, `ec2-ssmrole`): IAM 콘솔 → 역할 → **"활성 세션 취소(Revoke active sessions)"**. 정상 인스턴스는 새 자격 증명을 자동으로 받습니다.
4. **포털 인스턴스 `i-05816900800807b77`**: IMDSv2를 필수로 설정
5. **루트가 읽은 SSM 파라미터 값 교체** (DB 비밀번호, API 키 등)
6. **GuardDuty Findings 내보내기**: GuardDuty가 켜져 있으니 거기에 결정적인 단서가 있을 가능성이 큽니다.
7. **본인이 콘솔에 못 들어가는 이유 확인**: 비밀번호가 바뀌었는지, 권한이 회수됐는지에 따라 공격 범위 판단이 달라집니다.

## 추가로 뽑아 주실 로그

아래 명령을 차례대로 실행해서 결과를 보내 주세요. 길어도 괜찮습니다.

```bash
# A. 파일 전체 개요: 기간, 서비스별 건수(iam/signin 기록이 있는지 확인용), 주체별 건수
jq -r '[.Records[].eventTime] | "기간: \(min) ~ \(max)"' cloudtrail.json
jq -r '.Records[].eventSource' cloudtrail.json | sort | uniq -c | sort -rn
jq -r '.Records[] | [.userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn

# B. 루트 계정의 모든 활동
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.eventTime, .eventSource, .eventName, .sourceIPAddress, (.errorCode // "-"), .userAgent] | @tsv' cloudtrail.json | sort

# C. AWSAccount 사용자 관련 모든 기록 (주체이거나 대상인 경우 모두)
jq -r '.Records[] | select(tostring | contains("AWSAccount")) | [.eventTime, .eventName, (.userIdentity.arn // "-"), .sourceIPAddress, (.errorCode // "-"), (.userIdentity.accessKeyId // "-"), .userAgent] | @tsv' cloudtrail.json | sort

# D. 두 인스턴스 역할의 모든 활동
jq -r '.Records[] | select((.userIdentity.arn // "") | test("assumed-role/(ec2-ssmrole|patchsignal-ewc2enb8-portal-role)/")) | [.eventTime, .userIdentity.arn, .sourceIPAddress, .eventName, (.errorCode // "-"), .userAgent] | @tsv' cloudtrail.json | sort

# E. DryRun을 누가 무엇에 했는지
jq -r '.Records[] | select(.errorCode=="Client.DryRunOperation") | [.userIdentity.arn, .sourceIPAddress, .eventName] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn

# F. 비밀번호·인증 실패 상세
jq -r '.Records[] | select((.errorCode // "") | test("InvalidPassword|NotAuthorized|Unauthorized|AccessDenied")) | [.eventTime, .eventSource, .eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, .errorCode, (.errorMessage // "-")] | @tsv' cloudtrail.json | sort

# G. 보안 그룹 개방 내용, 읽은 파라미터 이름
jq -c '.Records[] | select(.eventName=="AuthorizeSecurityGroupIngress" or .eventName=="GetParameter") | {t:.eventTime, e:.eventName, who:.userIdentity.arn, req:.requestParameters}' cloudtrail.json

# H. 지난번 표에 없던 위험 이벤트
jq -r '.Records[] | select(.eventName | test("^(SendCommand|StartSession|ChangePassword|UpdateLoginProfile|DeleteLoginProfile|UpdateAccessKey|DeleteAccessKey|PutRolePolicy|CreatePolicyVersion|SetDefaultPolicyVersion|AddUserToGroup|AssumeRole|GetSessionToken|GetFederationToken|ModifyInstanceAttribute|CreateKeyPair|ImportKeyPair|DeactivateMFADevice|DeleteVirtualMFADevice|UpdateTrail|PutEventSelectors|UpdateDetector|ListSecrets|GetObject|PutObject|DeleteObject|GetCallerIdentity|ListUsers|ListRoles|ListBuckets|AdminSetUserPassword|AdminCreateUser|InitiateAuth|AdminInitiateAuth)$")) | [.eventTime, .eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort
```

**보내기 전에:** G 결과에 파라미터 **값**이 보이면 가려 주세요. 보통은 이름만 나옵니다. 액세스 키 ID는 앞 몇 자리만 남겨 주시면 됩니다.

## 함께 확인해 주실 것

- 연습 환경이라면 지난번에 말씀드린 개인정보 신고 의무는 보통 해당하지 않습니다. 대신 **연습 규칙(보고 방식, 조치 범위)** 을 운영 측에 확인하세요.
- `us-east-1` 로그나 다른 리전 로그를 구할 수 있는지 운영 측에 물어봐 주세요. 백도어 계정이 언제 만들어졌는지는 거기서 확인할 수 있습니다.

결과를 주시면 공격 경로(어디로 들어와서 무엇을 했는지)를 시간 순서로 정리하고, 고칠 항목 목록을 확정해 드리겠습니다.

## 사용자

두 번째 요청하신 A~H를 모두 뽑았습니다. 명령은 대부분 주신 그대로 실행했고, 길어서 바꾼 부분과 그 밖에 알려 드릴 점은 아래와 같습니다.

**바꿔서 뽑은 것**
- **A:** 세 번째 명령(주체별 건수) 결과가 길어서 앞 70줄과 그 뒤 나머지, 두 번에 나눠 붙였습니다.
- **B:** 첫 결과가 12,000자 제한에서 조금 잘려서, 끝 3줄을 따로 한 번 더 뽑아 붙였습니다. 마지막 줄은 04:48:52 UpdateStage입니다.
- **C:** 액세스 키 ID는 앞 8자리만 남기게 했는데, 이 기록에는 키 ID가 없어서 `-`로 나왔습니다.
- **D:** 원래 결과가 3,378줄(약 5만 자)이라 그대로는 다 붙일 수 없었습니다. 그래서 주체, IP, 이벤트명, 에러코드, userAgent가 같은 것끼리 묶어 건수와 처음·마지막 시각을 붙였습니다(python3).
- **H:** 1,088줄이라 두 부분으로 나눴습니다.
  - H-1: SendCommand, AssumeRole, GetCallerIdentity는 양이 많아서 이벤트명, 주체, IP, 에러코드별 건수로 묶었습니다. 시각은 빠져 있습니다.
  - H-2: 나머지 이벤트는 주신 형식 그대로 전부 붙였습니다.

**파일 자체에 없는 것**
- 이 파일에는 userAgent 값이 비어 있습니다. B, C, D의 마지막 칸이 비어 있는 이유입니다.
- G에서 AuthorizeSecurityGroupIngress의 requestParameters가 null입니다. 그래서 어떤 포트와 대역을 열었는지는 이 파일로는 알 수 없습니다.
- G에 파라미터 값은 들어 있지 않고 이름만 있습니다.

**질문에 대한 답**
- `AWSAccount` 사용자는 모릅니다. 아는 사실은 blue-team-1과 blue-team-2가 우리 팀원 계정이라는 것뿐입니다.
- blue-team-1의 보안 그룹 변경과 IP별 작업 내용은 저는 모릅니다. 사고 뒤 대응 작업(조회, 설정 변경)을 팀원이 했다는 것까지만 압니다.
- 연락이 온 경로와 제가 콘솔에 접속하지 못하는 이유도 모릅니다.
- 이 파일을 누가 어떻게 만들었는지(출처)도 모릅니다.

**확인 못 하거나 하지 않은 것**
- us-east-1이나 다른 리전 로그: 확인 못 함(그 로그는 없어요)
- GuardDuty Findings: 확인 못 함(그 자료는 없어요)
- 루트 비밀번호 변경, 역할 세션 취소 같은 조치: 저는 하지 않았습니다.

실행한 명령:
```
jq -r '[.Records[].eventTime] | "기간: \(min) ~ \(max)"' cloudtrail.json
jq -r '.Records[].eventSource' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
기간: 2026-10-11T04:30:01Z ~ 2026-10-11T07:25:01Z
   4170 logs.amazonaws.com
   1094 ec2.amazonaws.com
    893 cloudtrail.amazonaws.com
    883 ssm.amazonaws.com
    761 sts.amazonaws.com
    500 monitoring.amazonaws.com
    354 cognito-idp.amazonaws.com
    184 resource-explorer-2.amazonaws.com
    152 wafv2.amazonaws.com
    130 cloudshell.amazonaws.com
    116 observabilityadmin.amazonaws.com
    102 states.amazonaws.com
    101 eks.amazonaws.com
     89 elasticloadbalancing.amazonaws.com
     77 apigateway.amazonaws.com
     71 lambda.amazonaws.com
     68 s3.amazonaws.com
     66 kms.amazonaws.com
     56 autoscaling.amazonaws.com
     54 notifications.amazonaws.com
     53 config.amazonaws.com
     37 application-insights.amazonaws.com
     30 cloudcontrolapi.amazonaws.com
     28 signin.amazonaws.com
     21 sns.amazonaws.com
     15 oam.amazonaws.com
     14 resource-groups.amazonaws.com
     13 dynamodb.amazonaws.com
     12 guardduty.amazonaws.com
     12 compute-optimizer.amazonaws.com
     10 tagging.amazonaws.com
      8 cognito-identity.amazonaws.com
      7 events.amazonaws.com
      4 cloudformation.amazonaws.com
      3 iot.amazonaws.com
      2 transfer.amazonaws.com
      2 ssm-quicksetup.amazonaws.com
      2 servicequotas.amazonaws.com
      2 scheduler.amazonaws.com
      2 sagemaker.amazonaws.com
      2 networkflowmonitor.amazonaws.com
      2 gamelift.amazonaws.com
      2 ecs.amazonaws.com
      2 datasync.amazonaws.com
      2 athena.amazonaws.com
      2 aps.amazonaws.com
      1 ses.amazonaws.com
      1 schemas.amazonaws.com
      1 rolesanywhere.amazonaws.com
      1 rds.amazonaws.com
      1 pca-connector-ad.amazonaws.com
      1 osis.amazonaws.com
      1 network-firewall.amazonaws.com
      1 mediaconnect.amazonaws.com
      1 glue.amazonaws.com
      1 dms.amazonaws.com
      1 dataexchange.amazonaws.com
      1 codepipeline.amazonaws.com
      1 amazonmq.amazonaws.com
```

실행한 명령:
```
jq -r '.Records[] | [.userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn | head -70
```
결과:
```
   3207 AssumedRole	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1
   1547 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1
   1472 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1
    854 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1
    737 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1
    447 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1
    261 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1
    140 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1
    110 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	eks-nodegroup.amazonaws.com
    103 AWSService	-	delivery.logs.amazonaws.com
     95 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.9.1
     83 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com
     74 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com
     73 Root	arn:aws:iam::111122223333:root	198.18.18.1
     72 Root	arn:aws:iam::111122223333:root	198.18.0.3
     69 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com
     61 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.4.1
     60 AWSService	-	eks-nodegroup.amazonaws.com
     56 AWSService	-	config.amazonaws.com
     55 AWSService	-	eks.amazonaws.com
     49 AssumedRole	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1
     48 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling	autoscaling.amazonaws.com
     34 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com
     33 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	lambda.amazonaws.com
     27 AWSService	-	lambda.amazonaws.com
     26 Unknown	-	198.18.7.2
     26 AWSService	-	states.amazonaws.com
     25 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	apigateway.amazonaws.com
     21 Unknown	-	198.18.7.1
     18 Unknown	-	198.18.6.1
     18 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	observabilityadmin.amazonaws.com
     18 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	10.81.0.102
     18 AssumedRole	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497	eks.amazonaws.com
     18 AWSService	-	resource-explorer-2.amazonaws.com
     17 Unknown	-	198.18.23.1
     15 AWSService	-	cloudtrail.amazonaws.com
     14 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	eks.amazonaws.com
     13 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.19.1
     13 AssumedRole	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.9.1
     12 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	AWS Internal
     10 AWSService	-	ec2.amazonaws.com
      9 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	2001:db8:0:18::1
      9 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1
      8 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
      7 AWSService	-	AWS Internal
      6 Unknown	-	2001:db8:0:b::2
      6 AssumedRole	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s	eks.amazonaws.com
      5 AWSService	-	autoscaling.amazonaws.com
      4 Unknown	-	198.18.3.1
      4 Root	arn:aws:iam::111122223333:root	lambda.amazonaws.com
      4 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	lambda.amazonaws.com
      4 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.0.2
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1
      4 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSecurityHubV2/securityhub	securityhub.amazonaws.com
      4 AWSService	-	securityhub.amazonaws.com
      3 Unknown	-	198.18.5.1
      3 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	config.amazonaws.com
      2 Unknown	-	198.18.2.1
      2 Unknown	-	198.18.10.1
      2 Root	arn:aws:iam::111122223333:root	198.18.14.1
      2 IAMUser	arn:aws:iam::111122223333:user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1
      2 IAMUser	arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	198.18.8.1
      2 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.36.1
      2 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.33.1
      2 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.32.1
      2 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1
```

실행한 명령:
```
jq -r '.Records[] | [.userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn | tail -n +71
```
결과:
```
      1 Root	arn:aws:iam::111122223333:root	198.18.18.2
      1 Root	arn:aws:iam::111122223333:root	198.18.15.1
      1 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	ssm.amazonaws.com
      1 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	ssm-quicksetup.amazonaws.com
      1 IAMUser	arn:aws:iam::111122223333:user/blue-team-2	198.18.37.1
      1 IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.1.1
      1 IAMUser	arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.67.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.66.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.56.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.55.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.52.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.51.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.48.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.44.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.41.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.31.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.2
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.27.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.22.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.68.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.65.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.62.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.59.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.57.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.54.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.49.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.46.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.43.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.42.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.30.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.25.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.21.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.38.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.35.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.28.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.17.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.39.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.64.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.63.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.61.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.60.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.58.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.53.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.47.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.45.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.13.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3	198.18.8.1
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession	config.amazonaws.com
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession	config.amazonaws.com
      1 AssumedRole	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession	config.amazonaws.com
```

실행한 명령:
```
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.eventTime, .eventSource, .eventName, .sourceIPAddress, (.errorCode // "-"), .userAgent] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:42:48Z	sts.amazonaws.com	GetCallerIdentity	198.18.0.3	-	
2026-10-11T04:42:48Z	sts.amazonaws.com	GetCallerIdentity	198.18.0.3	-	
2026-10-11T04:42:49Z	apigateway.amazonaws.com	GetApi	198.18.0.3	-	
2026-10-11T04:42:49Z	dynamodb.amazonaws.com	DescribeContinuousBackups	198.18.0.3	-	
2026-10-11T04:42:49Z	dynamodb.amazonaws.com	DescribeTable	198.18.0.3	-	
2026-10-11T04:42:49Z	dynamodb.amazonaws.com	DescribeTable	198.18.0.3	-	
2026-10-11T04:42:49Z	dynamodb.amazonaws.com	DescribeTimeToLive	198.18.0.3	-	
2026-10-11T04:42:49Z	dynamodb.amazonaws.com	ListTagsOfResource	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeAddresses	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeAddressesAttribute	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeManagedPrefixLists	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	ec2.amazonaws.com	GetManagedPrefixListEntries	198.18.0.3	-	
2026-10-11T04:42:49Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.0.3	-	
2026-10-11T04:42:49Z	elasticloadbalancing.amazonaws.com	DescribeTargetGroupAttributes	198.18.0.3	-	
2026-10-11T04:42:49Z	elasticloadbalancing.amazonaws.com	DescribeTargetGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	logs.amazonaws.com	DescribeLogGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	logs.amazonaws.com	DescribeLogGroups	198.18.0.3	-	
2026-10-11T04:42:49Z	logs.amazonaws.com	ListTagsForResource	198.18.0.3	-	
2026-10-11T04:42:49Z	logs.amazonaws.com	ListTagsForResource	198.18.0.3	-	
2026-10-11T04:42:50Z	apigateway.amazonaws.com	GetApi	198.18.0.3	-	
2026-10-11T04:42:50Z	apigateway.amazonaws.com	GetStage	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeAddresses	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribePrefixLists	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.0.3	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.14.1	-	
2026-10-11T04:42:50Z	ec2.amazonaws.com	DescribeVpcEndpoints	198.18.0.3	-	
2026-10-11T04:42:50Z	elasticloadbalancing.amazonaws.com	DescribeCapacityReservation	198.18.0.3	-	
2026-10-11T04:42:50Z	elasticloadbalancing.amazonaws.com	DescribeLoadBalancerAttributes	198.18.0.3	-	
2026-10-11T04:42:50Z	elasticloadbalancing.amazonaws.com	DescribeLoadBalancers	198.18.0.3	-	
2026-10-11T04:42:50Z	ssm.amazonaws.com	GetParameter	198.18.0.3	-	
2026-10-11T04:42:51Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.0.3	-	
2026-10-11T04:42:51Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.0.3	-	
2026-10-11T04:42:51Z	elasticloadbalancing.amazonaws.com	DescribeListenerAttributes	198.18.0.3	-	
2026-10-11T04:42:51Z	elasticloadbalancing.amazonaws.com	DescribeListeners	198.18.0.3	-	
2026-10-11T04:42:51Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.0.3	-	
2026-10-11T04:42:51Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.0.3	-	
2026-10-11T04:42:52Z	apigateway.amazonaws.com	GetIntegration	198.18.0.3	-	
2026-10-11T04:42:52Z	elasticloadbalancing.amazonaws.com	DescribeRules	198.18.0.3	-	
2026-10-11T04:42:52Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.0.3	-	
2026-10-11T04:42:52Z	kms.amazonaws.com	Decrypt	lambda.amazonaws.com	-	
2026-10-11T04:42:52Z	kms.amazonaws.com	Decrypt	lambda.amazonaws.com	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	GetFunction20150331v2	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	GetFunction20150331v2	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	GetFunctionCodeSigningConfig	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	GetFunctionCodeSigningConfig	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	GetPolicy20150331v2	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	ListVersionsByFunction20150331	198.18.0.3	-	
2026-10-11T04:42:52Z	lambda.amazonaws.com	ListVersionsByFunction20150331	198.18.0.3	-	
2026-10-11T04:42:53Z	apigateway.amazonaws.com	GetRoute	198.18.0.3	-	
2026-10-11T04:42:53Z	states.amazonaws.com	DescribeStateMachine	198.18.0.3	-	
2026-10-11T04:42:53Z	states.amazonaws.com	ListStateMachineVersions	198.18.0.3	-	
2026-10-11T04:42:53Z	states.amazonaws.com	ListTagsForResource	198.18.0.3	-	
2026-10-11T04:42:55Z	ec2.amazonaws.com	DescribeInstanceTypes	198.18.0.3	-	
2026-10-11T04:42:55Z	ec2.amazonaws.com	DescribeInstances	198.18.0.3	-	
2026-10-11T04:42:55Z	ec2.amazonaws.com	DescribeTags	198.18.0.3	-	
2026-10-11T04:42:55Z	ec2.amazonaws.com	DescribeVpcs	198.18.0.3	-	
2026-10-11T04:42:56Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.0.3	-	
2026-10-11T04:42:56Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.0.3	-	
2026-10-11T04:42:56Z	ec2.amazonaws.com	DescribeVolumes	198.18.0.3	-	
2026-10-11T04:42:57Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.0.3	-	
2026-10-11T04:42:57Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.0.3	-	
2026-10-11T04:42:57Z	ec2.amazonaws.com	DescribeInstanceCreditSpecifications	198.18.0.3	-	
2026-10-11T04:42:57Z	elasticloadbalancing.amazonaws.com	DescribeTargetHealth	198.18.0.3	-	
2026-10-11T04:42:59Z	apigateway.amazonaws.com	GetApi	198.18.0.3	-	
2026-10-11T04:42:59Z	sts.amazonaws.com	GetCallerIdentity	198.18.14.1	-	
2026-10-11T04:43:00Z	apigateway.amazonaws.com	GetApi	198.18.0.3	-	
2026-10-11T04:43:00Z	apigateway.amazonaws.com	GetStage	198.18.0.3	-	
2026-10-11T04:43:00Z	apigateway.amazonaws.com	UpdateStage	198.18.0.3	-	
2026-10-11T04:45:23Z	apigateway.amazonaws.com	GetApi	198.18.15.1	-	
2026-10-11T04:48:40Z	sts.amazonaws.com	GetCallerIdentity	198.18.18.1	-	
2026-10-11T04:48:41Z	apigateway.amazonaws.com	GetApi	198.18.18.1	-	
2026-10-11T04:48:41Z	dynamodb.amazonaws.com	DescribeContinuousBackups	198.18.18.1	-	
2026-10-11T04:48:41Z	dynamodb.amazonaws.com	DescribeTable	198.18.18.1	-	
2026-10-11T04:48:41Z	dynamodb.amazonaws.com	DescribeTimeToLive	198.18.18.1	-	
2026-10-11T04:48:41Z	dynamodb.amazonaws.com	ListTagsOfResource	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	DescribeAddresses	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	DescribeAddressesAttribute	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	DescribeManagedPrefixLists	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.18.1	-	
2026-10-11T04:48:41Z	ec2.amazonaws.com	GetManagedPrefixListEntries	198.18.18.1	-	
2026-10-11T04:48:41Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.18.1	-	
2026-10-11T04:48:41Z	elasticloadbalancing.amazonaws.com	DescribeTargetGroupAttributes	198.18.18.1	-	
2026-10-11T04:48:41Z	elasticloadbalancing.amazonaws.com	DescribeTargetGroups	198.18.18.1	-	
2026-10-11T04:48:41Z	logs.amazonaws.com	DescribeLogGroups	198.18.18.1	-	
2026-10-11T04:48:41Z	logs.amazonaws.com	DescribeLogGroups	198.18.18.1	-	
2026-10-11T04:48:41Z	logs.amazonaws.com	ListTagsForResource	198.18.18.1	-	
2026-10-11T04:48:41Z	sts.amazonaws.com	GetCallerIdentity	198.18.18.1	-	
2026-10-11T04:48:42Z	apigateway.amazonaws.com	GetApi	198.18.18.1	-	
2026-10-11T04:48:42Z	apigateway.amazonaws.com	GetStage	198.18.18.1	-	
2026-10-11T04:48:42Z	dynamodb.amazonaws.com	DescribeTable	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribePrefixLists	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeSecurityGroups	198.18.18.1	-	
2026-10-11T04:48:42Z	ec2.amazonaws.com	DescribeVpcEndpoints	198.18.18.1	-	
2026-10-11T04:48:42Z	elasticloadbalancing.amazonaws.com	DescribeLoadBalancerAttributes	198.18.18.1	-	
2026-10-11T04:48:42Z	elasticloadbalancing.amazonaws.com	DescribeLoadBalancers	198.18.18.1	-	
2026-10-11T04:48:42Z	logs.amazonaws.com	ListTagsForResource	198.18.18.1	-	
2026-10-11T04:48:42Z	ssm.amazonaws.com	GetParameter	198.18.18.1	-	
2026-10-11T04:48:43Z	ec2.amazonaws.com	DescribeAddresses	198.18.18.1	-	
2026-10-11T04:48:43Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.18.1	-	
2026-10-11T04:48:43Z	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.18.1	-	
2026-10-11T04:48:43Z	elasticloadbalancing.amazonaws.com	DescribeCapacityReservation	198.18.18.1	-	
2026-10-11T04:48:43Z	elasticloadbalancing.amazonaws.com	DescribeListenerAttributes	198.18.18.1	-	
2026-10-11T04:48:43Z	elasticloadbalancing.amazonaws.com	DescribeListeners	198.18.18.1	-	
2026-10-11T04:48:43Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.18.1	-	
2026-10-11T04:48:43Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.18.1	-	
2026-10-11T04:48:44Z	apigateway.amazonaws.com	GetIntegration	198.18.18.1	-	
2026-10-11T04:48:44Z	elasticloadbalancing.amazonaws.com	DescribeRules	198.18.18.1	-	
2026-10-11T04:48:44Z	elasticloadbalancing.amazonaws.com	DescribeTags	198.18.18.1	-	
2026-10-11T04:48:44Z	kms.amazonaws.com	Decrypt	lambda.amazonaws.com	-	
2026-10-11T04:48:44Z	kms.amazonaws.com	Decrypt	lambda.amazonaws.com	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	GetFunction20150331v2	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	GetFunction20150331v2	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	GetFunctionCodeSigningConfig	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	GetFunctionCodeSigningConfig	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	GetPolicy20150331v2	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	ListVersionsByFunction20150331	198.18.18.1	-	
2026-10-11T04:48:44Z	lambda.amazonaws.com	ListVersionsByFunction20150331	198.18.18.1	-	
2026-10-11T04:48:45Z	apigateway.amazonaws.com	GetRoute	198.18.18.1	-	
2026-10-11T04:48:45Z	states.amazonaws.com	DescribeStateMachine	198.18.18.1	-	
2026-10-11T04:48:45Z	states.amazonaws.com	ListStateMachineVersions	198.18.18.1	-	
2026-10-11T04:48:45Z	states.amazonaws.com	ListTagsForResource	198.18.18.1	-	
2026-10-11T04:48:47Z	ec2.amazonaws.com	DescribeInstanceTypes	198.18.18.1	-	
2026-10-11T04:48:47Z	ec2.amazonaws.com	DescribeInstances	198.18.18.1	-	
2026-10-11T04:48:47Z	ec2.amazonaws.com	DescribeTags	198.18.18.1	-	
2026-10-11T04:48:47Z	ec2.amazonaws.com	DescribeVpcs	198.18.18.1	-	
2026-10-11T04:48:48Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.18.1	-	
2026-10-11T04:48:48Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.18.1	-	
2026-10-11T04:48:48Z	ec2.amazonaws.com	DescribeVolumes	198.18.18.1	-	
2026-10-11T04:48:49Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.18.1	-	
2026-10-11T04:48:49Z	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.18.1	-	
2026-10-11T04:48:49Z	ec2.amazonaws.com	DescribeInstanceCreditSpecifications	198.18.18.1	-	
2026-10-11T04:48:49Z	elasticloadbalancing.amazonaws.com	DescribeTargetHealth	198.18.18.1	-	
2026-10-11T04:48:51Z	apigateway.amazonaws.com	GetApi	198.18.18.1	-	
2026-10-11T04:48:51Z	sts.amazonaws.com	GetCallerIdentity	198.18.18.2	-	
2026-10-11T04:48:52Z	apigateway.amazonaws.com	GetApi	198.18.18.1	-	
2026-10-11T04:48:52Z	apigateway.amazonaws.com	GetStage	198.18.18.1	-	
2026-10-11T04:48:52Z	apigateway.amazonaws.com	UpdateStage	198.18.18.1	-
[... 출력 12,002자 중 앞 12,000자만]
```

실행한 명령:
```
jq -r '.Records[] | select(tostring | contains("AWSAccount")) | [.eventTime, .eventName, (.userIdentity.arn // "-"), .sourceIPAddress, (.errorCode // "-"), ((.userIdentity.accessKeyId // "-") | if . == "-" then . else .[0:8] + "****" end), .userAgent] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T05:09:58Z	GetBucketVersioning	arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2	AccessDenied	-
```

실행한 명령:
```
jq -r '.Records[] | select((.userIdentity.arn // "") | test("assumed-role/(ec2-ssmrole|patchsignal-ewc2enb8-portal-role)/")) | [.eventTime, .userIdentity.arn, .sourceIPAddress, .eventName, (.errorCode // "-"), .userAgent] | @tsv' cloudtrail.json | python3 -c '
import sys,collections
g={}
for l in sys.stdin:
  t,*k=l.rstrip("\n").split("\t");k=tuple(k)
  if k in g: g[k][0]+=1; g[k][1]=min(g[k][1],t); g[k][2]=max(g[k][2],t)
  else: g[k]=[1,t,t]
print("건수\t처음\t마지막\tarn\tIP\teventName\terrorCode\tuserAgent")
for k,v in sorted(g.items(),key=lambda x:x[1][1]): print(v[0],v[1],v[2],*k,sep="\t")'
```
결과:
```
건수	처음	마지막	arn	IP	eventName	errorCode	userAgent
10	2026-10-11T04:30:07Z	2026-10-11T06:00:13Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	ListInstanceAssociations	-	
2255	2026-10-11T04:30:12Z	2026-10-11T06:01:58Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	FilterLogEvents	-	
8	2026-10-11T04:30:39Z	2026-10-11T05:10:22Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	GetCallerIdentity	-	
9	2026-10-11T04:32:31Z	2026-10-11T05:52:35Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	ListInstanceAssociations	-	
18	2026-10-11T04:32:38Z	2026-10-11T06:46:25Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	CreateDataChannel	-	
18	2026-10-11T04:32:51Z	2026-10-11T05:57:54Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	10.81.0.102	GetFunction20150331v2	-	
41	2026-10-11T04:33:01Z	2026-10-11T07:23:01Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	UpdateInstanceInformation	-	
2	2026-10-11T04:33:29Z	2026-10-11T04:33:33Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	StartSession	AccessDenied	
41	2026-10-11T04:33:37Z	2026-10-11T07:23:37Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	UpdateInstanceInformation	-	
1	2026-10-11T04:44:35Z	2026-10-11T04:44:35Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	DescribeLogStreams	AccessDenied	
145	2026-10-11T04:45:11Z	2026-10-11T06:01:07Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	DescribeLogStreams	-	
725	2026-10-11T04:45:11Z	2026-10-11T06:01:07Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	GetLogEvents	-	
76	2026-10-11T05:00:03Z	2026-10-11T07:23:44Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	StartExecution	-	
1	2026-10-11T05:00:03Z	2026-10-11T05:00:03Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	GetCallerIdentity	-	
1	2026-10-11T05:00:18Z	2026-10-11T05:00:18Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	FilterLogEvents	AccessDenied	
10	2026-10-11T05:04:14Z	2026-10-11T05:54:33Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	DescribeExecution	-	
2	2026-10-11T06:09:40Z	2026-10-11T06:32:11Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	CreateDataChannel	-	
6	2026-10-11T06:36:22Z	2026-10-11T07:05:47Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	StartExecution	-	
1	2026-10-11T06:39:20Z	2026-10-11T06:39:20Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	StartSession	AccessDenied	
3	2026-10-11T06:52:08Z	2026-10-11T07:08:11Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	StartExecution	-	
1	2026-10-11T07:02:09Z	2026-10-11T07:02:09Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	StartSession	AccessDenied	
2	2026-10-11T07:11:37Z	2026-10-11T07:12:16Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	SendCommand	AccessDenied	
1	2026-10-11T07:19:43Z	2026-10-11T07:19:43Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	PutConfigurePackageResult	-	
1	2026-10-11T07:20:04Z	2026-10-11T07:20:04Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	PutConfigurePackageResult	-
```

실행한 명령:
```
jq -r '.Records[] | select(.errorCode=="Client.DryRunOperation") | [.userIdentity.arn, .sourceIPAddress, .eventName] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	CreateNetworkInterfacePermission
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	CreateNetworkInterface
     14 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	DescribeNetworkInterfaces
      1 arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	AuthorizeSecurityGroupIngress
```

실행한 명령:
```
jq -r '.Records[] | select((.errorCode // "") | test("InvalidPassword|NotAuthorized|Unauthorized|AccessDenied")) | [.eventTime, .eventSource, .eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, .errorCode, (.errorMessage // "-")] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:33:29Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied	-
2026-10-11T04:33:33Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied	-
2026-10-11T04:37:35Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:37:54Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:38:05Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:39:18Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:39:34Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:40:14Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.1	InvalidPasswordException	-
2026-10-11T04:42:04Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	-
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	-
2026-10-11T04:43:48Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	-
2026-10-11T04:43:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	-
2026-10-11T04:43:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.2	NotAuthorizedException	-
2026-10-11T04:44:03Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	-
2026-10-11T04:44:12Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	-
2026-10-11T04:44:22Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	-
2026-10-11T04:44:35Z	logs.amazonaws.com	DescribeLogStreams	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied	-
2026-10-11T04:48:18Z	cognito-idp.amazonaws.com	SignUp	Unknown	198.18.7.2	InvalidPasswordException	-
2026-10-11T04:53:14Z	observabilityadmin.amazonaws.com	ListCentralizationRulesForOrganization	arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	UnauthorizedException	-
2026-10-11T04:53:24Z	observabilityadmin.amazonaws.com	ListCentralizationRulesForOrganization	arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	UnauthorizedException	-
2026-10-11T05:00:18Z	logs.amazonaws.com	FilterLogEvents	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied	-
2026-10-11T05:06:51Z	observabilityadmin.amazonaws.com	ListCentralizationRulesForOrganization	arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1	UnauthorizedException	-
2026-10-11T05:09:58Z	s3.amazonaws.com	GetBucketVersioning	arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2	AccessDenied	-
2026-10-11T05:45:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	-
2026-10-11T05:45:49Z	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	198.18.7.1	NotAuthorizedException	-
2026-10-11T06:39:20Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied	-
2026-10-11T07:02:09Z	ssm.amazonaws.com	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	-
2026-10-11T07:11:37Z	ssm.amazonaws.com	SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	-
2026-10-11T07:12:16Z	ssm.amazonaws.com	SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied	-
```

실행한 명령:
```
jq -c '.Records[] | select(.eventName=="AuthorizeSecurityGroupIngress" or .eventName=="GetParameter") | {t:.eventTime, e:.eventName, who:.userIdentity.arn, req:.requestParameters}' cloudtrail.json
```
결과:
```
{"t":"2026-10-11T04:39:33Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:iam::111122223333:user/blue-team-1","req":null}
{"t":"2026-10-11T04:42:50Z","e":"GetParameter","who":"arn:aws:iam::111122223333:root","req":{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}
{"t":"2026-10-11T04:48:42Z","e":"GetParameter","who":"arn:aws:iam::111122223333:root","req":{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}
{"t":"2026-10-11T05:09:28Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:iam::111122223333:user/blue-team-1","req":null}
{"t":"2026-10-11T05:09:29Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:iam::111122223333:user/blue-team-1","req":null}
{"t":"2026-10-11T05:27:36Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:iam::111122223333:user/blue-team-1","req":null}
{"t":"2026-10-11T05:27:37Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:iam::111122223333:user/blue-team-1","req":null}
{"t":"2026-10-11T05:32:13Z","e":"GetParameter","who":"arn:aws:iam::111122223333:user/blue-team-2","req":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"t":"2026-10-11T05:57:21Z","e":"GetParameter","who":"arn:aws:iam::111122223333:user/blue-team-2","req":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"t":"2026-10-11T05:57:54Z","e":"GetParameter","who":"arn:aws:iam::111122223333:user/blue-team-2","req":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"t":"2026-10-11T07:18:34Z","e":"AuthorizeSecurityGroupIngress","who":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","req":null}
```

실행한 명령:
```
echo "== H-1: SendCommand/AssumeRole/GetCallerIdentity (대량이라 묶어서 건수)"; jq -r '.Records[] | select(.eventName | test("^(SendCommand|AssumeRole|GetCallerIdentity)$")) | [.eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort | uniq -c | sort -k2,2 -k1,1rn
echo "== H-2: 나머지 이벤트 전체"; jq -r '.Records[] | select(.eventName | test("^(StartSession|ChangePassword|UpdateLoginProfile|DeleteLoginProfile|UpdateAccessKey|DeleteAccessKey|PutRolePolicy|CreatePolicyVersion|SetDefaultPolicyVersion|AddUserToGroup|GetSessionToken|GetFederationToken|ModifyInstanceAttribute|CreateKeyPair|ImportKeyPair|DeactivateMFADevice|DeleteVirtualMFADevice|UpdateTrail|PutEventSelectors|UpdateDetector|ListSecrets|GetObject|PutObject|DeleteObject|ListUsers|ListRoles|ListBuckets|AdminSetUserPassword|AdminCreateUser|InitiateAuth|AdminInitiateAuth)$")) | [.eventTime, .eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort
```
결과:
```
== H-1: SendCommand/AssumeRole/GetCallerIdentity (대량이라 묶어서 건수)
     60 AssumeRole	AWSService	eks-nodegroup.amazonaws.com	-
     56 AssumeRole	AWSService	config.amazonaws.com	-
     55 AssumeRole	AWSService	eks.amazonaws.com	-
     27 AssumeRole	AWSService	lambda.amazonaws.com	-
     26 AssumeRole	AWSService	states.amazonaws.com	-
     18 AssumeRole	AWSService	resource-explorer-2.amazonaws.com	-
     10 AssumeRole	AWSService	ec2.amazonaws.com	-
      7 AssumeRole	AWSService	AWS Internal	-
      5 AssumeRole	AWSService	autoscaling.amazonaws.com	-
      4 AssumeRole	AWSService	securityhub.amazonaws.com	-
    237 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
     95 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.9.1	-
     61 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.4.1	-
     25 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	apigateway.amazonaws.com	-
     13 GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	eks.amazonaws.com	-
     13 GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.9.1	-
     10 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
     10 GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	eks-nodegroup.amazonaws.com	-
      8 GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.0.3	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.18.1	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.32.1	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.33.1	-
      2 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.36.1	-
      1 GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.14.1	-
      1 GetCallerIdentity	arn:aws:iam::111122223333:root	198.18.18.2	-
      1 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-1	198.18.1.1	-
      1 GetCallerIdentity	arn:aws:iam::111122223333:user/blue-team-2	198.18.37.1	-
      1 GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
    244 SendCommand	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
      8 SendCommand	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
      5 SendCommand	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
      5 SendCommand	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
      2 SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
== H-2: 나머지 이벤트 전체
2026-10-11T04:32:38Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
2026-10-11T04:33:29Z	StartSession	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
2026-10-11T04:33:33Z	StartSession	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1	AccessDenied
2026-10-11T04:33:57Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
2026-10-11T04:35:30Z	ListBuckets	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
2026-10-11T04:36:12Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T04:36:20Z	ListBuckets	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
2026-10-11T04:38:30Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
2026-10-11T04:38:54Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T04:41:54Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T04:42:01Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T04:42:04Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T04:42:12Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T04:43:38Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T04:43:47Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:43:47Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:43:48Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:43:48Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:49:03Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:49:06Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:50:27Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T04:50:28Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T05:06:14Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:09:01Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:13:06Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T05:17:31Z	InitiateAuth	Unknown	2001:db8:0:b::2	-
2026-10-11T05:19:46Z	ListBuckets	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:23:00Z	PutEventSelectors	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:23:34Z	ListBuckets	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	-
2026-10-11T05:24:22Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:24:36Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:24:42Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:24:47Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:24:52Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:24:56Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:29:30Z	InitiateAuth	Unknown	198.18.7.2	-
2026-10-11T05:29:52Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T05:30:13Z	ModifyInstanceAttribute	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:30:16Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:30:19Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:30:39Z	ModifyInstanceAttribute	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:30:54Z	StartSession	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-
2026-10-11T05:31:08Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T05:31:30Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:31:44Z	ModifyInstanceAttribute	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:32:18Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:33:02Z	ModifyInstanceAttribute	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T05:43:48Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:44:07Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:44:13Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-
2026-10-11T05:45:47Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T05:45:47Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T05:45:57Z	InitiateAuth	Unknown	198.18.7.1	-
2026-10-11T05:49:43Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:49:44Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:49:44Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:49:45Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:49:57Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:59:15Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T05:59:20Z	ListUsers	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T06:09:40Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T06:26:14Z	StartSession	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-
2026-10-11T06:26:59Z	InitiateAuth	Unknown	2001:db8:0:b::2	-
2026-10-11T06:39:20Z	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied
2026-10-11T07:02:09Z	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
2026-10-11T07:10:31Z	UpdateDetector	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2026-10-11T07:18:18Z	UpdateDetector	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
```

실행한 명령:
```
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.eventTime, .eventSource, .eventName, .sourceIPAddress, (.errorCode // "-"), .userAgent] | @tsv' cloudtrail.json | sort | tail -n 3
```
결과:
```
2026-10-11T04:48:52Z	apigateway.amazonaws.com	GetApi	198.18.18.1	-	
2026-10-11T04:48:52Z	apigateway.amazonaws.com	GetStage	198.18.18.1	-	
2026-10-11T04:48:52Z	apigateway.amazonaws.com	UpdateStage	198.18.18.1	-
```

## 채팅 AI

# CloudTrail 2차 분석 결과

## 결론

1. **포털 인스턴스의 AWS 자격 증명이 외부로 빠져나가 쓰였습니다.** 이번 사고의 핵심으로 보입니다. PatchSignal 포털 EC2(`i-05816900800807b77`)의 역할 자격 증명이 06:36 UTC(15:36 KST)부터 인스턴스가 아닌 외부 IP 두 곳에서 쓰였고, **Step Functions 실행 9건은 성공했습니다.**
2. **공격자로 보이는 출발지는 `198.18.7.1`, `198.18.7.2`, `198.18.50.1`입니다.** 7.1과 7.2는 04:37부터 포털 로그인(Cognito)을 반복해서 시도했고, 나중에 같은 IP가 탈취한 역할을 썼습니다.
3. **루트 계정 사용은 공격보다 자동화 도구(Terraform 등) 실행으로 보입니다.** 다만 누가 돌렸는지, API Gateway 설정을 무엇으로 바꿨는지는 확인해야 합니다.
4. 이 파일에는 **IAM 기록이 아예 없습니다**(`iam.amazonaws.com` 0건). 그래서 백도어 사용자나 키가 생겼는지는 여전히 알 수 없습니다.

## 지난 분석 정정

새 자료를 보니 제가 잘못 짚은 부분이 있습니다.

| 지난 판단 | 정정 |
|---|---|
| 루트가 SSM 비밀값을 읽음 (🔴) | 읽은 것은 `/aws/service/ami-amazon-linux-latest/...`입니다. AWS가 모두에게 공개하는 **최신 AMI ID**라 비밀값이 아닙니다. 교체할 필요가 없습니다. |
| DryRun 63건은 권한 탐색 흔적 | 62건은 EKS 서비스 역할의 정상 동작이고, 1건은 blue-team-1입니다. **문제없습니다.** |
| blue-team-1의 198.18.0.1 AccessDenied가 의심스러움 | 콘솔 화면이 조직(Organization) 기능을 조회하다 난 오류로 보입니다. **위험 신호로 보기 어렵습니다.** |
| `ec2-ssmrole` 자격 증명 탈취 가능성 | 모든 호출이 한 IP(198.18.6.1)에서만 나왔고 외부 사용 흔적이 없습니다. 대량의 로그 조회는 **팀의 모니터링·조사용 서버**로 보입니다. 팀에 확인만 하면 됩니다. |

참고로 `ListUsers`는 IAM이 아니라 **Cognito 사용자 목록 조회**입니다. 팀원이 포털 가입자를 조사한 것으로 보입니다.

## 공격 흐름 (추정)

| UTC (KST) | 출발지 | 내용 |
|---|---|---|
| 04:37–04:40 (13:37) | 7.1 | 포털 Cognito에 `SignUp` 6회, 모두 비밀번호 정책에 걸려 실패 |
| 04:41–04:42 | 7.1 | `InitiateAuth` 3회 통과, 다음 단계 `RespondToAuthChallenge` 실패 |
| 04:43:47–49 | 7.2 | **2초 사이에** 로그인 시도 4회, 챌린지 실패 4회 (도구로 자동화한 패턴) |
| 04:44–04:50 | 7.2 | `SignUp` 4회 실패, `InitiateAuth` 4회 통과 (**로그인에 성공했을 가능성**) |
| 05:09:58 (14:09) | 7.2 | `user/AWSAccount` 이름으로 S3 `GetBucketVersioning` 시도, 거부됨 |
| 05:29, 05:45 | 7.2, 7.1 | 추가 로그인 시도 (05:45 챌린지 실패 2회) |
| **06:36:22 (15:36)** | **7.1** | **포털 역할로 Step Functions `StartExecution` 성공** (07:05까지 6회) |
| 06:39:20 | 50.1 | 같은 역할로 SSM `StartSession`(서버 접속) 시도, 거부됨 |
| 06:52–07:08 | 50.1 | `StartExecution` 3회 성공 |
| 07:02, 07:11–07:12 (16:12) | 7.1 | `StartSession` 1회, `SendCommand` 2회 시도, 모두 거부됨 |

### 탈취로 판단한 근거
- EC2 역할 세션 이름은 인스턴스 ID입니다. 이 자격 증명은 원래 **그 인스턴스만** 받습니다.
- 포털 인스턴스 자신은 계속 `198.18.10.1`(SSM 에이전트가 5분마다 보내는 신호, 07:23까지 이어짐)과 사설 IP `10.81.0.102`에서 호출했습니다. 그런데 같은 시간대에 **다른 IP 두 곳에서 같은 세션이 쓰였습니다.**
- 외부 IP 쪽은 서버 원격 접속(StartSession, SendCommand)을 시도했습니다. 정상 앱이라면 하지 않는 동작입니다.

### 실제 피해로 확인된 것
- **Step Functions 실행 9건 성공.** 공격자가 넣은 입력으로 워크플로가 돌았습니다. 이 워크플로가 무엇을 하는지(어떤 Lambda를 부르고 어떤 데이터를 쓰는지)에 따라 피해 범위가 정해집니다.
- 그 밖의 시도(SSM 접속, S3 조회)는 이 파일 기준으로 모두 거부됐습니다.

## 아직 판단할 수 없는 것

**루트 계정 (중요도: 확인 필요)**
- 04:42와 04:48에 거의 똑같은 호출 약 70건이 순서까지 같게 반복되고, 각각 `UpdateStage` 한 건으로 끝납니다.
- 호출 구성(공개 AMI 파라미터 조회, `DescribeInstanceCreditSpecifications`, `GetFunctionCodeSigningConfig` 등)이 **Terraform이 현재 상태를 읽은 뒤 바뀐 부분만 적용할 때** 남기는 패턴과 같습니다.
- 그래서 사람이 공격한 흔적보다는 누군가 루트 키로 인프라 코드를 돌린 것으로 보입니다. 연습 운영 측이 시나리오를 주입했을 가능성도 있습니다.
- 다만 **API Gateway 스테이지를 무엇으로 바꿨는지** 꼭 봐야 합니다. 로그 기록을 끄거나, 요청 제한을 풀거나, 백엔드 주소를 바꿨을 수 있습니다.

**`user/AWSAccount`**
- 이 파일 전체에서 1건뿐이고, 거부됐고, 액세스 키 ID가 없으며, 출발지가 공격자 IP(7.2)입니다.
- 해석은 두 가지입니다. (a) 공격자가 이 이름의 IAM 사용자 자격 증명을 갖고 있다. (b) 원래 CloudTrail에서 "다른 AWS 계정의 요청"을 뜻하는 `userIdentity.type: AWSAccount`가, 이 파일을 만드는 과정에서 사용자 이름처럼 바뀌었다. 이 파일에는 `awsRegion`과 `userAgent`도 없어서, 가공됐을 가능성이 있습니다.
- 원본 기록을 보면 구분할 수 있습니다(아래 I).

**blue-team-1의 출발지가 10곳 가까이 됨**
- 여러 사람이 한 IAM 사용자를 함께 쓰는 것으로 보입니다. 그러면 팀원의 작업과 공격자의 작업을 구분할 수 없습니다. 팀원들이 쓴 IP 목록을 받아야 합니다.

## 지금 할 일 (권한 있는 팀원에게 요청)

삭제하지 말고 **차단과 비활성화까지만** 하세요.

**1. 포털 인스턴스 메타데이터 잠그기 (가장 먼저, 몇 초면 끝남)**
```bash
aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled
```
이렇게 하면 SSRF(앱이 사용자가 준 URL을 대신 요청하는 취약점)로 자격 증명을 빼 가는 가장 흔한 경로가 막힙니다. 05:30~05:33의 `ModifyInstanceAttribute` 4건이 이미 이 작업이었는지 팀원에게 확인하세요. 만약 그랬는데도 06:36에 탈취가 일어났다면, 경로는 메타데이터가 아니라 **앱의 원격 코드 실행이나 파일 읽기 취약점**일 수 있습니다.

**2. 포털 역할의 기존 세션 취소**
IAM → 역할 → `patchsignal-ewc2enb8-portal-role` → "활성 세션 취소". 공격자가 가진 자격 증명은 몇 시간 동안 계속 유효하므로 꼭 해야 합니다. 지난번에 "정상 인스턴스는 자동으로 새 자격 증명을 받는다"고 말씀드렸는데, 바로 받지 못해서 **포털이 잠시 오류를 낼 수 있습니다.** 필요하면 앱을 재시작하세요. 1번을 하지 않고 2번만 하면 다시 털릴 수 있으니 순서를 지키세요.

**3. 포털 역할 권한 줄이기**
- `ssm:StartSession`, `ssm:SendCommand`: 지금도 거부되고 있는지 확인하고 계속 막아 두세요.
- `states:StartExecution`: 포털이 실제로 쓰는 상태 머신 하나로만 제한하세요.
- `lambda:GetFunction`: 포털 인스턴스가 18번 호출했습니다. 이 권한이 있으면 Lambda 코드와 **복호화된 환경 변수(비밀값)** 를 받아 갈 수 있습니다. 정말 필요한지 검토하세요.

**4. 공격자가 돌린 Step Functions 실행 확인**
06:36~07:08 UTC 실행 목록과 실행 이력(입력값, 호출한 Lambda, 결과)을 확인하고, 아직 돌고 있으면 중지하세요.

**5. Cognito 정리**
- 04:37 UTC 이후 생성된 사용자를 확인하고, 의심스러운 계정은 **비활성화**(`AdminDisableUser`)와 전체 로그아웃(`AdminUserGlobalSignOut`)을 하세요.
- 셀프 가입이 필요 없는 서비스라면 꺼 두세요.
- Identity Pool이 있다면(cognito-identity 기록 8건) 그 역할의 권한도 확인하세요.

## 개발자로서 직접 보실 것: 포털 앱 취약점

자격 증명이 어디서 샜는지는 **포털 앱 쪽**에 답이 있을 가능성이 큽니다.
- 사용자가 준 URL을 서버가 대신 요청하는 기능(피드 등록, 웹훅, 미리보기, 이미지 가져오기 등)이 있는지 확인하세요.
- 포털 접근 로그와 앱 로그에서 06:36 UTC(15:36 KST) **이전**을 중심으로 아래를 찾아보세요.
```bash
grep -E "169\.254\.169\.254|meta-data|iam/security-credentials|latest/api/token|/proc/self|\.\./" access.log app.log
grep -E "198\.18\.7\.[12]|198\.18\.50\.1" access.log app.log
```
- 결과를 주시면 어느 기능이 뚫렸는지 함께 보겠습니다.

## 팀원과 운영자에게 물어볼 것

1. 오늘 루트 키로 Terraform 같은 도구를 돌린 사람이 있는지, 04:43과 04:48에 API Gateway 스테이지를 왜 바꿨는지
2. `AWSAccount`라는 IAM 사용자가 실제로 있는지 (IAM 콘솔 → 사용자)
3. `i-026754fe07a870049`(`ec2-ssmrole`)가 팀의 조사용 서버인지
4. blue-team-1과 blue-team-2를 쓴 사람들의 출발지 IP 목록
5. blue-team-1이 한 아래 작업의 내용
   - `AuthorizeSecurityGroupIngress` 5건: 어떤 포트를 어디에 열었는지
   - `ModifyInstanceAttribute` 4건
   - `PutEventSelectors`(05:23, CloudTrail 기록 범위 변경): 기록을 **늘린** 것이 맞는지
6. us-east-1 CloudTrail(IAM 기록)을 받을 수 있는지

## 추가로 뽑아 주실 로그

길면 지난번처럼 나눠 주셔도 됩니다. 결과에 비밀번호나 개인정보가 보이면 가려 주세요.

```bash
# I. 핵심 원본 기록: AWSAccount 1건, 루트 UpdateStage, PutEventSelectors
jq -c '.Records[] | select(((.userIdentity.arn // "") | endswith("user/AWSAccount")) or .eventName=="UpdateStage" or .eventName=="PutEventSelectors") | del(.tlsDetails)' cloudtrail.json

# J. 의심 IP의 모든 활동
jq -r '.Records[] | select(.sourceIPAddress | test("^198\\.18\\.7\\.|^198\\.18\\.50\\.1$|^2001:db8:0:b::2$")) | [.eventTime, .sourceIPAddress, .eventSource, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), (.errorCode // "-")] | @tsv' cloudtrail.json | sort

# K. 포털 역할: 같은 세션 키가 인스턴스와 외부에서 함께 쓰였는지 (키는 앞 4자리와 끝 4자리만 표시)
jq -r '.Records[] | select((.userIdentity.arn // "") | contains("portal-role")) | [((.userIdentity.accessKeyId // "-") | if length > 8 then .[0:4] + "…" + .[-4:] else . end), (.userIdentity.sessionContext.attributes.creationDate // "-"), .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c

# L. 공격자가 실행한 Step Functions (정상 비교용 2건 포함)
jq -c '.Records[] | select(.eventName=="StartExecution" and ((.userIdentity.arn // "") | contains("portal-role")) and .sourceIPAddress != "198.18.10.1") | {t:.eventTime, ip:.sourceIPAddress, req:.requestParameters, res:.responseElements}' cloudtrail.json
jq -c '[.Records[] | select(.eventName=="StartExecution" and .sourceIPAddress=="198.18.10.1") | {t:.eventTime, req:.requestParameters, res:.responseElements}] | .[0:2][]' cloudtrail.json

# M. Cognito: IP·이벤트·결과별 건수 (성공한 가입·로그인이 있었는지)
jq -r '.Records[] | select(.eventSource=="cognito-idp.amazonaws.com" or .eventSource=="cognito-identity.amazonaws.com") | [.sourceIPAddress, .eventSource, .eventName, (.errorCode // "OK")] | @tsv' cloudtrail.json | sort | uniq -c | sort -k2,2 -k1,1rn

# N. 콘솔 로그인 관련 기록 28건 (루트 로그인 여부 확인)
jq -r '.Records[] | select(.eventSource=="signin.amazonaws.com") | [.eventTime, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress, (.errorCode // "-"), (.responseElements | tostring), (.additionalEventData | tostring)] | @tsv' cloudtrail.json | sort
```

L의 `res`에 `executionArn`이 나오면, 권한 있는 팀원에게 아래 명령으로 실행 내용을 확인해 달라고 하세요. CloudTrail에는 실행 입력값이 가려져 있을 수 있습니다.
```bash
aws stepfunctions describe-execution --execution-arn <executionArn>
aws stepfunctions get-execution-history --execution-arn <executionArn> --max-items 50
```

결과를 주시면 탈취 경로와 피해 범위를 확정하고, 최종 조치 목록과 사후 보고용 타임라인을 정리해 드리겠습니다.

## 사용자

이번에 요청하신 I~N은 주신 명령을 그대로 실행해서 결과를 아래에 붙였습니다. 길지 않아서 나누거나 줄인 것은 없습니다.

**결과에서 보이는 점 (확인한 내용만 적었습니다)**
- **I:** 위 원본 기록에 나온 필드가 이 파일에 있는 전부입니다. UpdateStage 2건과 PutEventSelectors에는 requestParameters가 없습니다. 그래서 무엇을 바꿨는지는 이 파일로는 알 수 없습니다.
- **K:** `sessionContext.attributes.creationDate` 필드가 없어서 모두 `-`로 나왔습니다.
- **L:** `res`(responseElements)가 모두 null이고 executionArn이 없습니다. 그래서 describe-execution이나 get-execution-history로 이어 갈 수 없습니다. 지금은 CLI를 쓸 수 없기도 합니다.
- **N:** signin 기록 28건은 모두 위 결과에 나온 그대로입니다.

**뽑을 수 없었던 것**
- 포털 접근 로그(access.log)와 앱 로그(app.log)는 없어서 grep을 돌리지 못했습니다.

**팀원과 운영자에게 물어볼 것 (1~6번)**
- 제가 아는 사실은 이것뿐입니다.
  - blue-team-1과 blue-team-2는 우리 팀원 계정입니다.
  - 사고 뒤 대응 작업(조회, 설정 변경)은 팀원이 했습니다.
  - PatchSignal은 원래 있던 우리 서비스입니다.
  - 이 계정은 보안 공방전(연습) 환경입니다.
- 그 밖의 질문에는 저는 답을 모릅니다. 루트 키로 Terraform을 돌린 사람, `AWSAccount` 사용자가 실제로 있는지, `i-026754fe07a870049`의 용도, 팀원 출발지 IP, blue-team-1이 한 작업의 구체적 내용이 여기에 해당합니다.
- us-east-1 CloudTrail: 확인 못 함(그 로그는 없어요)

**지금 할 일 1~5번**
- 1~5번(메타데이터 잠금, 세션 취소, 권한 축소 등)은 저는 하지 않았습니다. 지금 콘솔과 CLI에 접속할 수 없습니다.

실행한 명령:
```
jq -c '.Records[] | select(((.userIdentity.arn // "") | endswith("user/AWSAccount")) or .eventName=="UpdateStage" or .eventName=="PutEventSelectors") | del(.tlsDetails)' cloudtrail.json
```
결과:
```
{"eventTime":"2026-10-11T04:43:00Z","eventSource":"apigateway.amazonaws.com","eventName":"UpdateStage","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:48:52Z","eventSource":"apigateway.amazonaws.com","eventName":"UpdateStage","sourceIPAddress":"198.18.18.1","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T05:09:58Z","eventSource":"s3.amazonaws.com","eventName":"GetBucketVersioning","sourceIPAddress":"198.18.7.2","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/AWSAccount"},"errorCode":"AccessDenied","requestParameters":{"bucketName":"pagesnap-final-s1-results-0e666173"}}
{"eventTime":"2026-10-11T05:23:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"PutEventSelectors","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAA29…08A0"}}
```

실행한 명령:
```
jq -r '.Records[] | select(.sourceIPAddress | test("^198\\.18\\.7\\.|^198\\.18\\.50\\.1$|^2001:db8:0:b::2$")) | [.eventTime, .sourceIPAddress, .eventSource, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), (.errorCode // "-")] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:37:35Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:37:54Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:38:05Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:39:18Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:39:34Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:39:48Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T04:40:14Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:40:26Z	198.18.7.1	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T04:41:32Z	198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	-
2026-10-11T04:41:54Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:42:01Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:42:04Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:42:04Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T04:42:14Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T04:42:16Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T04:43:47Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:43:47Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T04:43:48Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T04:43:49Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T04:43:49Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T04:44:03Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:44:12Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:44:22Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:48:18Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	InvalidPasswordException
2026-10-11T04:48:29Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T04:48:58Z	198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	-
2026-10-11T04:49:03Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:49:04Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T04:49:06Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:49:07Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T04:50:27Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T04:50:28Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T05:09:58Z	198.18.7.2	s3.amazonaws.com	GetBucketVersioning	IAMUser	arn:aws:iam::111122223333:user/AWSAccount	AccessDenied
2026-10-11T05:16:40Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T05:17:08Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T05:17:22Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	-
2026-10-11T05:17:31Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T05:17:32Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T05:28:39Z	198.18.7.2	cognito-idp.amazonaws.com	SignUp	Unknown	-	-
2026-10-11T05:29:20Z	198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	Unknown	-	-
2026-10-11T05:29:30Z	198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T05:29:30Z	198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T05:45:47Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T05:45:47Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T05:45:49Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T05:45:49Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	NotAuthorizedException
2026-10-11T05:45:57Z	198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T05:45:58Z	198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	Unknown	-	-
2026-10-11T06:26:59Z	2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	Unknown	-	-
2026-10-11T06:36:22Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T06:39:20Z	198.18.50.1	ssm.amazonaws.com	StartSession	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied
2026-10-11T06:40:45Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T06:41:53Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T06:52:08Z	198.18.50.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:02:09Z	198.18.7.1	ssm.amazonaws.com	StartSession	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied
2026-10-11T07:02:17Z	198.18.50.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:03:46Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:05:02Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:05:47Z	198.18.7.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:08:11Z	198.18.50.1	states.amazonaws.com	StartExecution	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	-
2026-10-11T07:11:37Z	198.18.7.1	ssm.amazonaws.com	SendCommand	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied
2026-10-11T07:12:16Z	198.18.7.1	ssm.amazonaws.com	SendCommand	AssumedRole	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	AccessDenied
```

실행한 명령:
```
jq -r '.Records[] | select((.userIdentity.arn // "") | contains("portal-role")) | [((.userIdentity.accessKeyId // "-") | if length > 8 then .[0:4] + "…" + .[-4:] else . end), (.userIdentity.sessionContext.attributes.creationDate // "-"), .sourceIPAddress] | @tsv' cloudtrail.json | sort | uniq -c
```
결과:
```
      9 ASIA…0AE1	-	198.18.10.1
     99 ASIA…2435	-	198.18.10.1
     18 ASIA…2E7A	-	10.81.0.102
     18 ASIA…35DA	-	198.18.10.1
     14 ASIA…4DE2	-	198.18.10.1
      4 ASIA…95CF	-	198.18.50.1
      9 ASIA…95CF	-	198.18.7.1
```

실행한 명령:
```
jq -c '.Records[] | select(.eventName=="StartExecution" and ((.userIdentity.arn // "") | contains("portal-role")) and .sourceIPAddress != "198.18.10.1") | {t:.eventTime, ip:.sourceIPAddress, req:.requestParameters, res:.responseElements}' cloudtrail.json
jq -c '[.Records[] | select(.eventName=="StartExecution" and .sourceIPAddress=="198.18.10.1") | {t:.eventTime, req:.requestParameters, res:.responseElements}] | .[0:2][]' cloudtrail.json
```
결과:
```
{"t":"2026-10-11T06:36:22Z","ip":"198.18.7.1","req":null,"res":null}
{"t":"2026-10-11T06:40:45Z","ip":"198.18.7.1","req":{"name":"case-redteam-validation-002"},"res":null}
{"t":"2026-10-11T06:41:53Z","ip":"198.18.7.1","req":{"name":"case-redteam-validation-003"},"res":null}
{"t":"2026-10-11T06:52:08Z","ip":"198.18.50.1","req":null,"res":null}
{"t":"2026-10-11T07:02:17Z","ip":"198.18.50.1","req":null,"res":null}
{"t":"2026-10-11T07:03:46Z","ip":"198.18.7.1","req":{"name":"test-run-1791702223"},"res":null}
{"t":"2026-10-11T07:05:02Z","ip":"198.18.7.1","req":{"name":"test-run-1791702300"},"res":null}
{"t":"2026-10-11T07:05:47Z","ip":"198.18.7.1","req":{"name":"test-run-1791702344"},"res":null}
{"t":"2026-10-11T07:08:11Z","ip":"198.18.50.1","req":null,"res":null}
{"t":"2026-10-11T05:00:03Z","req":{"name":"case-ec4331c54acf42f3a59e7132efe11b0f"},"res":null}
{"t":"2026-10-11T05:14:32Z","req":{"name":"case-eb91f8b2e2b04896a882c27133e28461"},"res":null}
```

실행한 명령:
```
jq -r '.Records[] | select(.eventSource=="cognito-idp.amazonaws.com" or .eventSource=="cognito-identity.amazonaws.com") | [.sourceIPAddress, .eventSource, .eventName, (.errorCode // "OK")] | @tsv' cloudtrail.json | sort | uniq -c | sort -k2,2 -k1,1rn
```
결과:
```
      5 198.18.2.1	cognito-idp.amazonaws.com	DescribeUserPool	OK
      4 198.18.2.1	cognito-idp.amazonaws.com	GetCSVHeader	OK
      4 198.18.2.1	cognito-idp.amazonaws.com	ListUserImportJobs	OK
      4 198.18.2.1	cognito-idp.amazonaws.com	ListUserPoolReplicas	OK
      2 198.18.2.1	cognito-idp.amazonaws.com	ListUserPoolClients	OK
      2 198.18.2.1	cognito-idp.amazonaws.com	ListUserPools	OK
      1 198.18.2.1	cognito-identity.amazonaws.com	ListIdentityPools	OK
      1 198.18.2.1	cognito-idp.amazonaws.com	DescribeUserPoolClient	OK
      1 198.18.2.1	cognito-idp.amazonaws.com	ListUsers	OK
     37 198.18.23.1	cognito-idp.amazonaws.com	DescribeUserPool	OK
     36 198.18.23.1	cognito-idp.amazonaws.com	ListUserPoolReplicas	OK
     27 198.18.23.1	cognito-idp.amazonaws.com	ListUserImportJobs	OK
     26 198.18.23.1	cognito-idp.amazonaws.com	GetCSVHeader	OK
     24 198.18.23.1	cognito-idp.amazonaws.com	AdminGetUser	OK
     18 198.18.23.1	cognito-idp.amazonaws.com	ListUsers	OK
      9 198.18.23.1	cognito-idp.amazonaws.com	AdminListGroupsForUser	OK
      7 198.18.23.1	cognito-idp.amazonaws.com	DescribeUserPoolClient	OK
      4 198.18.23.1	cognito-idp.amazonaws.com	ListUserPools	OK
      3 198.18.23.1	cognito-identity.amazonaws.com	ListIdentityPools	OK
      3 198.18.23.1	cognito-idp.amazonaws.com	ListGroups	OK
      3 198.18.23.1	cognito-idp.amazonaws.com	ListUserPoolClients	OK
      2 198.18.23.1	cognito-idp.amazonaws.com	GetProvisionedLimit	OK
      1 198.18.23.1	cognito-idp.amazonaws.com	AdminListUserAuthEvents	UserPoolAddOnNotEnabledException
     12 198.18.3.1	cognito-idp.amazonaws.com	AdminGetUser	OK
     12 198.18.3.1	cognito-idp.amazonaws.com	DescribeUserPool	OK
     10 198.18.3.1	cognito-idp.amazonaws.com	GetCSVHeader	OK
     10 198.18.3.1	cognito-idp.amazonaws.com	ListUserImportJobs	OK
     10 198.18.3.1	cognito-idp.amazonaws.com	ListUserPoolReplicas	OK
      6 198.18.3.1	cognito-idp.amazonaws.com	AdminListGroupsForUser	OK
      3 198.18.3.1	cognito-idp.amazonaws.com	ListUserPools	OK
      3 198.18.3.1	cognito-idp.amazonaws.com	ListUsers	OK
      2 198.18.3.1	cognito-identity.amazonaws.com	ListIdentityPools	OK
      2 198.18.3.1	cognito-idp.amazonaws.com	DescribeUserPoolClient	OK
      2 198.18.3.1	cognito-idp.amazonaws.com	ListGroups	OK
      2 198.18.3.1	cognito-idp.amazonaws.com	ListUserPoolClients	OK
      1 198.18.3.1	cognito-idp.amazonaws.com	GetUserPoolMfaConfig	OK
      6 198.18.7.1	cognito-idp.amazonaws.com	InitiateAuth	OK
      6 198.18.7.1	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      3 198.18.7.1	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      2 198.18.7.1	cognito-idp.amazonaws.com	SignUp	OK
      1 198.18.7.1	cognito-idp.amazonaws.com	ConfirmSignUp	OK
      9 198.18.7.2	cognito-idp.amazonaws.com	InitiateAuth	OK
      5 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      4 198.18.7.2	cognito-idp.amazonaws.com	RespondToAuthChallenge	NotAuthorizedException
      4 198.18.7.2	cognito-idp.amazonaws.com	SignUp	InvalidPasswordException
      2 198.18.7.2	cognito-idp.amazonaws.com	ConfirmSignUp	OK
      2 198.18.7.2	cognito-idp.amazonaws.com	SignUp	OK
      2 2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPool	OK
      2 2001:db8:0:18::1	cognito-idp.amazonaws.com	DescribeUserPoolClient	OK
      2 2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPoolReplicas	OK
      1 2001:db8:0:18::1	cognito-identity.amazonaws.com	ListIdentityPools	OK
      1 2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPoolClients	OK
      1 2001:db8:0:18::1	cognito-idp.amazonaws.com	ListUserPools	OK
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	InitiateAuth	OK
      2 2001:db8:0:b::2	cognito-idp.amazonaws.com	SignUp	OK
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	ConfirmSignUp	OK
      1 2001:db8:0:b::2	cognito-idp.amazonaws.com	RespondToAuthChallenge	OK
      1 resource-explorer-2.amazonaws.com	cognito-identity.amazonaws.com	ListIdentityPools	OK
```

실행한 명령:
```
jq -r '.Records[] | select(.eventSource=="signin.amazonaws.com") | [.eventTime, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress, (.errorCode // "-"), (.responseElements | tostring), (.additionalEventData | tostring)] | @tsv' cloudtrail.json | sort
```
결과:
```
2026-10-11T04:31:12Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null	null
2026-10-11T04:34:18Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T04:34:18Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T04:37:56Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T04:38:29Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null	null
2026-10-11T04:44:22Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T04:52:19Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null	null
2026-10-11T04:52:29Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T04:52:34Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null	null
2026-10-11T04:54:22Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:04:24Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:04:24Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:06:14Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
2026-10-11T05:08:37Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
2026-10-11T05:09:54Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T05:16:48Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:17:51Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
2026-10-11T05:21:13Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T05:27:01Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:31:48Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T05:31:58Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
2026-10-11T05:37:02Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:37:02Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:41:49Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null	null
2026-10-11T05:47:04Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:52:02Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
2026-10-11T05:57:15Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null	null
2026-10-11T05:57:32Z	CreateOAuth2Token	IAMUser	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-	null	null
```

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# 최종 사고 보고서: AWS 계정 침해 의심 건 (2026-10-11)

## 1. 한 줄 요약

공격자가 **PatchSignal 포털에 직접 회원가입해 로그인**했습니다. 이어서 **포털 EC2 인스턴스의 AWS 역할 자격 증명을 빼냈고**, 이를 외부에서 써서 **Step Functions 워크플로를 9번 실행**했습니다. 서버 원격 접속(SSM) 시도는 모두 거부됐습니다.

공격자가 빼낸 자격 증명과 가입한 포털 계정이 **아직 유효할 가능성이 높습니다.** 차단 조치가 가장 급합니다.

## 2. 판단 수준 구분

| 구분 | 내용 |
|---|---|
| **확정** (로그로 직접 확인) | 외부 IP 3곳에서 Cognito 가입·인증 성공, 포털 역할 자격 증명의 외부 사용, Step Functions 9회 실행, SSM 접속 4회 거부 |
| **추정** (근거는 있으나 직접 증거 없음) | 포털 앱의 취약점(SSRF 등)을 통한 자격 증명 탈취, 루트 활동은 자동화 도구 실행 |
| **미확인** (자료 없음) | 탈취에 쓰인 앱 기능, Step Functions 실행 내용, IAM 변경 여부(백도어 사용자·키), 다른 리전 활동, 루트를 쓴 사람 |

## 3. 무슨 일이 있었나

### 공격 경로

```
① 포털 셀프 회원가입 (비밀번호 정책을 시행착오로 파악)
        ↓
② 이메일 인증 → 포털 로그인 성공
        ↓
③ 포털 앱 기능 악용 (CloudTrail에 안 보임, 앱 로그 필요)
        ↓
④ 포털 EC2 역할 자격 증명 탈취 (세션 키 ASIA…95CF)
        ↓
⑤ 외부(198.18.7.1, 198.18.50.1)에서 자격 증명 사용
   ├─ Step Functions StartExecution 9회 → 성공
   └─ SSM StartSession·SendCommand 4회 → 모두 거부
```

### 타임라인

| KST (UTC) | 출발지 | 내용 | 결과 |
|---|---|---|---|
| 13:37–13:40 (04:37) | 7.1 | 포털 `SignUp` 8회. 비밀번호 정책에 6회 걸리다가 2회 성공 | 가입 성공 |
| 13:41 (04:41:32) | 7.1 | `ConfirmSignUp`(이메일 인증) | 성공 |
| 13:42 (04:42:14) | 7.1 | 로그인(`InitiateAuth` → `RespondToAuthChallenge`) | **로그인 성공** |
| 13:43 (04:43:47) | 7.2 | 2초 사이 로그인 4회, 모두 비밀번호 틀림 | 실패 (다른 계정 대입 시도로 보임) |
| 13:48–13:50 (04:48) | 7.2 | 새 계정 가입·인증·로그인 | **로그인 성공** |
| 14:09 (05:09:58) | 7.2 | S3 버킷 `pagesnap-final-s1-results-…` 조회 시도 | 거부 |
| 14:16 (05:16) | 2001:db8:0:b::2 | 가입·인증·로그인 | 성공 (공격자인지 미확인) |
| 14:28 (05:28) | 7.2 | 계정 하나 더 가입·인증·로그인 | 성공 |
| 14:45 (05:45) | 7.1 | 로그인 2회 실패 후 성공 | 성공 |
| 14:46–15:36 | — | **CloudTrail 공백**. 이 사이에 앱을 공격한 것으로 추정 | — |
| **15:36 (06:36:22)** | **7.1** | **탈취한 포털 역할로 `StartExecution`** | **성공** |
| 15:39 (06:39) | 50.1 | 같은 키로 SSM `StartSession` | 거부 |
| 15:40–15:41 | 7.1 | 실행 이름 `case-redteam-validation-002`, `-003` | 성공 |
| 15:52–16:08 | 50.1 | `StartExecution` 3회 | 성공 |
| 16:02 (07:02) | 7.1 | SSM `StartSession` | 거부 |
| 16:03–16:05 | 7.1 | 실행 이름 `test-run-1791702223` 등 3회 | 성공 |
| 16:11–16:12 (07:11) | 7.1 | SSM `SendCommand` 2회 | 거부 |
| 16:10, 16:18 | blue-team-1 | GuardDuty 설정 변경. Runtime Monitoring을 켠 것으로 보임 | — |
| 16:25 (07:25) | — | 로그 끝 | — |

### 핵심 근거

**자격 증명 탈취 (확정)**
- 포털 인스턴스 자신은 키 5개(`…0AE1`, `…2435`, `…35DA`, `…4DE2`, `…2E7A`)를 `198.18.10.1`과 사설 IP `10.81.0.102`에서 썼습니다.
- **`ASIA…95CF` 키는 인스턴스에서 한 번도 쓰이지 않았고, 외부 IP 두 곳(7.1, 50.1)에서만 13번 쓰였습니다.**
- 세션 이름이 인스턴스 ID(`i-05816900800807b77`)인 역할 자격 증명은 EC2가 그 인스턴스에만 발급합니다. 따라서 인스턴스에서 빼낸 것으로 볼 수밖에 없습니다.
- 7.1은 포털 가입·로그인을 한 바로 그 IP입니다. 같은 주체로 볼 근거가 됩니다.

**자동화 도구 사용 (확정)**
- 실행 이름 `test-run-1791702223`의 숫자는 유닉스 시각 2026-10-11 07:03:43 UTC입니다. 실제 호출 시각(07:03:46)과 3초 차이라서, 스크립트가 이름을 만든 것입니다.
- 정상 실행은 `case-<무작위 ID>` 형식입니다. 공격자는 `case-redteam-…`처럼 정상과 비슷한 이름을 붙였습니다. 연습의 레드팀으로 보입니다.
- 탈취 키로는 정찰 호출(`GetCallerIdentity` 등)이 한 번도 없었습니다. 처음부터 무엇을 호출할지 알고 있었다는 뜻입니다.

## 4. 지난 분석 정정

| 지난 판단 | 정정 |
|---|---|
| 공격자의 Cognito 가입은 모두 실패 | **틀렸습니다.** 지난번에는 오류 기록만 봐서 성공 건을 놓쳤습니다. 가입 6회 성공, 인증 4회, 로그인 여러 번 성공입니다. |
| 05:30~05:33 `ModifyInstanceAttribute`가 메타데이터(IMDS) 설정이었을 수 있음 | **틀렸습니다.** IMDS 설정 변경은 `ModifyInstanceMetadataOptions`라는 별도 이벤트입니다. 따라서 포털 인스턴스에 IMDSv2가 적용됐는지는 **모릅니다.** |
| `user/AWSAccount`는 백도어 IAM 사용자일 수 있음 | **실제 사용자가 아닐 가능성이 높습니다.** 같은 파일의 다른 IAM 사용자 기록에는 계정 ID와 액세스 키 ID가 다 있는데, 이 기록에만 둘 다 없습니다. 원본 CloudTrail에서 익명 요청이나 다른 계정의 요청은 `type: AWSAccount`로 남습니다. 이 파일을 만드는 과정에서 그것이 사용자 이름처럼 바뀐 것으로 보입니다. 즉, 공격자가 **인증 없이(또는 자기 계정으로) PageSnap 버킷을 조회하다 거부된 것**으로 판단합니다. 그래도 콘솔이 복구되면 IAM 사용자 목록은 한 번 확인하세요. |
| 루트가 장기 액세스 키로 자동화 도구를 돌림 | 키가 `ASIA…`(임시 세션)입니다. 콘솔이나 CloudShell 로그인 세션에서 나온 자격 증명입니다. 아래 7절에서 다시 다룹니다. |

## 5. 피해 범위

| 항목 | 판단 |
|---|---|
| Step Functions | **9회 실행됨.** 무엇을 하는 워크플로인지, 공격자 입력으로 무엇이 일어났는지는 미확인입니다. **가장 먼저 확인할 피해 항목입니다.** |
| 서버 장악 (SSM 원격 접속·명령) | 시도 4회 모두 거부됐습니다. 이 경로로는 장악되지 않았습니다. |
| PageSnap S3 결과 버킷 | 조회 1회 거부. 데이터 유출 흔적은 없습니다. |
| Cognito Identity Pool로 AWS 권한 획득 | 공격자 쪽 `GetId`, `GetCredentialsForIdentity` 기록이 없습니다. 흔적 없음. |
| IAM 변경, 다른 리전 활동 | **판단 불가.** 이 파일에 IAM 기록이 하나도 없고 ap-northeast-2 기록만 있습니다. |
| 포털 앱 데이터 | **판단 불가.** 공격자는 로그인한 사용자였으므로 앱 안에서 무엇을 봤는지는 앱 로그로만 알 수 있습니다. |

## 6. 고쳐야 할 것

본인은 지금 콘솔과 CLI를 쓸 수 없으니, **권한 있는 팀원이나 운영자**에게 전달하세요. 연습 환경이라면 운영 규칙이 허용하는 범위인지 먼저 확인하세요. **삭제하지 말고 비활성화까지만** 하세요.

### A. 즉시 차단 (순서대로)

**1. 포털 인스턴스 IMDSv2 강제**
```bash
aws ec2 modify-instance-metadata-options --instance-id i-05816900800807b77 \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled
```
가장 흔한 탈취 경로인 SSRF를 막습니다. 2번보다 먼저 해야 다시 털리지 않습니다.

**2. 포털 역할 세션 취소**
IAM → 역할 → `patchsignal-ewc2enb8-portal-role` → "활성 세션 취소". 탈취한 키 `ASIA…95CF`는 마지막 사용(16:12) 이후에도 몇 시간 유효할 수 있습니다. 실행 직후 포털이 잠시 오류를 낼 수 있으니 필요하면 앱을 재시작하세요.

**3. 공격자 Cognito 계정 비활성화와 강제 로그아웃**
로그에는 팀이 이 계정들을 막은 기록(`AdminDisableUser` 등)이 없습니다. 아래 시각에 생성된 사용자를 찾으세요. 가입 요청 시각이라 계정 생성 시각과 몇 초 차이가 날 수 있습니다.

| 생성 시각 (UTC) | 출발지 | 비고 |
|---|---|---|
| 04:39:48, 04:40:26 | 198.18.7.1 | 인증 완료 1건 |
| 04:48:29, 05:28:39 | 198.18.7.2 | 둘 다 인증 완료 |
| 05:16:40, 05:17:08 | 2001:db8:0:b::2 | 정상 사용자일 수 있으니 확인 후 조치 |

각 계정에 `AdminDisableUser`와 `AdminUserGlobalSignOut`을 실행하세요. 미인증(UNCONFIRMED) 계정도 함께 정리하세요.

**4. 셀프 회원가입 일시 중단**
운영상 가능하면 사용자 풀을 "관리자만 사용자 생성" 모드로 바꾸세요. 공격의 출발점이 셀프 가입이었습니다.

**5. 공격자 Step Functions 실행 확인**
아래 실행을 찾아 입력, 출력, 이력을 확인하고, 아직 돌고 있으면 중지하세요.
- 이름으로 찾기: `case-redteam-validation-001`~`003`, `test-run-1791702223`, `test-run-1791702300`, `test-run-1791702344`
- 시각으로 찾기: 06:36:22, 06:52:08, 07:02:17, 07:08:11 UTC (이름이 기록되지 않은 실행)

실행 결과로 데이터가 바뀌었거나 외부로 무언가 전송됐다면 그것이 실제 피해입니다.

### B. 원인 제거: 포털 앱 (백엔드 개발자로서 직접 보실 부분)

자격 증명이 새어 나간 지점은 **로그인한 사용자가 쓸 수 있는 포털 기능**일 가능성이 높습니다. 공격자는 로그인 후 약 50분(14:46~15:36) 뒤에 탈취한 키를 쓰기 시작했습니다.

**코드에서 찾을 것**
- 사용자가 준 URL이나 호스트로 서버가 요청을 보내는 기능: 피드·웹훅 등록, 링크 미리보기, 파일·이미지 가져오기, "연결 테스트" 버튼 등
- 사용자 입력이 파일 경로나 셸 명령, 템플릿에 들어가는 곳: 파일 읽기(`/proc/self/environ`, `~/.aws/`), 명령 실행 취약점
- 오류 메시지나 디버그 응답에 외부 응답 내용이 그대로 노출되는 곳

**고치는 방법 (SSRF 기준)**
- 허용 목록(allowlist)에 있는 도메인으로만 요청하게 하세요. 차단 목록 방식은 우회가 쉽습니다.
- DNS를 해석한 **뒤의 IP**를 검사해서 `169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fd00::/8`을 막으세요. 검사한 IP로 그대로 연결해야 DNS 재바인딩을 막을 수 있습니다.
- 리다이렉트 자동 추적을 끄세요.
- 외부 응답 본문을 사용자에게 그대로 돌려주지 마세요.

**로그 확인**
포털 앱 로그나 ALB 접근 로그를 구할 수 있게 되면, 14:39~15:36 KST 사이 7.1·7.2·IPv6 출발지 요청에서 `169.254.169.254`, `meta-data`, `security-credentials`, `../`를 찾아보세요. 블루팀이 15:09와 15:26 무렵 포털 인스턴스에 SSM으로 접속한 기록이 있으니, 그 팀원이 인스턴스 안 로그를 이미 봤을 수도 있습니다.

### C. 재발 방지

**포털 역할 권한 축소**
- `states:StartExecution`은 포털이 실제로 쓰는 상태 머신 ARN 하나로만 제한하세요.
- `lambda:GetFunction`: 포털이 18번 호출했습니다. 이 권한으로 Lambda 코드와 환경 변수(비밀값)를 받을 수 있습니다. 꼭 필요하지 않으면 빼세요.
- `ssm:StartSession`, `ssm:SendCommand`: 지금처럼 계속 막아 두세요. 이번에 이것이 피해를 막았습니다.
- 더 나아가면, EC2 역할 자격 증명을 VPC 밖에서 쓰지 못하게 막는 조건(`aws:EC2InstanceSourceVPC`)을 쓸 수 있습니다. 다만 VPC 엔드포인트 구성이 필요하니 운영 측과 상의하세요.

**Cognito**
- 위협 보호(Threat Protection, 구 Advanced Security)를 켜세요. 팀원의 `AdminListUserAuthEvents` 호출이 "기능 꺼짐" 오류로 실패했습니다. 이 기능이 켜져 있으면 사용자별 로그인 이력과 위험 로그인 차단을 쓸 수 있습니다.
- 셀프 가입이 꼭 필요하면 Pre sign-up Lambda로 이메일 도메인을 제한하거나 관리자 승인을 넣으세요.

**계정 운영**
- 루트 계정은 평소에 쓰지 말고, MFA를 켜고, 루트 액세스 키를 두지 마세요.
- `blue-team-1`을 10곳 가까운 IP에서 여러 사람이 같이 쓰고 있습니다. 사람마다 사용자나 역할을 나누세요. 그래야 사고 때 팀원 작업과 공격자 작업을 구분할 수 있습니다.

**로깅**
- CloudTrail을 **모든 리전**으로 기록하고, 원본 그대로 보관하세요. 이번 파일은 리전, userAgent, 요청 내용 같은 필드가 빠져 있어서 조사가 막혔습니다.
- Step Functions 실행 로깅, ALB 접근 로그, 앱 로그를 켜고 보관하세요.
- GuardDuty에서 `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` 탐지가 있는지 확인하세요. 이번 같은 "인스턴스 자격 증명 외부 사용"을 잡는 탐지입니다. Runtime Monitoring은 16:18에야 켜진 것으로 보여서, 이번 건의 런타임 탐지는 없을 수 있습니다.

## 7. 남은 미확인 사항 (운영자·팀에 전달)

**루트 계정 활동**
- 13:42과 13:48에 같은 임시 세션 키로 거의 똑같은 조회 약 70건이 반복됐고, 각각 API Gateway `UpdateStage`로 끝났습니다.
- 공개 AMI 파라미터 조회 등 호출 구성이 Terraform 같은 인프라 도구의 패턴과 같습니다. 그래서 공격보다는 운영 측 자동화나 시나리오 설정일 가능성이 높습니다.
- 다만 **같은 세션 키가 6분 사이 IP 5곳에서 쓰였다**는 점은 포털 역할 탈취 때와 같은 모양입니다. 로그만으로는 둘을 구분할 수 없습니다.
- 운영 측에 확인할 것: 누가 루트로 무엇을 실행했는지, 스테이지 설정(접근 로그, 요청 제한, 스테이지 변수)을 무엇으로 바꿨는지. 정체가 확인되지 않으면 루트 비밀번호를 바꾸고 MFA를 확인하세요.

**팀원 작업 내용 확인**
- 보안 그룹 개방 5건: 어떤 포트를 어디에 열었는지
- `ModifyInstanceAttribute` 4건
- `PutEventSelectors`(CloudTrail 기록 범위 변경): 기록을 줄이지 않았는지

**그 밖의 미확인 사항**
- **PageSnap**: 공격자가 이 서비스의 결과 버킷을 노렸습니다. 우리 팀 소관인지, 버킷의 공개 차단 설정이 켜져 있는지 확인하세요.
- **IAM 변경과 다른 리전 활동**: us-east-1 등 전체 리전 CloudTrail을 받기 전까지는 "백도어 없음"이라고 말할 수 없습니다.
- **본인이 콘솔에 접속하지 못하는 이유**: 이번 공격과의 관련 여부를 판단할 자료가 없습니다. 운영자에게 확인하세요.

## 8. 보고용 요약 (그대로 전달하셔도 됩니다)

> 2026-10-11 13:39 KST부터 외부 출발지(198.18.7.1, 198.18.7.2, 198.18.50.1)가 PatchSignal 포털에 셀프 가입해 로그인했다. 이후 포털 EC2 인스턴스(i-05816900800807b77)의 IAM 역할 자격 증명을 탈취해 15:36~16:12 KST 외부에서 사용했다. 그 결과 Step Functions 실행 9건이 성공했고, SSM 원격 접속·명령 시도 4건은 권한 부족으로 거부됐다. 탈취 경로는 포털 앱 취약점(SSRF 등)으로 추정되나 앱 로그가 없어 미확정이다. 즉시 조치로 IMDSv2 강제, 역할 세션 취소, 공격자 Cognito 계정 비활성화, 셀프 가입 중단, 공격자 실행 건 검토가 필요하다. IAM 변경과 다른 리전 활동은 해당 로그가 없어 판단하지 못했다.

이번 분석은 받은 파일(ap-northeast-2, 13:30~16:25 KST, 일부 필드 누락) 범위 안에서의 결론입니다. 앱 로그나 전체 리전 CloudTrail을 나중에 구하시면 이어서 확정해 드리겠습니다.

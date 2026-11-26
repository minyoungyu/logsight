## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

# AWS 계정 침해 의심 대응 가이드

보안 전문가가 아니어도 순서대로 따라 하시면 됩니다. 로그를 보내 주시면 같이 분석해 드릴게요.

---

## 0단계: 먼저 확인할 것

**연락이 진짜인지 확인하세요.** "계정이 공격받았다"는 메일이나 전화 자체가 피싱일 수 있습니다.
- 받은 메일의 링크로 로그인하지 말고, 브라우저에 직접 `console.aws.amazon.com`을 입력해 접속하세요.
- AWS가 보낸 연락이라면 콘솔 우측 상단 종 모양 아이콘(**AWS Health Dashboard**)이나 **Support Center**에 같은 내용의 케이스가 있을 겁니다.

**누구에게 연락받았는지** 알려 주세요. AWS, 사내 보안팀, 외부 제보 중 어디인지에 따라 대응이 달라집니다.

---

## 1단계: 지금 바로 할 일 (피해 확산 차단)

> ⚠️ **삭제하지 말고 "비활성화"만 하세요.** 지우면 나중에 원인을 추적할 증거가 사라집니다.

1. **루트 계정 비밀번호 변경 + MFA 확인**
   - 루트 계정에 MFA가 없다면 지금 바로 설정하세요.

2. **수상한 Access Key 비활성화**
   - IAM → Users → 각 사용자 → Security credentials
   - 모르는 키나 최근 생성된 키는 **Deactivate** 하세요.
   - 코드, GitHub, `.env`에 들어 있던 키는 유출됐다고 가정하는 게 안전합니다. 서비스 영향을 확인한 뒤 교체하세요.

3. **모르는 IAM 사용자·역할 확인**
   - 본인이 만들지 않은 사용자가 있으면 콘솔 로그인과 키를 비활성화하세요. 계정 자체는 삭제하지 마세요.

4. **모든 리전에서 EC2 확인**
   - 공격자는 평소 안 쓰는 리전(예: 상파울루, 뭄바이)에 고사양 인스턴스를 띄워 채굴하는 경우가 많습니다.
   - 아래 3단계의 명령어로 한 번에 확인할 수 있습니다.

5. **Billing 확인**
   - Billing → Bills / Cost Explorer에서 오늘 비용이 급증했는지 보세요.

---

## 2단계: 로그 뽑기 전 꼭 알아야 할 점

### ⏰ 시간대 주의
CloudTrail은 **UTC 기준**입니다.
- **한국 시간 13:30 = UTC 04:30**
- 연락받은 시점이 침입 시점이라는 보장은 없습니다. **최소 전날부터** 넉넉하게 뽑는 걸 권장합니다.

### 🌏 리전 주의
- CloudTrail Event History는 **리전별로** 따로 저장됩니다.
- IAM, 콘솔 로그인 같은 글로벌 이벤트는 주로 **us-east-1**에 기록됩니다.

---

## 3단계: 로그 추출 명령어

AWS CLI가 설정된 환경에서 실행하세요. 날짜는 실제 날짜로 바꿔 주세요.

### ① CloudTrail 이벤트 (가장 중요)
```bash
START="2025-01-14T00:00:00Z"   # 전날부터 넉넉하게

for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $region =="
  aws cloudtrail lookup-events \
    --region "$region" \
    --start-time "$START" \
    --max-results 1000 \
    --output json > "cloudtrail_${region}.json"
done
```

### ② IAM 자격증명 보고서 (누가 언제 키·비번을 썼는지)
```bash
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > credential_report.csv
```

### ③ 모든 리전의 실행 중인 EC2
```bash
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $region =="
  aws ec2 describe-instances --region "$region" \
    --query "Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,State.Name,KeyName]" \
    --output table
done
```

### ④ GuardDuty가 켜져 있다면
```bash
DETECTOR=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)
aws guardduty list-findings --detector-id "$DETECTOR"
```

---

## 4단계: 로그에서 주의 깊게 볼 이벤트

로그가 너무 길면 아래 이벤트만 걸러서 보내 주셔도 됩니다.

| 분류 | 이벤트 이름 | 의미 |
|---|---|---|
| **흔적 지우기** | `StopLogging`, `DeleteTrail`, `DisableDetector` | 🚨 매우 위험 신호 |
| **권한 확보** | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, `CreateRole`, `UpdateAssumeRolePolicy` | 백도어 계정 생성 |
| **로그인** | `ConsoleLogin` (특히 실패 후 성공, 낯선 IP) | 콘솔 침입 |
| **자원 남용** | `RunInstances`, `CreateKeyPair`, `ImportKeyPair`, `AuthorizeSecurityGroupIngress` | 채굴 등 |
| **데이터 접근** | `GetSecretValue`, `PutBucketPolicy`, `DeletePublicAccessBlock`, `GetParameter` | 정보 유출 가능성 |

필터링 예시:
```bash
jq '.Events[] | select(.EventName | test("CreateUser|CreateAccessKey|AttachUserPolicy|StopLogging|DeleteTrail|RunInstances|ConsoleLogin|GetSecretValue"))
    | {EventTime, EventName, Username, src: (.CloudTrailEvent|fromjson|.sourceIPAddress)}' cloudtrail_*.json
```

---

## 5단계: 로그를 보내 주실 때

- **Secret Access Key, 비밀번호, DB 접속정보**가 섞여 있지 않은지 확인하세요. CloudTrail에는 보통 Secret Key가 남지 않지만, 요청 파라미터에 민감 정보가 들어가 있을 수 있습니다.
- Access Key ID(`AKIA...`)와 IP는 분석에 필요하니 그대로 두셔도 됩니다. 부담되면 일부만 가리세요.

---

## 함께 진행할 것

- **AWS Support에 케이스 열기**: 무료 Basic 플랜에서도 "Account and billing" 카테고리로 침해 신고가 가능합니다. 부당 청구 감면을 받을 때도 도움이 됩니다.
- **사내 보고**: 팀장이나 보안 담당자에게 알리세요. **개인정보가 유출됐을 가능성**이 있으면 법적 신고 기한(인지 후 72시간)이 있으니 빨리 공유하셔야 합니다.

---

## 알려 주시면 더 정확히 도와드릴 수 있는 정보

1. 누구에게 어떤 내용으로 연락받았나요?
2. 개인 계정인가요, 회사(Organizations) 계정인가요?
3. 평소 사용하는 리전은 어디인가요? (예: 서울 `ap-northeast-2`)
4. 코드나 GitHub에 Access Key를 넣은 적이 있나요?
5. CloudTrail Trail(S3 저장)이나 GuardDuty를 따로 켜 두셨나요?

1단계 조치를 먼저 하시고, 로그와 함께 위 답변을 보내 주세요. 같이 하나씩 보겠습니다.

## 사용자

네, 말씀하신 것 중 이 파일들로 뽑을 수 있는 건 뽑아서 보내 드려요. 먼저 상황부터 말씀드릴게요.

- 지금 AWS 콘솔이나 CLI에 들어갈 수가 없어요. 그래서 1단계 조치(루트 비밀번호 변경, 키 비활성화, 사용자 확인, Billing 확인)는 **하지 못했어요**. 보내 주신 aws CLI 명령도 직접 실행하지 못했고요.
- 대신 미리 내려받아 둔 로그 파일 3개가 있어서, 거기서 같은 내용을 뽑았어요.
  - `cloudtrail.json` (CloudTrail 기록)
  - `waf.jsonl` (WAF 로그)
  - `alb.log` (ALB 접근 로그)
- 시각은 모두 UTC예요(한국 시간은 +9시간).

---

## ① CloudTrail 이벤트

- 날짜가 다릅니다. 예시에 있던 2025-01-14가 아니라 **2026-10-11**이고, 범위는 04:30:01Z ~ 07:25:01Z(한국 시간 13:30~16:25)예요.
- 파일은 ap-northeast-2(서울) 것 하나뿐이에요. 다른 리전이나 전날 로그는 확인 못 해요. 그 로그는 없어요.
- 전체 10,223건이라 너무 길어서 앞 20건만 붙여요. 아래는 잘린 결과예요.
- 기록에 들어 있는 항목은 eventName, eventSource, eventTime, sourceIPAddress, userIdentity예요(일부 기록은 requestParameters도 있어요). awsRegion 항목은 없어요.

뽑은 방법: `jq -c '.Records[0:20][]' cloudtrail.json`
```
{"eventTime":"2026-10-11T04:30:01Z","eventSource":"cloudshell.amazonaws.com","eventName":"GetEnvironmentStatus","sourceIPAddress":"198.18.0.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAAD7…EDF9"}}
{"eventTime":"2026-10-11T04:30:02Z","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"198.18.1.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA5EE3…EA4B"}}
{"eventTime":"2026-10-11T04:30:02Z","eventSource":"cloudshell.amazonaws.com","eventName":"PutCredentials","sourceIPAddress":"198.18.0.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAAD7…EDF9"}}
{"eventTime":"2026-10-11T04:30:02Z","eventSource":"ssm.amazonaws.com","eventName":"GetCommandInvocation","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:02Z","eventSource":"resource-explorer-2.amazonaws.com","eventName":"Search","sourceIPAddress":"198.18.3.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAAF1…E2BB"}}
{"eventTime":"2026-10-11T04:30:02Z","eventSource":"resource-explorer-2.amazonaws.com","eventName":"Search","sourceIPAddress":"198.18.3.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAAF1…E2BB"}}
{"eventTime":"2026-10-11T04:30:03Z","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"198.18.4.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"}}
{"eventTime":"2026-10-11T04:30:03Z","eventSource":"ssm.amazonaws.com","eventName":"GetCommandInvocation","sourceIPAddress":"198.18.5.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAE40A…C93B"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:05Z","eventSource":"ssm.amazonaws.com","eventName":"GetCommandInvocation","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:05Z","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"198.18.4.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"}}
{"eventTime":"2026-10-11T04:30:07Z","eventSource":"ssm.amazonaws.com","eventName":"ListInstanceAssociations","sourceIPAddress":"198.18.6.1","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049","accessKeyId":"ASIA791B…2A7A"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:08Z","eventSource":"ssm.amazonaws.com","eventName":"GetCommandInvocation","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:09Z","eventSource":"logs.amazonaws.com","eventName":"FilterLogEvents","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"}}
{"eventTime":"2026-10-11T04:30:11Z","eventSource":"lambda.amazonaws.com","eventName":"GetFunction20150331v2","sourceIPAddress":"198.18.5.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAED23…BD85"},"requestParameters":{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-feed-connector"}}
{"eventTime":"2026-10-11T04:30:11Z","eventSource":"ssm.amazonaws.com","eventName":"GetCommandInvocation","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"},"requestParameters":{"instanceId":"i-026754fe07a870049"}}
{"eventTime":"2026-10-11T04:30:12Z","eventSource":"logs.amazonaws.com","eventName":"FilterLogEvents","sourceIPAddress":"198.18.6.1","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049","accessKeyId":"ASIAFB04…3F63"}}
{"eventTime":"2026-10-11T04:30:12Z","eventSource":"logs.amazonaws.com","eventName":"FilterLogEvents","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"}}
{"eventTime":"2026-10-11T04:30:13Z","eventSource":"logs.amazonaws.com","eventName":"CreateLogStream","sourceIPAddress":"delivery.logs.amazonaws.com","userIdentity":{"type":"AWSService","invokedBy":"delivery.logs.amazonaws.com"}}
{"eventTime":"2026-10-11T04:30:14Z","eventSource":"logs.amazonaws.com","eventName":"FilterLogEvents","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8E46…2438"}}
{"eventTime":"2026-10-11T04:30:14Z","eventSource":"logs.amazonaws.com","eventName":"DescribeLogStreams","sourceIPAddress":"198.18.3.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA46D3…78D5"}}
```

## 4단계 표의 이벤트만 걸러낸 결과 (11건, 전부)

- 걸러낸 이벤트: 표에 있는 19개 이벤트 이름 전부(jq 예시에 있던 8개만이 아니에요).
- 뽑은 방법: 파일 구조가 `.Events[]`가 아니라 `.Records[]`라서 이 구조에 맞춰 바꿨어요. Username은 userIdentity의 userName이 없으면 arn으로 대신 넣었어요.

```
jq -c '.Records[] | select(.eventName | test("^(StopLogging|DeleteTrail|DisableDetector|CreateUser|CreateAccessKey|CreateLoginProfile|AttachUserPolicy|PutUserPolicy|CreateRole|UpdateAssumeRolePolicy|ConsoleLogin|RunInstances|CreateKeyPair|ImportKeyPair|AuthorizeSecurityGroupIngress|GetSecretValue|PutBucketPolicy|DeletePublicAccessBlock|GetParameter)$")) | {eventTime, eventName, user:(.userIdentity.userName // .userIdentity.arn // .userIdentity.type), src:.sourceIPAddress}' cloudtrail.json
```
```
{"eventTime":"2026-10-11T04:39:33Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:iam::111122223333:user/blue-team-1","src":"198.18.2.1"}
{"eventTime":"2026-10-11T04:42:50Z","eventName":"GetParameter","user":"arn:aws:iam::111122223333:root","src":"198.18.0.3"}
{"eventTime":"2026-10-11T04:48:42Z","eventName":"GetParameter","user":"arn:aws:iam::111122223333:root","src":"198.18.18.1"}
{"eventTime":"2026-10-11T05:09:28Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:iam::111122223333:user/blue-team-1","src":"198.18.2.1"}
{"eventTime":"2026-10-11T05:09:29Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:iam::111122223333:user/blue-team-1","src":"198.18.2.1"}
{"eventTime":"2026-10-11T05:27:36Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:iam::111122223333:user/blue-team-1","src":"198.18.2.1"}
{"eventTime":"2026-10-11T05:27:37Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:iam::111122223333:user/blue-team-1","src":"198.18.2.1"}
{"eventTime":"2026-10-11T05:32:13Z","eventName":"GetParameter","user":"arn:aws:iam::111122223333:user/blue-team-2","src":"198.18.23.1"}
{"eventTime":"2026-10-11T05:57:21Z","eventName":"GetParameter","user":"arn:aws:iam::111122223333:user/blue-team-2","src":"198.18.23.1"}
{"eventTime":"2026-10-11T05:57:54Z","eventName":"GetParameter","user":"arn:aws:iam::111122223333:user/blue-team-2","src":"198.18.23.1"}
{"eventTime":"2026-10-11T07:18:34Z","eventName":"AuthorizeSecurityGroupIngress","user":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","src":"guardduty.amazonaws.com"}
```

## ②, ③, ④는 확인하지 못했어요

- ② IAM 자격증명 보고서: 확인 못 해요. 그 로그는 없어요.
- ③ 전체 리전의 EC2 목록: 확인 못 해요. 인스턴스 설정 정보가 없어요.
- ④ GuardDuty 탐지 결과: 확인 못 해요. 그 로그는 없어요.

---

## 질문에 대한 답

1. **누구에게 어떤 내용으로 연락받았나요?** "공격받았을 수 있다"는 연락이었다는 것만 알아요. 누가 어떤 경로로 보냈는지는 몰라요.
   - 참고로 이 계정은 **보안 공방전(연습) 환경**이에요.
   - blue-team-1, blue-team-2는 우리 팀원 계정이에요. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했어요.
   - PatchSignal은 원래 있던 우리 서비스예요.
2. **개인 계정인가요, Organizations 계정인가요?** 몰라요.
3. **평소 쓰는 리전은?** 제가 가진 CloudTrail 파일은 ap-northeast-2(서울) 것이에요. 평소에 어디를 쓰는지까지는 몰라요.
4. **코드나 GitHub에 Access Key를 넣은 적이 있나요?** 몰라요.
5. **Trail이나 GuardDuty를 따로 켜 두었나요?** 몰라요.

WAF 로그(`waf.jsonl`)와 ALB 로그(`alb.log`)도 있으니 필요하시면 뽑을 내용을 말씀해 주세요.

## 채팅 AI

# 1차 분석 결과

결론부터 말씀드리면, **아직 공격을 확정할 근거는 없지만 반드시 확인해야 할 신호가 하나 있습니다.** 바로 **루트 계정이 사용된 기록**입니다. 그리고 지금 가진 로그만으로는 확인할 수 없는 부분이 많아서, 그 한계도 함께 정리했습니다.

---

## 🚨 가장 중요한 발견: 루트 계정 사용

```
04:42:50Z  GetParameter  root  198.18.0.3
04:48:42Z  GetParameter  root  198.18.18.1
```

- 루트 계정은 원래 **거의 쓰지 않는** 계정입니다. 일상 작업은 IAM 사용자(blue-team-1, 2)로 합니다.
- 6분 사이에 **서로 다른 IP 두 곳**에서 루트가 쓰였습니다.
- `GetParameter`는 SSM Parameter Store에서 값을 읽는 동작입니다. 여기에는 DB 비밀번호, API 키 같은 **비밀값**이 저장되는 경우가 많습니다.

**팀원 중 누군가 루트로 로그인해서 작업했는지 꼭 확인해 주세요.** 아무도 쓰지 않았다면 **루트 계정 탈취**를 강하게 의심해야 하는 상황입니다. 콘솔과 CLI에 들어갈 수 없게 된 것도 이 때문일 수 있습니다. 공격자가 루트 비밀번호나 MFA를 바꾸면 그런 일이 생깁니다.

---

## 나머지 이벤트에 대한 판단

| 이벤트 | 판단 | 이유 |
|---|---|---|
| blue-team-1의 `AuthorizeSecurityGroupIngress` 5건 | 🟡 확인 필요 | 평소 활동과 같은 IP(198.18.2.1)라서 팀원의 대응 작업으로 보입니다. 다만 **무엇을 열었는지**가 중요합니다. 팀원이 했더라도 `0.0.0.0/0`에 22번이나 3389번 포트를 열었다면 그 자체로 위험합니다. |
| blue-team-2의 `GetParameter` 3건 | 🟢 대응 작업 가능성 높음 | 어떤 파라미터를 읽었는지만 확인하면 됩니다. |
| GuardDuty 서비스 역할의 `AuthorizeSecurityGroupIngress` (07:18) | 🟢 정상 | GuardDuty Runtime Monitoring이 자체 VPC 엔드포인트용 보안 그룹(443 포트)을 만들 때 생기는 기록입니다. **GuardDuty가 켜져 있다는 뜻**이기도 하니(질문 5의 부분 답), 접근 권한이 있는 팀원에게 GuardDuty Findings 확인을 부탁해 보세요. |
| `ec2-ssmrole`(인스턴스 i-026754fe07a870049)이 `FilterLogEvents` 호출 | 🟡 약간 특이 | 인스턴스 역할이 CloudWatch 로그를 **조회**하는 건 흔하지 않습니다. 팀원이 SSM으로 그 인스턴스에서 명령을 실행 중이었으니 그 결과일 수도 있지만, 인스턴스 자격증명이 악용됐을 가능성도 따져봐야 합니다. 팀이 이 인스턴스를 집중 조사하고 있는 걸 보면, 이 인스턴스가 피해 지점일 가능성이 있습니다. |

---

## ⚠️ 지금 로그로는 판단할 수 없는 것 (중요)

필터 결과에 `CreateUser`, `ConsoleLogin` 등이 **없다고 해서 그런 일이 없었다는 뜻은 아닙니다.**

1. **IAM·콘솔 로그인 기록은 보통 us-east-1에 남습니다.** 서울 리전 파일에는 처음부터 없을 가능성이 큽니다. 루트가 API를 썼는데 `ConsoleLogin`이 안 보이는 것도 이 때문으로 보입니다.
2. **로그가 04:30:01부터 시작하는데, 그때 이미 팀원이 대응 중입니다.** 즉 침입은 그 **전**에 일어났을 수 있고, 그 구간은 이 파일에 없습니다.
3. **다른 리전 활동이 보이지 않습니다.** 첫 20건 안에도 `us-west-1`의 Lambda 함수(`patchsignal-...-feed-connector`)가 있습니다. PatchSignal 서비스가 us-west-1에서도 돌아간다는 뜻이니, 그쪽 로그도 필요합니다.
   - 덧붙이면, Lambda 호출은 보통 해당 리전에 기록되기 때문에 이 파일이 정말 서울 리전만 담고 있는지는 약간 불확실합니다(awsRegion 항목이 없어서 확인할 수 없음).
4. **IP로 위치를 판단할 수 없습니다.** `198.18.x.x`는 테스트용 예약 대역이라 실제 위치를 알 수 없습니다. IP끼리 **같은지 다른지** 비교하는 용도로만 쓸 수 있습니다.

---

## 지금 해야 할 일 (접속 문제부터)

본인은 접속할 수 없지만 **blue-team-1, 2는 접속이 되는 것으로 보입니다.** 그분들께 부탁하세요.

1. **루트 사용 여부 확인**: 팀 내 누가 루트를 썼는지 먼저 물어보세요.
2. **아무도 안 썼다면 즉시**:
   - 루트 비밀번호 재설정과 MFA 재설정. 접근할 수 없으면 AWS Support의 계정 복구 절차를 진행합니다.
   - 루트에 Access Key가 있다면 비활성화합니다.
   - 루트가 읽은 SSM 파라미터에 든 비밀값(DB 비밀번호, API 키 등)을 **교체**합니다.
3. **연습 환경 운영 측에 연락**: 공방전 환경이라면 운영팀(화이트팀)이 있을 겁니다. **본인 계정이 막힌 게 공격 때문인지, 운영 정책 때문인지** 확인하고, us-east-1·us-west-1 로그와 04:30 이전 로그를 요청하세요.

---

## 다음에 뽑아 주실 것

### CloudTrail (`cloudtrail.json`)

**① 루트 계정 활동 전부** (가장 중요)
```bash
jq -c '.Records[] | select(.userIdentity.type=="Root" or ((.userIdentity.arn // "") | endswith(":root")))' cloudtrail.json
```

**② 위 11건의 상세 내용** (무엇을 열었고, 무엇을 읽었는지)
```bash
jq -c '.Records[] | select(.eventName=="AuthorizeSecurityGroupIngress" or .eventName=="GetParameter")' cloudtrail.json
```

**③ 누가 어떤 IP에서 몇 번 활동했는지** (모르는 주체를 찾는 용도)
```bash
jq -r '.Records[] | [(.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type), .sourceIPAddress] | @tsv' cloudtrail.json \
  | sort | uniq -c | sort -rn
```

**④ 조회가 아닌 "변경" 작업 요약** (10,223건 중 실제로 뭔가 바꾼 것)
```bash
jq -r '.Records[] | select(.eventName | test("^(Get|List|Describe|Search|Filter|Lookup|BatchGet)") | not)
  | [.eventName, (.userIdentity.arn // .userIdentity.invokedBy // .userIdentity.type)] | @tsv' cloudtrail.json \
  | sort | uniq -c | sort -rn
```

**⑤ 인스턴스 역할(ec2-ssmrole)의 활동 요약**
```bash
jq -r '.Records[] | select((.userIdentity.arn // "") | contains("ec2-ssmrole")) | [.eventSource, .eventName, .sourceIPAddress] | @tsv' cloudtrail.json \
  | sort | uniq -c | sort -rn
```

### WAF / ALB 로그

형식이 환경마다 조금씩 달라서, **먼저 첫 두 줄씩만** 보여 주세요.
```bash
head -n 2 waf.jsonl
head -n 2 alb.log
```

표준 형식이라면 아래 명령도 바로 쓸 수 있습니다. 결과가 이상하면 위의 두 줄만 보내 주세요.
```bash
# WAF: 차단/허용별 상위 IP, 차단 규칙 순위
jq -r '[.action, .httpRequest.clientIp] | @tsv' waf.jsonl | sort | uniq -c | sort -rn | head -30
jq -r 'select(.action=="BLOCK") | .terminatingRuleId' waf.jsonl | sort | uniq -c | sort -rn

# ALB: 상위 접속 IP, 응답 코드 분포, 많이 요청된 경로
awk '{split($4,a,":"); print a[1]}' alb.log | sort | uniq -c | sort -rn | head -30
awk '{print $9}' alb.log | sort | uniq -c | sort -rn
awk '{print $14}' alb.log | sed 's/?.*//' | sort | uniq -c | sort -rn | head -50

# 루트가 쓴 IP가 웹 쪽에도 나타나는지
grep -E '198\.18\.0\.3[^0-9]|198\.18\.18\.1[^0-9]' waf.jsonl alb.log | head -20
```

---

## 팀에 확인할 질문

1. **루트 계정을 쓴 사람이 있나요?** (이게 제일 중요합니다)
2. 인스턴스 `i-026754fe07a870049`는 어떤 서버이고, 팀이 왜 이 인스턴스를 조사 중인가요?
3. 본인 계정이 막힌 정확한 증상은 뭔가요? (비밀번호 오류, MFA 오류, "권한 없음" 등)

①번 결과와 1번 질문의 답만 먼저 주셔도 상황이 훨씬 분명해집니다.

## 사용자

요청하신 것 모두 뽑았어요. 결과는 손대지 않고 그대로 붙였어요.

## 팀에 확인할 질문에 대한 답

1. **루트 계정을 쓴 사람이 있나요?** 몰라요. 저는 그 정보를 갖고 있지 않아요.
2. **인스턴스 `i-026754fe07a870049`는 어떤 서버이고, 팀은 왜 조사 중인가요?** 몰라요.
3. **본인 계정이 막힌 정확한 증상은?** 몰라요.
   - 지금 콘솔과 CLI에 접속할 수 없어서 로그 파일만 갖고 있다는 뜻이었어요. 계정이 막혔다는 뜻은 아니었어요.
   - blue-team-1, 2가 지금 접속되는지도 저는 몰라요.

---

## ① 루트 계정 활동 전부 (153건)

보내 주신 명령 그대로 실행했어요. 한 번에 나오는 출력 길이에 제한이 있어서 `| sed -n '시작,끝p'`로 나눠 뽑은 뒤 순서대로 이어 붙였어요. 줄은 빠지지 않았어요.

```
jq -c '.Records[] | select(.userIdentity.type=="Root" or ((.userIdentity.arn // "") | endswith(":root")))' cloudtrail.json
```
```
{"eventTime":"2026-10-11T04:42:48Z","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:48Z","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeTargetGroupAttributes","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"dynamodb.amazonaws.com","eventName":"DescribeTable","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"dynamodb.amazonaws.com","eventName":"ListTagsOfResource","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"apigateway.amazonaws.com","eventName":"GetApi","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeAddressesAttribute","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeManagedPrefixLists","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"dynamodb.amazonaws.com","eventName":"DescribeTable","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"logs.amazonaws.com","eventName":"DescribeLogGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeAddresses","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"logs.amazonaws.com","eventName":"ListTagsForResource","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"dynamodb.amazonaws.com","eventName":"DescribeTimeToLive","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"dynamodb.amazonaws.com","eventName":"DescribeContinuousBackups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeTargetGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"GetManagedPrefixListEntries","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeTags","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"logs.amazonaws.com","eventName":"DescribeLogGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroups","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:49Z","eventSource":"logs.amazonaws.com","eventName":"ListTagsForResource","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeAddresses","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeLoadBalancerAttributes","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.14.1","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeVpcEndpoints","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"apigateway.amazonaws.com","eventName":"GetStage","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"},"requestParameters":{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeCapacityReservation","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroupRules","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"apigateway.amazonaws.com","eventName":"GetApi","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"elasticloadbalancing.amazonaws.com","eventName":"DescribeLoadBalancers","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeNetworkInterfaces","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ec2.amazonaws.com","eventName":"DescribePrefixLists","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:42:51Z","eventSource":"ec2.amazonaws.com","

## 채팅 AI

# 받은 부분까지의 분석 (루트 활동 39/153건)

먼저 알려 드릴 것이 있습니다. **메시지가 중간에 잘렸습니다.** ① 루트 활동 153건 중 **39번째 줄(04:42:51Z) 중간까지만** 도착했고, ②~⑤ 결과와 WAF/ALB 로그는 받지 못했습니다. 아래 분석은 받은 39건만으로 한 것입니다.

---

## 1. 이전 답변 정정

**① "루트가 비밀값을 읽었다"는 우려는 근거가 약해졌습니다.**

루트가 읽은 파라미터는 이것이었습니다.
```
/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
```
이것은 **AWS가 공개로 제공하는 "최신 Amazon Linux AMI ID" 조회용 파라미터**입니다. 비밀값이 아니고 누구나 읽을 수 있습니다. Terraform이나 CloudFormation으로 EC2를 만들 때 흔히 읽는 값입니다.

**② "계정이 막힌 게 공격 때문일 수 있다"는 추측은 철회합니다.**
접속할 수 없는 것이 계정 차단 때문이 아니라는 설명을 듣고 보니, 그 추측은 근거가 없었습니다.

---

## 2. 받은 39건에서 보이는 것

| 관찰 | 해석 |
|---|---|
| 04:42:48~51, **약 3초 사이에 39건** | 사람이 콘솔에서 클릭한 속도가 아닙니다. **도구가 자동으로 연속 호출**한 패턴입니다. |
| 조회 대상: ELB, 보안 그룹, DynamoDB, API Gateway, CloudWatch Logs, VPC 엔드포인트, EIP | 한 서비스(PatchSignal로 추정)를 구성하는 자원을 **골고루 한꺼번에 조회**하고 있습니다. |
| `GetCallerIdentity`로 시작해서 AMI 파라미터 조회 | **Terraform `plan`/`refresh`의 전형적인 모습**과 일치합니다. |
| 전부 `Describe`/`Get`/`List` (읽기 전용) | 받은 범위 안에서는 **변경 작업이 없습니다.** |
| 액세스 키가 `ASIA...` (임시 자격증명) | 루트의 콘솔 세션, CloudShell, 또는 `GetSessionToken`으로 받은 임시 키입니다. 장기 키(`AKIA...`)는 아닙니다. |
| 같은 키(`ASIAFA49...`)가 같은 초에 `198.18.0.3`과 `198.18.14.1` 두 IP에서 사용됨 | 실제 환경이라면 의심할 만한 신호입니다. 다만 이 로그에서는 blue-team-1도 한 세션에서 여러 IP(198.18.2.1, 3.1, 4.1…)가 섞여 나오므로, **연습 환경이 IP를 합성한 결과**일 가능성이 있습니다. 판단은 보류하겠습니다. |

**현재 판단:** 받은 39건은 **공격자의 정찰이라기보다 IaC 도구(Terraform 등)가 루트 자격증명으로 실행된 모습**에 더 가깝습니다. 연습 환경을 구성하는 쪽(운영팀)이나 팀원이 돌렸을 수 있습니다.

다만 이것만으로 안심할 수는 없습니다.
- 루트로 IaC를 돌리는 것 자체가 보안상 나쁜 습관입니다.
- **나머지 114건에 변경 작업(생성, 수정, 삭제)이 있는지**가 핵심인데, 아직 보지 못했습니다.

---

## 3. 다음에 뽑아 주실 것 (출력이 짧게 나오도록 요약형으로)

153건을 다시 통째로 보내실 필요는 없습니다. 아래 명령은 결과가 짧게 나옵니다.

**A. 루트의 "변경" 작업만 (가장 중요)**
```bash
jq -c '.Records[] | select(.userIdentity.type=="Root")
  | select(.eventName | test("^(Get|List|Describe|Search|Filter|Lookup|BatchGet|Head)") | not)' cloudtrail.json
```
→ 결과가 **0건이면** 루트는 조회만 했다는 뜻이고, 상황이 많이 가벼워집니다.

**B. 루트 활동 요약 (서비스별, 이벤트별 횟수)**
```bash
jq -r '.Records[] | select(.userIdentity.type=="Root") | "\(.eventSource) \(.eventName)"' cloudtrail.json \
  | sort | uniq -c | sort -rn
```

**C. 루트가 쓴 키, IP, 시간 범위**
```bash
jq -r '.Records[] | select(.userIdentity.type=="Root") | [.userIdentity.accessKeyId, .sourceIPAddress, .eventTime] | @tsv' cloudtrail.json \
  | sort -k1,1 -k2,2 -k3,3 \
  | awk -F'\t' '{k=$1"\t"$2; if(!(k in f)) f[k]=$3; l[k]=$3; c[k]++} END{for(k in c) print c[k]"\t"k"\t"f[k]" ~ "l[k]}' | sort -rn
```
→ 04:42와 04:48 두 묶음이 **같은 키인지**, 그 사이와 이후에 무엇이 있었는지 확인합니다.

**D. 지난번 요청 중 받지 못한 것**
- ② `AuthorizeSecurityGroupIngress` / `GetParameter` 상세 (11건)
- ③ 주체별, IP별 활동 횟수
- ④ 변경 작업 요약
- ⑤ ec2-ssmrole 활동 요약
- WAF / ALB `head -n 2`

길면 **A → ② → ④ 순서로** 먼저 보내 주세요. 이 셋만 있어도 "실제로 무언가 바뀌었는가"를 판단할 수 있습니다.

---

## 4. 팀이나 운영 측에 물어볼 것 (하나만)

> **"04:42 UTC(한국 시간 13:42)쯤 루트 계정으로 Terraform(또는 다른 IaC 도구)을 실행한 사람이 있나요?"**

"그렇다"는 답이 나오면 루트 관련 의심은 대부분 풀립니다. 아무도 모른다면 A 결과를 보고 루트 자격증명 교체를 운영 측에 요청해야 합니다.

## 사용자

요청하신 것을 뽑았어요. 지난번처럼 메시지가 잘릴 수 있어서 말씀하신 우선순위대로 A → ② → ④를 먼저 보내고, 짧은 결과는 그 사이에 넣었어요. **④는 길어서 맨 끝에 뒀어요.** 끝이 잘려서 도착하면 말씀해 주세요. 나눠서 다시 보낼게요.

③(주체별·IP별 활동 횟수, 126줄)과 WAF/ALB 표준 명령 결과는 이미 뽑아 뒀어요. 길이 때문에 다음 메시지로 보낼게요.

## 4번 질문에 대한 답

**"04:42 UTC쯤 루트 계정으로 Terraform 등을 실행한 사람이 있나요?"** 몰라요. 저는 그 정보를 갖고 있지 않아요.

정정할 것도 하나 있어요. 제가 지난번에 말한 건 "지금 저는 콘솔과 CLI에 접속할 수 없어서 로그 파일만 가지고 있다"는 뜻이었어요. **왜 접속이 안 되는지는 몰라요.**

---

## A. 루트의 "변경" 작업만 (6건)

보내 주신 명령 그대로 실행했어요.
```
{"eventTime":"2026-10-11T04:42:52Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","sourceIPAddress":"lambda.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIA3982…9AC2"}}
{"eventTime":"2026-10-11T04:42:52Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","sourceIPAddress":"lambda.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIA3982…9AC2"}}
{"eventTime":"2026-10-11T04:43:00Z","eventSource":"apigateway.amazonaws.com","eventName":"UpdateStage","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
{"eventTime":"2026-10-11T04:48:44Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","sourceIPAddress":"lambda.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIA0C40…D406"}}
{"eventTime":"2026-10-11T04:48:44Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","sourceIPAddress":"lambda.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIA5117…8689"}}
{"eventTime":"2026-10-11T04:48:52Z","eventSource":"apigateway.amazonaws.com","eventName":"UpdateStage","sourceIPAddress":"198.18.18.1","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"}}
```

## ② AuthorizeSecurityGroupIngress / GetParameter 상세 (11건)

지난번 명령 그대로 실행했어요.
```
{"eventTime":"2026-10-11T04:39:33Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAA35E…DE4A"}}
{"eventTime":"2026-10-11T04:42:50Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.0.3","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"},"requestParameters":{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}
{"eventTime":"2026-10-11T04:48:42Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.18.1","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root","accountId":"111122223333","accessKeyId":"ASIAFA49…29C2"},"requestParameters":{"name":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}
{"eventTime":"2026-10-11T05:09:28Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:09:29Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:27:36Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"},"errorCode":"Client.DryRunOperation"}
{"eventTime":"2026-10-11T05:27:37Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"}}
{"eventTime":"2026-10-11T05:32:13Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.23.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-2","accessKeyId":"ASIAD175…1196"},"requestParameters":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"eventTime":"2026-10-11T05:57:21Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.23.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-2","accessKeyId":"ASIA241B…E78E"},"requestParameters":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"eventTime":"2026-10-11T05:57:54Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameter","sourceIPAddress":"198.18.23.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-2","accessKeyId":"ASIAA809…AE75"},"requestParameters":{"name":"/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/x86_64/standard/recommended"}}
{"eventTime":"2026-10-11T07:18:34Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"guardduty.amazonaws.com","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","accessKeyId":"ASIA3CF9…09AC"}}
```

## C. 루트가 쓴 키, IP, 시간 범위

보내 주신 명령 그대로 실행했어요.
```
73	ASIAFA49…29C2	198.18.18.1	2026-10-11T04:48:40Z ~ 2026-10-11T04:48:52Z
72	ASIAFA49…29C2	198.18.0.3	2026-10-11T04:42:48Z ~ 2026-10-11T04:43:00Z
2	ASIAFA49…29C2	198.18.14.1	2026-10-11T04:42:50Z ~ 2026-10-11T04:42:59Z
2	ASIA3982…9AC2	lambda.amazonaws.com	2026-10-11T04:42:52Z ~ 2026-10-11T04:42:52Z
1	ASIAFA49…29C2	198.18.18.2	2026-10-11T04:48:51Z ~ 2026-10-11T04:48:51Z
1	ASIAFA49…29C2	198.18.15.1	2026-10-11T04:45:23Z ~ 2026-10-11T04:45:23Z
1	ASIA5117…8689	lambda.amazonaws.com	2026-10-11T04:48:44Z ~ 2026-10-11T04:48:44Z
1	ASIA0C40…D406	lambda.amazonaws.com	2026-10-11T04:48:44Z ~ 2026-10-11T04:48:44Z
```

## B. 루트 활동 요약

보내 주신 명령 그대로 실행했어요.
```
     12 ec2.amazonaws.com DescribeSecurityGroupRules
      9 apigateway.amazonaws.com GetApi
      8 elasticloadbalancing.amazonaws.com DescribeTags
      8 ec2.amazonaws.com DescribeInstanceAttribute
      6 sts.amazonaws.com GetCallerIdentity
      6 ec2.amazonaws.com DescribeSecurityGroups
      6 ec2.amazonaws.com DescribeNetworkInterfaces
      4 logs.amazonaws.com ListTagsForResource
      4 logs.amazonaws.com DescribeLogGroups
      4 lambda.amazonaws.com ListVersionsByFunction20150331
      4 lambda.amazonaws.com GetFunctionCodeSigningConfig
      4 lambda.amazonaws.com GetFunction20150331v2
      4 kms.amazonaws.com Decrypt
      4 ec2.amazonaws.com DescribeAddresses
      4 dynamodb.amazonaws.com DescribeTable
      4 apigateway.amazonaws.com GetStage
      2 states.amazonaws.com ListTagsForResource
      2 states.amazonaws.com ListStateMachineVersions
      2 states.amazonaws.com DescribeStateMachine
      2 ssm.amazonaws.com GetParameter
      2 lambda.amazonaws.com GetPolicy20150331v2
      2 elasticloadbalancing.amazonaws.com DescribeTargetHealth
      2 elasticloadbalancing.amazonaws.com DescribeTargetGroups
      2 elasticloadbalancing.amazonaws.com DescribeTargetGroupAttributes
      2 elasticloadbalancing.amazonaws.com DescribeRules
      2 elasticloadbalancing.amazonaws.com DescribeLoadBalancers
      2 elasticloadbalancing.amazonaws.com DescribeLoadBalancerAttributes
      2 elasticloadbalancing.amazonaws.com DescribeListeners
      2 elasticloadbalancing.amazonaws.com DescribeListenerAttributes
      2 elasticloadbalancing.amazonaws.com DescribeCapacityReservation
      2 ec2.amazonaws.com GetManagedPrefixListEntries
      2 ec2.amazonaws.com DescribeVpcs
      2 ec2.amazonaws.com DescribeVpcEndpoints
      2 ec2.amazonaws.com DescribeVolumes
      2 ec2.amazonaws.com DescribeTags
      2 ec2.amazonaws.com DescribePrefixLists
      2 ec2.amazonaws.com DescribeManagedPrefixLists
      2 ec2.amazonaws.com DescribeInstances
      2 ec2.amazonaws.com DescribeInstanceTypes
      2 ec2.amazonaws.com DescribeInstanceCreditSpecifications
      2 ec2.amazonaws.com DescribeAddressesAttribute
      2 dynamodb.amazonaws.com ListTagsOfResource
      2 dynamodb.amazonaws.com DescribeTimeToLive
      2 dynamodb.amazonaws.com DescribeContinuousBackups
      2 apigateway.amazonaws.com UpdateStage
      2 apigateway.amazonaws.com GetRoute
      2 apigateway.amazonaws.com GetIntegration
```

## ⑤ ec2-ssmrole 활동 요약

지난번 명령 그대로 실행했어요.
```
   2256 logs.amazonaws.com	FilterLogEvents	198.18.6.1
    725 logs.amazonaws.com	GetLogEvents	198.18.6.1
    146 logs.amazonaws.com	DescribeLogStreams	198.18.6.1
     41 ssm.amazonaws.com	UpdateInstanceInformation	198.18.6.1
     18 ssm.amazonaws.com	CreateDataChannel	198.18.6.1
     10 ssm.amazonaws.com	ListInstanceAssociations	198.18.6.1
      8 sts.amazonaws.com	GetCallerIdentity	198.18.6.1
      2 ssm.amazonaws.com	StartSession	198.18.6.1
      1 ssm.amazonaws.com	PutConfigurePackageResult	198.18.6.1
```

## WAF / ALB 첫 두 줄

`head -n 2` 그대로 실행했어요. 파일 길이는 waf.jsonl 432줄, alb.log 122줄이에요.
```
{"timestamp": 1791693014000, "action": "ALLOW", "webaclId": "arn:aws:wafv2:us-west-1:111122223333:regional/webacl/midnight/x", "terminatingRuleId": "Default_Action", "httpRequest": {"clientIp": "198.18.7.1", "httpMethod": "GET", "uri": "/", "args": "", "headers": []}}
{"timestamp": 1791693014000, "action": "ALLOW", "webaclId": "arn:aws:wafv2:us-west-1:111122223333:regional/webacl/midnight/x", "terminatingRuleId": "Default_Action", "httpRequest": {"clientIp": "198.18.7.1", "httpMethod": "GET", "uri": "/app.js", "args": "", "headers": []}}
----
https 2026-10-11T04:42:19Z app/pagesnap-api/x 198.18.7.1:0 - 0 0 0 200 200 0 12 "GET https://pagesnap:443/api/jobs HTTP/1.1" "-"
https 2026-10-11T04:42:27Z app/pagesnap-api/x 198.18.7.1:0 - 0 0 0 200 200 0 12 "GET https://pagesnap:443/api/jobs HTTP/1.1" "-"
```

## ④ 조회가 아닌 "변경" 작업 요약 (96줄, 전부)

지난번 명령 그대로 실행했어요.
```
    262 SendCommand	arn:aws:iam::111122223333:user/blue-team-1
    103 CreateLogStream	delivery.logs.amazonaws.com
     91 StartQuery	arn:aws:iam::111122223333:user/blue-team-1
     85 StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77
     63 CheckCapacity	arn:aws:iam::111122223333:user/blue-team-1
     60 AssumeRole	eks-nodegroup.amazonaws.com
     56 AssumeRole	config.amazonaws.com
     55 AssumeRole	eks.amazonaws.com
     46 OpenDataChannel	Unknown
     41 UpdateInstanceInformation	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77
     41 UpdateInstanceInformation	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049
     36 AdminGetUser	arn:aws:iam::111122223333:user/blue-team-1
     33 Decrypt	arn:aws:iam::111122223333:user/blue-team-1
     31 AccessKubernetesApi	arn:aws:iam::111122223333:user/blue-team-2
     28 CreateOAuth2Token	arn:aws:iam::111122223333:user/blue-team-1
     27 DeleteSession	arn:aws:iam::111122223333:user/blue-team-1
     27 AssumeRole	lambda.amazonaws.com
     26 AssumeRole	states.amazonaws.com
     24 CreateNetworkInterfacePermission	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS
     24 CreateNetworkInterface	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS
     21 CreateSession	arn:aws:iam::111122223333:user/blue-team-1
     20 DeleteNetworkInterface	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1
     18 PutCredentials	arn:aws:iam::111122223333:user/blue-team-1
     18 CreateDataChannel	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049
     18 AssumeRole	resource-explorer-2.amazonaws.com
     17 InitiateAuth	Unknown
     16 SignUp	Unknown
     16 RespondToAuthChallenge	Unknown
     16 Decrypt	arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer
     15 AdminListGroupsForUser	arn:aws:iam::111122223333:user/blue-team-1
     13 ResumeSession	arn:aws:iam::111122223333:user/blue-team-2
     13 CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api
     13 CreateLogStream	arn:aws:sts

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI

# 최종 보고서: AWS 계정 침해 의심 건 (2026-10-11)

**분석 대상:** CloudTrail 파일 1개(04:30:01Z~07:25:01Z, 10,223건), WAF·ALB 로그(첫 두 줄만 확인)
**시각 표기:** UTC (한국 시간 = UTC + 9시간)

---

## 1. 요약

**받은 로그만으로는 공격을 확정할 수도, 배제할 수도 없습니다.**

- **확인된 것:** 이 파일에는 공격자가 흔히 남기는 이벤트가 없습니다. 로그 끄기, 사용자·액세스 키 생성, 권한 부여, 인스턴스 생성 같은 기록이 보이지 않습니다.
- **풀리지 않은 의문 네 가지:**
  1. 루트 계정 세션이 **API Gateway 설정을 두 번 변경**했고, **Lambda 환경변수(비밀값이 들어 있을 수 있음)를 복호화해 읽었습니다.** 누가 했는지 모릅니다.
  2. Cognito에 **익명 회원가입(SignUp) 16건**이 있습니다.
  3. PatchSignal 포털 서버의 역할이 **Step Functions를 85번 실행**했습니다. 정상 동작인지 모릅니다.
  4. blue-team-1이 **보안 그룹에 무엇을 열었는지** 모릅니다.
- **분석의 한계가 큽니다.** 로그는 대응이 이미 시작된 뒤인 04:30부터 시작합니다. 그 전에 침입이 있었다면 이 파일에는 없습니다.

---

## 2. 타임라인

| 시각 (UTC) | 주체 | 내용 | 판단 |
|---|---|---|---|
| 04:30:01 | blue-team-1 | 로그 시작. 이미 CloudShell, SSM, 로그 조회로 조사 중 | 대응 작업 |
| 04:39:33 | blue-team-1 | 보안 그룹 인바운드 규칙 추가 | 내용 확인 필요 |
| 04:42:48~04:43:00 | **루트** (키 `ASIAFA49…`) | 72건 자동 연속 조회 → Lambda 환경변수 복호화 2건 → **API Gateway `UpdateStage`** | 확인 필요 |
| 04:45:23 | 루트 (같은 키) | 단발 1건 | – |
| 04:48:40~04:48:52 | **루트** (같은 키) | 첫 번째와 거의 같은 패턴 73건 → 복호화 2건 → **`UpdateStage`** | 확인 필요 |
| 05:09:28~29 | blue-team-1 | 보안 그룹 규칙 추가 2건 | 내용 확인 필요 |
| 05:27:36~37 | blue-team-1 | DryRun으로 권한 확인 후 실제 추가 | 내용 확인 필요 |
| 05:32~05:57 | blue-team-2 | EKS 노드용 공개 AMI 파라미터 조회 | 정상 (EKS 작업) |
| 07:18:34 | GuardDuty 서비스 역할 | Runtime Monitoring용 보안 그룹 생성 | 정상 |
| 07:25:01 | – | 로그 끝 | – |

Cognito 가입 16건과 포털의 Step Functions 실행 85건은 시각을 뽑지 않아 표에 넣지 못했습니다.

---

## 3. 주요 발견과 판단

### 🔴 발견 1: 루트 세션이 설정을 바꾸고 비밀값을 읽었음

**관찰한 내용**
- 임시 키(`ASIA…`) 하나로 약 6분 간격을 두고 **같은 패턴의 묶음이 두 번** 실행됐습니다. 각 묶음은 약 12초 동안 70여 건입니다.
- 두 묶음 모두 `GetCallerIdentity`로 시작해 여러 서비스(EC2, ELB, DynamoDB, Lambda, Step Functions, API Gateway, Logs)를 조회한 뒤 `UpdateStage`로 끝납니다.
- 조회 대상은 공개 AMI 파라미터뿐이었습니다. Parameter Store의 비밀값은 읽지 않았습니다.
- `kms Decrypt` 4건(호출 경로는 `lambda.amazonaws.com`)과 `GetFunction` 4건은 횟수가 정확히 같습니다. **`GetFunction`을 호출하면 Lambda가 호출자 권한으로 환경변수를 복호화해 돌려주기 때문**입니다. 즉 루트 세션은 Lambda 함수 2개의 **환경변수 평문**을 받았습니다.

**해석**
- 이 패턴은 **Terraform 같은 IaC 도구로 `apply`를 두 번 실행한 모습**과 가장 잘 맞습니다. 매번 `UpdateStage`가 나오는 것은 Terraform에서 흔한 "적용할 때마다 생기는 차이" 현상일 수 있습니다.
- 그렇다면 운영팀이나 팀원이 한 정상 작업일 가능성이 있습니다. 하지만 **누가 했는지 확인하기 전까지는 판단할 수 없습니다.**
- 공격자였다면 우려되는 점은 두 가지입니다.
  - 환경변수에 든 비밀값(API 키, DB 비밀번호 등)이 유출됐을 수 있습니다.
  - `UpdateStage`로 **API Gateway 접근 로그를 끄거나 스테이지 변수를 바꿨을** 수 있습니다.
- 같은 키가 여러 IP에서 쓰인 점은 판단 근거로 쓰지 않았습니다. blue-team 계정에서도 같은 현상이 보여, 연습 환경이 IP를 합성한 결과일 가능성이 있기 때문입니다.

### 🟡 발견 2: Cognito 익명 회원가입 16건

**관찰한 내용**
- 로그인하지 않은 주체(`Unknown`)가 `SignUp` 16건, `InitiateAuth` 17건, `RespondToAuthChallenge` 16건을 호출했습니다.
- blue-team-1이 `AdminGetUser` 36건, `AdminListGroupsForUser` 15건으로 **Cognito 사용자를 조사**했습니다.

**해석**
- 팀이 Cognito 쪽을 의심하고 있었다는 뜻입니다.
- 관리자만 계정을 만들어야 하는 서비스에서 셀프 가입이 열려 있으면, 공격자가 직접 가입해 토큰을 받을 수 있습니다.
- 앱 클라이언트가 `custom:role` 같은 속성을 사용자가 쓸 수 있게 허용하면 **권한 상승**으로 이어집니다. 이는 실제로 자주 쓰이는 공격 방식입니다.
- 다만 이 로그만으로는 가입이 악의적이었는지 판단할 수 없습니다.

### 🟡 발견 3: 포털 서버 역할의 Step Functions 실행 85건

**관찰한 내용**
- `patchsignal-ewc2enb8-portal-role`(인스턴스 `i-05816900800807b77`)이 `StartExecution`을 85번 호출했습니다.

**해석**
- 서비스의 정상 동작일 수 있습니다.
- 다만 웹 서버가 뚫리면 공격자는 **그 서버의 역할 권한**으로 AWS API를 호출합니다. 평소 실행 횟수와 비교해 봐야 합니다.

### 🟡 발견 4: blue-team-1의 보안 그룹 변경 4건 (DryRun 제외)

- 팀원의 대응 작업으로 보입니다.
- 그러나 로그에 상세 내용(포트, CIDR)이 없습니다. 대응 중에 `0.0.0.0/0`으로 22번이나 3389번 포트를 열어 두는 실수가 흔하므로 확인이 필요합니다.

### 🟢 정상 또는 대응 작업으로 판단한 것

| 항목 | 판단 근거 |
|---|---|
| `ec2-ssmrole`(`i-026754fe07a870049`)의 로그 조회 3,000여 건 | blue-team-1이 이 인스턴스로 `SendCommand`를 262번 보냈습니다. **팀의 분석용 서버**에서 명령을 실행한 결과로 보입니다. (이 서버의 용도는 확인 권장) |
| 루트·blue-team-2의 `GetParameter` | 모두 AWS 공개 AMI 파라미터입니다. 비밀값이 아닙니다. |
| EKS 관련 `AssumeRole`, 네트워크 인터페이스 생성·삭제 | EKS 서비스와 노드의 일반 동작입니다. |
| `pagesnap-final-s1-renderer-role`의 `Decrypt` | Lambda가 자기 환경변수를 읽는 일반 동작입니다. |
| GuardDuty의 보안 그룹 생성 | Runtime Monitoring의 일반 동작입니다. GuardDuty가 켜져 있다는 뜻이기도 합니다. |

---

## 4. 이 분석이 다루지 못한 범위

결론의 신뢰도를 판단할 때 꼭 함께 봐 주세요.

1. **04:30 이전 기록이 없습니다.** 로그 시작 시점에 이미 대응이 진행 중이었으므로, 침입은 그 전에 일어났을 수 있습니다.
2. **IAM과 콘솔 로그인 기록이 없을 수 있습니다.** 이런 기록은 보통 us-east-1에 남습니다. 루트가 어떻게 로그인했는지도 이 때문에 확인할 수 없습니다.
3. **리전이 확실하지 않습니다.** 파일은 서울 리전 것이라고 했지만, WAF(`midnight`)와 Lambda는 **us-west-1**에 있습니다. 서비스 대부분이 us-west-1에 있을 가능성이 높고, 그쪽 로그가 완전한지 알 수 없습니다.
4. **상세 내용이 빠져 있습니다.** `UpdateStage`, `AuthorizeSecurityGroupIngress`, `GetFunction`의 요청 파라미터가 없어서 **무엇이 바뀌었고 어떤 함수였는지** 모릅니다.
5. **받지 못한

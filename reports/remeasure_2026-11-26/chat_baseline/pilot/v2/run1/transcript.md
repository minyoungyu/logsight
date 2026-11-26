## 사용자

오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. 저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. 로그는 제가 뽑아 드릴 수 있어요.

## 채팅 AI

# AWS 계정 침해 의심 대응 가이드

보안 전문가가 아니어도 순서대로 따라 하실 수 있게 정리했습니다. 로그를 보내주시면 무슨 일이 있었는지 함께 분석하겠습니다.

---

## 0단계: 연락의 출처부터 확인하세요 (2분)

- **누구에게서 연락이 왔나요?** AWS(지원 케이스/이메일), GuardDuty 알림, 사내 다른 팀, 외부인 중 어디인가요?
- 이메일이라면 **본문 링크를 누르지 말고** AWS 콘솔에 직접 로그인하세요. 그다음 **Support Center → 케이스**와 **Health Dashboard**에 같은 알림이 있는지 확인하세요. "계정이 공격받았다"는 메일 자체가 피싱인 경우도 흔합니다.

---

## 1단계: 지금 바로 할 일 (피해 확산 차단)

> ⚠️ **원칙: 지우지 말고 막으세요.** 리소스나 키를 삭제하면 원인을 추적할 증거가 사라집니다.

1. **상사 또는 보안 담당자에게 즉시 알리세요.** 혼자 처리할 일이 아닙니다. 개인정보 유출 가능성이 있으면 법적 신고 의무가 생길 수도 있습니다.
2. **루트 계정 비밀번호를 변경하고 MFA가 켜져 있는지 확인하세요.**
3. **결제 대시보드(Billing)를 확인하세요.** 비용이 갑자기 늘었다면 평소 안 쓰는 리전에서 암호화폐 채굴용 EC2가 돌고 있을 가능성이 큽니다. 가장 흔한 공격 유형입니다.
4. **의심스러운 액세스 키는 "삭제"가 아니라 "비활성화(Inactive)"하세요.**
   - 단, 운영 서비스가 쓰는 키라면 서비스가 멈출 수 있습니다. 어떤 키가 문제인지는 로그를 본 뒤 판단하는 게 안전합니다.
5. **수상한 EC2는 terminate하지 말고 stop하세요.** 가능하면 스냅샷부터 떠 두세요.
6. **AWS Support에 케이스를 여세요.** 침해 대응을 도와주고, 채굴 비용 같은 경우 청구 조정을 받을 수도 있습니다.

---

## 2단계: 로그 추출

> 🕐 **시간대 주의:** AWS 로그는 **UTC** 기준입니다. 한국시간 13:30은 **UTC 04:30**입니다.
> 실제 최초 침입은 알림보다 앞설 수 있으니, **최소 하루 전부터** 뽑는 걸 권장합니다.

CLI를 쓸 때는 **유출이 의심되지 않는 자격 증명**(가능하면 새로 만든 것)을 사용하세요.

### (1) CloudTrail – 누가 어떤 API를 호출했는지 (가장 중요)

CloudTrail 이벤트 기록은 **리전별**로 저장되므로 모든 리전을 돌아야 합니다.

```bash
START="2025-01-14T00:00:00Z"   # 날짜는 실제에 맞게 수정하세요 (하루 전부터 권장)
mkdir -p ct_logs
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "== $r =="
  aws cloudtrail lookup-events --region "$r" \
    --start-time "$START" \
    --output json > "ct_logs/$r.json"
done
```

- IAM, 콘솔 로그인 같은 글로벌 이벤트는 주로 `us-east-1.json`에 들어 있습니다.
- 조직에 별도의 CloudTrail Trail(S3 저장)이 있다면, 그쪽 로그가 더 완전합니다.

### (2) IAM 자격 증명 보고서 – 계정 사용자와 키 현황

```bash
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > credential_report.csv
```

### (3) GuardDuty 탐지 결과 (켜져 있다면)

```bash
DET=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)
aws guardduty list-findings --detector-id "$DET" --output json > gd_ids.json
aws guardduty get-findings --detector-id "$DET" \
  --finding-ids $(jq -r '.FindingIds[]' gd_ids.json | head -50) > gd_findings.json
```

GuardDuty도 리전별입니다. 알림이 온 리전을 우선 확인하세요.

### (4) 전 리전 실행 중인 EC2 목록

```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws ec2 describe-instances --region "$r" \
    --query "Reservations[].Instances[].[InstanceId,InstanceType,State.Name,LaunchTime]" \
    --output text | sed "s/^/$r\t/"
done > ec2_all_regions.txt
```

---

## 3단계: 로그를 보낼 때 주의할 점

- **시크릿 액세스 키, 비밀번호, 토큰은 절대 붙여넣지 마세요.** 액세스 키 ID(`AKIA...`)는 괜찮지만, 시크릿 키는 안 됩니다.
- 계정 ID나 고객 개인정보는 필요하면 마스킹하세요. 예: `123456789012` → `1234****9012`
- 로그가 너무 길면 우선 아래 이벤트만 걸러서 보내주셔도 됩니다.

```bash
jq '.Events[] | select(.EventName | test("CreateUser|CreateAccessKey|AttachUserPolicy|PutUserPolicy|CreateLoginProfile|ConsoleLogin|RunInstances|StopLogging|DeleteTrail|DeleteDetector|AuthorizeSecurityGroupIngress|ImportKeyPair|CreateKeyPair|PutBucketPolicy|GetSecretValue|CreateFunction|AssumeRole")) | {EventTime, EventName, Username, CloudTrailEvent}' ct_logs/*.json > suspicious.json
```

---

## 참고: 제가 로그에서 확인할 것들

미리 알아두시면 직접 훑어보실 때도 도움이 됩니다.

| 의심 신호 | 의미 |
|---|---|
| `CreateUser`, `CreateAccessKey`, `CreateLoginProfile` | 공격자가 백도어 계정이나 키를 만듦 |
| `AttachUserPolicy` (AdministratorAccess) | 권한 상승 |
| 평소 안 쓰는 리전의 `RunInstances` (GPU 등 대형 인스턴스) | 채굴 |
| `StopLogging`, `DeleteTrail`, `DeleteDetector` | 흔적 지우기 (매우 위험한 신호) |
| 처음 보는 IP나 국가의 `ConsoleLogin` | 탈취된 비밀번호로 로그인 |
| `GetSecretValue`, 대량 S3 접근, `PutBucketPolicy` | 데이터 유출 시도 |
| `AuthorizeSecurityGroupIngress` 0.0.0.0/0 | 외부에 포트 개방 |

---

## 이후 진행 순서

1. **로그 분석:** 어떤 키나 사용자가 언제 어디서 무엇을 했는지 파악합니다.
2. **원인 파악:** GitHub에 키가 올라갔는지, 서버가 뚫렸는지, 비밀번호가 유출됐는지 확인합니다.
3. **복구:** 공격자가 만든 리소스와 사용자를 정리하고, 관련 키를 교체합니다.
4. **재발 방지:** MFA 강제, 장기 액세스 키를 IAM Role로 전환, GuardDuty와 CloudTrail 상시 활성화 등을 적용합니다.

**우선 0단계와 1단계를 진행하시고, 다음 내용을 알려주세요.**
- 연락을 어디서 받았는지
- 결제 금액에 이상이 있었는지
- 위에서 뽑은 로그 (특히 `suspicious.json`, `credential_report.csv`, `ec2_all_regions.txt`)

막히는 명령어가 있으면 에러 메시지를 그대로 보내주세요.

## 사용자

로그를 뽑아서 보내드립니다. 질문하신 것부터 답할게요.

- **연락을 어디서 받았는지:** 저는 공격받았을 수 있다는 연락만 받았고, 누가 어떤 경로로 보냈는지는 모릅니다.
- **결제 금액 이상 여부:** 지금 AWS 콘솔과 CLI에 접속할 수 없어서 확인하지 못했습니다(비용 자료는 없어요). 같은 이유로 1단계 조치(루트 비밀번호, MFA, 키 비활성화, Support 케이스)도 지금은 할 수 없습니다.
- **참고로 아시면 좋은 것:**
  - 이 계정은 보안 공방전(연습) 환경입니다.
  - blue-team-1, blue-team-2는 우리 팀원 계정이고, 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했습니다.
  - PatchSignal은 원래 있던 우리 서비스입니다.

**보내는 것**
- **suspicious.json → 미리 받아 둔 CloudTrail 파일에서 뽑음**
  - `lookup-events`를 돌릴 수 없어서 미리 받아 둔 파일(`cloudtrail.json`)에서 뽑았습니다. ap-northeast-2 리전만 있고, 시간은 UTC 2026-10-11 04:30경~07:25경(한국 시간 13:30~16:25 무렵)입니다. 다른 리전과 하루 전 기록은 없습니다.
  - 파일 형식이 `.Events[]`가 아니라 `{"Records":[...]}`입니다. 그래서 주신 jq 필터의 이벤트 이름 목록을 그대로 `.Records[]`에 적용했습니다.
  - 필드도 다릅니다. EventTime/Username/CloudTrailEvent 대신 eventTime, eventSource, eventName, sourceIPAddress, userIdentity, requestParameters, errorCode가 있습니다.
- **결과를 세 부분으로 나눈 이유:** 걸린 것 278건 중 AssumeRole이 268건이라 전부 붙이면 너무 깁니다. 그래서 이렇게 나눴습니다.
  1. 이벤트 이름별 건수
  2. AssumeRole 계열을 뺀 나머지 이벤트 전체
  3. AssumeRole 계열은 호출자, IP, 대상 역할, 오류 코드별 건수와 처음·마지막 시각으로 요약 (AssumeRole 기록에는 roleArn 값이 없어서 그 칸은 "-"로 나옵니다)

**뽑지 못한 것**
- **credential_report.csv:** IAM 설정 자료가 없어 확인하지 못했습니다(그 로그는 없어요).
- **GuardDuty 탐지 결과:** 확인하지 못했습니다(그 로그는 없어요).
- **ec2_all_regions.txt (전 리전 EC2 목록):** 인스턴스 설정 자료가 없어 확인하지 못했습니다(그 로그는 없어요).

실행한 명령:
```
F='CreateUser|CreateAccessKey|AttachUserPolicy|PutUserPolicy|CreateLoginProfile|ConsoleLogin|RunInstances|StopLogging|DeleteTrail|DeleteDetector|AuthorizeSecurityGroupIngress|ImportKeyPair|CreateKeyPair|PutBucketPolicy|GetSecretValue|CreateFunction|AssumeRole'
echo "## 1) 필터 해당 이벤트 이름별 건수"; jq -r --arg f "$F" '.Records[]|select(.eventName|test($f))|.eventName' cloudtrail.json | sort | uniq -c | sort -rn
echo; echo "## 2) AssumeRole 계열 제외한 해당 이벤트 전체"; jq -c --arg f "$F" '.Records[]|select(.eventName|test($f))|select(.eventName|test("^AssumeRole")|not)' cloudtrail.json
echo; echo "## 3) AssumeRole 계열 요약 (eventName / 호출자 arn / sourceIP / 대상 roleArn / errorCode 별 건수, 최초~최종 시각)"; jq -r --arg f "$F" '.Records[]|select(.eventName|test("^AssumeRole"))|[.eventName, (.userIdentity.arn // .userIdentity.type // "-"), .sourceIPAddress, (.requestParameters.roleArn // "-"), (.errorCode // "-"), .eventTime]|@tsv' cloudtrail.json | sort | awk -F'\t' '{k=$1"\t"$2"\t"$3"\t"$4"\t"$5; c[k]++; if(!(k in f)) f[k]=$6; l[k]=$6} END{for(k in c) print c[k]"\t"k"\t"f[k]"\t"l[k]}' | sort -k1,1 -rn
```
결과:
```
## 1) 필터 해당 이벤트 이름별 건수
    268 AssumeRole
      6 AuthorizeSecurityGroupIngress
      4 AssumeRoleWithWebIdentity

## 2) AssumeRole 계열 제외한 해당 이벤트 전체
{"eventTime":"2026-10-11T04:39:33Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAA35E…DE4A"}}
{"eventTime":"2026-10-11T05:09:28Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:09:29Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:27:36Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"},"errorCode":"Client.DryRunOperation"}
{"eventTime":"2026-10-11T05:27:37Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"}}
{"eventTime":"2026-10-11T07:18:34Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"guardduty.amazonaws.com","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","accessKeyId":"ASIA3CF9…09AC"}}

## 3) AssumeRole 계열 요약 (eventName / 호출자 arn / sourceIP / 대상 roleArn / errorCode 별 건수, 최초~최종 시각)
60	AssumeRole	AWSService	eks-nodegroup.amazonaws.com	-	-	2026-10-11T04:31:33Z	2026-10-11T06:01:34Z
56	AssumeRole	AWSService	config.amazonaws.com	-	-	2026-10-11T04:30:25Z	2026-10-11T05:55:23Z
55	AssumeRole	AWSService	eks.amazonaws.com	-	-	2026-10-11T04:31:08Z	2026-10-11T06:01:08Z
27	AssumeRole	AWSService	lambda.amazonaws.com	-	-	2026-10-11T04:42:19Z	2026-10-11T05:56:07Z
26	AssumeRole	AWSService	states.amazonaws.com	-	-	2026-10-11T05:00:03Z	2026-10-11T06:00:43Z
18	AssumeRole	AWSService	resource-explorer-2.amazonaws.com	-	-	2026-10-11T04:30:31Z	2026-10-11T05:55:48Z
10	AssumeRole	AWSService	ec2.amazonaws.com	-	-	2026-10-11T04:49:21Z	2026-10-11T05:53:30Z
7	AssumeRole	AWSService	AWS Internal	-	-	2026-10-11T04:30:49Z	2026-10-11T06:00:49Z
5	AssumeRole	AWSService	autoscaling.amazonaws.com	-	-	2026-10-11T04:47:07Z	2026-10-11T05:42:00Z
4	AssumeRole	AWSService	securityhub.amazonaws.com	-	-	2026-10-11T04:31:06Z	2026-10-11T06:00:42Z
2	AssumeRoleWithWebIdentity	arn:aws:iam::111122223333:user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1	-	-	2026-10-11T04:30:41Z	2026-10-11T05:30:35Z
2	AssumeRoleWithWebIdentity	arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	198.18.8.1	-	-	2026-10-11T04:43:09Z	2026-10-11T05:48:49Z
```

## 채팅 AI

# 로그 분석 결과

## 한 줄 요약

**보내주신 결과만으로는 공격 흔적이 확인되지 않습니다. 다만 "공격이 없었다"는 뜻도 아닙니다.** 제가 드린 필터가 이 환경(EKS 중심)에 맞지 않았고, 이 파일 구조상 원래 잡힐 수 없는 이벤트도 있습니다. 필터 범위를 바꿔서 한 번 더 봐야 합니다.

---

## 1. 이벤트별 해석

### (1) AuthorizeSecurityGroupIngress: blue-team-1, 5건 (04:39 ~ 05:27)

- 팀원 계정이고 IP(198.18.2.1)도 일정해서, 대응 작업일 가능성이 높습니다.
- 다만 이 레코드에는 **`requestParameters`가 없어서 어떤 포트를 어디에 열었는지 알 수 없습니다.**
- 05:27:36에 DryRun(권한 시험)을 한 뒤 1초 뒤에 실제로 실행한 패턴은 사람이나 스크립트 모두 흔히 하는 방식입니다.
- 액세스 키가 세 번 바뀐 것(ASIA… 세 종류)은 세션을 세 번 새로 받았다는 뜻입니다. 이것만으로는 이상하지 않습니다.
- **확인 필요:** blue-team-1 본인에게 이 시각에 어떤 보안그룹을 어떻게 바꿨는지 물어봐 주세요. 본인이 한 일이 아니라면 이 자격 증명이 탈취된 것이므로 가장 중요한 단서가 됩니다.

### (2) AuthorizeSecurityGroupIngress: GuardDuty, 07:18

- GuardDuty Runtime Monitoring이 에이전트용 VPC 엔드포인트 보안그룹을 자동으로 설정할 때 남는 기록입니다. **정상입니다.**
- 이 시각에 처음 생겼다면, 팀원이 대응 중에 Runtime Monitoring을 켰을 가능성이 있습니다.
- 어쨌든 **GuardDuty가 켜져 있으므로 탐지 결과가 존재할 수 있습니다.** 접근 권한이 있는 분께 요청할 가치가 있습니다.

### (3) AssumeRole 268건: 전부 AWS 서비스

EKS, Config, Lambda, Step Functions, Security Hub 등이 자기 역할을 쓴 기록입니다. 일상적인 백그라운드 동작으로 보입니다.

- 한 가지 눈에 띄는 점이 있습니다. **서비스 호출이 모두 06:01 무렵에 끊기는데, 파일은 07:25까지 있습니다.** 이 시간대에 클러스터나 서비스를 멈췄는지, 아니면 파일이 그렇게 잘린 것인지 확인해 주세요.

### (4) AssumeRoleWithWebIdentity 4건: 쿠버네티스 파드의 IRSA

| 서비스 계정 | 시각 | 해석 |
|---|---|---|
| `kube-system:blue-team-1-tetragon-fluent-bit` | 04:30, 05:30 | 정확히 1시간 간격으로, 정상적인 토큰 갱신 패턴 |
| `device-support:portal-api` | 04:43, 05:48 | 약 65분 간격으로, 역시 정상 갱신 패턴 |

이 호출 자체는 정상으로 보입니다. 하지만 **portal-api가 가장 주목할 대상**입니다. 이름상 외부에 노출된 API일 가능성이 높습니다. 공격자가 이 파드를 장악하면 이 역할로 AWS 자격 증명을 받을 수 있습니다. 그 경우 이후 행동은 `AssumedRole/...portal-api 역할` 이름으로 남는데, 제 필터에는 그런 이벤트가 하나도 포함되지 않았습니다.

---

## 2. 제 필터가 놓쳤을 수 있는 것

1. **IAM 이벤트는 이 파일에 원래 없습니다.** CreateUser, CreateAccessKey, AttachUserPolicy 같은 IAM 이벤트는 **us-east-1**에 기록됩니다. 콘솔 로그인도 대부분 그렇습니다. ap-northeast-2 파일에 없다고 해서 그런 일이 없었다는 뜻은 아닙니다.
2. **필터가 "계정 탈취형" 공격만 겨냥했습니다.** 이 환경은 EKS와 컨테이너 중심입니다. 이런 환경에서는 보통 다음 순서로 공격이 진행됩니다.
   - 웹 앱(파드) 장악
   - 파드나 노드의 역할 자격 증명 탈취
   - 정찰: `GetCallerIdentity`, `List*`, `Describe*`, 다수의 `AccessDenied`
   - 데이터 접근: S3, Secrets Manager, SSM 등

   이 이벤트들은 제 키워드 목록에 없었습니다.
3. **콘솔과 CLI에 갑자기 접속할 수 없게 된 이유도 중요합니다.** 연습 운영 측이 권한을 회수한 것인지, 누군가 비밀번호나 정책을 바꾼 것인지에 따라 해석이 완전히 달라집니다.

---

## 3. 다음에 실행해 주실 명령

모두 같은 `cloudtrail.json`을 대상으로 합니다.

```bash
# A) AWS 서비스를 제외한 "사람/워크로드" 활동 전체 요약 (가장 중요)
jq -r '.Records[] | select(.userIdentity.type != "AWSService")
  | [(.userIdentity.arn // .userIdentity.type), .eventSource, .eventName, .sourceIPAddress, (.errorCode // "-")] | @tsv' \
  cloudtrail.json | sort | uniq -c | sort -rn > A_actors.tsv

# B) 실패한 호출 (정찰 흔적: AccessDenied 등)
jq -r '.Records[] | select(.errorCode)
  | [.eventTime, (.userIdentity.arn // .userIdentity.type), .eventName, .sourceIPAddress, .errorCode] | @tsv' \
  cloudtrail.json > B_errors.tsv

# C) 신원별로 쓴 IP 목록 (한 신원이 여러 IP를 쓰면 의심)
jq -r '.Records[] | [(.userIdentity.arn // .userIdentity.type), .sourceIPAddress] | @tsv' \
  cloudtrail.json | sort -u > C_ip_by_actor.tsv

# D) portal-api / PatchSignal 관련 기록 전체
jq -c '.Records[] | select(tostring | test("portal-api|PatchSignal|device-support"; "i"))' \
  cloudtrail.json > D_app.json

# E) 보안그룹 변경 레코드 원본 (숨은 필드가 있는지 확인)
jq '.Records[] | select(.eventName | test("SecurityGroup"))' cloudtrail.json > E_sg.json

# F) 10분 단위 이벤트 수 (06:01 이후 공백 확인용)
jq -r '.Records[].eventTime[0:15]' cloudtrail.json | sort | uniq -c > F_timeline.txt
```

`A_actors.tsv`가 길면 상위 100줄만 보내주셔도 됩니다.

---

## 4. 함께 알려주시면 좋은 것

1. **팀원 대응 작업 목록:** 누가 몇 시에 무엇을 했는지 알려주세요. 그래야 공격자 행동과 구분할 수 있습니다. 위에서 말씀드린 blue-team-1의 보안그룹 변경도 포함해서요.
2. **콘솔과 CLI에 접속할 수 없게 된 이유와 시점**
3. **portal-api와 PatchSignal이 각각 무엇을 하는 서비스인지:** 외부에 노출되는지, 어떤 AWS 권한을 갖는지
4. **다른 로그가 있는지:** Tetragon fluent-bit가 동작 중이었으므로 **Tetragon(런타임) 로그**가 어딘가에 쌓였을 가능성이 높습니다. 그 밖에 EKS 감사 로그(CloudWatch)나 애플리케이션 로그가 있으면 컨테이너 쪽 공격을 확인하는 데 결정적입니다.
5. **us-east-1 CloudTrail 파일:** IAM 변경과 로그인 기록을 확인하는 데 필요합니다.

---

## 지금 시점의 잠정 조치 (권한이 있는 분께 요청)

- blue-team-1이 바꾼 보안그룹 규칙 중 `0.0.0.0/0` 개방이 있는지 확인하기
- portal-api 서비스 계정에 연결된 IAM 역할의 권한 범위 확인하기 (너무 넓다면 최소 권한으로 축소)
- GuardDuty 탐지 결과 열람 요청하기

**무엇을 고쳐야 하는지는 A~F 결과를 본 뒤에 구체적으로 말씀드리겠습니다.** 지금 단계에서 단정하면 엉뚱한 곳을 고치게 될 수 있습니다.

## 사용자

A~F를 모두 같은 `cloudtrail.json`에서 뽑았습니다. 결과가 길어서 일부는 나누거나 요약했습니다.

**결과를 이렇게 바꿔서 보냈습니다**
- **A:** 전체 864줄 중 말씀하신 대로 상위 100줄만 보냅니다.
- **B:** 204줄 전체를 보냅니다. 한 번에 붙지 않아 1~70, 71~140, 141~204줄 세 번으로 나눴습니다.
- **C:** 전체 126줄을 그대로 보냅니다.
- **D:** 대소문자를 가리지 않고 찾아서 `patchsignal-...` 역할과 Lambda 이름도 함께 걸렸고, 모두 243건(약 88KB)입니다. 원문을 다 붙일 수 없어서 두 가지로 요약했습니다.
  - D-1: eventName, 신원, IP, errorCode 조합별 건수와 처음·마지막 시각
  - D-2: eventName과 requestParameters 조합별 건수
- **E:** SecurityGroup 이벤트 89건을 나눠서 보냅니다.
  - E-1: Describe가 아닌 9건은 원본을 한 줄씩 그대로 보냅니다.
  - E-2: Describe 80건은 신원, IP, errorCode, requestParameters 조합별 건수와 처음·마지막 시각으로 요약했습니다.
- **F:** 전체를 그대로 보냅니다.

**4번 질문 답**
1. **팀원 대응 작업 목록:** 누가 몇 시에 무엇을 했는지 정리된 목록은 없습니다. 제가 아는 건 blue-team-1, blue-team-2가 팀원 계정이고, 사고 뒤 대응 작업(조회, 설정 변경)을 팀원이 했다는 것까지입니다. blue-team-1의 보안그룹 변경 내용은 모릅니다.
2. **콘솔과 CLI에 접속할 수 없는 이유와 시점:** 모릅니다.
3. **portal-api와 PatchSignal:** PatchSignal은 원래 있던 우리 서비스입니다. 외부에 노출되는지, 어떤 권한을 갖는지는 모릅니다. portal-api가 무엇인지도 모릅니다.
4. **다른 로그:** 제가 가진 건 이 CloudTrail 파일 말고 WAF 로그(`waf.jsonl`)와 ALB 접근 로그(`alb.log`)뿐입니다. Tetragon 로그, EKS 감사 로그, 애플리케이션 로그는 확인하지 못했습니다(그 로그는 없어요).
5. **us-east-1 CloudTrail:** 확인하지 못했습니다(그 로그는 없어요).

06:01 이후 기록이 줄어든 이유(서비스를 멈췄는지, 파일이 잘린 것인지)도 모릅니다.

실행한 명령:
```
echo "## A) AWSService 제외 활동 요약 (상위 100줄 / 전체 864줄)"; jq -r '.Records[] | select(.userIdentity.type != "AWSService") | [(.userIdentity.arn // .userIdentity.type), .eventSource, .eventName, .sourceIPAddress, (.errorCode // "-")] | @tsv' cloudtrail.json | sort | uniq -c | sort -rn | head -100
```
결과:
```
## A) AWSService 제외 활동 요약 (상위 100줄 / 전체 864줄)
   2255 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	logs.amazonaws.com	FilterLogEvents	198.18.6.1	-
    725 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	logs.amazonaws.com	GetLogEvents	198.18.6.1	-
    417 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	LookupEvents	198.18.0.1	-
    307 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	GetCommandInvocation	198.18.2.1	-
    246 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	FilterLogEvents	198.18.2.1	-
    244 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	SendCommand	198.18.2.1	-
    237 arn:aws:iam::111122223333:user/blue-team-1	sts.amazonaws.com	GetCallerIdentity	198.18.2.1	-
    211 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	LookupEvents	198.18.23.1	-
    201 arn:aws:iam::111122223333:user/blue-team-1	monitoring.amazonaws.com	DescribeAlarms	198.18.23.1	-
    153 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	GetQueryResults	198.18.23.1	-
    146 arn:aws:iam::111122223333:user/blue-team-1	monitoring.amazonaws.com	DescribeAlarms	198.18.0.1	-
    145 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	logs.amazonaws.com	DescribeLogStreams	198.18.6.1	-
     95 arn:aws:iam::111122223333:user/blue-team-1	sts.amazonaws.com	GetCallerIdentity	198.18.9.1	-
     89 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	StartQuery	198.18.23.1	-
     76 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	states.amazonaws.com	StartExecution	198.18.10.1	-
     65 arn:aws:iam::111122223333:user/blue-team-2	logs.amazonaws.com	DescribeMetricFilters	198.18.23.1	-
     61 arn:aws:iam::111122223333:user/blue-team-1	sts.amazonaws.com	GetCallerIdentity	198.18.4.1	-
     60 arn:aws:iam::111122223333:user/blue-team-1	monitoring.amazonaws.com	DescribeAlarms	198.18.5.1	-
     55 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeSnapshots	198.18.2.1	-
     54 arn:aws:iam::111122223333:user/blue-team-1	wafv2.amazonaws.com	CheckCapacity	198.18.23.1	-
     46 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling	ec2.amazonaws.com	DescribeInstanceStatus	autoscaling.amazonaws.com	-
     42 arn:aws:iam::111122223333:user/blue-team-1	resource-explorer-2.amazonaws.com	Search	198.18.23.1	-
     41 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	ssm.amazonaws.com	UpdateInstanceInformation	198.18.10.1	-
     41 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	ssm.amazonaws.com	UpdateInstanceInformation	198.18.6.1	-
     41 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeInstances	198.18.23.1	-
     38 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	DescribeMetricFilters	198.18.2.1	-
     37 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	DescribeUserPool	198.18.23.1	-
     36 arn:aws:iam::111122223333:user/blue-team-2	monitoring.amazonaws.com	DescribeAlarms	198.18.23.1	-
     36 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeInstanceStatus	198.18.23.1	-
     36 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	ListUserPoolReplicas	198.18.23.1	-
     33 arn:aws:iam::111122223333:user/blue-team-1	kms.amazonaws.com	Decrypt	lambda.amazonaws.com	-
     32 arn:aws:iam::111122223333:user/blue-team-1	resource-explorer-2.amazonaws.com	Search	198.18.5.1	-
     31 arn:aws:iam::111122223333:user/blue-team-2	eks.amazonaws.com	AccessKubernetesApi	198.18.23.1	-
     30 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	autoscaling.amazonaws.com	DescribeAutoScalingGroups	eks-nodegroup.amazonaws.com	-
     30 arn:aws:iam::111122223333:user/blue-team-1	wafv2.amazonaws.com	GetSampledRequests	198.18.23.1	-
     28 arn:aws:iam::111122223333:user/blue-team-1	wafv2.amazonaws.com	ListWebACLs	198.18.23.1	-
     27 arn:aws:iam::111122223333:user/blue-team-2	resource-explorer-2.amazonaws.com	Search	198.18.23.1	-
     27 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	ListUserImportJobs	198.18.23.1	-
     26 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	GetCSVHeader	198.18.23.1	-
     25 arn:aws:iam::111122223333:user/blue-team-2	sts.amazonaws.com	GetCallerIdentity	apigateway.amazonaws.com	-
     25 arn:aws:iam::111122223333:user/blue-team-1	resource-explorer-2.amazonaws.com	Search	198.18.3.1	-
     25 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeInstances	198.18.2.1	-
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ec2.amazonaws.com	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
     24 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ec2.amazonaws.com	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
     24 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeInstanceTypes	198.18.23.1	-
     24 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	GetCommandInvocation	198.18.3.1	-
     24 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeInstances	198.18.5.1	-
     24 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	AdminGetUser	198.18.23.1	-
     23 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	DescribeMetricFilters	198.18.23.1	-
     22 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	DescribeAccountPolicies	198.18.0.1	-
     21 arn:aws:iam::111122223333:user/blue-team-1	cloudshell.amazonaws.com	DeleteSession	198.18.23.1	-
     21 arn:aws:iam::111122223333:user/blue-team-1	cloudshell.amazonaws.com	CreateSession	198.18.23.1	-
     20 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	ec2.amazonaws.com	DescribeRouteTables	eks-nodegroup.amazonaws.com	-
     20 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	ec2.amazonaws.com	DescribeLaunchTemplateVersions	eks-nodegroup.amazonaws.com	-
     20 arn:aws:iam::111122223333:user/blue-team-1	observabilityadmin.amazonaws.com	GetTelemetryEvaluationStatusForOrganization	198.18.23.1	-
     20 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.2.1	-
     19 arn:aws:iam::111122223333:user/blue-team-2	cloudshell.amazonaws.com	GetEnvironmentStatus	198.18.23.1	-
     19 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeInstanceStatus	198.18.5.1	-
     19 arn:aws:iam::111122223333:user/blue-team-1	application-insights.amazonaws.com	ListProblems	198.18.23.1	-
     18 arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	lambda.amazonaws.com	GetFunction20150331v2	10.81.0.102	-
     18 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497	ec2.amazonaws.com	DescribeInstances	eks.amazonaws.com	-
     18 arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	ssm.amazonaws.com	CreateDataChannel	198.18.6.1	-
     18 arn:aws:iam::111122223333:user/blue-team-1	observabilityadmin.amazonaws.com	GetTelemetryEvaluationStatus	198.18.23.1	-
     18 arn:aws:iam::111122223333:user/blue-team-1	cognito-idp.amazonaws.com	ListUsers	198.18.23.1	-
     18 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	LookupEvents	198.18.5.1	-
     18 Unknown	ssm.amazonaws.com	OpenDataChannel	198.18.6.1	-
     17 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	ListLogGroups	198.18.0.1	-
     17 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	ListAggregateLogGroupSummaries	198.18.23.1	-
     17 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	GetLogEvents	198.18.23.1	-
     17 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	GetTrailStatus	198.18.5.1	-
     17 arn:aws:iam::111122223333:user/blue-team-1	cloudshell.amazonaws.com	PutCredentials	198.18.23.1	-
     17 Unknown	ssm.amazonaws.com	OpenDataChannel	198.18.23.1	-
     16 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	ListCommands	198.18.2.1	-
     16 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	DescribeTrails	198.18.5.1	-
     15 arn:aws:iam::111122223333:user/blue-team-1	observabilityadmin.amazonaws.com	GetTelemetryEvaluationStatus	observabilityadmin.amazonaws.com	-
     15 arn:aws:iam::111122223333:user/blue-team-1	config.amazonaws.com	DescribeConfigurationRecorders	198.18.0.1	-
     15 arn:aws:iam::111122223333:user/blue-team-1	config.amazonaws.com	DescribeConfigurationRecorderStatus	198.18.0.1	-
     14 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	ec2.amazonaws.com	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
     14 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	cloudcontrolapi.amazonaws.com	ListResources	config.amazonaws.com	-
     14 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	ec2.amazonaws.com	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
     14 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeAddresses	198.18.23.1	-
     14 arn:aws:iam::111122223333:user/blue-team-1	logs.amazonaws.com	DescribeMetricFilters	198.18.5.1	-
     14 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	GetTrailStatus	198.18.0.1	-
     14 arn:aws:iam::111122223333:user/blue-team-1	cloudtrail.amazonaws.com	DescribeTrails	198.18.0.1	-
     13 arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	sts.amazonaws.com	GetCallerIdentity	198.18.9.1	-
     13 arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	sts.amazonaws.com	GetCallerIdentity	eks.amazonaws.com	-
     13 arn:aws:iam::111122223333:user/blue-team-2	ssm.amazonaws.com	ResumeSession	198.18.23.1	-
     13 arn:aws:iam::111122223333:user/blue-team-2	cloudtrail.amazonaws.com	DescribeTrails	198.18.23.1	-
     13 arn:aws:iam::111122223333:user/blue-team-1	notifications.amazonaws.com	ListNotificationHubs	198.18.23.1	-
     13 arn:aws:iam::111122223333:user/blue-team-1	monitoring.amazonaws.com	ListDashboards	198.18.23.1	-
     13 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeSecurityGroupRules	198.18.2.1	-
     13 arn:aws:iam::111122223333:user/blue-team-1	ec2.amazonaws.com	DescribeInstances	198.18.3.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	notifications.amazonaws.com	ListNotificationHubs	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	elasticloadbalancing.amazonaws.com	DescribeLoadBalancers	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeVolumes	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeNetworkInterfaces	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	ec2.amazonaws.com	DescribeInstanceAttribute	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-2	cloudtrail.amazonaws.com	GetTrailStatus	198.18.23.1	-
     12 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	ListCommandInvocations	198.18.2.1	-
     12 arn:aws:iam::111122223333:user/blue-team-1	ssm.amazonaws.com	GetDocument	198.18.2.1	-
```

실행한 명령:
```
echo "## B) 실패한 호출 전체 204줄 중 1~70줄 (eventTime / 신원 / eventName / IP / errorCode, 파일 순서)"; jq -r '.Records[] | select(.errorCode) | [.eventTime, (.userIdentity.arn // .userIdentity.type), .eventName, .sourceIPAddress, .errorCode] | @tsv' cloudtrail.json | sed -n '1,70p'
```
결과:
```
## B) 실패한 호출 전체 204줄 중 1~70줄 (eventTime / 신원 / eventName / IP / errorCode, 파일 순서)
2026-10-11T04:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:30:50Z	arn:aws:iam::111122223333:user/blue-team-1	GetInsightSelectors	198.18.5.1	InsightNotEnabledException
2026-10-11T04:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:32:54Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetStage	resource-explorer-2.amazonaws.com	NotFoundException
2026-10-11T04:32:55Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetStage	resource-explorer-2.amazonaws.com	NotFoundException
2026-10-11T04:33:29Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	StartSession	198.18.6.1	AccessDenied
2026-10-11T04:33:33Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	StartSession	198.18.6.1	AccessDenied
2026-10-11T04:33:58Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T04:33:59Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T04:35:50Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.0.1	DashboardNotFoundError
2026-10-11T04:36:07Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	DescribeNetworkInterfaces	config.amazonaws.com	Client.InvalidNetworkInterfaceID.NotFound
2026-10-11T04:36:11Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:36:19Z	arn:aws:iam::111122223333:user/blue-team-1	GetBucketObjectLockConfiguration	198.18.5.1	ObjectLockConfigurationNotFoundError
2026-10-11T04:36:29Z	arn:aws:iam::111122223333:user/blue-team-1	GetBucketObjectLockConfiguration	198.18.5.1	ObjectLockConfigurationNotFoundError
2026-10-11T04:36:32Z	arn:aws:iam::111122223333:user/blue-team-1	GetBucketObjectLockConfiguration	198.18.5.1	ObjectLockConfigurationNotFoundError
2026-10-11T04:37:32Z	arn:aws:iam::111122223333:user/blue-team-1	GetBucketObjectLockConfiguration	198.18.5.1	ObjectLockConfigurationNotFoundError
2026-10-11T04:37:35Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:37:54Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:38:05Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:39:08Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:39:17Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:39:18Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:39:34Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:39:53Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:40:14Z	Unknown	SignUp	198.18.7.1	InvalidPasswordException
2026-10-11T04:41:49Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.5.1	DashboardNotFoundError
2026-10-11T04:42:04Z	Unknown	RespondToAuthChallenge	198.18.7.1	NotAuthorizedException
2026-10-11T04:43:00Z	AWSService	CreateLogStream	delivery.logs.amazonaws.com	ResourceAlreadyExistsException
2026-10-11T04:43:48Z	Unknown	RespondToAuthChallenge	198.18.7.2	NotAuthorizedException
2026-10-11T04:43:48Z	Unknown	RespondToAuthChallenge	198.18.7.2	NotAuthorizedException
2026-10-11T04:43:49Z	Unknown	RespondToAuthChallenge	198.18.7.2	NotAuthorizedException
2026-10-11T04:43:49Z	Unknown	RespondToAuthChallenge	198.18.7.2	NotAuthorizedException
2026-10-11T04:44:03Z	Unknown	SignUp	198.18.7.2	InvalidPasswordException
2026-10-11T04:44:12Z	Unknown	SignUp	198.18.7.2	InvalidPasswordException
2026-10-11T04:44:22Z	Unknown	SignUp	198.18.7.2	InvalidPasswordException
2026-10-11T04:44:35Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	DescribeLogStreams	198.18.6.1	AccessDenied
2026-10-11T04:45:04Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetStage	resource-explorer-2.amazonaws.com	NotFoundException
2026-10-11T04:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:45:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T04:48:18Z	Unknown	SignUp	198.18.7.2	InvalidPasswordException
2026-10-11T04:48:52Z	AWSService	CreateLogStream	delivery.logs.amazonaws.com	ResourceAlreadyExistsException
2026-10-11T04:48:52Z	AWSService	CreateLogStream	delivery.logs.amazonaws.com	ResourceAlreadyExistsException
2026-10-11T04:50:11Z	arn:aws:iam::111122223333:user/blue-team-1	GetInsightSelectors	198.18.5.1	InsightNotEnabledException
2026-10-11T04:50:16Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.5.1	ResourceNotFoundException
2026-10-11T04:52:08Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:52:19Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetStage	resource-explorer-2.amazonaws.com	NotFoundException
2026-10-11T04:53:06Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:53:14Z	arn:aws:iam::111122223333:user/blue-team-1	ListCentralizationRulesForOrganization	198.18.0.1	UnauthorizedException
2026-10-11T04:53:14Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:53:15Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRulesForOrganization	198.18.0.1	ValidationException
2026-10-11T04:53:19Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:53:24Z	arn:aws:iam::111122223333:user/blue-team-1	ListCentralizationRulesForOrganization	198.18.0.1	UnauthorizedException
2026-10-11T04:53:25Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T04:53:25Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRulesForOrganization	198.18.0.1	ValidationException
2026-10-11T04:54:17Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T04:54:24Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.19.1	InsightNotEnabledException
2026-10-11T04:54:26Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T04:54:35Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T04:54:49Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T04:55:00Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T04:55:11Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:00:18Z	arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	FilterLogEvents	198.18.6.1	AccessDenied
```

실행한 명령:
```
echo "## B) 실패한 호출 71~140줄"; jq -r '.Records[] | select(.errorCode) | [.eventTime, (.userIdentity.arn // .userIdentity.type), .eventName, .sourceIPAddress, .errorCode] | @tsv' cloudtrail.json | sed -n '71,140p'
```
결과:
```
## B) 실패한 호출 71~140줄
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:06:51Z	arn:aws:iam::111122223333:user/blue-team-1	ListCentralizationRulesForOrganization	198.18.0.1	UnauthorizedException
2026-10-11T05:06:52Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.0.1	ValidationException
2026-10-11T05:06:52Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRulesForOrganization	198.18.0.1	ValidationException
2026-10-11T05:09:58Z	arn:aws:iam::111122223333:user/AWSAccount	GetBucketVersioning	198.18.7.2	AccessDenied
2026-10-11T05:10:29Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:10:44Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:10:52Z	arn:aws:iam::111122223333:user/blue-team-2	GetDashboard	198.18.23.1	ResourceNotFoundException
2026-10-11T05:10:53Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:11:00Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.23.1	InsightNotEnabledException
2026-10-11T05:11:05Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:11:18Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.0.1	ThrottlingException
2026-10-11T05:13:37Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.23.1	InsightNotEnabledException
2026-10-11T05:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:15:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:15:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:15:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:19:34Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.23.1	InsightNotEnabledException
2026-10-11T05:21:21Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.23.1	InsightNotEnabledException
2026-10-11T05:22:00Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.23.1	DashboardNotFoundError
2026-10-11T05:22:08Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.23.1	ValidationException
2026-10-11T05:22:32Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.23.1	DashboardNotFoundError
2026-10-11T05:22:38Z	arn:aws:iam::111122223333:user/blue-team-2	GetDashboard	198.18.23.1	DashboardNotFoundError
2026-10-11T05:22:59Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.23.1	ValidationException
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketObjectLockConfiguration	config.amazonaws.com	ObjectLockConfigurationNotFoundError
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketLifecycle	config.amazonaws.com	NoSuchLifecycleConfiguration
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketTagging	config.amazonaws.com	NoSuchTagSet
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketReplication	config.amazonaws.com	ReplicationConfigurationNotFoundError
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketCors	config.amazonaws.com	NoSuchCORSConfiguration
2026-10-11T05:23:34Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	GetBucketWebsite	config.amazonaws.com	NoSuchWebsiteConfiguration
2026-10-11T05:23:55Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.23.1	ValidationException
2026-10-11T05:27:36Z	arn:aws:iam::111122223333:user/blue-team-1	AuthorizeSecurityGroupIngress	198.18.2.1	Client.DryRunOperation
2026-10-11T05:29:12Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetTopicAttributes	resource-explorer-2.amazonaws.com	NotFoundException
2026-10-11T05:29:12Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	GetResource	resource-explorer-2.amazonaws.com	ResourceNotFoundException
2026-10-11T05:29:59Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	GetTopicAttributes	config.amazonaws.com	NotFoundException
2026-10-11T05:30:45Z	arn:aws:iam::111122223333:user/blue-team-2	GetDocument	198.18.23.1	InvalidDocument
2026-10-11T05:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:31:55Z	arn:aws:iam::111122223333:user/blue-team-2	GetInsightSelectors	198.18.23.1	InsightNotEnabledException
2026-10-11T05:32:13Z	arn:aws:iam::111122223333:user/blue-team-1	AdminListUserAuthEvents	198.18.23.1	UserPoolAddOnNotEnabledException
2026-10-11T05:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:45:49Z	Unknown	RespondToAuthChallenge	198.18.7.1	NotAuthorizedException
2026-10-11T05:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:45:49Z	Unknown	RespondToAuthChallenge	198.18.7.1	NotAuthorizedException
2026-10-11T05:45:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T05:48:07Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:13Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:19Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:25Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:31Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:37Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:44Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:48:51Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:49:01Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:49:10Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:49:18Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
```

실행한 명령:
```
echo "## B) 실패한 호출 141~204줄"; jq -r '.Records[] | select(.errorCode) | [.eventTime, (.userIdentity.arn // .userIdentity.type), .eventName, .sourceIPAddress, .errorCode] | @tsv' cloudtrail.json | sed -n '141,204p'
```
결과:
```
## B) 실패한 호출 141~204줄
2026-10-11T05:49:25Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	ThrottlingException
2026-10-11T05:50:37Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	InvalidLookupAttributesException
2026-10-11T05:51:11Z	arn:aws:iam::111122223333:user/blue-team-1	LookupEvents	198.18.23.1	InvalidLookupAttributesException
2026-10-11T05:51:39Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.23.1	DashboardNotFoundError
2026-10-11T05:51:47Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.23.1	ValidationException
2026-10-11T05:51:50Z	arn:aws:iam::111122223333:user/blue-team-1	GetDashboard	198.18.23.1	DashboardNotFoundError
2026-10-11T05:51:52Z	arn:aws:iam::111122223333:user/blue-team-1	ListTelemetryRules	198.18.23.1	ValidationException
2026-10-11T05:55:22Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	GetDataCatalog	config.amazonaws.com	InvalidRequestException
2026-10-11T05:57:29Z	arn:aws:iam::111122223333:user/blue-team-2	DescribeInsightsRefresh	198.18.23.1	ResourceNotFoundException
2026-10-11T06:00:39Z	arn:aws:iam::111122223333:user/blue-team-1	GetFunctionEventInvokeConfig	198.18.23.1	ResourceNotFoundException
2026-10-11T06:00:39Z	arn:aws:iam::111122223333:user/blue-team-1	GetFunctionEventInvokeConfig	198.18.23.1	ResourceNotFoundException
2026-10-11T06:00:40Z	arn:aws:iam::111122223333:user/blue-team-1	DescribeStackResources	198.18.23.1	ValidationException
2026-10-11T06:00:40Z	arn:aws:iam::111122223333:user/blue-team-1	GetRestApi	AWS Internal	NotFoundException
2026-10-11T06:00:41Z	arn:aws:iam::111122223333:user/blue-team-1	DescribeSchema	198.18.23.1	NotFoundException
2026-10-11T06:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	DescribeNetworkInterfaces	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:00:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:00:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:15:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:17:27Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T06:17:28Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T06:29:58Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T06:30:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:30:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:39:20Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	StartSession	198.18.50.1	AccessDenied
2026-10-11T06:45:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:45:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:45:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:45:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T06:55:43Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T06:55:43Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T06:55:43Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T07:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:00:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:00:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:00:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:02:09Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	StartSession	198.18.7.1	AccessDenied
2026-10-11T07:11:37Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	SendCommand	198.18.7.1	AccessDenied
2026-10-11T07:12:16Z	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	SendCommand	198.18.7.1	AccessDenied
2026-10-11T07:13:29Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:13:30Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterfacePermission	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:15:49Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:15:50Z	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	CreateNetworkInterface	eks.amazonaws.com	Client.DryRunOperation
2026-10-11T07:17:37Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:17:38Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:17:40Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidNetworkInterface.InUse
2026-10-11T07:19:00Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T07:19:00Z	arn:aws:iam::111122223333:user/blue-team-1	DeleteSession	198.18.23.1	InvalidStatusException
2026-10-11T07:20:40Z	arn:aws:iam::111122223333:user/blue-team-1	UpdateIPSet	198.18.23.1	WAFOptimisticLockException
2026-10-11T07:21:28Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:21:29Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:21:31Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:24:59Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:25:00Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
2026-10-11T07:25:01Z	arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	DeleteNetworkInterface	198.18.8.1	Client.InvalidParameterValue
```

실행한 명령:
```
echo "## C) 신원별 IP 목록 (전체 126줄)"; jq -r '.Records[] | [(.userIdentity.arn // .userIdentity.type), .sourceIPAddress] | @tsv' cloudtrail.json | sort -u
```
결과:
```
## C) 신원별 IP 목록 (전체 126줄)
AWSService	AWS Internal
AWSService	autoscaling.amazonaws.com
AWSService	cloudtrail.amazonaws.com
AWSService	config.amazonaws.com
AWSService	delivery.logs.amazonaws.com
AWSService	ec2.amazonaws.com
AWSService	eks-nodegroup.amazonaws.com
AWSService	eks.amazonaws.com
AWSService	lambda.amazonaws.com
AWSService	resource-explorer-2.amazonaws.com
AWSService	securityhub.amazonaws.com
AWSService	states.amazonaws.com
Unknown	198.18.10.1
Unknown	198.18.2.1
Unknown	198.18.23.1
Unknown	198.18.3.1
Unknown	198.18.5.1
Unknown	198.18.6.1
Unknown	198.18.7.1
Unknown	198.18.7.2
Unknown	2001:db8:0:b::2
arn:aws:iam::111122223333:root	198.18.0.3
arn:aws:iam::111122223333:root	198.18.14.1
arn:aws:iam::111122223333:root	198.18.15.1
arn:aws:iam::111122223333:root	198.18.18.1
arn:aws:iam::111122223333:root	198.18.18.2
arn:aws:iam::111122223333:root	lambda.amazonaws.com
arn:aws:iam::111122223333:user/AWSAccount	198.18.7.2
arn:aws:iam::111122223333:user/blue-team-1	198.18.0.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.0.2
arn:aws:iam::111122223333:user/blue-team-1	198.18.1.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.4.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1
arn:aws:iam::111122223333:user/blue-team-1	198.18.9.1
arn:aws:iam::111122223333:user/blue-team-1	2001:db8:0:18::1
arn:aws:iam::111122223333:user/blue-team-1	AWS Internal
arn:aws:iam::111122223333:user/blue-team-1	lambda.amazonaws.com
arn:aws:iam::111122223333:user/blue-team-1	observabilityadmin.amazonaws.com
arn:aws:iam::111122223333:user/blue-team-2	198.18.19.1
arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1
arn:aws:iam::111122223333:user/blue-team-2	198.18.32.1
arn:aws:iam::111122223333:user/blue-team-2	198.18.33.1
arn:aws:iam::111122223333:user/blue-team-2	198.18.36.1
arn:aws:iam::111122223333:user/blue-team-2	198.18.37.1
arn:aws:iam::111122223333:user/blue-team-2	apigateway.amazonaws.com
arn:aws:iam::111122223333:user/blue-team-2	lambda.amazonaws.com
arn:aws:iam::111122223333:user/blue-team-2	ssm-quicksetup.amazonaws.com
arn:aws:iam::111122223333:user/blue-team-2	ssm.amazonaws.com
arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	198.18.8.1
arn:aws:iam::111122223333:user/system:serviceaccount:kube-system:blue-team-1-tetragon-fluent-bit	198.18.8.1
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/eks-event-service-6831ca82bff36e2cc0fe	eks.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	eks-nodegroup.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring	guardduty.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling	autoscaling.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AutoScalingDescribeHandlerSession	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/CodePipelineDescribeHandlerSession	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/ConfigResourceCompositionSession	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/EC2DescribeHandlerSession	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/SNSDescribeHandlerSession	config.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2	resource-explorer-2.amazonaws.com
arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSecurityHubV2/securityhub	securityhub.amazonaws.com
arn:aws:sts::111122223333:assumed-role/blue-team-1-eks-tetragon-fluent-bit/SXu9AihGioR8CksEaI4xOXcsKAYhhtQ3	198.18.8.1
arn:aws:sts::111122223333:assumed-role/ec2-ssmrole/i-026754fe07a870049	198.18.6.1
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/amazon-vpc-resource-controller-k8s	eks.amazonaws.com
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-cluster/aws-go-sdk-1791687713567903497	eks.amazonaws.com
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.8.1
arn:aws:sts::111122223333:assumed-role/midnight-s3-w1-finals3-2i80ea-eks-node/i-0b5758c0524609dd1	198.18.9.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.12.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.13.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.45.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.47.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.53.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.58.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.60.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.61.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.63.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-api-role/pagesnap-final-s1-api	198.18.64.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.20.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-recovery-role/pagesnap-final-s1-recovery	198.18.39.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.16.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.17.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.20.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.26.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.28.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.34.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.35.1
arn:aws:sts::111122223333:assumed-role/pagesnap-final-s1-renderer-role/pagesnap-final-s1-renderer	198.18.38.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.21.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.25.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.30.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.42.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.43.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.46.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.49.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.54.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.57.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.59.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.62.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.65.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.68.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	10.81.0.102
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.22.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.27.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.2
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.31.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.41.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.44.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.48.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.51.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.52.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.55.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.56.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.66.1
arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.67.1
```

실행한 명령:
```
echo "## D-1) portal-api|PatchSignal|device-support 포함 레코드(243건) 요약: 건수 / 최초 / 최종 / eventName / 신원 / IP / errorCode"; jq -r '.Records[] | select(tostring | test("portal-api|PatchSignal|device-support"; "i"))|[.eventName,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,(.errorCode//"-"),.eventTime]|@tsv' cloudtrail.json | awk -F'\t' '{k=$1"\t"$2"\t"$3"\t"$4; c[k]++; if(!(k in f)) f[k]=$5; l[k]=$5} END{for(k in c) print c[k]"\t"f[k]"\t"l[k]"\t"k}' | sort -t$'\t' -k2,2
```
결과:
```
## D-1) portal-api|PatchSignal|device-support 포함 레코드(243건) 요약: 건수 / 최초 / 최종 / eventName / 신원 / IP / errorCode
1	2026-10-11T04:30:11Z	2026-10-11T04:30:11Z	GetFunction20150331v2	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-
9	2026-10-11T04:32:31Z	2026-10-11T05:52:35Z	ListInstanceAssociations	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
18	2026-10-11T04:32:51Z	2026-10-11T05:57:54Z	GetFunction20150331v2	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	10.81.0.102	-
41	2026-10-11T04:33:01Z	2026-10-11T07:23:01Z	UpdateInstanceInformation	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
1	2026-10-11T04:42:52Z	2026-10-11T04:42:52Z	GetPolicy20150331v2	arn:aws:iam::111122223333:root	198.18.0.3	-
2	2026-10-11T04:42:52Z	2026-10-11T04:42:52Z	GetFunction20150331v2	arn:aws:iam::111122223333:root	198.18.0.3	-
2	2026-10-11T04:42:52Z	2026-10-11T04:42:52Z	GetFunctionCodeSigningConfig	arn:aws:iam::111122223333:root	198.18.0.3	-
2	2026-10-11T04:42:52Z	2026-10-11T04:42:52Z	ListVersionsByFunction20150331	arn:aws:iam::111122223333:root	198.18.0.3	-
2	2026-10-11T04:43:09Z	2026-10-11T05:48:49Z	AssumeRoleWithWebIdentity	arn:aws:iam::111122223333:user/system:serviceaccount:device-support:portal-api	198.18.8.1	-
1	2026-10-11T04:48:44Z	2026-10-11T04:48:44Z	GetPolicy20150331v2	arn:aws:iam::111122223333:root	198.18.18.1	-
2	2026-10-11T04:48:44Z	2026-10-11T04:48:44Z	GetFunction20150331v2	arn:aws:iam::111122223333:root	198.18.18.1	-
2	2026-10-11T04:48:44Z	2026-10-11T04:48:44Z	GetFunctionCodeSigningConfig	arn:aws:iam::111122223333:root	198.18.18.1	-
2	2026-10-11T04:48:44Z	2026-10-11T04:48:44Z	ListVersionsByFunction20150331	arn:aws:iam::111122223333:root	198.18.18.1	-
1	2026-10-11T05:00:03Z	2026-10-11T05:00:03Z	GetCallerIdentity	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
76	2026-10-11T05:00:03Z	2026-10-11T07:23:44Z	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
2	2026-10-11T05:00:04Z	2026-10-11T05:56:07Z	Decrypt	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.20.1	-
1	2026-10-11T05:00:08Z	2026-10-11T05:00:08Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.21.1	-
1	2026-10-11T05:00:10Z	2026-10-11T05:00:10Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.22.1	-
10	2026-10-11T05:04:14Z	2026-10-11T05:54:33Z	DescribeExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
1	2026-10-11T05:14:33Z	2026-10-11T05:14:33Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.25.1	-
1	2026-10-11T05:14:33Z	2026-10-11T05:14:33Z	Decrypt	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.26.1	-
1	2026-10-11T05:14:38Z	2026-10-11T05:14:38Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.27.1	-
1	2026-10-11T05:24:09Z	2026-10-11T05:24:09Z	Decrypt	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.1	-
1	2026-10-11T05:24:16Z	2026-10-11T05:24:16Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.30.1	-
1	2026-10-11T05:24:18Z	2026-10-11T05:24:18Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.31.1	-
1	2026-10-11T05:54:03Z	2026-10-11T05:54:03Z	Decrypt	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.40.1	-
1	2026-10-11T05:54:07Z	2026-10-11T05:54:07Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.42.1	-
1	2026-10-11T05:54:07Z	2026-10-11T05:54:07Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.41.1	-
1	2026-10-11T05:56:15Z	2026-10-11T05:56:15Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.43.1	-
1	2026-10-11T05:56:15Z	2026-10-11T05:56:15Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.44.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	GetFunctionConcurrency	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	GetRuntimeManagementConfig	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	ListAliases20150331	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	ListEventSourceMappings20150331	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	ListFunctionUrlConfigs	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	ListProvisionedConcurrencyConfigs	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	GetFunctionConfiguration20150331v2	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
2	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	GetFunctionEventInvokeConfig	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	ResourceNotFoundException
2	2026-10-11T06:00:39Z	2026-10-11T06:00:39Z	ListVersionsByFunction20150331	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
8	2026-10-11T06:00:39Z	2026-10-11T06:00:46Z	GetFunction20150331v2	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:40Z	2026-10-11T06:00:40Z	GetFunctionCodeSigningConfig	arn:aws:iam::111122223333:user/blue-team-1	198.18.23.1	-
1	2026-10-11T06:00:40Z	2026-10-11T06:00:40Z	GetPolicy20150331	arn:aws:iam::111122223333:user/blue-team-1	AWS Internal	-
2	2026-10-11T06:00:40Z	2026-10-11T06:00:41Z	ListEventSourceMappings20150331	arn:aws:iam::111122223333:user/blue-team-1	AWS Internal	-
2	2026-10-11T06:09:40Z	2026-10-11T06:32:11Z	CreateDataChannel	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
1	2026-10-11T06:10:28Z	2026-10-11T06:10:28Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.46.1	-
1	2026-10-11T06:34:25Z	2026-10-11T06:34:25Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.48.1	-
1	2026-10-11T06:34:26Z	2026-10-11T06:34:26Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.49.1	-
6	2026-10-11T06:36:22Z	2026-10-11T07:05:47Z	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	-
1	2026-10-11T06:39:20Z	2026-10-11T06:39:20Z	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	AccessDenied
1	2026-10-11T06:39:49Z	2026-10-11T06:39:49Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.51.1	-
1	2026-10-11T06:40:52Z	2026-10-11T06:40:52Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.52.1	-
1	2026-10-11T06:49:30Z	2026-10-11T06:49:30Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.54.1	-
1	2026-10-11T06:49:32Z	2026-10-11T06:49:32Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.55.1	-
3	2026-10-11T06:52:08Z	2026-10-11T07:08:11Z	StartExecution	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.50.1	-
1	2026-10-11T06:52:11Z	2026-10-11T06:52:11Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.56.1	-
1	2026-10-11T06:52:12Z	2026-10-11T06:52:12Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.57.1	-
1	2026-10-11T06:59:48Z	2026-10-11T06:59:48Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.59.1	-
1	2026-10-11T06:59:56Z	2026-10-11T06:59:56Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.29.2	-
1	2026-10-11T07:02:09Z	2026-10-11T07:02:09Z	StartSession	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
1	2026-10-11T07:09:30Z	2026-10-11T07:09:30Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.62.1	-
2	2026-10-11T07:11:37Z	2026-10-11T07:12:16Z	SendCommand	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.7.1	AccessDenied
1	2026-10-11T07:18:39Z	2026-10-11T07:18:39Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.65.1	-
1	2026-10-11T07:18:43Z	2026-10-11T07:18:43Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.66.1	-
1	2026-10-11T07:19:43Z	2026-10-11T07:19:43Z	PutConfigurePackageResult	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-portal-role/i-05816900800807b77	198.18.10.1	-
1	2026-10-11T07:23:48Z	2026-10-11T07:23:48Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-provider-role/patchsignal-ewc2enb8-provider-api	198.18.67.1	-
1	2026-10-11T07:23:49Z	2026-10-11T07:23:49Z	CreateLogStream	arn:aws:sts::111122223333:assumed-role/patchsignal-ewc2enb8-feed-role/patchsignal-ewc2enb8-feed-connector	198.18.68.1	-
```

실행한 명령:
```
echo "## D-2) 같은 243건의 eventName + requestParameters 조합별 건수"; jq -r '.Records[] | select(tostring | test("portal-api|PatchSignal|device-support"; "i"))|[.eventName,(.requestParameters|tojson)]|@tsv' cloudtrail.json | sort | uniq -c | sort -rn
```
결과:
```
## D-2) 같은 243건의 eventName + requestParameters 조합별 건수
     41 UpdateInstanceInformation	{"instanceId":"i-05816900800807b77"}
     26 CreateLogStream	null
     20 GetFunction20150331v2	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
     10 DescribeExecution	null
      9 ListInstanceAssociations	{"instanceId":"i-05816900800807b77"}
      7 GetFunction20150331v2	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      5 Decrypt	null
      4 StartExecution	null
      4 ListVersionsByFunction20150331	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      3 GetFunctionCodeSigningConfig	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      3 GetFunction20150331v2	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      2 StartSession	null
      2 SendCommand	null
      2 ListVersionsByFunction20150331	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
      2 GetPolicy20150331v2	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      2 GetFunctionEventInvokeConfig	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      2 GetFunctionCodeSigningConfig	{"functionName":"patchsignal-ewc2enb8-feed-connector"}
      2 CreateDataChannel	null
      2 AssumeRoleWithWebIdentity	null
      1 StartExecution	{"name":"test-run-1791702344"}
      1 StartExecution	{"name":"test-run-1791702300"}
      1 StartExecution	{"name":"test-run-1791702223"}
      1 StartExecution	{"name":"case-redteam-validation-003"}
      1 StartExecution	{"name":"case-redteam-validation-002"}
      1 StartExecution	{"name":"case-fbb05947e56c499e96d1d16d2c892dc0"}
      1 StartExecution	{"name":"case-fa0d1770f10a411fa41828583ed12629"}
      1 StartExecution	{"name":"case-f6c5d9a230de4a01801f741390f2e3b2"}
      1 StartExecution	{"name":"case-f4b1237d8e5c4f3783b6044947f151dd"}
      1 StartExecution	{"name":"case-f0a5af86a3e44a9ebaff1b4bebcd08f8"}
      1 StartExecution	{"name":"case-ed703c00f8d244078c7556ffb60e51fe"}
      1 StartExecution	{"name":"case-ec4331c54acf42f3a59e7132efe11b0f"}
      1 StartExecution	{"name":"case-eb91f8b2e2b04896a882c27133e28461"}
      1 StartExecution	{"name":"case-eb71ed0b742a427a95a43510221f7b09"}
      1 StartExecution	{"name":"case-e916046f53354298993ded760794f74b"}
      1 StartExecution	{"name":"case-e8750b17c50c4ca1a969c651378e30d1"}
      1 StartExecution	{"name":"case-d6f2d75697cf4d08a93b33f732041ca2"}
      1 StartExecution	{"name":"case-d6eedaf93586449181c041640420353f"}
      1 StartExecution	{"name":"case-d5f1222f52fe42e8b92425303221593c"}
      1 StartExecution	{"name":"case-d29e27d29f7248aab5a84a408e412a67"}
      1 StartExecution	{"name":"case-cf9e53c9db264165bdf9c0c2c9e68eae"}
      1 StartExecution	{"name":"case-ce9a3813730946a589abe7594a1333d7"}
      1 StartExecution	{"name":"case-cb72d8aee366407d893a24225873062f"}
      1 StartExecution	{"name":"case-cb02cccacd70467596f974a47a96587b"}
      1 StartExecution	{"name":"case-ca2cc76cc42945f496c9765225aab09b"}
      1 StartExecution	{"name":"case-c36bdc34305b443590da6326c1654059"}
      1 StartExecution	{"name":"case-c19372bae32149bdbc205a80516afaf1"}
      1 StartExecution	{"name":"case-c0c4b96befa94fa188b722778b75aa0f"}
      1 StartExecution	{"name":"case-bb4c5667790542719e2ee83f062fd919"}
      1 StartExecution	{"name":"case-bb38364049494742898ed45450660962"}
      1 StartExecution	{"name":"case-b84950bc61a944ffae0fa25712edb685"}
      1 StartExecution	{"name":"case-b4e1f4a4843e4e778d71dde9e86bbe61"}
      1 StartExecution	{"name":"case-b4d3e90ede9841ddb46913fbaf2d089c"}
      1 StartExecution	{"name":"case-b22c6e2168874834b2bd0f33771fddfb"}
      1 StartExecution	{"name":"case-b1a40ea5454c414f9f1f8ecfe6ed1187"}
      1 StartExecution	{"name":"case-a8e4cd31749f44e69e83e632c003e44b"}
      1 StartExecution	{"name":"case-a7c0409ec5fc420cab3441d5e8588f3e"}
      1 StartExecution	{"name":"case-a6ee907fb65742e8a63a41aa431f9a85"}
      1 StartExecution	{"name":"case-a5580f6c439849f592c64ffdd12b2524"}
      1 StartExecution	{"name":"case-a4202545a011401389be9b97eb47ee9e"}
      1 StartExecution	{"name":"case-9d42843c59b34949a7abe721618cce8f"}
      1 StartExecution	{"name":"case-9c5f0ced9a8f40dca63cc1d2fee0847c"}
      1 StartExecution	{"name":"case-991521209e1e4cb6b73d4e72e93240c8"}
      1 StartExecution	{"name":"case-93bea42739fa4138918068ed138e6c42"}
      1 StartExecution	{"name":"case-938d4738cd374b98be678f5bfda9a983"}
      1 StartExecution	{"name":"case-9339665a7b8c4d74926d4bbcb5d4f4a0"}
      1 StartExecution	{"name":"case-8919cca21f05494487d4b868d6029921"}
      1 StartExecution	{"name":"case-872925e26fe14d5081d3d31708b8ee31"}
      1 StartExecution	{"name":"case-85f359ca6cd44366af38ca65888bf9e5"}
      1 StartExecution	{"name":"case-80c425dae7044b85a0b8851ad4e209ee"}
      1 StartExecution	{"name":"case-7fe6fd5484b245a0b0559b9d0cdbee15"}
      1 StartExecution	{"name":"case-7a12923a50e2475491968cd7e4236c40"}
      1 StartExecution	{"name":"case-76124a0dad8f4187b03c04eaf3b45940"}
      1 StartExecution	{"name":"case-6957139478d34a6998057315d61b2f92"}
      1 StartExecution	{"name":"case-63096791d5354d03a127d9942433627b"}
      1 StartExecution	{"name":"case-61578bcb434a4dd8aa9ff5420f0ecf26"}
      1 StartExecution	{"name":"case-5b9a97abada54c929975b280e7f79dc7"}
      1 StartExecution	{"name":"case-578eefa07daf4478b50f6d3c6948fa28"}
      1 StartExecution	{"name":"case-560ab29b419d4fd6857f12a96b0c9339"}
      1 StartExecution	{"name":"case-55ae4197ed9c42d19eb6d1e12fa4240a"}
      1 StartExecution	{"name":"case-54cf79d907514c33b7ddbd5f69ab5490"}
      1 StartExecution	{"name":"case-536113bf81ee42e88b160ecc8d6ea3cc"}
      1 StartExecution	{"name":"case-5102fac6957a4fd889c56947d670d00c"}
      1 StartExecution	{"name":"case-4a6e7d5d8c1f4d389c662dd4700abf27"}
      1 StartExecution	{"name":"case-46e7e80716864a6c97b4a5b7557afbdb"}
      1 StartExecution	{"name":"case-469d6faa796c4c52b95b01b2c6e2a418"}
      1 StartExecution	{"name":"case-432772485c824a46ba2a4e50606182bf"}
      1 StartExecution	{"name":"case-4220d74b91684fd4851f292c7266fd0c"}
      1 StartExecution	{"name":"case-3d760f72c0da458f922642252a5254b6"}
      1 StartExecution	{"name":"case-3d6beffade09439383d13b1332e53e3c"}
      1 StartExecution	{"name":"case-3cbd0f0899b14af5900e19b947a3f548"}
      1 StartExecution	{"name":"case-34fdf7faf8e447f6b86865480a9414ba"}
      1 StartExecution	{"name":"case-27234d5bb55e4f6eadb510aa4201afd3"}
      1 StartExecution	{"name":"case-26a3b3e40ded4ffa8fa538f5f0672ba5"}
      1 StartExecution	{"name":"case-1d973696c12246fdbb7e872793de1f42"}
      1 StartExecution	{"name":"case-17d2b4cf3d3c427b8280756aa59dcda8"}
      1 StartExecution	{"name":"case-0eb18af607204850a7043b9377a77821"}
      1 StartExecution	{"name":"case-0e49e9d53e854399b746229fb6064a35"}
      1 StartExecution	{"name":"case-0471810233df4c408149a45e82a4870a"}
      1 StartExecution	{"name":"case-0284eab122bd4d41a708da6a81cafc6c"}
      1 StartExecution	{"name":"case-01847f5d9bef4b21b1279a787990f575"}
      1 PutConfigurePackageResult	null
      1 ListProvisionedConcurrencyConfigs	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 ListFunctionUrlConfigs	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 ListEventSourceMappings20150331	{"functionName":"patchsignal-ewc2enb8-provider-api:$LATEST"}
      1 ListEventSourceMappings20150331	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 ListEventSourceMappings20150331	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      1 ListAliases20150331	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 GetRuntimeManagementConfig	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      1 GetPolicy20150331	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      1 GetFunctionConfiguration20150331v2	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 GetFunctionConfiguration20150331v2	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-provider-api"}
      1 GetFunctionConcurrency	{"functionName":"patchsignal-ewc2enb8-provider-api"}
      1 GetFunction20150331v2	{"functionName":"arn:aws:lambda:us-west-1:111122223333:function:patchsignal-ewc2enb8-feed-connector"}
      1 GetCallerIdentity	null
```

실행한 명령:
```
echo "## E-1) SecurityGroup 이벤트 중 Describe 제외 원본 전체"; jq -c '.Records[] | select(.eventName | test("SecurityGroup")) | select(.eventName|test("^Describe")|not)' cloudtrail.json
echo; echo "## E-2) Describe* SecurityGroup 이벤트(80건) 요약: 건수 / 최초 / 최종 / eventName / 신원 / IP / errorCode / requestParameters"; jq -r '.Records[] | select(.eventName | test("^DescribeSecurityGroup"))|[.eventName,(.userIdentity.arn//.userIdentity.type),.sourceIPAddress,(.errorCode//"-"),(.requestParameters|tojson),.eventTime]|@tsv' cloudtrail.json | awk -F'\t' '{k=$1"\t"$2"\t"$3"\t"$4"\t"$5; c[k]++; if(!(k in f)) f[k]=$6; l[k]=$6} END{for(k in c) print c[k]"\t"f[k]"\t"l[k]"\t"k}' | sort -t$'\t' -k2,2
```
결과:
```
## E-1) SecurityGroup 이벤트 중 Describe 제외 원본 전체
{"eventTime":"2026-10-11T04:39:33Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAA35E…DE4A"}}
{"eventTime":"2026-10-11T05:09:28Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:09:29Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIA8AA2…CB09"}}
{"eventTime":"2026-10-11T05:27:36Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"},"errorCode":"Client.DryRunOperation"}
{"eventTime":"2026-10-11T05:27:37Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAF61C…0505"}}
{"eventTime":"2026-10-11T05:38:38Z","eventSource":"ec2.amazonaws.com","eventName":"RevokeSecurityGroupIngress","sourceIPAddress":"198.18.2.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/blue-team-1","accessKeyId":"ASIAAAE2…BA68"}}
{"eventTime":"2026-10-11T07:18:34Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"guardduty.amazonaws.com","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","accessKeyId":"ASIA3CF9…09AC"}}
{"eventTime":"2026-10-11T07:18:34Z","eventSource":"ec2.amazonaws.com","eventName":"CreateSecurityGroup","sourceIPAddress":"guardduty.amazonaws.com","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","accessKeyId":"ASIA3CF9…09AC"}}
{"eventTime":"2026-10-11T07:18:35Z","eventSource":"ec2.amazonaws.com","eventName":"RevokeSecurityGroupEgress","sourceIPAddress":"guardduty.amazonaws.com","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyRuntimeMonitoring","accessKeyId":"ASIA3CF9…09AC"}}

## E-2) Describe* SecurityGroup 이벤트(80건) 요약: 건수 / 최초 / 최종 / eventName / 신원 / IP / errorCode / requestParameters
3	2026-10-11T04:30:40Z	2026-10-11T05:41:29Z	DescribeSecurityGroups	arn:aws:iam::111122223333:user/blue-team-1	198.18.3.1	-	null
11	2026-10-11T04:30:44Z	2026-10-11T04:39:59Z	DescribeSecurityGroups	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null
7	2026-10-11T04:30:49Z	2026-10-11T06:00:49Z	DescribeSecurityGroups	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS	eks.amazonaws.com	-	null
10	2026-10-11T04:31:33Z	2026-10-11T06:01:33Z	DescribeSecurityGroups	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS	eks-nodegroup.amazonaws.com	-	null
3	2026-10-11T04:33:20Z	2026-10-11T04:34:26Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:user/blue-team-1	198.18.5.1	-	null
13	2026-10-11T04:39:16Z	2026-10-11T05:38:40Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null
1	2026-10-11T04:39:53Z	2026-10-11T04:39:53Z	DescribeSecurityGroups	arn:aws:iam::111122223333:user/blue-team-1	198.18.2.1	-	null
4	2026-10-11T04:40:13Z	2026-10-11T05:40:57Z	DescribeSecurityGroups	arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForConfig/AWSConfig-Describe	config.amazonaws.com	-	null
3	2026-10-11T04:42:49Z	2026-10-11T04:42:49Z	DescribeSecurityGroups	arn:aws:iam::111122223333:root	198.18.0.3	-	null
5	2026-10-11T04:42:49Z	2026-10-11T04:42:50Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:root	198.18.0.3	-	null
1	2026-10-11T04:42:50Z	2026-10-11T04:42:50Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:root	198.18.14.1	-	null
3	2026-10-11T04:48:41Z	2026-10-11T04:48:42Z	DescribeSecurityGroups	arn:aws:iam::111122223333:root	198.18.18.1	-	null
6	2026-10-11T04:48:42Z	2026-10-11T04:48:42Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:root	198.18.18.1	-	null
9	2026-10-11T05:14:04Z	2026-10-11T05:58:46Z	DescribeSecurityGroups	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-	null
1	2026-10-11T05:58:46Z	2026-10-11T05:58:46Z	DescribeSecurityGroupRules	arn:aws:iam::111122223333:user/blue-team-2	198.18.23.1	-	null
```

실행한 명령:
```
echo "## F) 10분 단위 이벤트 수"; jq -r '.Records[].eventTime[0:15]' cloudtrail.json | sort | uniq -c
```
결과:
```
## F) 10분 단위 이벤트 수
   1096 2026-10-11T04:3
    806 2026-10-11T04:4
    876 2026-10-11T04:5
    636 2026-10-11T05:0
    822 2026-10-11T05:1
   1169 2026-10-11T05:2
   1289 2026-10-11T05:3
   1247 2026-10-11T05:4
   1549 2026-10-11T05:5
    362 2026-10-11T06:0
     88 2026-10-11T06:1
     58 2026-10-11T06:2
     42 2026-10-11T06:3
     51 2026-10-11T06:4
     22 2026-10-11T06:5
     34 2026-10-11T07:0
     50 2026-10-11T07:1
     26 2026-10-11T07:2
```

## 채팅 AI



## 사용자

메시지가 비어 있어서 받은 내용이 없습니다. 그래서 이번에는 새로 뽑아서 보내는 것이 없습니다. 지난번에 보낸 A~F 결과를 보시고 확인할 명령이나 질문이 있으면 다시 보내 주세요.

이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지).

## 채팅 AI



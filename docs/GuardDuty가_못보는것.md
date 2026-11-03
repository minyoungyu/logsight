# GuardDuty가 보지 못하는 것: 탐지 유형 대조

확인일 2026-11-03. 근거는 AWS 공식 문서(맨 아래 출처)와 공방전 로그(가명 처리본)다. "평소와 다를 때만", "추정"으로 적은 곳은 문서에 명시되지 않은 판단이다.

## 결론 먼저

1. **GuardDuty는 켜기 전의 일을 보지 못한다.** FAQ: GuardDuty "does not look at historical data, only activity that starts after it is enabled." 공방전에서 블루팀은 공격(14:10~16:08 KST)이 끝난 뒤 16:09에 GuardDuty를 켰다(CloudTrail `CreateDetector` 07:09:19Z, 블루팀 보고서 "GuardDuty는 16:09:19에 활성화했다"). 그래서 이 사고에 대한 GuardDuty 결과는 0건이다. LogSight는 이미 쌓인 로그를 사후에 읽으므로 같은 상황에서 분석이 된다.
2. **GuardDuty는 웹과 서버 안쪽을 보지 못한다.** 읽는 로그는 CloudTrail 관리 이벤트, VPC Flow Logs, DNS 로그(그리고 유료 보호 플랜)뿐이고 ALB·WAF·웹서버·auth.log는 읽지 않는다. 공식 탐지 유형 목록(약 200개)에 HTTP 요청 내용(SQL 인젝션, 경로 조작, IDOR, SSRF 등)을 보는 유형이 없다.
3. **그래서 "어떻게 들어왔나"를 모른다.** 공방전 공격은 웹(WAF·ALB 기록) → 서버 역할 키 외부 사용(CloudTrail) 순서였다. GuardDuty가 켜져 있었다면 뒷부분(키 외부 사용)은 잡았겠지만, 앞부분(웹 진입)은 GuardDuty 데이터에 없다.
4. **반대로 GuardDuty가 보는데 LogSight가 못 보는 것도 많다.** DNS 기반 탐지(C&C, 채굴, DGA), 악성코드 검사, 서버 프로세스 감시(Runtime Monitoring), EKS·RDS·Lambda, 위협 정보 IP 목록, 계정별 평소 행동 학습. LogSight는 GuardDuty를 대체하지 않는다.

## 1. 공방전 사고에 대입

| 단계(블루팀 보고서) | 남은 로그 | GuardDuty(켜져 있었다면) | LogSight 실제 결과 |
| --- | --- | --- | --- |
| G1 웹앱에 메타데이터 주소 요청(WAF 차단) | WAF | 못 봄(WAF 로그를 읽지 않음) | 탐지(WAF_BLOCKED) |
| G2 서명 없는 토큰으로 EKS 지원 API 접근 | WAF | 못 봄 | 탐지(WAF_BLOCKED) |
| G3 PageSnap PDF 내려받기 | ALB | 못 봄 | **못 잡음**(정상 다운로드와 구별 못 함) |
| G4 EC2 역할 임시 키를 외부 IP에서 사용 | CloudTrail | 잡았을 것(InstanceCredentialExfiltration.OutsideAWS) | 탐지(CT_INSTANCE_CRED_MULTI_IP) |
| G5 그 키로 워크플로 실행 성공 | CloudTrail | 같은 키의 결과·공격 순서에 묶였을 것(추정) | 탐지, 같은 사건으로 묶음 |
| G6 그 키로 SSM 명령·세션 시도(거부) | CloudTrail | 같은 키의 결과에 묶였을 것(추정) | 탐지, 같은 사건으로 묶음 |
| 실제 (GuardDuty 16:09 활성화) | | **0건**(과거 데이터를 보지 않음) | 위 결과 그대로 |

G1~G3은 GuardDuty 범위 밖이고, G3은 LogSight도 놓쳤다. G4~G6은 둘 다 본다. 다른 점은 LogSight가 G1·G2(웹)와 G4~G6(키)을 같은 IP·같은 /24로 한 사건 묶음으로 잇고, 원인 설정(IMDSv1 허용 등)과 수정안을 붙인다는 것이다(설정 스냅샷이 있을 때).

## 2. LogSight 규칙과 GuardDuty 탐지 유형 대조

GuardDuty 공식 "활성 탐지 유형" 목록과 LogSight 규칙을 하나씩 맞췄다. 있음 = 같은 일을 하는 탐지 유형이 있음, 조건부 = 평소와 다를 때만(학습 기반)·유료 플랜·위협 정보 목록에 오른 IP만, 없음 = 대응 유형이 없거나 그 로그를 읽지 않음.

**요약(규칙 48개, GuardDuty 결과 입력 규칙 제외)**

| 로그 | 있음 | 조건부 | 없음 |
| --- | --- | --- | --- |
| CloudTrail (13) | 3 | 8 | 2 |
| VPC Flow Logs (2) | 2 | 0 | 0 |
| 서버 auth.log (2) | 1 (Flow Logs로 접속 패턴만) | 0 | 1 (로그인 성공) |
| WAF 로그 (2) | 0 | 0 | 2 |
| ALB 접속 로그 (3) | 0 | 0 | 3 |
| 웹서버 로그 (24) | 0 | 0 | 24 |
| 웹 루트 파일 목록 (2) | 0 | 2 | 0 |

웹서버 규칙이 24개라 "없음" 숫자가 커 보인다. 숫자보다 **어느 단계가 비는지**가 핵심이다. CloudTrail·Flow Logs 영역은 GuardDuty가 대부분 덮고, 웹 요청과 서버 로그인 결과는 전혀 덮지 않는다.

| 로그 | LogSight 규칙 | GuardDuty 대응 | 판정 |
| --- | --- | --- | --- |
| CloudTrail | 감사 로그(CloudTrail/Flow Logs) 중지·삭제 | Stealth:IAMUser/CloudTrailLoggingDisabled (Flow Logs 삭제는 해당 유형 없음) | 조건부 |
| CloudTrail | 루트 계정 사용 | Policy:IAMUser/RootCredentialUsage | 있음 |
| CloudTrail | IAM 사용자·키·권한 생성/변경 | Persistence:IAMUser/AnomalousBehavior (평소와 다를 때만) | 조건부 |
| CloudTrail | 보안그룹을 0.0.0.0/0에 개방 | 해당 유형 없음 (설정 점검은 Security Hub·Config 영역) | 없음 |
| CloudTrail | 스냅샷·AMI를 외부 계정과 공유 | Exfiltration:IAMUser/AnomalousBehavior (평소와 다를 때만) | 조건부 |
| CloudTrail | 인스턴스 역할 자격증명이 여러 IP에서 사용 | UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS/OutsideAWS | 있음 |
| CloudTrail | 인스턴스 역할 자격증명이 인스턴스 밖에서 사용 | UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS | 있음 |
| CloudTrail | 권한 없는 API를 연속 시도(권한 탐색) | Discovery:IAMUser/AnomalousBehavior (평소와 다를 때만) | 조건부 |
| CloudTrail | 계정·자원 목록 조회 연속 실행 | Discovery:IAMUser/AnomalousBehavior (평소와 다를 때만) | 조건부 |
| CloudTrail | S3 객체 대량 조회 | Exfiltration:S3/AnomalousBehavior (S3 보호 플랜, 추가 요금) | 조건부 |
| CloudTrail | 신뢰 목록 밖 IP에서 자격증명 사용 | MaliciousIPCaller / TorIPCaller (위협 정보에 오른 IP만. 우리 팀 IP 목록 기준은 없음) | 조건부 |
| CloudTrail | MFA 없는 콘솔 로그인 | 해당 유형 없음 (ConsoleLoginSuccess.B는 이상 로그인) | 없음 |
| CloudTrail | 인스턴스 대량 생성(자원 탈취 의심) | Impact:IAMUser/AnomalousBehavior (평소와 다를 때만) | 조건부 |
| VPC Flow Logs | 여러 포트에 대한 접속 시도(포트 스캔) | Recon:EC2/Portscan, Impact:EC2/PortSweep | 있음 |
| VPC Flow Logs | 외부에서 관리 포트(22/3389) 접속 허용 | Recon:EC2/PortProbeUnprotectedPort | 있음 |
| WAF 로그 | SQL 인젝션 탐지됐지만 차단 안 됨(COUNT/ALLOW) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| WAF 로그 | WAF가 공격 요청 차단 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 서버 auth.log | SSH 비밀번호 연속 실패(무차별 대입) | UnauthorizedAccess:EC2/SSHBruteForce (Flow Logs로 접속 패턴만) | 있음 |
| 서버 auth.log | 연속 실패 뒤 SSH 로그인 성공 | 해당 유형 없음 (로그인 성공 여부는 auth.log에만 있음) | 없음 |
| ALB 접속 로그 | 웹 요청에 SQL 인젝션 패턴 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| ALB 접속 로그 | 없는 경로를 연속 요청(웹 스캐너) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| ALB 접속 로그 | 남의 객체 번호를 바꿔 가며 접근 시도(IDOR 탐색) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 웹 요청에 SQL 인젝션 패턴 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 경로 조작·파일 열람(../, 민감 파일) 시도 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 원격 파일 포함(RFI) 시도 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 운영체제 명령 삽입 시도 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 교차 사이트 스크립트(XSS) 시도 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 취약점 스캐너·자동 도구 탐지 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 존재하지 않는 경로 연속 탐색(열거) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 설정·비밀 파일 접근 시도(.env 등) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 웹셸로 보이는 경로에 접근 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 업로드 폴더의 스크립트 실행 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 웹 로그인 무차별 대입 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 로그인 연속 실패 뒤 성공 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 요청 헤더(User-Agent 등)에 실행 코드 삽입(로그 포이즈닝 준비) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 관리자 영역 접근 성공(기본 계정 로그인 의심) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 서버를 이용해 내부 주소를 요청(SSRF) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 열린 리다이렉트(외부 사이트로 보내기) 시도 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 다른 사람의 주문 번호를 차례로 열람(IDOR) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 로그인 없이 관리자 영역 접근(쿠키 위조 의심) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 외부 사이트에서 관리자 작업 요청(CSRF 의심) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 백업·덤프·소스(.git 등) 파일이 외부에 노출됨 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 업로드 폴더 목록이 외부에 공개됨 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 알려진 취약점 공격 문자열(헤더) 시도 — Log4Shell·Shellshock 등 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 공격 요청에 서버 오류(500) 응답 — 취약점 반응 | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹서버 로그(nginx/apache) | 공격 요청 뒤 비정상적으로 큰 응답(데이터 유출 의심) | 해당 유형 없음 (GuardDuty는 이 로그를 읽지 않음) | 없음 |
| 웹 루트 파일 목록 | 웹 루트에서 웹셸 의심 파일 발견 | Execution:EC2/MaliciousFile (EBS 악성코드 검사, 알려진 악성 파일)·Runtime Monitoring(추가 요금) | 조건부 |
| 웹 루트 파일 목록 | 웹 루트에서 의심스러운 신규·수정 파일 | Runtime Monitoring의 NewBinaryExecuted 등(추가 요금, 실행될 때) | 조건부 |

## 3. "조건부"가 뜻하는 것

- **평소와 다를 때만**: `AnomalousBehavior` 계열은 계정의 평소 행동을 학습해 벗어날 때만 결과를 낸다(GuardDuty 문서). 처음 쓰는 계정이나 원래 관리자가 자주 하는 작업이면 안 나올 수 있다. LogSight 규칙은 정해진 조건이면 항상 표시한다. 어느 쪽이 나은지는 상황에 따라 다르다. 학습 기반은 오탐이 적고, 규칙은 예측 가능하다.
- **위협 정보 IP만**: `MaliciousIPCaller`는 알려진 악성 IP 목록에 있을 때다. LogSight의 `CT_UNTRUSTED_IP`는 사용자가 적은 "우리 IP" 목록 밖이면 표시한다. 둘은 기준이 다르다.
- **유료 플랜**: S3 데이터 이벤트(S3 보호), 서버 프로세스(Runtime Monitoring, vCPU당 월 1.5달러), 악성코드 검사는 기본 요금에 들어 있지 않다.

## 4. GuardDuty가 보는데 LogSight가 못 보는 것

| 영역 | GuardDuty 탐지 유형 예 | LogSight |
| --- | --- | --- |
| DNS 기반(C&C 접속, 채굴, DGA, DNS 유출) | Backdoor:EC2/C&CActivity.B!DNS, Trojan:EC2/DNSDataExfiltration | 없음(DNS 로그를 안 읽음) |
| 위협 정보 IP·Tor | UnauthorizedAccess:EC2/TorClient, Recon:IAMUser/MaliciousIPCaller | 없음(위협 정보 목록 없음) |
| 서버 프로세스·파일(에이전트) | Execution:Runtime/ReverseShell, CryptoMinerExecuted | 없음 |
| 악성코드 검사 | Execution:EC2/MaliciousFile | 웹 루트 파일 이름·위치만 봄 |
| EKS·RDS·Lambda | Kubernetes, RDS 로그인, Lambda 네트워크 계열 | 없음 |
| 평소 행동 학습 | *:IAMUser/AnomalousBehavior | 없음(고정 규칙) |
| 대규모 트래픽 이상 | Behavior:EC2/TrafficVolumeUnusual, DenialOfService | 없음 |

## 5. 정리: LogSight가 맡을 자리

- GuardDuty는 **켜 둔 뒤부터 24시간 감시하는 경보기**다. 계정·네트워크 수준의 위협은 GuardDuty가 넓고 정확하다.
- LogSight가 메울 수 있는 빈칸은 세 가지다(위 대조와 공방전 사례 근거).
  1. **켜기 전 / 이미 지난 사고**: 남아 있는 로그로 사후 분석한다.
  2. **웹·서버 안쪽**: WAF·ALB·웹서버·auth.log로 "어떻게 들어왔나"와 "실제로 성공했나"를 본다.
  3. **고칠 설정**: GuardDuty 일반 결과에는 수정 방법이 없다(FAQ, 공격 순서 결과에만 단계별 권고가 있다). LogSight는 설정 스냅샷과 대조해 이 계정의 어떤 설정을 바꿀지 근거와 함께 보여 준다.
- 한계: G3처럼 정상 요청과 모양이 같은 공격은 LogSight도 놓친다. 웹 규칙은 패턴 기반이라 우회될 수 있다. 이 대조는 탐지 유형 이름과 문서 설명 기준이며, 같은 데이터에 GuardDuty를 실제로 돌려 비교한 것은 아니다(GuardDuty는 과거 로그를 넣어 돌릴 수 없다).

## 출처

- [GuardDuty 활성 탐지 유형 목록](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [GuardDuty foundational data sources](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html)
- [GuardDuty FAQ](https://aws.amazon.com/guardduty/faqs/): 과거 데이터를 보지 않음, 로그를 보관하지 않음, 결과 90일 보관, 공격 순서 결과의 단계별 권고
- [GuardDuty Extended Threat Detection](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-extended-threat-detection.html)
- 공방전: `data/gongbang/cloudtrail.json`(가명, 저장소 밖) `CreateDetector` 2026-10-11T07:09:19Z, 블루팀 최종 보고서, `reports/ctf/gongbang_rules_v3.json`

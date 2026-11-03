# GuardDuty와 LogSight: 보는 로그와 비용

확인일: 2026-11-03. 출처는 맨 아래 AWS 공식 문서. 요금은 AWS 요금 페이지 예시 기준(us-east-1)이며 리전마다 다르다.

## 1. GuardDuty가 읽는 로그와 못 읽는 로그

GuardDuty를 켜면 아래 세 가지(기본 데이터 원본)를 **사용자가 따로 켜지 않아도** AWS 내부 사본으로 읽는다.

| 로그 | GuardDuty | LogSight |
| --- | --- | --- |
| CloudTrail 관리 이벤트 | 읽음(기본) | 읽음 |
| VPC Flow Logs | 읽음(기본, 사용자가 안 켜도 됨) | 읽음(사용자가 켜야 함) |
| Route53 DNS 쿼리 로그 | 읽음(기본) | 안 읽음 |
| S3 데이터 이벤트, EKS 감사 로그, RDS 로그인, Lambda 네트워크 | 보호 플랜을 켜면 읽음(추가 요금) | S3 데이터 이벤트만 읽음 |
| **ALB 접속 로그** | **읽지 않음** | 읽음 |
| **WAF 로그** | **읽지 않음** | 읽음 |
| **서버 OS 로그(auth.log, 서버 방화벽)** | **읽지 않음** | 읽음 |
| 웹서버 로그(nginx/apache) | 읽지 않음 | 읽음 |

ALB·WAF·OS 로그는 GuardDuty 공식 문서의 데이터 원본 목록에 없다. 다만 두 가지는 정확히 적어 둔다.

- **SSH 무차별 대입 자체는 GuardDuty도 잡는다.** VPC Flow Logs로 22번 포트 접속 패턴을 보고 `UnauthorizedAccess:EC2/SSHBruteForce`를 낸다(통합 샘플에도 이 결과가 있다). 하지만 Flow Logs에는 로그인 성공 여부가 없다. **비밀번호를 틀리다가 결국 들어왔는지**는 auth.log에만 있다.
- **Runtime Monitoring**(서버에 GuardDuty 에이전트 설치, vCPU당 월 1.5달러)은 프로세스 실행, 파일 접근, 네트워크 연결을 본다. 공식 문서는 auth.log 같은 로그 파일을 읽는다고 하지 않는다.

즉 GuardDuty가 못 보는 곳은 **"웹·서버 안에서 실제로 무슨 일이 있었나"**다. SQL 인젝션 요청, 객체 번호 탐색(IDOR), WAF가 막은 것과 통과시킨 것, SSH 로그인 성공은 GuardDuty 결과에 나오지 않는다. LogSight는 이 로그들을 CloudTrail·Flow Logs와 한 사건으로 묶는다.

## 2. GuardDuty도 돈이 든다

이전 문서의 "추가 비용 없음"은 **GuardDuty 위에 얹는 Extended Threat Detection(공격 순서 묶기)이 추가 요금 없다**는 뜻이었다. GuardDuty 자체는 30일 무료 체험이 끝나면 사용량만큼 낸다. 문장이 오해를 부를 수 있어 고쳤다.

| 항목 | 요금(us-east-1 예시) |
| --- | --- |
| CloudTrail 관리 이벤트 | 100만 건당 4달러 |
| VPC Flow Logs + DNS 로그 | GB당 1달러(처음 500GB) |
| S3 보호(데이터 이벤트) | 100만 건당 0.8달러 |
| Runtime Monitoring | vCPU당 월 1.5달러 |

작은 팀(서버 몇 대, 관리 이벤트 월 수십만 건, Flow·DNS 월 수 GB)이면 **월 몇 달러 수준**으로 추정한다. 실제 금액은 계정마다 다르고, 30일 체험 중 GuardDuty 콘솔의 사용량 화면에서 예상 비용을 볼 수 있다.

## 3. "GuardDuty보다 싸면 우리 걸 쓰나?" → 가격으로는 이기기 어렵다

- 작은 계정에서 GuardDuty는 이미 월 몇 달러다. LogSight가 더 싸도 차이가 작다.
- LogSight도 비용이 0은 아니다. 분석할 로그를 켜야 하고(Flow Logs 월 0.2~0.3달러, WAF를 쓰면 월 8~9달러), Claude 모드는 API 요금이 든다. 규칙 모드는 AI 요금이 없다.
- 둘은 하는 일이 다르다. GuardDuty는 **24시간 감시하다 알려 주는 경보기**이고, LogSight는 **경보나 이상 징후가 생긴 뒤 무슨 일이 있었고 무엇을 고칠지 정리하는 도구**다. 경보기를 빼고 LogSight만 쓰면 사건을 늦게 알게 된다.

그래서 내세울 것은 가격이 아니라 **GuardDuty가 못 보는 로그와, 결과를 고칠 설정으로 바꿔 주는 것**이다.

> GuardDuty는 켜 두세요(무료 체험부터). LogSight는 GuardDuty 결과와 GuardDuty가 읽지 않는 ALB·WAF·서버 로그를 함께 읽어, 공격이 실제로 성공했는지와 고칠 설정을 근거와 함께 보여 줍니다.

이 위치가 맞는지는 고객 인터뷰에서 "GuardDuty를 켜 두었나, 경보를 받고 다음에 무엇을 했나"를 물어 확인한다(추정, 미검증).

## 출처

- [GuardDuty foundational data sources](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html): 기본 데이터 원본 3가지, 사용자가 Flow Logs를 따로 켤 필요 없음
- [Concepts and key terms in GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_concepts.html)
- [GuardDuty FAQ](https://aws.amazon.com/guardduty/faqs/): Runtime Monitoring이 보는 것(파일 접근, 프로세스 실행, 네트워크 연결)
- [GuardDuty 요금](https://aws.amazon.com/guardduty/pricing/)
- [GuardDuty Extended Threat Detection](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-extended-threat-detection.html): "There is no additional cost associated with the usage of Extended Threat Detection."

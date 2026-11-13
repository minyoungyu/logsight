"""탐지 규칙 명세(Palantir ADS 형식을 줄인 것).

규칙마다 다음을 적는다. 탐지 코드(detect.py, web/webdetect.py, web/webscan.py)의 실제 조건과 맞아야 한다.
- logs:   읽는 로그
- when:   걸리는 조건(코드 그대로의 기준값)
- blind:  사각지대 — 이 규칙이 놓치는 경우. 공개 데이터 측정에서 확인한 것은 [측정]을 붙였다
- fp:     오탐 — 정상인데 걸리는 경우와 줄이는 방법
- first:  걸렸을 때 먼저 할 일

검증(양성·음성 예시)은 tests/test_rule_validation.py에 규칙마다 하나씩 있다.
문서는 python scripts/rule_spec_doc.py 로 docs/규칙_명세.md를 다시 만든다.
"""
from __future__ import annotations

SPEC: dict[str, dict] = {
    # ------------------------------------------------------------------ CloudTrail 단건
    "CT_LOGGING_TAMPER": {
        "logs": "CloudTrail",
        "when": "StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, DeleteFlowLogs, GuardDuty DeleteDetector·"
                "UpdateDetector, WAF DeleteLoggingConfiguration, Config 기록 중지·삭제, CloudWatch DeleteLogGroup, "
                "Route 53 Resolver 질의 로그 삭제·해제, Security Hub 끄기, Access Analyzer 삭제, Bedrock 호출 로그 끄기, "
                "LeaveOrganization(조직 통제 벗어나기) 호출 1건. 이름에 trail·log·audit가 든 버킷의 수명 주기 설정(로그 자동 삭제)도 포함",
        "blind": ["로그 버킷 이름에 trail·log·audit가 없으면 수명 주기로 로그 지우기를 놓침",
                  "로그를 끄면 그 뒤 기록이 없으므로, 끄기 전 기록이 있어야 걸림"],
        "fp": ["운영자가 추적(trail) 설정을 바꾸는 정상 작업. 정상 작업 목록에 넣어도 '위험 설정'으로 남음"],
        "first": "누가 껐는지 확인하고 바로 다시 켠다. 끈 계정의 키를 의심한다.",
    },
    "CT_ROOT_USAGE": {
        "logs": "CloudTrail",
        "when": "userIdentity.type이 Root인 호출 1건(AWS 서비스가 대신 남긴 AwsServiceEvent는 뺌)",
        "blind": ["루트가 아닌 관리자 계정의 남용은 이 규칙으로 보지 않음"],
        "fp": ["루트로만 할 수 있는 작업(결제, 계정 설정). 그 자체보다 '루트를 일상적으로 쓰는 습관'이 위험",
               "다른 행동(MFA 변경 등) 표본에서 루트 사용으로만 걸려 원래 행동을 가린 사례가 있음 [측정]"],
        "first": "누가 왜 루트를 썼는지 확인하고, 루트에 MFA를 걸고 루트 키는 지운다.",
    },
    "CT_IAM_PERSISTENCE": {
        "logs": "CloudTrail",
        "when": "CreateUser, CreateAccessKey, Create/UpdateLoginProfile, Attach/Put(User|Role)Policy, AddUserToGroup, "
                "CreateRole, UpdateAssumeRolePolicy, Create·SetDefaultPolicyVersion, 임시 연합 토큰(GetFederationToken), "
                "IAM Roles Anywhere 신뢰 앵커·프로필 생성, EC2 키 페어 생성·가져오기 호출 1건(성공·실패 모두)",
        "blind": ["정책·그룹 삭제, SAML 공급자 변경은 보지 않음",
                  "역할을 '외부 계정이 맡을 수 있게' 만든 것과 내부용 역할을 구별하지 않음"],
        "fp": ["배포 도구(Terraform·CloudFormation)의 정상 IAM 변경. 배포 역할을 정상 작업 목록에 넣는다"],
        "first": "새로 생긴 사용자·키·권한이 의도한 것인지 확인하고, 아니면 키를 비활성화하고 권한을 되돌린다.",
    },
    "CT_SG_OPENED": {
        "logs": "CloudTrail",
        "when": "AuthorizeSecurityGroupIngress 요청에 0.0.0.0/0이 들어 있음. 네트워크 ACL에 0.0.0.0/0 인바운드 허용 "
                "항목을 만들거나 바꾸는 호출(Create·ReplaceNetworkAclEntry)도 포함",
        "blind": ["IPv6 전체(::/0) 개방은 보지 않음",
                  "네트워크 ACL 항목 삭제(DeleteNetworkAclEntry)로 막던 규칙을 없애는 것은 보지 않음",
                  "포트를 가리지 않음(80/443 공개와 22 공개를 같게 취급)"],
        "fp": ["웹 서버의 80/443 공개처럼 의도한 개방. 정상 작업 목록에 넣으면 '위험 설정'으로 표시"],
        "first": "어떤 포트가 열렸는지 보고, 관리 포트(22·3389)면 바로 닫는다.",
    },
    "CT_S3_PUBLIC": {
        "logs": "CloudTrail",
        "when": "PutBucketAcl·PutObjectAcl·PutBucketPolicy 등에서 AllUsers·AuthenticatedUsers 권한, public-read(-write) "
                "ACL, Principal '*' 허용 정책이 들어 있음. 퍼블릭 액세스 차단을 지우거나 끄는 호출도 포함. "
                "버킷 정책이 우리 계정이 아닌 계정 ID를 허용하는 경우도 포함",
        "blind": ["정책에 조건(Condition)이 붙어 실제로는 제한된 경우도 공개로 봄",
                  "공개된 뒤 외부인이 파일을 올리거나 읽은 것은 S3 접근 로그가 필요해 보지 않음 [측정]",
                  "복제 설정으로 다른 계정에 복사는 보지 않음 [측정]",
                  "다른 계정이 우리 조직 계정이어도 외부로 봄(조직 계정 목록을 모름)"],
        "fp": ["정적 웹사이트 호스팅 버킷처럼 일부러 공개한 경우"],
        "first": "공개가 의도한 것인지 확인하고, 아니면 버킷의 퍼블릭 액세스 차단을 켠다.",
    },
    "CT_SNAPSHOT_SHARE": {
        "logs": "CloudTrail",
        "when": "ModifySnapshotAttribute(createVolumePermission) 또는 ModifyImageAttribute(launchPermission) 호출, "
                "RDS ModifyDB(Cluster)SnapshotAttribute로 우리 계정이 아닌 계정·all에 복원 권한을 준 호출",
        "blind": ["공유 대상이 우리 조직 계정인지 외부 계정인지 구별하지 않음",
                  "스냅샷을 다른 계정으로 복사(CopySnapshot)하는 것은 보지 않음"],
        "fp": ["조직 안 다른 계정으로의 정상 백업 공유"],
        "first": "공유 대상 계정 ID를 확인하고, 모르는 계정이면 공유를 취소한다.",
    },
    "CT_SECRET_ACCESS": {
        "logs": "CloudTrail",
        "when": "같은 주체가 10분 안에 서로 다른 비밀값 5개 이상을 성공적으로 읽음(Secrets Manager GetSecretValue, "
                "SSM GetParameter(s) 복호화, 인스턴스 시작 스크립트(userData) 조회). BatchGetSecretValue 성공, EC2 GetPasswordData(Windows 관리자 암호) 호출은 1건으로도",
        "blind": ["천천히(10분에 4개 이하) 읽으면 걸리지 않음",
                  "앱 자신의 역할로 평소 읽던 비밀값을 공격자가 읽으면 구별하지 못함"],
        "fp": ["배포·시작 때 여러 설정 값을 한꺼번에 읽는 앱. 그 역할을 정상 작업 목록에 넣는다"],
        "first": "읽힌 비밀값 목록을 보고 모두 교체(rotate)한다. 읽은 주체의 키를 의심한다.",
    },
    "CT_INSTANCE_EXEC": {
        "logs": "CloudTrail",
        "when": "SSM SendCommand·StartSession, EC2 Instance Connect·직렬 콘솔로 SSH 키 밀어넣기, "
                "ModifyInstanceAttribute로 시작 스크립트(userData) 바꾸기 호출 1건(성공·실패 모두)",
        "blind": ["명령 내용은 CloudTrail에 남지 않음(SSM 실행 기록이나 서버 로그 필요)",
                  "SSH 키를 서버 안에서 직접 추가한 것은 보지 않음"],
        "fp": ["운영자의 정상 SSM 접속·패치 명령. 이 규칙만 걸린 사건은 '판단 불가'로 두고, 우리 팀 확인(logsight team)으로 뺀다",
               "공방전(개발 데이터)에서 블루팀의 SSM 명령 약 260건이 걸림 [측정]"],
        "first": "어느 인스턴스에 무엇을 했는지 확인하고, 모르는 접속이면 그 주체의 키를 막고 인스턴스를 격리한다.",
    },
    "CT_SERVERLESS_CHANGE": {
        "logs": "CloudTrail",
        "when": "Lambda 함수 생성·코드 바꾸기, 레이어를 붙이는 설정 변경, 다른 계정·모두(*)에 호출 권한 주기, "
                "SageMaker 노트북 시작 스크립트(lifecycle config) 만들기·바꾸기 1건",
        "blind": ["함수 환경 변수만 바꾸는 것, 함수 URL 공개는 보지 않음",
                  "Glue·ECS 작업 정의 변경은 보지 않음"],
        "fp": ["배포 파이프라인의 정상 배포가 자주 걸린다. 이 규칙만 걸린 사건은 '판단 불가'로 두고, 배포 역할을 정상 작업 목록에 넣는다"],
        "first": "바뀐 함수와 바꾼 주체를 확인한다. 배포가 아니면 이전 버전으로 되돌리고 그 주체의 키를 막는다.",
    },
    "CT_DATA_DESTRUCTION": {
        "logs": "CloudTrail(S3 삭제·암호화는 S3 데이터 이벤트 필요)",
        "when": "같은 주체가 10분 안에 S3 객체·AMI·스냅샷·버킷 삭제 20건 이상, 또는 DeleteObjects(일괄 삭제) 3회 이상, "
                "또는 고객 키(SSE-C)로 객체 5개 이상 다시 쓰기. 버킷 버전 관리 중지, KMS 키 삭제 예약·끄기, "
                "백업 지점·보관함 삭제, 마지막 스냅샷 없이 RDS 삭제는 1건으로도",
        "blind": ["S3 데이터 이벤트가 꺼져 있으면 객체 삭제·암호화를 볼 수 없음",
                  "공격자 계정의 KMS 키(SSE-KMS)로 다시 쓰는 수법은 보지 않음"],
        "fp": ["수명 주기·정리 작업의 정상 대량 삭제, 키 교체 뒤 옛 키 삭제 예약"],
        "first": "삭제·암호화를 한 주체의 키를 바로 막고, 버전 관리·백업에서 복구할 수 있는지 확인한다.",
    },
    "CT_ACCOUNT_SECURITY": {
        "logs": "CloudTrail",
        "when": "MFA 장치 끄기·삭제(DeactivateMFADevice, DeleteVirtualMFADevice), 계정 비밀번호 정책 바꾸기·삭제 1건",
        "blind": ["콘솔 로그인 연속 실패, MFA 단계 실패, 여러 IP 동시 로그인은 보지 않음 [측정]"],
        "fp": ["MFA 장치를 바꾸는 직원의 정상 작업(끄고 새로 등록)"],
        "first": "누가 바꿨는지 확인하고 MFA를 다시 켠다. 본인이 아니면 그 계정의 비밀번호와 키를 바꾼다.",
    },
    "CT_CONSOLE_NO_MFA": {
        "logs": "CloudTrail",
        "when": "ConsoleLogin 성공이고 MFAUsed가 No",
        "blind": ["콘솔 로그인 연속 실패(비밀번호 대입)는 보지 않음 [측정]"],
        "fp": ["MFA를 아직 안 건 직원의 정상 로그인. 그 자체로는 공격이 아니라 위험한 습관"],
        "first": "그 계정에 MFA를 건다. 로그인 IP가 평소와 다르면 비밀번호를 바꾼다.",
    },
    "CT_UNTRUSTED_IP": {
        "logs": "CloudTrail + 설정(trusted_ips)",
        "when": "trusted_ips가 있을 때, IAM 사용자·루트의 호출이 목록 밖 IP에서 옴",
        "blind": ["trusted_ips를 적지 않으면 꺼져 있음",
                  "역할(AssumedRole) 세션은 보지 않음"],
        "fp": ["재택·출장·모바일 회선. 목록을 넓게 적거나 VPN 대역을 넣는다"],
        "first": "그 IP가 우리 직원 것인지 확인하고, 아니면 키를 비활성화한다.",
    },
    "CT_INSTANCE_CRED_OUTSIDE": {
        "logs": "CloudTrail + 설정(instances)",
        "when": "설정에 적힌 인스턴스의 역할 자격증명이 그 인스턴스의 공인·사설 IP가 아닌 곳에서 쓰임",
        "blind": ["instances 목록이 없으면 꺼져 있음(대신 CT_INSTANCE_CRED_MULTI_IP가 동작)",
                  "NAT·VPC 엔드포인트를 거치면 출발지 IP가 바뀌어 판단이 어려움"],
        "fp": ["NAT 게이트웨이 IP를 instances에 적지 않은 경우"],
        "first": "인스턴스 역할 세션을 무효화(권한 회수)하고, 메타데이터 서비스를 IMDSv2로 바꾼다.",
    },
    "CT_INSTANCE_CRED_MULTI_IP": {
        "logs": "CloudTrail",
        "when": "같은 인스턴스의 역할 자격증명이 서로 다른 공인 IP 2곳 이상에서 쓰임(가장 많이 쓴 IP를 정상으로 봄)",
        "blind": ["공격자가 가장 많이 썼다면 정상·의심이 뒤바뀜",
                  "사설 IP 호출은 세지 않음"],
        "fp": ["오토스케일링·여러 NAT 출구. 신원 확인(GetCallerIdentity)만 있으면 '판단 불가'로 낮춤"],
        "first": "의심 IP가 우리 것인지 확인하고, 아니면 역할 세션을 무효화한다.",
    },
    # ------------------------------------------------------------------ CloudTrail 시간창
    "CT_ACCESS_DENIED_BURST": {
        "logs": "CloudTrail",
        "when": "같은 공인 IP에서 10분 안에 AccessDenied·UnauthorizedOperation 오류 5건 이상",
        "blind": ["거부가 2~4건이면 걸리지 않음 [측정]",
                  "IP를 바꿔 가며 나눠 시도하면 걸리지 않음",
                  "AssumeRole 실패를 대량으로 시도하는 역할 이름 대입은 오류 코드가 달라 보지 않음 [측정]"],
        "fp": ["권한이 부족한 자동화 도구(모니터링·백업)의 반복 실패. 그 도구 계정을 정상 작업 목록에 넣는다"],
        "first": "어떤 키로 무엇을 시도했는지 보고, 모르는 IP면 그 키를 비활성화한다.",
    },
    "CT_DISCOVERY_BURST": {
        "logs": "CloudTrail",
        "when": "같은 공인 IP에서 10분 안에 정해진 목록 조회 API(ListUsers, DescribeInstances, DescribeInstanceAttribute, "
                "ListSecrets, SES 조회 등 29종) 중 4종 이상",
        "blind": ["CloudWatch 로그 대량 읽기 등 목록에 없는 조회 API는 보지 않음 [측정]",
                  "천천히(10분에 3종 이하) 조회하면 걸리지 않음"],
        "fp": ["보안 점검 도구·콘솔 화면 열기·연동 계정(예: SIEM 수집 계정)의 정기 조회 [측정]"],
        "first": "조회한 계정과 IP를 확인한다. 조회 뒤 변경·생성이 이어졌는지 같은 사건에서 본다.",
    },
    "CT_S3_BULK_READ": {
        "logs": "CloudTrail(S3 데이터 이벤트)",
        "when": "같은 공인 IP에서 10분 안에 서로 다른 GetObject 성공 20건 이상",
        "blind": ["S3 데이터 이벤트를 켜지 않으면 기록 자체가 없음(가장 흔한 경우)",
                  "DataSync·Batch·복제로 옮기는 것은 GetObject가 아니라 보지 않음 [측정]"],
        "fp": ["백업·분석 작업의 정상 대량 읽기"],
        "first": "읽은 객체 목록과 크기를 확인하고, 모르는 IP면 키를 비활성화한다.",
    },
    "CT_RUN_INSTANCES_BURST": {
        "logs": "CloudTrail",
        "when": "같은 공인 IP에서 30분 안에 RunInstances 성공 5건 이상(실패는 권한 거부 규칙이 맡음)",
        "blind": ["모두 실패한 대량 생성 시도는 이 규칙이 아니라 권한 거부 규칙으로만 보임 [측정]",
                  "Lambda·ECS로 자원을 쓰는 경우는 보지 않음"],
        "fp": ["오토스케일링·배포 파이프라인의 정상 생성"],
        "first": "생성된 인스턴스를 멈추고 종류(고성능 GPU 등)와 리전을 확인한다.",
    },
    # ------------------------------------------------------------------ VPC Flow / 서버 방화벽
    "VPC_PORT_SCAN": {
        "logs": "VPC Flow Logs 또는 서버 방화벽 로그",
        "when": "같은 외부 IP가 5분 안에 서로 다른 대상 포트 10개 이상(서버 응답 방향 흐름은 뺌). "
                "사내 IP는 웹·서버 로그에서 의심 행동이 잡힌 IP만, 그 행동 앞뒤 6시간 안에서 본다",
        "blind": ["포트 9개 이하만 두드리는 표적 스캔",
                  "출발 포트를 일부러 낮게 고정한 스캔은 응답으로 오인해 뺄 수 있음"],
        "fp": ["외부 서비스와 대량 통신하는 서버(응답 흐름 제외 규칙이 대부분 막음) [측정]"],
        "first": "그 IP가 들어온 포트 중 허용(ACCEPT)된 것이 있는지 본다.",
    },
    "VPC_REMOTE_ADMIN_EXPOSED": {
        "logs": "VPC Flow Logs 또는 서버 방화벽 로그 + 설정(trusted_ips)",
        "when": "외부 IP에서 22·3389 포트로의 접속이 ACCEPT됨(trusted_ips 안의 IP는 뺌). "
                "사내 IP는 웹·서버 로그에서 의심 행동이 잡힌 IP만, 그 행동 앞뒤 6시간 안에서 본다",
        "blind": ["관리 포트를 바꿔 쓰면(예: 2222) 보지 않음",
                  "접속 허용만 보고 로그인 성공 여부는 SSH 로그가 있어야 앎"],
        "fp": ["인터넷 스캐너가 열린 포트를 두드린 것. 다른 행동이 없으면 '위험 설정'으로 낮춤 [측정]"],
        "first": "관리 포트를 인터넷 전체가 아니라 관리자 IP에만 열어 둔다.",
    },
    # ------------------------------------------------------------------ WAF
    "WAF_SQLI_NOT_BLOCKED": {
        "logs": "AWS WAF",
        "when": "SQL 인젝션 규칙이 걸렸는데(COUNT·라벨) 요청이 허용(ALLOW/COUNT)됨",
        "blind": ["WAF에 SQL 인젝션 규칙 그룹이 없으면 보지 않음"],
        "fp": ["검색어에 따옴표가 든 정상 요청을 관리형 규칙이 오탐한 경우"],
        "first": "그 규칙을 COUNT에서 BLOCK으로 바꾸고, 같은 IP의 다른 요청과 응답 코드를 본다.",
    },
    "WAF_BLOCKED": {
        "logs": "AWS WAF",
        "when": "WAF가 막은(BLOCK) 요청 1건 이상, IP별로 묶음",
        "blind": ["막히지 않고 통과한 공격은 다른 규칙이 맡음"],
        "fp": ["WAF 규칙의 정상 요청 차단. 막혔으므로 피해는 없음(낮음)"],
        "first": "급하지 않다. 같은 IP가 다른 경로로 통과한 요청이 있는지만 본다.",
    },
    # ------------------------------------------------------------------ SSH
    "SSH_BRUTE_FORCE": {
        "logs": "SSH 인증 로그(auth.log)",
        "when": "같은 IP에서 10분 안에 서로 다른 실패 줄 5건 이상(Invalid user 줄 포함, 같은 시도의 중복은 뺌)",
        "blind": ["IP를 바꿔 가며 천천히 시도하는 분산 대입",
                  "키 인증만 허용한 서버에서의 실패 형식 일부"],
        "fp": ["비밀번호를 잊은 직원의 반복 실패(보통 5건 미만)"],
        "first": "비밀번호 로그인을 끄고 키 인증만 허용한다. 성공한 로그인이 이어졌는지 본다.",
    },
    "SSH_SUCCESS_AFTER_FAIL": {
        "logs": "SSH 인증 로그(auth.log)",
        "when": "같은 IP에서 로그인 성공 직전 30분 안에 실패 2건 이상",
        "blind": ["다른 IP에서 실패하고 새 IP로 성공하면 보지 않음"],
        "fp": ["오타 두 번 뒤 정상 로그인"],
        "first": "그 계정으로 무엇을 했는지 셸 기록을 보고, 모르는 IP면 계정 비밀번호와 키를 바꾼다.",
    },
    # ------------------------------------------------------------------ ALB·WAF 웹 요청
    "WEB_SQLI_PATTERN": {
        "logs": "ALB·WAF·웹서버 로그",
        "when": "쿼리 문자열에 SQL 인젝션 패턴(따옴표+OR/UNION SELECT/sleep( 등), WAF가 막지 않은 요청",
        "blind": ["POST 본문의 인젝션은 로그에 없어 보지 않음"],
        "fp": ["따옴표가 든 검색어"],
        "first": "같은 IP 요청의 응답 코드·크기를 보고, 해당 페이지의 입력 처리를 점검한다.",
    },
    "WEB_PATH_PROBE": {
        "logs": "ALB·웹서버 로그",
        "when": "같은 IP가 5분 안에 서로 다른 경로 20개 이상에서 403/404",
        "blind": ["느린 스캐너"],
        "fp": ["깨진 링크가 많은 사이트를 도는 검색엔진 봇"],
        "first": "급하지 않다. 같은 IP가 200으로 성공한 경로가 있는지 본다.",
    },
    "WEB_OBJECT_ENUM": {
        "logs": "ALB·API Gateway 로그",
        "when": "같은 IP가 같은 API의 서로 다른 객체 번호 5개 이상에 10분 안에 403/404",
        "blind": ["남의 객체 열람에 성공(200)한 경우는 거부가 없어 보지 않음"],
        "fp": ["지워진 객체 링크를 여러 번 누른 사용자"],
        "first": "같은 IP가 200을 받은 객체 번호가 있는지 보고, 그 API의 권한 검사를 점검한다.",
    },
    "GD_FINDING": {
        "logs": "GuardDuty 결과(콘솔 내보내기·EventBridge)",
        "when": "GuardDuty 결과 1건마다 1개. 심각도 7 이상 높음, 4 이상 중간",
        "blind": ["GuardDuty를 켜기 전의 일, ALB·WAF·서버 로그 안의 일은 GuardDuty가 보지 않음"],
        "fp": ["GuardDuty 자체의 오탐. 포트 탐색 결과만 있으면 '위험 설정'으로 낮춤 [측정]"],
        "first": "결과의 대상(인스턴스·키)을 확인하고, 같은 사건에 엮인 다른 로그를 본다.",
    },
    # ------------------------------------------------------------------ 웹서버 로그(웹 모듈)
    "WEBLOG_SQLI": {
        "logs": "웹서버 접근 로그",
        "when": "디코드한 경로+쿼리에 UNION SELECT, 따옴표 뒤 항상-참 조건, sleep(·information_schema 등, "
                "또는 따옴표·주석과 함께 SELECT…FROM",
        "blind": ["POST 본문 인젝션", "이중 인코딩을 넘는 난독화"],
        "fp": ["따옴표 없는 일반 문장은 잡지 않도록 좁혀 둠"],
        "first": "응답 코드와 크기로 성공 여부를 보고, 해당 페이지의 쿼리를 매개변수화한다.",
    },
    "WEBLOG_TRAVERSAL": {
        "logs": "웹서버 접근 로그",
        "when": "경로·쿼리에 ../, /etc/passwd, php://filter, /proc/self/, 로그 파일 경로 등",
        "blind": ["응용프로그램이 내부에서 경로를 조합하는 경우(로그에 안 보임)"],
        "fp": ["정상 URL에 ../가 들어가는 일은 드묾"],
        "first": "200 응답이 있었는지 보고, 파일 경로를 입력으로 받는 코드를 막는다.",
    },
    "WEBLOG_RFI": {
        "logs": "웹서버 접근 로그",
        "when": "쿼리 값이 http(s)://·ftp://로 시작",
        "blind": ["주소를 인코딩·축약한 경우 일부"],
        "fp": ["리다이렉트·공유 기능처럼 URL을 값으로 받는 정상 페이지"],
        "first": "그 매개변수가 파일 포함에 쓰이는지 코드를 확인하고, allow_url_include를 끈다.",
    },
    "WEBLOG_CMD_INJECTION": {
        "logs": "웹서버 접근 로그",
        "when": "쿼리에 ;id, |cat, `…`, $(…), &&whoami, wget http 등 또는 base64로 감춘 셸 명령",
        "blind": ["POST 본문으로 보낸 명령"],
        "fp": ["프로그래밍 질문 게시판처럼 명령어 문자열을 정상으로 주고받는 사이트"],
        "first": "서버에서 그 시각 이후 실행된 프로세스와 새 파일을 확인한다.",
    },
    "WEBLOG_XSS": {
        "logs": "웹서버 접근 로그",
        "when": "경로·쿼리에 <script, javascript:, onerror=, onload=, <img src= 등",
        "blind": ["저장형 XSS의 실행 시점(다른 사용자 브라우저)은 로그에 없음"],
        "fp": ["HTML 편집기에서 보내는 정상 요청"],
        "first": "출력 이스케이프를 점검한다. 관리자 쿠키 탈취로 이어졌는지 관리자 접근 기록을 본다.",
    },
    "WEBLOG_SCANNER": {
        "logs": "웹서버 접근 로그",
        "when": "User-Agent에 sqlmap, nikto, nmap, nuclei, wpscan, gobuster 등 알려진 도구 이름(신뢰 IP 제외)",
        "blind": ["User-Agent를 브라우저로 바꾼 도구"],
        "fp": ["우리 팀의 정기 점검. 그 IP를 신뢰 목록에 넣는다"],
        "first": "급하지 않다. 같은 IP의 공격 패턴 요청이 성공했는지 본다.",
    },
    "WEBLOG_ENUM_404": {
        "logs": "웹서버 접근 로그",
        "when": "같은 IP가 5분 안에 서로 다른 경로 15개 이상에서 404(신뢰 IP 제외)",
        "blind": ["느린 열거"],
        "fp": ["검색엔진 봇이 옛 링크를 도는 경우"],
        "first": "급하지 않다. 같은 IP가 200을 받은 경로를 본다.",
    },
    "WEBLOG_SENSITIVE_FILE": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(sensitive_files)",
        "when": "경로에 .env, wp-config.php, id_rsa, .git/config 등 프로필의 민감 파일 이름",
        "blind": ["프로필에 없는 민감 파일 이름"],
        "fp": ["404로 끝난 탐색은 피해가 없음(백업 노출은 별도 규칙)"],
        "first": "그 요청이 200이었는지 보고, 200이면 들어 있던 비밀을 모두 바꾼다.",
    },
    "WEBLOG_WEBSHELL_ACCESS": {
        "logs": "웹서버 접근 로그",
        "when": "스크립트 파일에 cmd=·exec= 같은 명령 인자(해시 같은 값 제외), 또는 c99·wso 같은 웹셸 이름, 응답이 404가 아님",
        "blind": ["흔한 이름(up.php 등)에 명령 인자 없이 POST로만 쓰는 웹셸 — 업로드 실행 규칙·파일 검사로 보완"],
        "fp": ["c=, cmd= 인자를 정상으로 쓰는 앱(값이 해시면 제외)"],
        "first": "그 파일을 서버에서 찾아 격리하고, 처음 올라온 시각 전후 요청을 본다.",
    },
    "WEBLOG_UPLOAD_EXEC": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(upload_dirs)",
        "when": "업로드 폴더(/uploads 등) 안의 .php·.jsp·.asp 같은 스크립트 요청",
        "blind": ["업로드 폴더 이름이 프로필·기본값과 다르면 보지 않음"],
        "fp": ["업로드 폴더 안에 일부러 둔 스크립트(드묾)"],
        "first": "업로드 폴더에서 스크립트 실행을 막고, 그 파일을 격리한다.",
    },
    "WEBLOG_AUTH_BRUTE": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(login_paths·admin_paths)",
        "when": "같은 IP가 10분 안에 로그인 경로로 POST 10건 이상",
        "blind": ["로그인 경로가 프로필·기본값과 다르면 보지 않음", "IP를 나눈 분산 대입"],
        "fp": ["여러 사용자가 한 NAT IP를 공유하는 회사·학교"],
        "first": "로그인 시도 제한과 잠금을 켜고, 성공한 로그인이 이어졌는지 본다.",
    },
    "WEBLOG_AUTH_SUCCESS_AFTER_FAIL": {
        "logs": "웹서버 접근 로그",
        "when": "같은 IP의 로그인 POST 중 실패 응답 5건 이상 뒤 리다이렉트(301·302·303) 응답",
        "blind": ["실패와 성공 응답 코드가 같은 앱(둘 다 200)"],
        "fp": ["실패해도 리다이렉트하는 앱. 사이트 프로필로 로그인 경로를 좁힌다"],
        "first": "그 계정 비밀번호를 바꾸고, 로그인 뒤 한 작업을 본다.",
    },
    "WEBLOG_CODE_IN_HEADER": {
        "logs": "웹서버 접근 로그",
        "when": "User-Agent·Referer에 <?php, eval(, base64_decode(, system($_ 등 실행 코드",
        "blind": ["로그에 남지 않는 다른 헤더"],
        "fp": ["거의 없음"],
        "first": "그 로그 파일을 웹에서 열 수 있는 경로(LFI)가 있는지 확인한다.",
    },
    "WEBLOG_ADMIN_ACCESS": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(admin_paths·trusted_ips)",
        "when": "신뢰 IP가 아닌 곳에서 /admin 아래 경로에 2xx, 또는 관리자 로그인 302",
        "blind": ["관리자 경로가 /admin으로 시작하지 않으면 보지 않음"],
        "fp": ["재택 관리자. trusted_ips에 넣는다"],
        "first": "그 IP가 관리자 것인지 확인하고, 아니면 관리자 비밀번호와 세션을 바꾼다.",
    },
    "WEBLOG_SSRF": {
        "logs": "웹서버 접근 로그",
        "when": "url=·src=·callback= 같은 인자에 127.0.0.1, localhost, 169.254.169.254, 사설 대역 주소",
        "blind": ["주소를 10진수·IPv6 등으로 바꾼 우회"],
        "fp": ["내부 주소를 일부러 받는 관리 도구"],
        "first": "메타데이터 서비스를 IMDSv2로 바꾸고, 그 시각 이후 인스턴스 역할 키 사용을 CloudTrail에서 본다.",
    },
    "WEBLOG_OPEN_REDIRECT": {
        "logs": "웹서버 접근 로그",
        "when": "next=·return=·redirect= 인자에 외부 http(s) 주소",
        "blind": ["//evil.example 같은 스킴 생략 주소"],
        "fp": ["외부 결제·로그인 연동으로 정상 리다이렉트"],
        "first": "리다이렉트 대상을 허용 목록으로 제한한다.",
    },
    "WEBLOG_IDOR_ENUM": {
        "logs": "웹서버 접근 로그",
        "when": "같은 IP가 5분 안에 /order.php에 서로 다른 쿼리로 10건 이상 성공",
        "blind": ["/order.php 경로에만 맞춰져 있어 다른 사이트에서는 거의 동작하지 않음(일반화는 WEB_OBJECT_ENUM)"],
        "fp": ["주문 목록을 넘겨 보는 관리자"],
        "first": "그 페이지의 소유자 확인 로직을 점검한다.",
    },
    "WEBLOG_ADMIN_FORGED": {
        "logs": "웹서버 접근 로그",
        "when": "관리자 페이지 2xx가 있는 IP에 같은 로그 안의 로그인(login.php POST→302) 기록이 없음",
        "blind": ["로그인 경로가 login.php가 아닌 앱"],
        "fp": ["로그 기간 전에 로그인해 세션이 남아 있던 관리자"],
        "first": "관리자 세션·쿠키 서명 키를 바꾼다.",
    },
    "WEBLOG_CSRF_SUSPECT": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(own_hosts)",
        "when": "관리자 경로로의 POST에 다른 사이트 Referer",
        "blind": ["Referer를 보내지 않는 브라우저·설정"],
        "fp": ["own_hosts에 우리 도메인을 적지 않은 경우"],
        "first": "관리자 작업에 CSRF 토큰을 넣는다.",
    },
    "WEBLOG_BACKUP_LEAK": {
        "logs": "웹서버 접근 로그",
        "when": "backup·dump·.sql·.bak·.zip·.tar.gz·/.git/ 경로가 200으로 응답",
        "blind": ["다른 이름의 백업 파일"],
        "fp": ["일부러 내려받게 한 압축 파일"],
        "first": "그 파일을 웹 루트에서 치우고, 안에 든 비밀번호·키를 모두 바꾼다.",
    },
    "WEBLOG_DIR_LISTING": {
        "logs": "웹서버 접근 로그 + 사이트 프로필(upload_dirs)",
        "when": "업로드 폴더 경로(끝이 /)에 GET 200",
        "blind": ["업로드 폴더가 아닌 곳의 목록 공개"],
        "fp": ["폴더 주소에 index 페이지가 있는 경우"],
        "first": "웹서버의 디렉터리 목록 기능을 끈다.",
    },
    "WEBLOG_EXPLOIT_PROBE": {
        "logs": "웹서버 접근 로그",
        "when": "User-Agent·Referer에 ${jndi:(Log4Shell), () { :; }(Shellshock) 같은 공격 문자열",
        "blind": ["다른 헤더·본문에 넣은 공격 문자열"],
        "fp": ["거의 없음. 대부분 무차별 스캐너"],
        "first": "해당 취약 버전을 쓰는지 확인한다. 쓰지 않으면 급하지 않다.",
    },
    "WEBLOG_EXPLOIT_5XX": {
        "logs": "웹서버 접근 로그",
        "when": "공격 패턴 요청에 500대 응답",
        "blind": ["오류를 200으로 감추는 앱"],
        "fp": ["이상한 입력에 앱이 원래 500을 내는 경우"],
        "first": "같은 시각 웹 오류 로그를 보고 어떤 코드가 깨졌는지 확인한다.",
    },
    "WEBLOG_LARGE_EXFIL": {
        "logs": "웹서버 접근 로그",
        "when": "공격 패턴 요청 또는 관리자 경로 요청이 200이고 응답 50,000바이트 이상",
        "blind": ["작게 나눠 여러 번 가져가는 유출"],
        "fp": ["원래 큰 관리자 페이지(대시보드)"],
        "first": "그 응답에 어떤 데이터가 담겼는지 같은 요청을 재현해 확인한다.",
    },
    # ------------------------------------------------------------------ 파일 검사
    "FILE_WEBSHELL": {
        "logs": "웹 루트 파일(읽기 전용 검사)",
        "when": "강한 신호(eval(base64_decode(, system($_GET, 웹셸 표식, 800자 넘는 한 줄 등)가 있고 점수 합 6 이상. 업로드 폴더 안의 스크립트는 +4",
        "blind": ["강하게 난독화한 웹셸", "PHP 외 언어 일부"],
        "fp": ["플러그인 코드의 정상 base64·eval 사용(강한 신호가 없으면 건너뜀)"],
        "first": "파일을 지우지 말고 격리·보관한 뒤, 만든 시각 전후 접근 로그를 본다.",
    },
    "FILE_SUSPICIOUS": {
        "logs": "웹 루트 파일(읽기 전용 검사)",
        "when": "강한 신호(점수 4 이상인 신호 또는 800자 넘는 한 줄)가 있지만 합이 4~5",
        "blind": ["FILE_WEBSHELL과 같음"],
        "fp": ["관리 도구·설치 스크립트"],
        "first": "파일의 출처(배포본에 있는지)를 확인한다.",
    },
}

# 변경 기록

이 프로젝트는 [SemVer](https://semver.org/lang/ko/)를 따른다. 버전 번호는 변경 내용이 정한다.

## 미출시

## 0.4.1 (시험판) - 2026-11-06

0.4.0의 설정 점검 수정안 오류를 고친 버전. 특히 WAF 수정 명령이 기본 동작이 차단인 웹 방화벽을 열어 버릴 수 있었으니 0.4.0 대신 이 버전을 쓴다.

### 추가
- SQL 인젝션 성공 신호를 코드가 판단한다(`detect.sqli_success_signal`). 웹서버·ALB 로그의 응답 크기를 읽어, 같은 경로의 평소 응답과 같으면 "성공 근거 없음", 크게 다르면 "성공 의심", 크기가 없으면 "판단 불가"로 `WEB_SQLI_PATTERN` 설명에 붙인다. AI 판정·설명 프롬프트에는 이 판단을 따르고 2xx만으로 성공이라 쓰지 말라고 적었다.

### 고침(설정 점검)
- 깨진 environment.json이나 빠진 필드 때문에 분석 전체가 멈추던 문제: 이제 수정안만 건너뛰고 이유를 보고서 '가정'에 적는다.
- 포트 범위·IPv6·모든 프로토콜 규칙의 보안그룹 revoke 명령이 원래 규칙과 달라 실패하던 문제: `--ip-permissions`로 정확히 같은 규칙을 지우고, 범위가 넓으면 함께 닫히는 포트를 경고한다.
- 사건 서버에 붙지 않은 보안그룹까지 원인으로 지목하던 문제, NACL을 서버 서브넷과 무관하게 첫 번째 것으로 고르던 문제. `collect environment`가 인스턴스 서브넷을 함께 모은다.
- WAF 수정 명령이 기본 동작을 `Allow`로 고정해, 기본이 Block인 ACL을 열어 버릴 수 있던 문제.
- IMDS 설정을 모를 때 "optional"로 단정하던 표시.

## 0.4.0 (시험판) - 2026-11-06

0.3.0 이후 '미출시'에 쌓인 경보 연동·통지·자동 격리·우리 팀 알아보기 등도 이 버전에 들어간다(아래 '추가(제품)' 목록).

### 보안
- AI 재검토를 로그 속 주입 문장으로부터 보호(`logsight/guard.py`). 공격자가 쓸 수 있는 값(User-Agent, 요청 주소, API 파라미터, SSH 로그인 이름)을 `untrusted` 아래로 옮겨 보내고, 그 안의 지시는 따르지 말라고 시스템 문구에 적었다. 판정·무시를 요구하는 문장을 찾으면 보고서에 "로그에 AI를 속이려는 문장"으로 표시하고, AI가 낮춘 판정을 공격으로 되돌린다. 규칙이 공격으로 본 사건을 AI가 낮추면 "규칙과 의견 다름 · 확인 필요"로 표시하고 '판단 불가'보다 아래로 내리지 않는다. 시키는 대로 하는 가짜 모델로 끝에서 끝까지 시험(`tests/test_guard.py`).
- CI에 비밀값 검사(gitleaks)를 더했다.

### 추가
- 탐지 공백 보강(개발 데이터): 새 규칙 5개(CT_SECRET_ACCESS 비밀값 대량 조회, CT_INSTANCE_EXEC 인스턴스 원격 명령·접속, CT_SERVERLESS_CHANGE Lambda·SageMaker 변경, CT_DATA_DESTRUCTION 삭제·랜섬웨어·복구 수단 제거, CT_ACCOUNT_SECURITY MFA·비밀번호 정책 약화)와 기존 규칙 5개 범위 확장(로그 끄기, NACL 개방, 다른 계정 공유, IAM 지속성, 목록 조회). Splunk 표본 16→26(개발 데이터), 기존 16개 유지. 운영 작업과 같은 모양의 규칙만 걸린 사건은 '판단 불가'로 둔다. 기록 `docs/탐지공백_보강.md`.
- 회귀 시험: 처음 보는 데이터(Splunk attack_data)에서 한 번 맞게 잡은 16개를 계속 잡는지(`scripts/public/regress_splunk.py`, 기준 파일은 다시 만들지 않음), 저장소 샘플 결과 고정(`scripts/regress_samples.py`, `tests/regression/samples.json`).
- 시험판 배포: `pyproject.toml`(`pip install`, `logsight` 명령), `logsight --version`, 태그를 올리면 설치 파일·샘플 보고서·Docker 이미지를 만드는 `.github/workflows/release.yml`. 시험판 안내 `docs/사용자평가/시험판_안내.md`, 이슈 양식 "시험판 의견".
- Stratus Red Team 공격 재현 준비(`lab/aws/stratus/`): 46개 기법의 예상(잡음 15, 놓침 28, 기준에 따라 3)을 실행 전에 고정하고, 실행·채점 스크립트를 더했다. 실행은 0회.
- CI: pytest와 커버리지(88%), ruff.

### 고침
- CI가 unittest만 돌려 함수 형식 시험 9개(`test_triage.py`, `test_gongbang_convert.py`)를 건너뛰고 있었다. 그중 1개는 깨져 있었다(파이프라인 연결 시험). 고치고 pytest로 바꿨다.
- 쓰지 않는 import·변수 정리(ruff).
- Lambda 이벤트 이름의 버전 꼬리(`UpdateFunctionCode20150331v2`)를 떼어 규칙이 알아보게 했다.
- `team.py`의 `datetime.utcnow()` 경고 제거.
- Docker 이미지 빌드 실패: Dockerfile이 측정 결과 폴더(`reports/`)의 공방전 비교 화면 파일을 복사하려 했지만, 이미지에는 측정 데이터를 넣지 않는 규칙(`.dockerignore`)이 막고 있었다. 복사를 빼고(데모의 `/compare`는 파일이 없다고 안내), 시험이 파일 단위 복사도 잡게 했다.
- CI: 비공개 저장소의 macOS 실행 시간 한도를 넘어 macOS 작업이 시작되지 못하고 실패로 끝났다. PR마다 Ubuntu·Windows만 돌고 macOS는 직접 실행할 때만 돌게 했다. 브랜치 push와 PR이 같은 커밋을 두 번 돌던 것도 없앴다.

### 추가(제품)
- 자동 격리·AI 재검토 보강: 탈취된 인스턴스 역할의 세션을 무효화하는 수정안(`IAM_ROLE_SESSION_REVOKE`, 사람이 실행, 되돌리기 포함). 자동 격리 마감 기본값 5분 → 10분(늦게 도착하는 로그까지 보고 판단). AI가 코드 점검 밖에서 낸 변경 제안은 '검증 안 된 제안'으로 따로 표시. `on-alert --respond`에 집행 경로가 없으면 경고.
- 경보 연동(`logsight/alert.py`, `logsight watch`, `logsight on-alert`): GuardDuty 결과·CloudWatch 경보·위험 API 호출(EventBridge)을 SQS 대기열로 받아, 경보 시각 앞뒤의 로컬·S3 로그로 분석을 자동 실행하고 `reports/alerts/<시각>_<종류>_<id>/`에 보고서와 통지용 요약(summary.txt)을 남긴다. 등급 기준·중복 경보 무시(cooldown)·실패 시 재시도(DLQ)·보고서 뒤 실행할 통지 명령(`--notify-cmd`) 지원. 배포 템플릿 `deploy/aws/logsight-alerts.yaml`, 설명 `docs/경보_연동.md`. AWS 설정은 바꾸지 않는다(읽기만).
- 우리 팀 알아보기(`logsight/team.py`, `logsight team`, `--team`): 사람 계정·콘솔 작업·오래 활동·수상한 모습 없음을 모두 만족하는 계정을 우리 팀 후보로 제안하고, 사람이 확인한 계정의 작업만 공격 판정에서 뺀다. 보고서에 후보 카드. 공방전(개발 데이터) 판정 4/7 → 6/7, 처음 보는 Splunk 표본 44개에서 공격자를 후보로 낸 경우 0. 측정 `docs/우리팀_알아보기_측정.md`.
- 고객 설치(`logsight onboard-link`, `deploy/aws/logsight-onboard.yaml`, `deploy/aws/logsight-hub.yaml`): 고객 계정에는 버튼 하나로 경보 전달·보관용 CloudTrail·읽기 전용 역할(고르면 격리 역할)만 더하고, 경보는 LogSight 허브 대기열 하나로, 로그는 LogSight 보관 버킷으로 모은다. `--s3` 접두어에 `{account}`·`{region}`을 넣으면 경보가 난 고객 폴더만 읽는다. 설명 `docs/고객_설치.md`.
- 통지(`logsight/notify.py`, `--notify notify.json`, `logsight notify-test`): 이메일(SMTP·SES SMTP, 정보성 고지와 마스킹된 보고서 첨부)·디스코드·슬랙·일반 웹훅(HMAC 서명)을 설정으로 골라 쓴다. 채널마다 기준 등급, 주소·비밀번호는 환경변수, 실패해도 분석은 계속, 디스코드·슬랙 전체 호출(@everyone, <!channel>) 차단. 예시 `deploy/notify.example.json`, 설명 `docs/통지.md`.
- 자동 격리(`logsight/respond.py`, `logsight respond`, `watch --respond`): 높음 경보 뒤 5분 안에 확인이 없으면 기준선 이후 외부에서 만든 액세스 키(비활성)·IAM 사용자·역할(AWSDenyAll 부착)·보안그룹 규칙(닫기)만 격리한다. 허용 목록은 CloudTrail 생성 기록(배포 주체, 또는 관리자+관리 IP+MFA)으로 자동 갱신. 기본은 시험 모드(기록만), 사건당·하루 한도, 끄는 스위치, 되돌리기(`respond undo`, `undo.sh`). 실행 역할 템플릿 `deploy/aws/logsight-responder.yaml`, 설명 `docs/자동_격리.md`.
- 수집 보호: 계정 밖 Object Lock 보관 버킷(`deploy/aws/logsight-log-archive.yaml`), 감시 대상 계정 트레일·Flow Logs·서버 쓰기 전용 정책(`deploy/aws/logsight-source-logging.yaml`), 로그 끄기 금지 SCP 예시, 서버 로그 즉시 전송 Fluent Bit 설정(`deploy/host/`), 생존 신호가 끊기면 경보(`logsight heartbeat`, `watch --heartbeat`). 설명 `docs/수집_보호.md`.
- 처음 보는 데이터 측정: 규칙을 고정(20e4562)하고 Splunk attack_data의 AWS 표본 52개로 한 번 쟀다(맞게 탐지 16개). `scripts/public/eval_splunk_attack_data.py`, 결과 `docs/처음보는데이터_측정.md`.
- 규칙 명세(`logsight/rulespec.py` → `docs/규칙_명세.md`): 규칙 50개마다 조건·사각지대·오탐·먼저 할 일. 모든 규칙의 양성·음성 검증 예(`tests/test_rule_validation.py`)와 명세 누락·문서 갱신 검사.
- 사용자 평가 설계(`docs/사용자평가/`)와 집계 스크립트(`scripts/study_score.py`), 고객 인터뷰 가이드(`docs/고객검증/`).
- 실제 AWS 로그 측정(Splunk BOTSv3, CC0): Splunk 없이 색인에서 원본 로그를 꺼내는 `scripts/public/botsv3_extract.py`와 결과 `docs/BOTSv3_측정.md`.
- S3 버킷 공개 규칙(`CT_S3_PUBLIC`): PutBucketAcl·PutObjectAcl·PutBucketPolicy 등으로 버킷을 인터넷 전체(AllUsers, `*`)에 연 호출을 잡는다.
- "GuardDuty 다음" 위치: 보고서의 로그 범위 칸에 GuardDuty 결과와 GuardDuty가 읽지 않는 로그(WAF·ALB·웹서버·SSH·서버 방화벽)를 함께 넣었는지 한 문장으로 알린다(`explain.guardduty_note`). `logsight check`의 WAF·ALB·GuardDuty 설명에 "GuardDuty는 이 로그를 읽지 않음", "켜기 전의 일은 보지 않음"을 넣었다. README·발표 자료에 위치와 장기 계획(GuardDuty 결과 하나로 시작하기)을 적었다.
- AI 사건 재검토(`logsight/triage.py`): 사건마다 공격·정상 활동·위험 설정·판단 불가를 판정해 공격 사건을 위로 올리고, 같은 공격으로 보이는 사건을 묶는다. 근거 ref와 사건 ID는 코드로 다시 검사한다. API 키가 없으면 규칙 순서 그대로다.
- 클라우드 공방전 통합로그 변환·가명 처리 스크립트(`scripts/ctf/convert_gongbang.py`)와 블루팀 보고서 기반 채점 스크립트(`scripts/ctf/eval_gongbang.py`). 결과는 `docs/공방전_로그_측정.md`.
- API 객체 번호 탐색 규칙(`WEB_OBJECT_ENUM`): ALB·API Gateway 로그에서 같은 IP가 같은 API의 서로 다른 객체 번호 5개 이상에 10분 안에 403/404를 받으면 IDOR 탐색으로 표시한다.
- AI 없이 동작하는 사건 판정과 설명(`logsight/explain.py`): 공격 의심·위험 설정·판단 불가·정상 활동 판정, 규칙별 한국어 문장 틀, 로그 범위 문장, 같은 IP·액세스 키·/24 대역(2시간 안)으로 사건 연결. API 키가 없으면 이 판정으로 순서를 정한다.
- 정상 작업 목록(`known_activity`, environment.json): 운영자·배포 계정·관리 IP와 맞는 이벤트에 표시하고, 그것만으로 된 사건을 정상 활동으로 내린다. `trusted_ips`도 목록으로 쓴다.
- 보고서: 맨 위 "AI 사용 안 함 / Claude 사용" 표시, 로그 범위 막대와 "알 수 없는 것", 사건별 판정과 판정 이유, 왼쪽 목차. 디자인을 새로 짰다(다크 모드·모바일·인쇄).
- 설명 방식 비교 화면(`scripts/compare_modes.py`, 웹 `/compare`): 같은 사건의 규칙 판정과 Claude 판정을 나란히, 정답이 있으면 맞음·틀림까지.
- 공방전 채점에 규칙 판정 점수와 `--env`(정상 작업 목록) 추가. 결과 `reports/ctf/gongbang_rules_v3*.json`.
- 공격 흐름 그림(`logsight/graph.py`): 사건마다, 그리고 같은 공격 묶음마다 출발지 → 들어온 곳 → 쓴 권한 → AWS 서비스를 번호 붙은 선으로 그리고, 번호별 시각·결과·근거 로그 표를 붙인다. 선은 근거 이벤트로만 만들고, 그린 뒤 모든 이벤트가 어느 선에 들어갔는지 다시 대조해 결과를 그림 아래에 적는다. GuardDuty 결과는 선이 아니라 해당 서버·역할에 붙는 표시다. 서버와 역할 사이 점선은 CloudTrail 세션 이름이나 인스턴스 ID가 그 서버일 때만 그린다.
- AI 재검토에 로그 범위 요약(`coverage`)을 함께 보낸다. 로그 종류·기간, 빠진 로그 종류, S3 객체 호출 수, 탈취 의심 키의 전체 호출 내역이 들어 있어 '로그에 없음'과 '일어나지 않음'을 구별하게 한다.

### 변경
- EventBridge로 받은 GuardDuty 결과(camelCase 키)도 읽는다. auth.log의 `Invalid user` 줄을 SSH 실패로 센다.
- VPC 흐름에서 서버 응답(서비스 포트 → 임시 포트)은 포트 스캔으로 세지 않는다.
- 규칙 판정: 인터넷 스캐너가 관리 포트를 두드린 것만 있는 사건은 '위험 설정'으로, 정상 작업 목록 계정의 위험한 설정 변경은 '정상' 대신 '위험 설정'으로, 목록 계정이라도 키 유출 징후(권한 거부 폭주·여러 IP)가 있으면 '판단 불가'로 둔다. 공방전 채점 점수는 그대로다.
- 규칙 판정의 사건 연결에서 "같은 서버를 노림"을 뺐다. 출발지가 다른 공격자를 같은 공격으로 묶는 경우가 있었다(통합 샘플 INC-001과 INC-002). 공방전 채점 점수는 그대로다.
- 결과 JSON의 `triage`는 키가 없어도 규칙 판정(`mode: "rules"`)을 담는다. 사건에 `verdict`, `verdict_by`가 붙고, `ai_verdict`는 Claude 판정일 때만 붙는다. 규칙 판정은 `rule_triage`에 항상 따로 남는다.
- 규칙 기반 보고서의 `report`에 `verdict`, `verdict_reason`이 붙는다(회귀 기준값 갱신).
- 공방전 변환기의 IP 가명 처리가 /24(IPv6는 /64) 관계를 남긴다. 같은 대역의 공격자 IP를 잇는 근거가 가명 처리에서 사라지던 문제. 정답지의 공격자 IP도 같은 실제 IP의 새 가명으로 옮겼다.
- 웹 판정: 약한 성공 신호(웹셸 경로 접근, 큰 응답, 관리자 페이지 접근) 하나만으로는 "침해 가능성 높음"으로 올리지 않는다. 공격 시도나 다른 성공 신호가 같은 사건에 있어야 한다.
- 웹 로그인 무차별 대입: 로그인 경로를 따로 적지 않았으면 `login`이 든 관리자 경로만 앞부분으로 보고, 나머지 관리자 경로는 정확히 같을 때만 센다.

### 수정
- ALB 상태 코드 이름을 `http_status`로 바꾼 뒤 API 객체 번호 탐색 규칙(`WEB_OBJECT_ENUM`)이 동작하지 않던 문제.
- 해시 같은 값의 `c=` 인자와 스크립트가 아닌 경로를 웹셸 명령으로 보던 오탐.
- `/wp-content/uploads/`처럼 경로 중간에 있는 업로드 폴더의 스크립트 실행을 놓치던 문제.
- base64로 감춘 셸 명령을 놓치던 문제.

## 0.3.0

### 추가
- 웹서버 침해 판단 엔진(`logsight scan`): nginx·Apache 접속·오류 로그와 인증 로그, 웹 루트 파일 점검.
- 판정(침해 확인 / 침해 가능성 높음 / 의심 / 근거 없음)과 사건별 공격 흐름, 근거 로그 위치.
- 비숙련자용 요약 카드(`logsight/web/layman.py`)와 숙련자용 상세 보고서(`logsight/web/expert.py`): 타임라인, IOC, ATT&CK 매핑, 차단 규칙(nginx·iptables·ufw). 차단 규칙은 자동 적용하지 않는다.
- 웹 API: `POST /api/web/scan`, 상태 확인용 `GET /healthz`.
- 공개 데모 모드(`LOGSIGHT_DEMO=1`): 업로드·API 문서·AI 호출을 끈다.
- `Makefile`(`make test`, `make smoke`, `make run`).

### 변경
- 없음. 기존 AWS 로그 분석(`logsight analyze`)의 출력은 웹 모듈 추가 전과 같음을 회귀 테스트로 확인했다(`tests/test_regression.py`).

### 수정
- 없음.

### 제거
- 없음.

### 호환성 주의
- 없음. 새 명령과 새 API만 추가되었고 기존 명령·출력 형식은 그대로다.

## 0.2.0 (태그 `v0.2.0`)

- AWS 로그 분석(CloudTrail, VPC Flow Logs, WAF, ALB, SSH 인증 로그), 규칙 탐지, 사건 묶기, 설정 점검, 보고서.

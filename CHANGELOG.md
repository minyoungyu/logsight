# 변경 기록

이 프로젝트는 [SemVer](https://semver.org/lang/ko/)를 따른다. 버전 번호는 변경 내용이 정한다.

## 미출시

### 추가
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

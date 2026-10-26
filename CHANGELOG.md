# 변경 기록

이 프로젝트는 [SemVer](https://semver.org/lang/ko/)를 따른다. 버전 번호는 변경 내용이 정한다.

## 미출시

### 변경
- 웹 판정: 약한 성공 신호(웹셸 경로 접근, 큰 응답, 관리자 페이지 접근) 하나만으로는 "침해 가능성 높음"으로 올리지 않는다. 공격 시도나 다른 성공 신호가 같은 사건에 있어야 한다.
- 웹 로그인 무차별 대입: 로그인 경로를 따로 적지 않았으면 `login`이 든 관리자 경로만 앞부분으로 보고, 나머지 관리자 경로는 정확히 같을 때만 센다.

### 수정
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

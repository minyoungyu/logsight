# CTF 로그로 탐지 성능 재기 (수집 가이드)

동아리 CTF에서 서버 침투 과정의 로그를 모아, LogSight가 공격을 얼마나 잡는지 **독립된 정답**으로 잰다.
공격 시나리오를 LogSight 규칙을 만든 사람이 아니라 CTF 운영자가 정하므로, 자체 시나리오 과적합을 줄일 수 있다.

## 0. 먼저 지킬 것

- **허가된 환경만.** 동아리가 운영하는 CTF 서버에서만 수집한다. 제3자 서버의 로그는 수집하지 않는다.
- **참가자 동의.** 로그에는 참가자의 IP와 접속 기록이 남는다. 참가 안내에 "분석 목적으로 로그를 보관하고 재현율 측정에 쓴다"를 넣는다.
- **저장소에 올리지 않는다.** 로그와 정답 파일은 `.gitignore`에 있는 폴더(예: `data/`)에만 둔다. 공개 저장소에 올리지 않는다.
- **IP는 익명화하지 않는다.** 판정에 IP가 필요하다. 보관 기간을 정해 두고 측정 후 지운다.

## 1. 수집할 로그

| 종류 | 위치 (Ubuntu 기준) | 필수 | 비고 |
|---|---|---|---|
| 웹 접속 로그 | `/var/log/nginx/access.log` 또는 `/var/log/apache2/access.log` | 필수 | 기본 `combined` 형식이어야 한다. 프록시 뒤라면 `X-Forwarded-For`가 남아야 한다. |
| 웹 오류 로그 | `/var/log/nginx/error.log` 또는 `/var/log/apache2/error.log` | 권장 | 로그 포이즈닝·경로 오류 흔적이 여기 남는다. |
| 인증 로그 | `/var/log/auth.log`(Ubuntu) 또는 `/var/log/secure`(RHEL) | 권장 | SSH 무차별 대입·계정 탈취 판정에 쓴다. |
| 웹 루트 사본 | 웹 루트 디렉터리 | 권장 | 웹셸 점검용. **원본을 건드리지 말고 사본을 만든다.** |
| 애플리케이션 로그 | 앱이 따로 남긴 로그 | 참고 | **현재 LogSight는 읽지 못한다.** 이 로그에만 남는 공격은 사각지대로 따로 표시한다. |

시작·종료 시각을 정확히 맞춘다. 서버 시각이 UTC인지 확인하고, 아니라면 `profile.json`의 `since`/`until`을 같은 시간대(ISO 형식, 예: `2026-10-25T10:00:00+09:00`)로 적는다.

## 2. 수집 방법

```bash
# 1) CTF 종료 후 로그를 복사하고 해시를 남긴다(원본은 그대로 둔다)
mkdir -p data/ctf-2026-10/raw && cd data/ctf-2026-10/raw
sudo cp -p /var/log/nginx/access.log* /var/log/nginx/error.log* .
sudo cp -p /var/log/auth.log* .
sudo chown -R "$USER" . 
sha256sum * > SHA256SUMS

# 2) 웹 루트 사본(권한 필요 시 sudo)
sudo rsync -a --exclude='*.log' /var/www/<사이트>/ ../webroot/
```

- 로테이션된 파일(`access.log.1`, `.gz`)도 함께 넣는다. LogSight는 `.gz`를 읽는다.
- 로그를 편집하거나 줄을 지우지 않는다. 필요하면 시간 범위만 `since`/`until`로 자른다.

## 3. 정답(ground truth) 기록

CTF 운영자가 **공격이 일어난 순간마다** 기록한다. 나중에 기억으로 쓰지 않는다.

```json
{
  "scenario": "sqli-login-bypass",
  "time_utc": "2026-10-25T10:12:31Z",
  "attacker_ip": "203.0.113.45",
  "method": "POST",
  "path": "/login.php",
  "technique": "T1190",
  "step_note": "로그인 폼에 ' OR 1=1 -- 입력",
  "flag_stage": "flag1 획득",
  "detectable": true,
  "expected_rules": ["WEBLOG_SQLI"]
}
```

- `attacker_ip`: 팀 단위로 같은 NAT를 쓰면 팀 IP를 적고, 팀 이름을 `team` 필드에 추가한다.
- `detectable`: 접속 로그에 흔적이 남는 공격이면 `true`. 본문만 바뀌거나 앱 로그에만 남으면 `false`로 적는다. 이 항목이 재현율 분모를 정한다.
- `expected_rules`: LogSight 규칙 ID로 적는다. 규칙 목록은 `python -m logsight rules`로 본다. 규칙 이름을 모르겠으면 `technique`만 적고 나중에 맞춘다.
- 정상 트래픽(운영자 점검, 봇, 검색 엔진)도 `"malicious": false`로 적는다. 오탐을 재려면 이 항목이 필요하다.

기록 파일 이름은 `data/ctf-2026-10/ground_truth.json`처럼 CTF 로그와 같은 폴더에 둔다.

## 4. 분석 실행

```bash
# 프로필 예시: data/ctf-2026-10/profile.json
# {
#   "name": "동아리 CTF 서버",
#   "webroot": "data/ctf-2026-10/webroot",
#   "log_paths": {
#     "access": ["data/ctf-2026-10/raw/access.log*"],
#     "weberror": ["data/ctf-2026-10/raw/error.log*"],
#     "auth": ["data/ctf-2026-10/raw/auth.log*"]
#   },
#   "since": "2026-10-25T10:00:00+09:00",
#   "until": "2026-10-25T12:00:00+09:00",
#   "year": 2026
# }

python -m logsight scan --profile data/ctf-2026-10/profile.json --no-ai --out data/ctf-2026-10/report
```

- `--no-ai`로 규칙만 돌려야 측정이 재현된다. AI 호출은 결과가 바뀔 수 있다.
- 보고서의 탐지 IP를 정답의 `attacker_ip`와 맞춰 재현율과 오탐을 센다. 측정 스크립트는 `lab/evaluate.py`와 같은 방식으로 만들 예정이다.

## 5. 측정 전 확인 체크리스트

- [ ] 로그 형식이 `combined`인지 첫 줄을 확인했다 (`head -1 access.log`)
- [ ] 시간대와 `since`/`until`이 맞다
- [ ] 해시(`SHA256SUMS`)를 남겼고 원본을 건드리지 않았다
- [ ] 정답 파일의 모든 공격 행에 `time_utc`와 `attacker_ip`가 있다
- [ ] 정상 트래픽이 정답에 함께 들어 있다(오탐 측정용)
- [ ] 앱 로그에만 남는 공격은 `detectable: false`로 표시했다
- [ ] 데이터 폴더가 `.gitignore`에 들어 있고 `git status`에 나오지 않는다
- [ ] 보관 기간과 삭제 날짜를 정했다

## 6. 알려진 한계

- LogSight는 웹 서버 로그와 인증 로그만 읽는다. 앱 내부 로그와 DB 로그는 보지 못한다.
- 한 IP에 여러 참가자가 섞이면 탐지 IP로 사람을 구분할 수 없다. 팀별 IP를 따로 받는 것이 좋다.
- 정답을 CTF 운영자가 쓰므로 기록 누락이 있을 수 있다. 누락된 공격은 재현율을 낮춘다(보수적인 방향).

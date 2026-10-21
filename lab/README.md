# lab/ — 로컬 검증 환경 (취약 사이트 + 공격 재현 + 채점)

실제 사이트 없이 **정답을 아는 로그**로 탐지 성능을 재기 위한 환경이다.
공격은 오직 로컬 서버(127.0.0.1)에만 보낸다. 외부로는 아무 요청도 가지 않는다.

```
bash lab/serve.sh start      # nginx + php-fpm 으로 취약 사이트 2종을 띄움(실제 로그가 쌓임)
python3 lab/attack.py        # 정상 + 공격 트래픽 생성, ground_truth.json 기록
python -m logsight scan --profile lab/profiles/shopmall.json --no-ai --out lab/reports/shopmall
python3 lab/evaluate.py      # 탐지 결과를 정답과 대조(재현율/오탐)
bash lab/serve.sh stop
```

- `sites/shopmall`, `sites/board` — **의도적으로 취약한** 테스트 사이트(배포 금지).
  경로 구조·업로드 폴더가 서로 달라, 프로필만으로 다른 사이트를 다루는 것을 보인다.
- `profiles/*.json` — 각 사이트용 프로필(실제 사이트에선 이 파일만 바꾸면 됨).
- `attack.py` — SQLi/경로조작/명령삽입/스캐너/무차별대입/웹셸 업로드·실행 시나리오.
- `evaluate.py` — 기대 규칙 재현율과 정상 트래픽 오탐을 센다(기존 무료 도구 비교를 끼울 자리).

런타임 산출물(`logs/`, `runtime/`, `reports/`, `*.sqlite`, 업로드물)은 커밋하지 않는다.
서버 없이 보고 싶으면 저장소에 포함된 `samples/web/` 로 바로 돌릴 수 있다:

```
python -m logsight scan --profile samples/web/profile.json --no-ai --out reports/web_demo
```

필요 패키지: `nginx`, `php-fpm`(php-sqlite3 포함). Ubuntu: `apt-get install nginx php-fpm php-sqlite3`.

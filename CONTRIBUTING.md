# 기여 안내

## 개발 환경

    pip install -e ".[dev,web]"
    make test      # pytest + 커버리지
    make lint      # ruff
    make regress   # 샘플 결과 고정 비교 + 처음 보는 데이터에서 잡은 것 계속 잡는지

GitHub Actions가 PR마다 Ubuntu·Windows × Python 3.10·3.13에서 시험을 돌리고(macOS는 Actions 화면에서 직접 실행할 때만), lint, 회귀(Splunk attack_data), 비밀값 검사(gitleaks)를 함께 한다.
모두 통과해야 합친다.

## 시험판 내기

`logsight/__init__.py`의 `__version__`과 CHANGELOG의 제목(`## 0.4.0`)을 맞추고 `v0.4.0` 태그를 올린다.
`.github/workflows/release.yml`이 설치 파일(whl), 샘플 보고서, Docker 이미지(GHCR)를 만들어 시험판 릴리스로 올린다.

## 규칙

- **탐지 규칙을 더하거나 고치면** `logsight/rulespec.py`에 명세(조건, 사각지대, 오탐, 먼저 할 일)를 쓰고
  `python scripts/rule_spec_doc.py`로 [docs/규칙_명세.md](docs/규칙_명세.md)를 다시 만든다. 양성·음성 예를 `tests/test_rule_validation.py`에 더한다.
  샘플 결과가 바뀌면 `python scripts/regress_samples.py --update`로 고정 파일을 다시 쓰고 차이를 PR에 적는다.
- **AI에 보내는 값을 더하면** 공격자가 쓸 수 있는 값인지 보고, 그렇다면 `logsight/guard.py`의 `UNTRUSTED_KEYS`에 넣는다.
- **측정 숫자는 데이터와 함께 적는다.** 규칙을 고친 데이터로 잰 숫자는 "개발 데이터"로, 처음 보는 데이터로 잰 숫자와 섞지 않는다.
  측정하지 않은 것은 "미측정" 또는 "구상"으로 적는다.
- **실제 로그·키·계정 ID를 커밋하지 않는다.** 측정 원본은 `data/`(무시됨)에 두고, 저장소에는 가명 처리한 결과만 올린다.
- 커밋 메시지와 문서는 한국어로, 짧은 문장으로 쓴다. 변경 내용은 [CHANGELOG.md](CHANGELOG.md)의 "미출시"에 적는다.

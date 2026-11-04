# 기여 안내

## 개발 환경

    pip install -r requirements.txt httpx "moto[ec2,s3,cloudtrail,iam,wafv2,elbv2,guardduty,sts,sqs]>=5"
    python -m unittest discover -s tests

GitHub Actions가 Ubuntu·Windows·macOS × Python 3.10·3.13에서 같은 테스트를 돌린다. 모두 통과해야 합친다.

## 규칙

- **탐지 규칙을 더하거나 고치면** `logsight/rulespec.py`에 명세(조건, 사각지대, 오탐, 먼저 할 일)를 쓰고
  `python scripts/rule_spec_doc.py`로 [docs/규칙_명세.md](docs/규칙_명세.md)를 다시 만든다. 양성·음성 예를 `tests/test_rule_validation.py`에 더한다.
- **측정 숫자는 데이터와 함께 적는다.** 규칙을 고친 데이터로 잰 숫자는 "개발 데이터"로, 처음 보는 데이터로 잰 숫자와 섞지 않는다.
  측정하지 않은 것은 "미측정" 또는 "구상"으로 적는다.
- **실제 로그·키·계정 ID를 커밋하지 않는다.** 측정 원본은 `data/`(무시됨)에 두고, 저장소에는 가명 처리한 결과만 올린다.
- 커밋 메시지와 문서는 한국어로, 짧은 문장으로 쓴다. 변경 내용은 [CHANGELOG.md](CHANGELOG.md)의 "미출시"에 적는다.

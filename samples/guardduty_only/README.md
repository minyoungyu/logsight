# GuardDuty 결과만 있을 때 (합성 예시)

GuardDuty 결과 5건만 넣고 LogFinder가 한국어로 해석하는 예시다. 필드 구조는 GuardDuty `get-findings` 결과와 같게 만들었지만
**값은 합성**이다(IP는 문서용 대역, 키·계정은 가짜). 실제 계정에서는 `aws guardduty create-sample-findings`로 만든 샘플이나
실제 결과를 `aws guardduty get-findings ... > findings.json`으로 내려받아 같은 명령에 넣으면 된다.

    python -m logsight analyze samples/guardduty_only --out reports/guardduty_only --no-ai

이야기: 쇼핑몰 웹서버(i-0shop0web0001)에 포트 두드림 → 메타데이터를 노린 요청 → 서버 역할 키가 밖에서 쓰임 →
그 키로 주문 버킷을 평소와 다르게 읽음 → 서버에서 리버스 셸.

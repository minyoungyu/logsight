# GuardDuty 결과를 받아 해석하기 (사양서 FR-34)

작성 2026-11-21. "탐지는 AWS, 해석과 조치는 LogFinder"라는 위치를 기능으로 만든 기록이다.

## 무엇을 하나

GuardDuty 결과 파일(콘솔·CLI `get-findings` 결과, S3 내보내기, EventBridge 경보)을 넣으면, 다른 로그가 없어도 다음을 만든다.

1. **한국어 제목과 한 줄 풀이.** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` → "서버 역할 키가 AWS 밖에서 쓰임. 서버에만 있어야 할 임시 키가 인터넷의 다른 컴퓨터에서 쓰였습니다…"
2. **먼저 할 일과 대상.** 결과가 가리키는 키(가린 형식)·역할·서버·버킷·DB·클러스터 이름을 붙여, 번지는 것 막기 → 들어온 길 닫기 → 원인 고치기 순서로. 설정 스냅샷이 있으면 같은 뜻의 LogFinder 규칙의 CLI 수정·되돌리기 명령도 나온다(같은 일을 하는 조치는 한 번만).
3. **성공 여부를 지어내지 않음.** GuardDuty 결과에는 공격이 성공했는지가 없다. 이전에는 이를 '모두 막히거나 실패'로 세어 "급하지 않을 수 있습니다"라고 적었다(잘못). 이제는 "GuardDuty 결과에는 성공 여부가 없어 같은 시각의 CloudTrail·웹·서버 로그로 확인해야 합니다"라고 적는다.
4. GuardDuty가 읽지 않는 로그(WAF·ALB·웹서버·SSH)를 함께 넣으면 같은 IP·서버·키로 한 사건으로 엮는다(기존 기능).

    python -m logsight analyze samples/guardduty_only --out reports/guardduty_only --no-ai

`samples/guardduty_only`는 필드 구조만 실제와 같고 값은 합성이다.
실제 계정에서는 `aws guardduty create-sample-findings --detector-id <ID> --finding-types <유형>`로 샘플 결과를 만들거나,
실제 결과를 `aws guardduty list-findings` → `get-findings`로 내려받아 같은 명령에 넣는다.

## 측정: 유형 몇 종을 풀어 주나

    python scripts/gd_coverage.py          # 요약
    python scripts/gd_coverage.py --list   # 유형별 제목·먼저 할 일

유형 목록은 AWS 공식 문서의 활성 유형 표(2026-11-21 열람)를 `samples/guardduty/finding_types.tsv`로 옮긴 것이다.

| 항목 | 결과 |
|---|---|
| GuardDuty 활성 유형 | 211종 |
| 한국어 제목·풀이·먼저 할 일 | 211종(100%) = 유형별로 쓴 문장 72종 + 낱말 조합 139종 |
| 같은 뜻의 LogFinder 규칙에 연결(단계·기법) | 23종 |
| 그중 설정 수정 명령(CLI·되돌리기)까지 나오는 것 | 15종 |

**이 숫자를 읽을 때 주의할 것**

- **100%는 이 목록을 보고 낱말 사전을 만들었기 때문에 나온 값이다(개발 점수).** AWS가 새 유형을 더하면 모르는 낱말이 생기고, 그 유형은 영어 이름이 남은 채 'raw'로 표시된다. 스크립트를 다시 돌리면 몇 종이 raw인지 바로 보인다.
- 139종은 "자원: 행동"을 낱말로 조합한 제목이라, 유형별로 쓴 72종보다 풀이가 일반적이다(예: "쿠버네티스(EKS): 알려진 악성 IP에서 호출"). 먼저 할 일도 자원별 기본 문장이다.
- 풀이가 **맞는지, 비전문가가 이해하는지는 재지 않았다.** 사용자 시험(S3)에서 GuardDuty 시나리오를 넣어 확인해야 한다.
- 설정 수정 명령까지 나오는 15종은 CloudTrail·VPC Flow 계열이다. 런타임·EKS·RDS·Lambda·악성코드 유형은 명령 없이 조치 문장만 준다.

## 고객에게 하는 말

> GuardDuty는 켜 두세요. 경보가 오면 결과 파일(또는 경보 자체)을 LogFinder에 넣으면, 무슨 뜻인지와 먼저 할 일 3가지가 한국어로 나옵니다.
> 웹·서버 로그를 함께 넣으면 GuardDuty가 보지 못하는 "실제로 들어왔는지"까지 한 사건으로 봅니다.

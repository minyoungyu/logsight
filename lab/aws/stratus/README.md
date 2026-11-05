# Stratus Red Team으로 AWS 공격 재현 (준비됨, 실행 0회)

우리가 만든 시나리오가 아니라 **남이 만든 공격**으로 탐지를 재는 두 번째 방법이다.
[Stratus Red Team](https://github.com/DataDog/stratus-red-team)(DataDog, Apache-2.0)은 AWS 공격 기법 46개를
준비 → 실행 → 정리 순서로 시험 계정에서 일으킨다. 탐지 도구를 만드는 팀들이 규칙 검증에 쓰는 도구다.

## 순서

1. **예상을 먼저 고정한다.** [expected.tsv](expected.tsv)는 실행 전에 `logsight/detect.py` 코드만 보고 적었다
   (2026-11-04). 잡을 것 15, 놓칠 것 28, 기준에 따라 다름 3. 실행 뒤에도 이 파일은 고치지 않는다.
2. 실습 전용 계정에 `../terraform`으로 환경을 올리고(트레일에 S3 데이터 이벤트 포함), 비용 알람($5)을 건다.
3. `bash lab/aws/stratus/run.sh` → 기법마다 실행 시각이 `data/stratus/<날짜>/times.tsv`에 남는다.
4. 15분 뒤 `bash lab/aws/collect.sh ...`로 로그를 받고 `python -m logsight analyze <폴더> --no-ai --out reports/stratus`.
5. `python lab/aws/stratus/score.py data/stratus/<날짜>/times.tsv reports/stratus/report.json`
6. 결과를 `docs/Stratus_재현_측정.md`에 적는다. 예상과 다른 것(잡을 줄 알았는데 놓침, 그 반대)을 따로 적는다.

## 안전

- **실습 전용 계정에서만.** Stratus는 실제로 IAM 사용자·키를 만들고 트레일을 끄고 스냅샷을 공유한다. 각 기법 뒤에 정리하지만,
  끝나면 `stratus cleanup --all`과 `terraform destroy`로 한 번 더 지운다.
- 스냅샷·AMI 공유 기법은 Stratus가 정한 가짜 외부 계정 ID로 공유한다. 실제 남의 계정이 아니다.
- 결과 로그와 계정 ID는 `data/`(무시됨)에만 둔다.

## 이 측정의 성격

**2026-11-05 주의:** 이 기법 목록과 Splunk의 놓친 목록을 보고 규칙 5개를 더하고 5개를 넓혔다([탐지공백_보강](../../../docs/탐지공백_보강.md)).
그래서 Stratus 결과는 처음 보는 데이터가 아니라 **개발 데이터**로 적는다. expected.tsv는 규칙을 더하기 전(v0.4.0 이전 코드) 예상이라,
결과와 비교하면 보강의 효과를 볼 수 있다.

예상을 미리 고정했고 규칙을 이 데이터로 고치지 않았으므로 **처음 보는 공격에 가깝다.** 다만 기법 목록은 공개돼 있어
규칙을 만든 사람이 본 적이 있을 수 있다. 측정 뒤 규칙을 고치면 그 다음 측정은 개발 데이터로 적는다.

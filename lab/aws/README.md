# AWS 실습 랩 (직접 측정용)

내 AWS 계정에 작은 취약 환경을 올려, 내가 직접 공격을 재현하고 LogSight 탐지 성능을
**독립 정답**으로 재기 위한 구성이다. 자세한 절차는 [`docs/AWS_실습_재현_가이드.md`](../../docs/AWS_실습_재현_가이드.md)를 본다.

## 구성

| 경로 | 내용 |
|---|---|
| `terraform/` | EC2(nginx+취약 PHP 사이트) + S3(민감/로그) + IAM 역할 + CloudTrail(S3 데이터 이벤트) + VPC Flow Log |
| `collect.sh` | CloudTrail·Flow Log(S3)와 서버 로그(nginx/auth)를 `data/aws_lab/<stamp>/`로 수집 |
| `to_environment.py` | `aws describe-*`(읽기 전용)로 설정 점검용 `environment.json` 생성 |
| `ground_truth.template.json` | 정답 파일 템플릿. 복사해 `data/aws_lab/<stamp>/ground_truth.json`로 쓴다 |

## 안전 수칙 (요약)

- **내가 만든 자원에만** 공격을 재현한다. 제3자 대상 금지, AWS AUP 준수.
- DoS·flooding 금지. 무차별 대입은 수십 회 수준.
- 자격증명·`.pem`·계정 번호를 저장소/채팅에 올리지 않는다. 로그·정답은 `data/`(gitignore)에만.
- S3 민감 데이터는 합성 CSV. IMDSv1(`http_tokens="optional"`)은 탈취 사슬 재현용 실습 설정이다.
- 끝나면 `terraform destroy`. 배포 전 비용 알람($5)부터 건다.

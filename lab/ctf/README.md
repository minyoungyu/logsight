# LogSight CTF 대회 인프라

설계: "LogSight 검증용 CTF 형식안"(3장 인프라, 3-3 우회 점검)과 "CTF 실제 구축 진행 플랜".
대회 전용 AWS 계정(ctf_server 프로젝트, 시드니 `ap-southeast-2`)에만 올린다.

## 올라가는 것

| 구성 | 내용 |
|---|---|
| 네트워크 | VPC 10.20.0.0/16, 퍼블릭 서브넷 2개(ALB·CTFd), 팀 서브넷 10.20.10.0/24(인터넷 경로 없음, NAT 없음) |
| 엔드포인트 | S3 게이트웨이(무료), SSM·ssmmessages·ec2messages 인터페이스(플래그 주입용) |
| 팀 서버 | t3.small × 10, Amazon Linux 2023, 10.20.10.11~20, IMDSv1(F5), CPU 무제한, 16GB |
| 입구 | ALB 포트 8001~8010 → 팀 서버, 팀별 nginx 기본 인증 |
| WAF | 스캐너 UA 차단, 로그인 5분 10회, IP당 5분 100건(공용 IP 세트는 500건), SQLi·Common COUNT |
| 로그 | CloudTrail(단일 리전, 플래그 버킷 데이터 이벤트), VPC Flow v5(1분), ALB, WAF, 호스트(nginx·auth·messages, 1분마다 S3) |
| 점수판 | CTFd(Docker) t3.small, 퍼블릭 IP |
| vCPU | 22개 사용(쿼터 32) |

## 플래그가 놓이는 곳 (3-3 원칙: 한 곳, 한 권한)

| 플래그 | 위치 | 넣는 방법 |
|---|---|---|
| F1 | `/var/lib/ctf/f1_path`(숨은 경로), `/var/lib/ctf/f1` | `inject_flags.sh`(SSM) |
| F2 | `/var/lib/ctf/f2` — 관리자 로그인 성공 화면에서만 | SSM |
| F3 | `/usr/local/bin/proof`(0711, 실행만) | SSM에서 컴파일 |
| F4 | `/root/flag4.txt`(0600) | SSM |
| F5 | 팀 역할 이름 `ctf-tNN-<16hex>` (IMDS·sts로만 보임) | Terraform |
| F6 | `s3://<flags 버킷>/tNN/flag6.txt`, VPC 엔드포인트 경유 읽기 거부 | Terraform |

user-data에는 플래그가 없다(IMDSv1로 읽힌다). 상태 파일·출력에는 있으므로 운영진 PC에만 둔다.

## 남은 일

- `site/`: 지금은 자리표시자다. `lab/sites/shopmall`에서 설계 밖 취약점을 걷어 낸 CTF 버전을 여기에 만든다(3-3 표). 사이트는 위 경로에서 F1·F2를 읽고, DB는 `/var/lib/ctf/` 아래에 둔다.
- CTFd 팀·문제·플래그 등록 스크립트.
- 대회 후 `hosts/tNN/<로그>/<epoch>-<offset>.log` 조각을 이름순으로 이어 붙이는 수집 스크립트(`lab/aws/collect.sh` 확장).

## 실행 순서

```bash
cd lab/ctf/terraform
cp terraform.tfvars.example terraform.tfvars   # operator_cidrs 채우기
terraform init
terraform plan -out ctf.plan                   # 자원 수와 비용 확인 후
terraform apply ctf.plan                       # 운영진 승인 후에만
bash ../inject_flags.sh                        # 서버가 SSM Online이 되면 F1~F4 주입
terraform output -json flags > ~/ctf-flags.json   # CTFd 등록용, 저장소 밖에 보관

# 대회 10:00
terraform apply -var contest_open=true
# 대회 19:00
terraform apply -var contest_open=false
# 수집 후 정리(로그 버킷은 force_destroy=false라 남는다)
terraform destroy
```

팀 서버 하나가 망가지면 `terraform apply -replace='aws_instance.team["t03"]'` 후 `bash ../inject_flags.sh t03`.

## 리허설에서 확인할 것

- 팀 서버의 `dnf install`이 S3 게이트웨이로 되는지(`/var/log/ctf-bootstrap.log`). 안 되면 이미지 굽기로 바꾼다.
- 무료 플랜에서 SSM 인터페이스 엔드포인트·WAF 로그·ALB 로그·CloudTrail 데이터 이벤트가 켜지는지.
- 팀 서버 A에서 B로, 팀 서버에서 인터넷으로 연결이 안 되는지.
- 서버 안에서 서버 역할로 `flag6.txt`를 읽으면 AccessDenied, 밖에서 같은 키로 읽으면 성공하는지.

## 데이터 확보 우선 (입문자 대상)

참가자 대부분이 입문자라 F3~F5에서 막히기 쉽다. 제품(LogSight)에 가장 값진 데이터는
클라우드 단계(F5·F6)의 로그이므로, 로그가 끝까지 나오게 난이도를 낮추고 아래를 지킨다.

1. **황금 샘플(필수):** 대회 전날 검증 때, 전용 서버 1대에서 F1~F6을 깨끗하게 한 번 풀고
   그 로그 8종을 따로 수집·라벨링한다. 팀들이 어디까지 가든 완전한 전체 사슬 데이터가 100% 확보된다.
   이 서버는 검증 후 그대로 두고(팀 서버만 재생성), 수집 폴더를 `golden/` 으로 따로 보관한다.
2. **F5 단서:** `admin/fetch.php` 도움말에 메타데이터(169.254.169.254)·내부 주소 예시를 남겨
   개념만 알면 SSRF로 풀리게 했다. 너무 쉬우면 그 문구를 지운다.
3. **힌트 일정:** 45분·90분 막힘 힌트에 더해, F5(클라우드) 개념 힌트를 14:00 → 13:00 으로 당긴다.
4. **정상 트래픽 봇은 유지:** 탐지 오탐 측정용 정상 사용자/관리자 로그는 그대로 둔다.

성공 지표는 등수가 아니라 **단계별 로그 커버리지**다: F5·F6에 도달한 팀 수와, 8종 로그가 모두
채워졌는지를 본다.

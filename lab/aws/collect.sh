#!/usr/bin/env bash
# LogSight AWS 랩 — 로그 수집기.
# S3 에서 CloudTrail·VPC Flow Logs 를 받고, EC2 에서 nginx·auth 로그를 scp 로 받아
# data/aws_lab/<날짜> 에 모은다. 그 폴더를 `python -m logsight analyze` 에 넣으면 된다.
#
# 사용: bash lab/aws/collect.sh <logs_bucket> <region> <web_public_ip> [ssh_key.pem] [ssh_user]
#   예: bash lab/aws/collect.sh logsight-lab-logs-ab12cd ap-northeast-2 203.0.113.9 ~/logsight-lab.pem ubuntu
# AWS 자격증명은 본인 PC의 `aws configure` 로 설정돼 있어야 한다. 채팅/저장소에 키를 넣지 않는다.
set -euo pipefail

BUCKET="${1:?logs_bucket 필요}"
REGION="${2:?region 필요}"
WEB_IP="${3:?web_public_ip 필요}"
SSH_KEY="${4:-}"
SSH_USER="${5:-ubuntu}"

STAMP="$(date -u +%Y%m%d_%H%M)"
OUT="data/aws_lab/${STAMP}"
mkdir -p "$OUT"
echo "[*] 출력 폴더: $OUT"

echo "[*] CloudTrail 내려받기…"
aws s3 cp "s3://${BUCKET}/cloudtrail/" "$OUT/cloudtrail/" --recursive --region "$REGION" --only-show-errors || echo "  (아직 비어 있을 수 있음 — CloudTrail 전달은 몇 분 지연된다)"

echo "[*] VPC Flow Logs 내려받기…"
aws s3 cp "s3://${BUCKET}/vpcflow/" "$OUT/vpcflow/" --recursive --region "$REGION" --only-show-errors || echo "  (아직 비어 있을 수 있음 — Flow Logs S3 전달은 약 10분 지연된다)"

if [[ -n "$SSH_KEY" ]]; then
  echo "[*] nginx·auth 로그 scp…"
  mkdir -p "$OUT/host"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "${SSH_USER}@${WEB_IP}:/var/log/nginx/access.log" "$OUT/host/nginx-access.log" || echo "  (nginx access 로그 실패)"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "${SSH_USER}@${WEB_IP}:/var/log/nginx/error.log" "$OUT/host/nginx-error.log" || echo "  (nginx error 로그 실패)"
  # auth.log 는 root 소유라 sudo 로 복사본을 만든 뒤 받는다.
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "${SSH_USER}@${WEB_IP}" \
    "sudo cp /var/log/auth.log /tmp/auth.log && sudo chmod 644 /tmp/auth.log" || echo "  (auth.log 복사 실패)"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "${SSH_USER}@${WEB_IP}:/tmp/auth.log" "$OUT/host/auth.log" || echo "  (auth.log scp 실패)"
else
  echo "[!] ssh_key 를 안 줘서 nginx·auth 로그는 건너뛴다(S3 로그만 받음)."
fi

echo "[*] 설정 스냅샷(environment.json) 만들기…"
python3 lab/aws/to_environment.py --region "$REGION" --out "$OUT/environment.json" || echo "  (describe 권한이 없으면 건너뛴다)"

echo
echo "[완료] 분석:"
echo "  python -m logsight analyze $OUT --env $OUT/environment.json --no-ai --out reports/aws_lab"
echo "  (API 키가 있으면 --no-ai 를 빼면 AI 설명까지)"

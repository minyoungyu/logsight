#!/usr/bin/env bash
# LogSight 서버 로그 전송 설치(Ubuntu/Amazon Linux). 사용: sudo bash install.sh <보관 버킷> <리전> [서버 이름]
# 전제: 이 서버의 인스턴스 역할에 logsight-host-shipper 정책(쓰기 전용)이 붙어 있고,
#       보관 버킷 정책의 HostShipperRoleArns 에 그 역할이 들어 있다.
set -euo pipefail
BUCKET="${1:?보관 버킷 이름}"
REGION="${2:?리전}"
HOST="${3:-$(hostname -s)}"
HOST="${HOST//[^A-Za-z0-9._-]/_}"

if ! command -v fluent-bit >/dev/null && [ ! -x /opt/fluent-bit/bin/fluent-bit ]; then
  echo "[*] Fluent Bit 설치(공식 설치 스크립트)"
  curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
fi
mkdir -p /etc/fluent-bit /var/lib/fluent-bit/buffer
sed -e "s|@BUCKET@|${BUCKET}|g" -e "s|@REGION@|${REGION}|g" -e "s|@HOST@|${HOST}|g" \
  "$(dirname "$0")/fluent-bit.conf" > /etc/fluent-bit/fluent-bit.conf
systemctl enable --now fluent-bit
systemctl restart fluent-bit
echo "[완료] 1~2분 뒤 s3://${BUCKET}/heartbeat/${HOST}/ 에 생존 신호가 쌓이는지 확인:"
echo "  python -m logsight heartbeat s3://${BUCKET}/heartbeat/"

#!/usr/bin/env bash
# VPC Flow Logs 대신 서버 방화벽 로그를 남기는 설정 (무료).
# 서버로 새로 들어오는 연결을 커널 로그에 "LOGSIGHT-NEW" 접두어로 기록한다.
# - 보안그룹을 통과해 서버까지 온 연결만 보인다(보안그룹이 막은 것은 안 보임).
# - 분당 30건으로 제한해 디스크를 채우지 않는다.
# - 되돌리기: sudo bash setup_hostfw_log.sh --remove
# 로그 위치: Ubuntu /var/log/kern.log (ufw 사용 시 /var/log/ufw.log도),
#           Amazon Linux 2023: journalctl -k -o short-iso > hostfw_kern.log
# 분석: python -m logsight analyze hostfw_kern.log
set -euo pipefail
RATE="${RATE:-30/minute}"
PREFIX="LOGSIGHT-NEW "

if [[ $EUID -ne 0 ]]; then echo "root 권한으로 실행하세요(sudo)."; exit 1; fi

if command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
  if [[ "${1:-}" == "--remove" ]]; then
    nft delete table inet logsight 2>/dev/null || true; echo "제거 완료"; exit 0
  fi
  nft delete table inet logsight 2>/dev/null || true   # 다시 실행해도 규칙이 중복되지 않게
  nft add table inet logsight
  nft 'add chain inet logsight input { type filter hook input priority -10; policy accept; }'
  nft add rule inet logsight input ct state new iifname != "lo" limit rate "$RATE" log prefix "\"$PREFIX\""
  echo "nftables 규칙 추가 완료 (table inet logsight)"
  exit 0
fi

RULE=(-m conntrack --ctstate NEW ! -i lo -m limit --limit "$RATE" --limit-burst 60 -j LOG --log-prefix "$PREFIX" --log-level 4)
if [[ "${1:-}" == "--remove" ]]; then
  iptables -D INPUT "${RULE[@]}" 2>/dev/null && echo "제거 완료" || echo "규칙이 없음"; exit 0
fi
if iptables -C INPUT "${RULE[@]}" 2>/dev/null; then
  echo "이미 설정됨"
else
  iptables -I INPUT 1 "${RULE[@]}"
  echo "iptables 규칙 추가 완료. 재부팅 후에도 유지하려면 iptables-persistent(netfilter-persistent save) 사용."
fi

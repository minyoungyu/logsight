#!/bin/bash
# 1분마다 호스트 로그의 "새로 쌓인 부분"만 S3로 보낸다.
# 키: hosts/<팀>/<로그이름>/<epoch>-<시작바이트>.log  → 수집 때 이름순으로 이어 붙이면 원래 파일이 된다.
# 파일이 잘리거나 바뀌면(크기 < 기록한 위치) 처음부터 다시 보낸다.
set -uo pipefail
: "${TEAM:?}" "${REGION:?}" "${LOGS_BUCKET:?}"
STATE=/var/lib/ctf-ship
mkdir -p "$STATE"
chmod 0700 "$STATE"

ship() {
  local name="$1" path="$2"
  [ -f "$path" ] || return 0
  local size off
  size=$(stat -c %s "$path")
  off=$(cat "$STATE/$name.off" 2>/dev/null || echo 0)
  [ "$size" -lt "$off" ] && off=0
  [ "$size" -eq "$off" ] && return 0
  local tmp
  tmp=$(mktemp)
  tail -c +"$((off + 1))" "$path" | head -c "$((size - off))" > "$tmp"
  if aws s3 cp "$tmp" "s3://$LOGS_BUCKET/hosts/$TEAM/$name/$(date -u +%s)-$off.log" \
       --region "$REGION" --only-show-errors; then
    echo "$size" > "$STATE/$name.off"
  fi
  rm -f "$tmp"
}

ship nginx-access /var/log/nginx/access.log
ship nginx-error  /var/log/nginx/error.log
ship auth         /var/log/auth.log
ship secure       /var/log/secure
ship messages     /var/log/messages
ship php-fpm      /var/log/php-fpm/error.log

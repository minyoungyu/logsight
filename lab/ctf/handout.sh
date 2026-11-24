#!/usr/bin/env bash
# 팀별 배부 정보 표: 문제 사이트 링크 + 기본 인증 ID(=팀명) + 비밀번호.
# 플래그(정답)는 절대 출력하지 않는다. CTFd 점수판 주소는 모두 공통.
# 사용: (terraform apply 뒤) bash handout.sh          # 표
#       bash handout.sh --csv > teams.csv             # CSV
set -euo pipefail
cd "$(dirname "$0")/terraform"
URLS=$(terraform output -json team_urls)
AUTH=$(terraform output -json basic_auth)
CTFD=$(terraform output -raw ctfd_url)
teams=$(jq -r 'keys[]' <<<"$URLS" | sort)

if [ "${1:-}" = "--csv" ]; then
  echo "team,site_url,basic_auth_id,basic_auth_password"
  for t in $teams; do
    printf '%s,%s,%s,%s\n' "$t" "$(jq -r --arg t "$t" '.[$t]' <<<"$URLS")" "$t" "$(jq -r --arg t "$t" '.[$t]' <<<"$AUTH")"
  done
  exit 0
fi

echo "CTFd 점수판(모두 공통, 플래그 제출처): $CTFD"
echo
printf "%-5s  %-48s  %-5s  %s\n" "팀" "문제 사이트 링크" "ID" "기본인증 비밀번호"
printf "%-5s  %-48s  %-5s  %s\n" "----" "------------------------------------------------" "-----" "------------------"
for t in $teams; do
  printf "%-5s  %-48s  %-5s  %s\n" "$t" "$(jq -r --arg t "$t" '.[$t]' <<<"$URLS")" "$t" "$(jq -r --arg t "$t" '.[$t]' <<<"$AUTH")"
done
echo
echo "※ 각 줄을 해당 팀에게만 비공개로 전달하세요. 기본 인증을 통과해야 문제 사이트가 열립니다."

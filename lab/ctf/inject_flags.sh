#!/usr/bin/env bash
# 팀 서버에 F1~F4와 민감 설정(기본 인증 비밀번호·F4 sudo 규칙·F6 버킷 이름)을 SSM으로 넣는다.
# user-data에 넣으면 IMDSv1 user-data로 그대로 노출되므로(3-3), 부팅 후 운영진 자격증명으로 주입한다.
# F5는 역할 이름, F6는 S3 객체라 Terraform이 이미 만들었다.
#
# 사용: (lab/ctf/terraform 에서 apply 한 뒤)  bash ../inject_flags.sh [t01 t02 ...]
#   팀을 안 주면 전부. 서버를 다시 만든 팀만 다시 넣을 때 팀 번호를 준다.
# 필요: aws CLI, jq, 운영진 자격증명(환경 변수 또는 aws configure). 플래그 값을 화면에 찍지 않는다.
set -euo pipefail
cd "$(dirname "$0")/terraform"

REGION=$(terraform output -raw region 2>/dev/null || echo "${AWS_DEFAULT_REGION:-ap-southeast-2}")
FLAGS=$(terraform output -json flags)
INST=$(terraform output -json team_instances)
AUTH=$(terraform output -json basic_auth)        # 팀 기본 인증 비밀번호
SUDO_RULE=$(terraform output -raw f4_sudo_rule)   # F4 sudo 규칙
FLAG_BUCKET=$(terraform output -json buckets | jq -r '.flags')  # F6 버킷
TEAMS=("$@")
[ ${#TEAMS[@]} -eq 0 ] && mapfile -t TEAMS < <(jq -r 'keys[]' <<<"$FLAGS")

for t in "${TEAMS[@]}"; do
  id=$(jq -r --arg t "$t" '.[$t].instance_id' <<<"$INST")
  f1=$(jq -r --arg t "$t" '.[$t].f1' <<<"$FLAGS")
  f1p=$(jq -r --arg t "$t" '.[$t].f1_path' <<<"$FLAGS")
  f2=$(jq -r --arg t "$t" '.[$t].f2' <<<"$FLAGS")
  f3=$(jq -r --arg t "$t" '.[$t].f3' <<<"$FLAGS")
  f4=$(jq -r --arg t "$t" '.[$t].f4' <<<"$FLAGS")
  bp=$(jq -r --arg t "$t" '.[$t]' <<<"$AUTH")

  echo "[*] $t ($id): SSM 등록 대기"
  for _ in $(seq 1 60); do
    st=$(aws ssm describe-instance-information --region "$REGION" \
      --filters "Key=InstanceIds,Values=$id" --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
    [ "$st" = "Online" ] && break
    sleep 10
  done
  [ "$st" = "Online" ] || { echo "  [!] $t: SSM Online 아님(부팅 로그 /var/log/ctf-bootstrap.log 확인)"; continue; }

  # 서버에서 실행할 스크립트. 값은 printf %q 로 안전하게 넣는다.
  script=$(cat <<EOS
set -eu
install -d -o root -g nginx -m 0750 /var/lib/ctf
# F1: 숨은 경로 이름과 값(사이트가 그 경로 응답에서만 보여 준다)
printf '%s\n' $(printf %q "$f1p") > /var/lib/ctf/f1_path
printf '%s\n' $(printf %q "$f1")  > /var/lib/ctf/f1
# F2: 관리자 로그인 성공 화면에서만(DB에 두지 않는다)
printf '%s\n' $(printf %q "$f2")  > /var/lib/ctf/f2
chown root:nginx /var/lib/ctf/f1_path /var/lib/ctf/f1 /var/lib/ctf/f2
chmod 0640 /var/lib/ctf/f1_path /var/lib/ctf/f1 /var/lib/ctf/f2
# F3: 실행만 되고 읽을 수 없는 프로그램(0711) — 파일 읽기 취약점으로는 못 얻고 명령 실행이 필요
src=\$(mktemp --suffix=.c /root/.f3XXXXXX)
printf '#include <stdio.h>\nint main(void){puts("%s");return 0;}\n' $(printf %q "$f3") > "\$src"
gcc -O2 -s -o /usr/local/bin/proof "\$src" && rm -f "\$src"
chown root:root /usr/local/bin/proof && chmod 0711 /usr/local/bin/proof
# F4: root만 읽는 파일
printf '%s\n' $(printf %q "$f4") > /root/flag4.txt
chmod 0600 /root/flag4.txt
# F4 sudo 규칙(user-data에 두면 IMDS로 F4 정답이 노출되므로 여기서 만든다)
printf '%s\n' $(printf %q "$SUDO_RULE") > /etc/sudoers.d/90-ctf
chmod 0440 /etc/sudoers.d/90-ctf
visudo -cf /etc/sudoers.d/90-ctf
# 기본 인증: 부팅 때 잠가 둔 htpasswd를 실제 팀 비밀번호로 바꾼다(비밀번호는 user-data에 없음)
printf '%s:%s\n' $(printf %q "$t") "$(openssl passwd -apr1 $(printf %q "$bp"))" > /etc/nginx/ctf.htpasswd
chown root:nginx /etc/nginx/ctf.htpasswd && chmod 0640 /etc/nginx/ctf.htpasswd
# F6 버킷 이름을 app.ini에 채운다(user-data에는 비워 둠)
if [ -f /etc/ctf/app.ini ]; then sed -i "s|^bucket =.*|bucket = $(printf %q "$FLAG_BUCKET")|" /etc/ctf/app.ini; fi
# SSM이 남긴 스크립트 사본 지우기(root를 얻은 뒤 다른 플래그 사본이 보이지 않게)
find /var/lib/amazon/ssm -path '*document/orchestration*' -type f -name '_script.sh' -delete 2>/dev/null || true
echo injected
EOS
)
  params=$(jq -n --arg s "$script" '{commands: [$s]}')
  cid=$(aws ssm send-command --region "$REGION" --instance-ids "$id" \
    --document-name AWS-RunShellScript --comment "ctf inject $t" \
    --parameters "$params" --query 'Command.CommandId' --output text)
  aws ssm wait command-executed --region "$REGION" --command-id "$cid" --instance-id "$id" \
    && echo "  [ok] $t" || echo "  [!] $t 실패: aws ssm get-command-invocation --command-id $cid --instance-id $id"
done

echo "[*] 확인: 각 팀 포트에서 F1 경로 응답, 관리자 로그인, /usr/local/bin/proof 권한을 리허설 체크리스트로 본다."

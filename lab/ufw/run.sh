#!/usr/bin/env bash
# 실제 ufw 방화벽 로그를 무료로 만드는 실습 (리눅스 한 대, root 필요. 클라우드 비용 없음)
# - 네트워크 이름공간(atk) 하나를 '외부 접속자'로 두고 veth로 서버(이 컴퓨터)에 붙인다
# - 서버: ufw 기본 차단 + 22·80 허용 + 443 허용(log). 22·80·443에 가짜 서비스를 띄운다
# - 시나리오: 정상 사용자 HTTP → ping → 포트 스캔(TCP 22개·UDP 4개) → SSH 연속 접속 25회 → 웹 경로 탐색 → 서버에서 바깥 4444로 나가는 연결
# - ufw logging low·medium·full 세 단계로 같은 시나리오를 돌려 out/에 저장한다
# 준비(Ubuntu): apt-get install -y ufw rsyslog iproute2 iputils-ping
# 주의: 이 컴퓨터의 ufw 설정을 바꾼다. 끝나면 `ufw --force reset; ufw disable; ip netns del atk`로 되돌린다
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "root로 실행하세요"; exit 1; }

# rsyslog: Ubuntu 24.04 기본 형식(ISO 시각) + 예전 형식(Nov 13 11:12:21) 두 파일로 받는다
echo ':msg,contains,"[UFW " /var/log/ufw-traditional.log;RSYSLOG_TraditionalFileFormat' > /etc/rsyslog.d/19-trad.conf
pgrep rsyslogd >/dev/null || (rsyslogd || true); sleep 1

if ! ip netns list | grep -q '^atk'; then
  ip netns add atk
  ip link add veth-srv type veth peer name veth-atk
  ip link set veth-atk netns atk
  ip addr add 203.0.113.10/24 dev veth-srv; ip addr add 198.51.100.10/24 dev veth-srv; ip link set veth-srv up
  ip -n atk addr add 203.0.113.50/24 dev veth-atk; ip -n atk addr add 198.51.100.77/24 dev veth-atk
  ip -n atk link set veth-atk up; ip -n atk link set lo up
fi
sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow log 443/tcp >/dev/null
ufw --force enable >/dev/null

mkdir -p www && echo hi > www/index.html
(cd www && nohup python3 ../server.py >/dev/null 2>&1 &)
ip netns exec atk nohup python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",4444)); s.listen(8)
while True:
    c,_=s.accept(); c.close()' >/dev/null 2>&1 &
sleep 1

mkdir -p out
for level in low medium full; do
  ufw logging "$level" >/dev/null
  sleep 61   # ufw 기록 한도(분당 3건, 한 번에 10건)가 다시 찰 때까지 기다린다
  : > /var/log/ufw.log; : > /var/log/ufw-traditional.log
  N="ip netns exec atk"
  $N python3 traffic.py benign; sleep 2
  $N ping -c3 -i0.3 203.0.113.10 >/dev/null; sleep 1
  $N python3 traffic.py scan; sleep 2
  $N python3 traffic.py brute; sleep 2
  $N python3 traffic.py web; sleep 2
  python3 -c "import socket;s=socket.create_connection(('203.0.113.50',4444),2);s.close()"
  sleep 3
  # 실습 인터페이스 줄만 남긴다(이 컴퓨터의 다른 통신은 빼서 실제 주소가 섞이지 않게)
  grep veth-srv /var/log/ufw.log > "out/ufw_${level}.log" || true
  grep veth-srv /var/log/ufw-traditional.log > "out/ufw_${level}_traditional.log" || true
  echo "$level: $(wc -l < "out/ufw_${level}.log")줄"
done
echo "분석: python -m logsight analyze lab/ufw/out --no-ai"

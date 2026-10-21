#!/usr/bin/env bash
# 로컬 테스트 서버(nginx + php-fpm)를 띄우고 내린다. 실제 접속·오류 로그를 lab/logs/ 에 쌓는다.
# 사용: lab/serve.sh start | stop
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
RT="$LAB/runtime"
LOGS="$LAB/logs"
SOCK="$RT/php.sock"
mkdir -p "$RT/body" "$LOGS"

gen_conf() {
  cat > "$RT/php-fpm.conf" <<EOF
[global]
pid = $RT/php-fpm.pid
error_log = $RT/php-fpm.log
daemonize = yes
[www]
user = www-data
group = www-data
listen = $SOCK
listen.owner = www-data
listen.group = www-data
listen.mode = 0666
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
php_admin_value[allow_url_include] = On
php_admin_value[allow_url_fopen] = On
EOF

  cat > "$RT/nginx.conf" <<EOF
pid $RT/nginx.pid;
error_log $RT/nginx-global.log;
events { worker_connections 256; }
http {
  client_body_temp_path $RT/body;
  proxy_temp_path $RT/proxy;
  fastcgi_temp_path $RT/fcgi;
  uwsgi_temp_path $RT/uwsgi;
  scgi_temp_path $RT/scgi;
  access_log off;
  default_type application/octet-stream;
  types { text/html html; text/plain txt; text/css css; application/javascript js; }
  # nginx 기본 제공 "combined" 로그 형식(= Apache Combined Log Format)을 그대로 쓴다.
  # 테스트 클라이언트를 구분하려고 X-Forwarded-For 의 IP를 실제 클라이언트로 쓴다
  # (프록시/로드밸런서 뒤에 있는 실제 사이트와 같은 상황). 공인 IP만 신뢰하도록 로컬만 허용.
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Forwarded-For;

  server {
    listen 127.0.0.1:8081;
    root $LAB/sites/shopmall;
    index index.php;
    access_log $LOGS/shopmall_access.log combined;
    error_log  $LOGS/shopmall_error.log info;
    location ~ \.php\$ {
      fastcgi_pass unix:$SOCK;
      fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
      fastcgi_param QUERY_STRING \$query_string;
      fastcgi_param REQUEST_METHOD \$request_method;
      fastcgi_param CONTENT_TYPE \$content_type;
      fastcgi_param CONTENT_LENGTH \$content_length;
      fastcgi_param REQUEST_URI \$request_uri;
      fastcgi_param DOCUMENT_ROOT \$document_root;
    }
  }

  server {
    listen 127.0.0.1:8082;
    root $LAB/sites/board;
    index index.php;
    access_log $LOGS/board_access.log combined;
    error_log  $LOGS/board_error.log info;
    location ~ \.php\$ {
      fastcgi_pass unix:$SOCK;
      fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
      fastcgi_param QUERY_STRING \$query_string;
      fastcgi_param REQUEST_METHOD \$request_method;
      fastcgi_param CONTENT_TYPE \$content_type;
      fastcgi_param CONTENT_LENGTH \$content_length;
      fastcgi_param REQUEST_URI \$request_uri;
      fastcgi_param DOCUMENT_ROOT \$document_root;
    }
  }
}
EOF
}

start() {
  gen_conf
  # www-data 가 SQLite DB·업로드 파일을 만들 수 있게 런타임 쓰기 권한 부여(저장소 권한과 무관).
  rm -f "$LAB/sites/shopmall/runtime.sqlite" "$LAB/sites/board/runtime.sqlite"
  rm -rf "$LAB/sites/shopmall/uploads"/* "$LAB/sites/board/data"/*
  mkdir -p "$LAB/sites/shopmall/uploads" "$LAB/sites/board/data"
  chmod -R 0777 "$LAB/sites/shopmall" "$LAB/sites/board"
  php-fpm8.3 -y "$RT/php-fpm.conf" || { echo "php-fpm 시작 실패"; exit 1; }
  nginx -c "$RT/nginx.conf" || { echo "nginx 시작 실패"; exit 1; }
  sleep 1
  echo "started: shopmall=http://127.0.0.1:8081  board=http://127.0.0.1:8082"
}

stop() {
  [ -f "$RT/nginx.pid" ] && nginx -c "$RT/nginx.conf" -s stop 2>/dev/null
  [ -f "$RT/php-fpm.pid" ] && kill "$(cat "$RT/php-fpm.pid")" 2>/dev/null
  pkill -f "$RT/php-fpm.conf" 2>/dev/null
  echo "stopped"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "사용: $0 start|stop"; exit 2 ;;
esac

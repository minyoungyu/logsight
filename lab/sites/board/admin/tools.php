<?php
// 취약점: host 파라미터를 셸 명령에 직접 전달(명령 삽입). 테스트 전용.
header('Content-Type: text/plain; charset=utf-8');
$host = isset($_GET['host']) ? $_GET['host'] : '';
if ($host !== '') {
    echo shell_exec("ping -c 1 " . $host . " 2>&1"); // 취약
    exit;
}
echo "사용법: /admin/tools.php?host=127.0.0.1";

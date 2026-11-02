<?php
// 취약점: 사용자 입력 경로를 그대로 include/읽기 (LFI·경로 조작). 테스트 전용.
$page = isset($_GET['page']) ? $_GET['page'] : 'about.txt';
header('Content-Type: text/plain; charset=utf-8');
$path = __DIR__ . '/pages/' . $page; // 취약: ../ 로 상위 탈출 가능
if (is_readable($path)) {
    echo file_get_contents($path);
} else {
    http_response_code(404);
    echo "문서를 찾을 수 없습니다: " . $page;
}

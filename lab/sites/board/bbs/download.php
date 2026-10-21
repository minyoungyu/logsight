<?php
// 취약점: 파일명 경로 조작 가능. 테스트 전용.
$f = isset($_GET['file']) ? $_GET['file'] : 'notice.txt';
header('Content-Type: text/plain; charset=utf-8');
$path = __DIR__ . '/../files/' . $f; // 취약: ../ 탈출 가능
if (is_readable($path)) echo file_get_contents($path);
else { http_response_code(404); echo "파일 없음: $f"; }

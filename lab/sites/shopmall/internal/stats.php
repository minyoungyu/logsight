<?php
// 내부 전용 통계 페이지: 서버 자기 자신(127.0.0.1)에서만 열린다고 가정. 테스트 전용.
// 취약 설계: 외부 요청을 서버가 대신 보내 주면(SSRF) 이 검사를 통과해 버린다.
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') { http_response_code(403); echo 'forbidden'; exit; }
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['users' => 5, 'products' => 2000, 'internal_token' => 'tok_live_9f2c41d0a7'], JSON_UNESCAPED_UNICODE);

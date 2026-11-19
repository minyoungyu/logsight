<?php
// 내부 전용 통계: 127.0.0.1 에서만 열린다. SSRF 로 서버가 대신 요청하면 통과한다(F5 보조 표적, 플래그 아님).
if (($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') { http_response_code(403); echo 'forbidden'; exit; }
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['users' => 4, 'products' => 2000, 'note' => 'internal only'], JSON_UNESCAPED_UNICODE);

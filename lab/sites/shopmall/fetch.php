<?php
// 상품 이미지 가져오기: 외부 주소를 서버가 대신 받아 온다. 취약점: 내부 주소도 막지 않음(SSRF). 테스트 전용.
$url = $_GET['url'] ?? '';
if ($url === '') { http_response_code(400); echo 'url 파라미터가 필요합니다.'; exit; }
$body = @file_get_contents($url); // 취약: 127.0.0.1, 내부망 주소도 그대로 요청
if ($body === false) { http_response_code(502); echo '가져오기 실패'; exit; }
header('Content-Type: text/plain; charset=utf-8');
echo substr($body, 0, 200000);

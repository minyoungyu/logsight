<?php
// 상품 일괄 등록(XML). 취약점: 외부 엔티티를 풀어서 읽는다(XXE). 테스트 전용.
header('Content-Type: text/plain; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo 'POST 로 XML을 보내세요.'; exit; }
$xml = file_get_contents('php://input');
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT); // 취약: 엔티티 치환 허용
if ($doc === false) { http_response_code(400); echo 'XML 형식 오류'; exit; }
foreach ($doc->product as $p) { echo 'imported: ' . (string)$p->name . "\n"; }

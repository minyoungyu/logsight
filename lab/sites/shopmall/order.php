<?php
// 주문 조회: 주문 번호만 알면 누구나 열람한다(권한 검사 없음, IDOR). 테스트 전용.
require __DIR__ . '/_init.php';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$st = db()->prepare("SELECT name, address, phone, item FROM orders WHERE id = ?");
$st->execute([$id]);
$o = $st->fetch(PDO::FETCH_ASSOC);
header_html('주문 조회');
if (!$o) { http_response_code(404); echo '<p>주문을 찾을 수 없습니다.</p>'; footer_html(); exit; }
echo '<div class="card"><h2>주문 #' . $id . '</h2><p>상품: ' . htmlspecialchars($o['item']) . '</p>'
   . '<p>수령인: ' . htmlspecialchars($o['name']) . ' · ' . htmlspecialchars($o['phone']) . '</p>'
   . '<p>주소: ' . htmlspecialchars($o['address']) . '</p></div>';
footer_html();

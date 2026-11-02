<?php
// 상품 상세: 이 페이지는 안전하게(매개변수 바인딩) 만들었다 — 정상 사이트 트래픽 모방용.
require __DIR__ . '/_init.php';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$db = db();
$st = $db->prepare("SELECT name,price,category,stock FROM products WHERE id = ?");
$st->execute([$id]);
$p = $st->fetch(PDO::FETCH_ASSOC);
if (!$p) { http_response_code(404); header_html('없음'); echo '<p>상품을 찾을 수 없습니다.</p>'; footer_html(); exit; }
header_html(htmlspecialchars($p['name']));
echo '<div class="card"><h2>' . htmlspecialchars($p['name']) . '</h2>'
   . '<p>카테고리: ' . htmlspecialchars($p['category']) . ' · 재고 ' . (int)$p['stock'] . '개</p>'
   . '<p><b>' . number_format($p['price']) . '원</b></p></div>';
// 후기: 저장할 때 검사하지 않고, 보여 줄 때도 이스케이프하지 않는다(저장형 XSS). 테스트 전용.
echo '<h3>상품 후기</h3>';
$rv = $db->prepare("SELECT author, body FROM reviews WHERE product_id = ? ORDER BY id DESC LIMIT 20");
$rv->execute([$id]);
foreach ($rv as $r) echo '<div class="card"><b>' . htmlspecialchars($r['author']) . '</b><p>' . $r['body'] . '</p></div>';
echo '<form method="post" action="/review.php" class="card"><input type="hidden" name="product_id" value="' . $id . '">'
   . '<input name="author" placeholder="작성자"><br><textarea name="body" rows="3" style="width:100%" placeholder="후기"></textarea>'
   . '<br><button>등록</button></form>';
footer_html();

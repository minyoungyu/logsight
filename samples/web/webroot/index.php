<?php
// 홈: 추천 상품 목록(상세 페이지로 연결)
require __DIR__ . '/_init.php';
$db = db();
header_html('홈');
echo '<h2>추천 상품</h2><div class="grid">';
foreach ($db->query("SELECT id,name,price FROM products ORDER BY id LIMIT 12") as $r) {
    echo '<a class="card" style="text-decoration:none;color:inherit" href="/product.php?id=' . (int)$r['id'] . '">'
       . htmlspecialchars($r['name']) . '<br><b>' . number_format($r['price']) . '원</b></a>';
}
echo '</div>';
footer_html();

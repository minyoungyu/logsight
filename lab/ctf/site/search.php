<?php
// 검색: 매개변수 바인딩(안전), 출력 이스케이프(안전). 3-3: 로그인 외 페이지의 SQL은 매개변수화.
require __DIR__ . '/_init.php';
$q = isset($_GET['q']) ? (string)$_GET['q'] : '';
header_html('검색');
echo '<h2>' . htmlspecialchars('"' . $q . '" 검색 결과') . '</h2>';
$db = db();
$st = $db->prepare("SELECT name, price FROM products WHERE name LIKE ? LIMIT 50");
$st->execute(['%' . $q . '%']);
echo '<ul>';
foreach ($st as $r) echo '<li>' . htmlspecialchars($r['name']) . ' — ' . number_format($r['price']) . '원</li>';
echo '</ul>';
footer_html();

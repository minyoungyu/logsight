<?php
// 검색. 취약점 1: 검색어를 SQL 문자열에 그대로 붙임(SQL 인젝션).
// 취약점 2: 검색어를 HTML에 이스케이프 없이 되돌려 줌(반사형 XSS). 테스트 전용.
require __DIR__ . '/_init.php';
$q = isset($_GET['q']) ? $_GET['q'] : '';
header_html('검색');
echo '<h2>"' . $q . '" 검색 결과</h2>';            // 취약: 반사형 XSS
try {
    $db = db();
    $rows = $db->query("SELECT name, price FROM products WHERE name LIKE '%$q%'"); // 취약: SQLi
    if ($rows === false) { http_response_code(500); echo '<p>검색 중 오류가 발생했습니다.</p>'; footer_html(); exit; }
    echo '<ul>';
    foreach ($rows as $r) {
        echo '<li>' . htmlspecialchars($r['name']) . ' — ' . number_format($r['price']) . '원</li>';
    }
    echo '</ul>';
} catch (Throwable $e) {
    http_response_code(500);
    echo '<p>검색 중 오류가 발생했습니다.</p>';
}
footer_html();

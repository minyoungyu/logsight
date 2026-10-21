<?php
// 취약점: 사용자 입력을 SQL에 그대로 붙임 (SQL 인젝션). 테스트 전용.
require __DIR__ . '/_init.php';
$q = isset($_GET['q']) ? $_GET['q'] : '';
header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html><meta charset=utf-8><h1>검색 결과</h1>";
try {
    $db = db();
    $sql = "SELECT name, price FROM products WHERE name LIKE '%$q%'"; // 취약
    $rows = $db->query($sql);
    if ($rows === false) { http_response_code(500); echo "<p>쿼리 오류</p>"; exit; }
    echo "<ul>";
    foreach ($rows as $r) {
        echo "<li>" . htmlspecialchars($r['name']) . " - " . htmlspecialchars($r['price']) . "원</li>";
    }
    echo "</ul>";
} catch (Throwable $e) {
    http_response_code(500);
    echo "<p>오류: " . htmlspecialchars($e->getMessage()) . "</p>";
}

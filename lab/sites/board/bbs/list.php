<?php
// 취약점: id 를 SQL에 직접 삽입. 테스트 전용.
require __DIR__ . '/../_init.php';
header('Content-Type: text/html; charset=utf-8');
$id = isset($_GET['id']) ? $_GET['id'] : '1';
try {
    $db = db();
    $sql = "SELECT title, body FROM posts WHERE id = $id"; // 취약
    $rows = $db->query($sql);
    if ($rows === false) { http_response_code(500); echo "쿼리 오류"; exit; }
    foreach ($rows as $r) echo "<h2>".htmlspecialchars($r['title'])."</h2><p>".htmlspecialchars($r['body'])."</p>";
} catch (Throwable $e) { http_response_code(500); echo "오류: ".htmlspecialchars($e->getMessage()); }

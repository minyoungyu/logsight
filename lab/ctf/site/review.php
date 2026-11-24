<?php
// 후기 등록. 저장은 바인딩(안전). 출력은 product.php 에서 이스케이프한다.
require __DIR__ . '/_init.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
$pid = (int)($_POST['product_id'] ?? 0);
$body = trim(mb_substr((string)($_POST['body'] ?? ''), 0, 500));
$author = trim(mb_substr((string)($_POST['author'] ?? ''), 0, 40)) ?: '익명';
$rating = min(5, max(1, (int)($_POST['rating'] ?? 5)));
if ($body !== '') {
    $st = db()->prepare("INSERT INTO reviews(product_id, author, rating, body, created_at) VALUES(?,?,?,?,?)");
    $st->execute([$pid, $author, $rating, $body, date('Y-m-d')]);
    flash('상품평이 등록되었습니다. 소중한 후기 감사합니다.');
}
header('Location: /product.php?id=' . $pid . '#reviews', true, 302);

<?php
// 후기 등록. 입력값을 검사하지 않고 저장한다(저장형 XSS 원인). 테스트 전용.
require __DIR__ . '/_init.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
$db = db();
$st = $db->prepare("INSERT INTO reviews(product_id, author, body) VALUES(?,?,?)");
$st->execute([(int)($_POST['product_id'] ?? 0), $_POST['author'] ?? '익명', $_POST['body'] ?? '']);
header('Location: /product.php?id=' . (int)($_POST['product_id'] ?? 0), true, 302);

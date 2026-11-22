<?php
// 후기 등록. 저장은 바인딩(안전). 출력은 product.php 에서 이스케이프한다.
require __DIR__ . '/_init.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
$db = db();
$st = $db->prepare("INSERT INTO reviews(product_id, author, body) VALUES(?,?,?)");
$st->execute([(int)($_POST['product_id'] ?? 0), substr((string)($_POST['author'] ?? '익명'),0,40), substr((string)($_POST['body'] ?? ''),0,500)]);
header('Location: /product.php?id=' . (int)($_POST['product_id'] ?? 0), true, 302);

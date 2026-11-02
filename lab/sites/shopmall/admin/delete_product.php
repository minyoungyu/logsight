<?php
// 상품 삭제(관리자). 취약점: CSRF 토큰·Referer 검사 없음. 테스트 전용.
require __DIR__ . '/../_init.php';
if (!isset($_COOKIE['admin'])) { header('Location: /admin/login.php', true, 302); exit; }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = db();
    $st = $db->prepare("DELETE FROM products WHERE id = ?");
    $st->execute([(int)($_POST['id'] ?? 0)]);
    header('Location: /admin/members.php', true, 302);
    exit;
}
http_response_code(405);

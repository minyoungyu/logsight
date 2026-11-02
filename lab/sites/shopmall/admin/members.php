<?php
// 관리자 회원·상품 목록. 쿠키 검사만 한다(세션 없음). 목록을 통째로 내려받을 수 있다. 테스트 전용.
require __DIR__ . '/../_init.php';
if (!isset($_COOKIE['admin'])) { header('Location: /admin/login.php', true, 302); exit; }
$db = db();
header_html('회원 관리');
echo '<h2>회원 목록</h2><table><tr><th>ID</th><th>아이디</th><th>이메일</th><th>권한</th></tr>';
foreach ($db->query("SELECT id,username,email,role FROM users") as $u) {
    echo '<tr><td>' . $u['id'] . '</td><td>' . htmlspecialchars($u['username']) . '</td><td>'
       . htmlspecialchars($u['email']) . '</td><td>' . htmlspecialchars($u['role']) . '</td></tr>';
}
echo '</table><h2>상품 목록</h2><table>';
foreach ($db->query("SELECT id,name,price,stock FROM products") as $p) {
    echo '<tr><td>' . $p['id'] . '</td><td>' . htmlspecialchars($p['name']) . '</td><td>'
       . number_format($p['price']) . '</td><td>' . $p['stock'] . '</td></tr>';
}
echo '</table>';
footer_html();

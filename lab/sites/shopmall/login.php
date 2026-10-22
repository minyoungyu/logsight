<?php
// 사용자 로그인. 실패 횟수 제한이 없다(무차별 대입 가능). 테스트 전용.
require __DIR__ . '/_init.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = db();
    $st = $db->prepare("SELECT id FROM users WHERE username=? AND password=?");
    $st->execute([$_POST['username'] ?? '', $_POST['password'] ?? '']);
    // 취약: 로그인 뒤 보낼 주소(next)를 검사하지 않는다(열린 리다이렉트)
    if ($st->fetch()) { header('Location: ' . ($_GET['next'] ?? '/'), true, 302); exit; }
    http_response_code(401);
    header_html('로그인'); echo '<p>아이디 또는 비밀번호가 맞지 않습니다.</p>'; footer_html(); exit;
}
header_html('로그인');
echo '<form method="post" class="card" style="max-width:320px"><p><input name="username" placeholder="아이디"></p>'
   . '<p><input name="password" type="password" placeholder="비밀번호"></p><button>로그인</button></form>';
footer_html();

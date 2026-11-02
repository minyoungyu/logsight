<?php
// 관리자 로그인. 설치 후 기본 계정(shopadmin/admin)을 바꾸지 않은 상황을 흉내 낸다. 테스트 전용.
require __DIR__ . '/../_init.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = db();
    $st = $db->prepare("SELECT id FROM users WHERE username=? AND password=? AND role='admin'");
    $st->execute([$_POST['username'] ?? '', $_POST['password'] ?? '']);
    if ($st->fetch()) {
        setcookie('admin', '1', 0, '/');
        header('Location: /admin/members.php', true, 302);
        exit;
    }
    http_response_code(401);
    header_html('관리자'); echo '<p>관리자 정보가 맞지 않습니다.</p>'; footer_html(); exit;
}
header_html('관리자 로그인');
echo '<form method="post" class="card" style="max-width:320px"><p><input name="username" placeholder="관리자 아이디"></p>'
   . '<p><input name="password" type="password" placeholder="비밀번호"></p><button>로그인</button></form>';
footer_html();

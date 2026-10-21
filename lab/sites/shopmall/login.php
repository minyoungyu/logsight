<?php
// 취약점: 로그인 시도 제한 없음(무차별 대입 가능). 테스트 전용.
require __DIR__ . '/_init.php';
header('Content-Type: text/html; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = isset($_POST['username']) ? $_POST['username'] : '';
    $p = isset($_POST['password']) ? $_POST['password'] : '';
    $db = db();
    $st = $db->prepare("SELECT id FROM users WHERE username=? AND password=?");
    $st->execute([$u, $p]);
    if ($st->fetch()) {
        header('Location: /dashboard.php', true, 302); // 성공: 리다이렉트
        exit;
    }
    http_response_code(401);
    echo "<p>로그인 실패</p>";
    exit;
}
echo '<!doctype html><meta charset=utf-8><h1>로그인</h1>
<form method=post><input name=username placeholder=아이디>
<input name=password type=password placeholder=비밀번호><button>로그인</button></form>';

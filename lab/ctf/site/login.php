<?php
// 일반 회원 로그인: 매개변수 바인딩(안전). 정상 트래픽/실패 로그 모방용.
require __DIR__ . '/_init.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = db();
    $st = $db->prepare("SELECT id,password FROM users WHERE username=? AND role='user'");
    $st->execute([$_POST['username'] ?? '']);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if ($row && password_verify($_POST['password'] ?? '', $row['password'])) {
        $_SESSION['uid'] = $row['id'];
        header('Location: /', true, 302); exit;
    }
    http_response_code(401);
    header_html('로그인'); echo '<p>아이디 또는 비밀번호가 맞지 않습니다.</p>'; footer_html(); exit;
}
header_html('로그인');
echo '<form method="post" class="card" style="max-width:320px"><p><input name="username" placeholder="아이디"></p>'
   . '<p><input name="password" type="password" placeholder="비밀번호"></p><button>로그인</button></form>';
footer_html();

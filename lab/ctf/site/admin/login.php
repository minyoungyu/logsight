<?php
// 관리자 로그인 — F2. 설계한 취약점: 로그인 쿼리에 입력을 그대로 붙인다(SQL 인젝션).
// 예: username 에  admin' --   을 넣으면 비밀번호 검사가 주석 처리되어 우회된다.
// 성공 화면에서만 F2 를 보여 준다(DB·코드에 F2 값을 두지 않는다, 3-3).
require __DIR__ . '/../_init.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = (string)($_POST['username'] ?? '');
    $p = (string)($_POST['password'] ?? '');
    $db = db();
    // 취약: 문자열 결합. (로그인 페이지 한 곳에만 남긴 설계 취약점)
    $sql = "SELECT id, username FROM users WHERE username='$u' AND password='$p' AND role='admin'";
    $ok = false;
    try { $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC); $ok = (bool)$row; }
    catch (Throwable $e) { $ok = false; }
    if ($ok) {
        session_regenerate_id(true);
        $_SESSION['admin'] = true;
        header('Location: /admin/index.php', true, 302); exit;
    }
    http_response_code(401);
    header_html('관리자'); echo '<p>관리자 정보가 맞지 않습니다.</p>'; footer_html(); exit;
}
header_html('관리자 로그인');
echo '<form method="post" class="card" style="max-width:320px"><p><input name="username" placeholder="관리자 아이디"></p>'
   . '<p><input name="password" type="password" placeholder="비밀번호"></p><button>로그인</button></form>';
footer_html();

<?php
// 관리자 로그인 — F2. 설계한 취약점: 로그인 쿼리에 입력을 그대로 붙인다(SQL 인젝션).
// 예: username 에  admin' --   을 넣으면 비밀번호 검사가 주석 처리되어 우회된다.
// 성공 화면에서만 F2 를 보여 준다(DB·코드에 F2 값을 두지 않는다, 3-3).
require __DIR__ . '/../_init.php';
$err = '';
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
    $err = '관리자 정보가 맞지 않습니다.';
}
?><!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>파트너센터 로그인 | <?= SHOP_NAME ?></title><link rel="icon" href="/static/img/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/static/admin.css"></head>
<body class="alogin"><div class="ctfbar">LogSight 보안 교육용 CTF 대회 환경 · 가상 관리자 화면</div><main>
  <div class="lbrand"><img src="/static/img/logo.svg" alt="" width="40" height="40"><div><b><?= SHOP_NAME ?></b><span>파트너센터</span></div></div>
  <form method="post" class="lcard">
    <h1>관리자 로그인</h1><p>운영자 계정으로 로그인해 주세요.</p>
    <?php if ($err): ?><div class="alert"><?= h($err) ?></div><?php endif; ?>
    <label>관리자 아이디<input name="username" autocomplete="username" required></label>
    <label>비밀번호<input name="password" type="password" autocomplete="current-password"></label>
    <button>로그인</button>
    <small>CTF 실습용 가상 관리자 로그인입니다.</small>
  </form>
  <footer>© 2026 LogSight CTF</footer>
</main></body></html>

<?php
// 일반 회원 로그인: 매개변수 바인딩(안전). 정상 트래픽/실패 로그 모방용.
require __DIR__ . '/_init.php';
$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $st = db()->prepare("SELECT id,password FROM users WHERE username=? AND role='user'");
    $st->execute([$_POST['username'] ?? '']);
    $row = $st->fetch();
    if ($row && password_verify($_POST['password'] ?? '', $row['password'])) {
        session_regenerate_id(true);
        $_SESSION['uid'] = $row['id'];
        flash('로그인되었습니다.');
        header('Location: /', true, 302); exit;
    }
    http_response_code(401);
    $err = '아이디 또는 비밀번호가 맞지 않습니다.';
}
header_html('로그인');
?>
<section class="auth card">
  <h1>로그인</h1><p class="muted">CTF 실습용 계정입니다. 실제 사용하는 아이디·비밀번호를 넣지 마세요.</p>
  <?php if ($err): ?><div class="alert"><?= h($err) ?></div><?php endif; ?>
  <form method="post">
    <input name="username" placeholder="아이디" autocomplete="username" value="<?= h($_POST['username'] ?? '') ?>" required>
    <input name="password" type="password" placeholder="비밀번호" autocomplete="current-password" required>
    <label class="check"><input type="checkbox" name="keep"> 로그인 상태 유지</label>
    <button class="btn block">로그인</button>
  </form>
  <div class="authlinks"><a href="/signup.php">회원가입</a><span>|</span><a href="/support.php#faq">아이디·비밀번호 찾기</a></div>
</section>
<?php footer_html();

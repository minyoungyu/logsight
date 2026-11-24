<?php
// 회원가입: 입력 검증 + 매개변수 바인딩(안전). 역할은 항상 'user'(관리자 권한은 만들 수 없다).
require __DIR__ . '/_init.php';
$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = (string)($_POST['username'] ?? '');
    $p = (string)($_POST['password'] ?? '');
    $n = trim(mb_substr((string)($_POST['name'] ?? ''), 0, 20));
    $e = trim(mb_substr((string)($_POST['email'] ?? ''), 0, 80));
    if (!preg_match('/^[a-z0-9_]{4,20}$/', $u)) $err = '아이디는 영문 소문자, 숫자, 밑줄로 4~20자입니다.';
    elseif (strlen($p) < 8) $err = '비밀번호는 8자 이상이어야 합니다.';
    elseif (($_POST['password2'] ?? '') !== $p) $err = '비밀번호 확인이 일치하지 않습니다.';
    elseif ($n === '') $err = '이름을 입력해 주세요.';
    elseif (!filter_var($e, FILTER_VALIDATE_EMAIL)) $err = '이메일 형식을 확인해 주세요.';
    elseif (empty($_POST['agree'])) $err = '필수 약관에 동의해 주세요.';
    else {
        $db = db();
        $st = $db->prepare("SELECT 1 FROM users WHERE username = ?");
        $st->execute([$u]);
        if ($st->fetch()) $err = '이미 사용 중인 아이디입니다.';
        else {
            $db->prepare("INSERT INTO users(username,password,email,role,name,created_at) VALUES(?,?,?,'user',?,?)")
               ->execute([$u, password_hash($p, PASSWORD_DEFAULT), $e, $n, date('Y-m-d H:i:s')]);
            session_regenerate_id(true);
            $_SESSION['uid'] = (int)$db->lastInsertId();
            flash('가입을 환영합니다! 3,000원 할인쿠폰이 지급되었습니다.');
            header('Location: /', true, 302); exit;
        }
    }
}
header_html('회원가입');
?>
<section class="auth card wide">
  <h1>회원가입</h1><p class="muted">CTF 실습용 가상 회원가입입니다. 실제 이름·이메일·비밀번호 대신 지어낸 값을 쓰세요.</p>
  <?php if ($err): ?><div class="alert"><?= h($err) ?></div><?php endif; ?>
  <form method="post">
    <label>아이디<input name="username" value="<?= h($_POST['username'] ?? '') ?>" placeholder="영문 소문자·숫자 4~20자" required></label>
    <label>비밀번호<input name="password" type="password" placeholder="8자 이상" autocomplete="new-password" required></label>
    <label>비밀번호 확인<input name="password2" type="password" autocomplete="new-password" required></label>
    <label>이름<input name="name" value="<?= h($_POST['name'] ?? '') ?>" required></label>
    <label>이메일<input name="email" type="email" value="<?= h($_POST['email'] ?? '') ?>" required></label>
    <div class="terms"><label class="check"><input type="checkbox" name="agree" value="1"> [필수] 이용약관 및 개인정보 수집·이용 동의</label>
    <label class="check"><input type="checkbox" name="marketing"> [선택] 할인·이벤트 정보 수신 동의</label></div>
    <button class="btn block">가입하기</button>
  </form>
</section>
<?php footer_html();

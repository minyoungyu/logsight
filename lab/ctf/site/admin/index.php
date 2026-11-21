<?php
// 관리자 대시보드. 세션 검사. 성공 화면에서 F2 를 보여 준다.
require __DIR__ . '/../_init.php';
require_admin();
$f2 = ctf_read('f2');
header_html('관리자');
echo '<div class="card"><h2>관리자 콘솔</h2>';
echo '<p>로그인에 성공했습니다. 2단계 플래그:</p>';
echo '<pre>flag: ' . htmlspecialchars($f2 ?? '(준비되지 않음 — 운영진 주입 대기)') . '</pre></div>';
echo '<div class="card"><h3>상품 이미지 관리</h3>'
   . '<p><a href="/admin/upload.php">이미지 업로드</a> · <a href="/admin/fetch.php">외부 이미지 가져오기</a></p></div>';
echo '<div class="card"><h3>회원 목록</h3><table><tr><th>ID</th><th>아이디</th><th>권한</th></tr>';
foreach (db()->query("SELECT id,username,role FROM users") as $uu) {
    echo '<tr><td>' . (int)$uu['id'] . '</td><td>' . htmlspecialchars($uu['username']) . '</td><td>' . htmlspecialchars($uu['role']) . '</td></tr>';
}
echo '</table></div>';
footer_html();

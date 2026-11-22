<?php
// 관리자 대시보드. 세션 검사. 성공 화면에서 F2 를 보여 준다.
require __DIR__ . '/../_init.php';
require_admin();
$f2 = ctf_read('f2');
$db = db();
$k = $db->query("SELECT (SELECT COUNT(*) FROM orders) o, (SELECT COALESCE(SUM(total),0) FROM orders) s, (SELECT COUNT(*) FROM users WHERE role='user') u, (SELECT COUNT(*) FROM products WHERE stock=0) z")->fetch();
admin_header('대시보드', 'index');
?>
<div class="kpis">
  <div><span>누적 주문</span><b><?= number_format((int)$k['o']) ?>건</b></div>
  <div><span>누적 매출</span><b><?= number_format((int)$k['s']) ?>원</b></div>
  <div><span>회원 수</span><b><?= number_format((int)$k['u']) ?>명</b></div>
  <div><span>품절 상품</span><b class="warn"><?= number_format((int)$k['z']) ?>개</b></div>
</div>
<section class="panel flagpanel"><h2>관리자 콘솔</h2>
  <p>로그인에 성공했습니다. 2단계 플래그:</p>
  <pre>flag: <?= h($f2 ?? '(준비되지 않음 — 운영진 주입 대기)') ?></pre></section>
<div class="cols">
<section class="panel"><h2>상품 이미지 관리</h2>
  <p>상세페이지 이미지를 올리거나, 제조사 사이트의 이미지를 주소로 가져올 수 있습니다.</p>
  <p><a class="abtn" href="/admin/upload.php">이미지 업로드</a> <a class="abtn line" href="/admin/fetch.php">외부 이미지 가져오기</a></p></section>
<section class="panel"><h2>회원 목록</h2><table><tr><th>ID</th><th>아이디</th><th>이름</th><th>권한</th></tr>
<?php foreach ($db->query("SELECT id,username,name,role FROM users ORDER BY id LIMIT 12") as $uu): ?>
  <tr><td><?= (int)$uu['id'] ?></td><td><?= h($uu['username']) ?></td><td><?= h($uu['name']) ?></td><td><span class="tag <?= $uu['role'] === 'admin' ? 'admin' : '' ?>"><?= h($uu['role']) ?></span></td></tr>
<?php endforeach; ?></table></section>
</div>
<section class="panel"><h2>최근 주문</h2><table><tr><th>주문번호</th><th>상품</th><th>금액</th><th>상태</th><th>주문일시</th></tr>
<?php foreach ($db->query("SELECT id,item,total,status,created_at FROM orders ORDER BY id DESC LIMIT 8") as $o): ?>
  <tr><td><?= (int)$o['id'] ?></td><td><?= h($o['item']) ?></td><td><?= number_format((int)$o['total']) ?>원</td><td><?= h($o['status']) ?></td><td><?= h($o['created_at']) ?></td></tr>
<?php endforeach; ?></table></section>
<?php admin_footer();

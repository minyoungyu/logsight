<?php
// 마이페이지: 로그인한 회원 본인의 주문만 보여 준다(바인딩).
require __DIR__ . '/_init.php';
$u = current_user();
if (!$u) { flash('로그인이 필요한 메뉴입니다.'); header('Location: /login.php', true, 302); exit; }
$st = db()->prepare("SELECT id, item, qty, total, status, created_at FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 20");
$st->execute([$u['id']]);
$orders = $st->fetchAll();
header_html('마이페이지');
?>
<section class="mypage">
  <div class="card hello"><div><b><?= h($u['name'] ?: $u['username']) ?></b>님, 안녕하세요.<div class="muted"><?= h($u['email']) ?> · 일반 회원</div></div>
  <div class="mstats"><div><span>쿠폰</span><b>1장</b></div><div><span>적립금</span><b>0P</b></div><div><span>주문</span><b><?= count($orders) ?>건</b></div></div></div>
  <div class="card"><h3>최근 주문 내역</h3>
  <?php if (!$orders): ?><p class="muted">최근 주문 내역이 없습니다.</p>
  <?php else: ?><table class="carttable"><thead><tr><th>주문번호</th><th>상품</th><th>금액</th><th>상태</th><th>주문일</th></tr></thead><tbody>
  <?php foreach ($orders as $o): ?><tr><td><a href="/order.php?id=<?= (int)$o['id'] ?>"><?= (int)$o['id'] ?></a></td><td><?= h($o['item']) ?></td><td><?= won($o['total']) ?></td><td><span class="badge inline"><?= h($o['status']) ?></span></td><td><?= h(substr($o['created_at'], 0, 10)) ?></td></tr><?php endforeach; ?>
  </tbody></table><?php endif; ?></div>
</section>
<?php footer_html();

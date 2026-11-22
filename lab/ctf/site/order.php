<?php
// 주문 조회(IDOR, 가짜 데이터). 정상/노이즈 트래픽용 — 플래그 아님.
// 주문번호만 알면 누구 주문이든 보인다(실제 서비스에서 흔한 설계 실수를 그대로 둔 노이즈).
require __DIR__ . '/_init.php';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($id <= 0) {
    header_html('주문/배송 조회');
    echo '<section class="card narrow"><h1>주문/배송 조회</h1><p class="muted">주문 완료 문자로 받은 주문번호를 입력해 주세요.</p>'
       . '<form method="get" class="row"><input name="id" inputmode="numeric" placeholder="주문번호" required><button class="btn">조회</button></form></section>';
    footer_html(); exit;
}
$st = db()->prepare("SELECT * FROM orders WHERE id = ?");
$st->execute([$id]);
$o = $st->fetch();
if (!$o) not_found('주문을 찾을 수 없습니다.');
header_html('주문 상세');
$flow = ['결제완료', '상품준비중', '배송중', '배송완료'];
$cur = array_search($o['status'] === '구매확정' ? '배송완료' : $o['status'], $flow, true);
?>
<section class="card narrow">
  <div class="shead"><h1>주문번호 <?= $id ?></h1><span class="muted"><?= h($o['created_at']) ?></span></div>
  <ol class="track"><?php foreach ($flow as $i => $s): ?><li class="<?= $i <= $cur ? 'done' : '' ?>"><?= $s ?></li><?php endforeach; ?></ol>
  <table class="kv">
    <tr><th>상품</th><td><?= h($o['item']) ?> (<?= (int)$o['qty'] ?>개)</td></tr>
    <tr><th>결제금액</th><td><b><?= won($o['total']) ?></b></td></tr>
    <tr><th>받는 분</th><td><?= h($o['name']) ?> · <?= h($o['phone']) ?></td></tr>
    <tr><th>배송지</th><td><?= h($o['address']) ?></td></tr>
    <tr><th>상태</th><td><span class="badge inline"><?= h($o['status']) ?></span></td></tr>
  </table>
  <div class="row"><a class="btn line" href="/support.php#faq">교환/반품 안내</a><a class="btn" href="/">쇼핑 계속하기</a></div>
</section>
<?php footer_html();

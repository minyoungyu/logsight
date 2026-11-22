<?php
// 상품 상세: 매개변수 바인딩(안전). 정상 사이트 트래픽 모방용.
require __DIR__ . '/_init.php';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$db = db();
$st = $db->prepare("SELECT * FROM products WHERE id = ?");
$st->execute([$id]);
$p = $st->fetch();
if (!$p) not_found('상품을 찾을 수 없습니다.');
$sale = sale_price($p);
$rv = $db->prepare("SELECT author, rating, body, created_at FROM reviews WHERE product_id = ? ORDER BY id DESC LIMIT 30");
$rv->execute([$id]);
$reviews = $rv->fetchAll();
$rel = $db->prepare("SELECT * FROM products WHERE category = ? AND id <> ? ORDER BY sold DESC LIMIT 5");
$rel->execute([$p['category'], $id]);
header_html($p['name'], $p['category']);
$ship = $sale >= 30000 ? '무료배송' : '배송비 3,000원 (3만원 이상 무료)';
$arrive = date('n/j', strtotime('+' . ((int)date('N') >= 5 ? 8 - (int)date('N') : 1) . ' day'));
?>
<nav class="crumb"><a href="/">홈</a> › <a href="/category.php?c=<?= h($p['category']) ?>"><?= h(cat_name($p['category'])) ?></a> › <?= h($p['brand']) ?></nav>
<section class="pdp">
  <div class="gallery"><?= product_img($p, 'hero-img') ?><div class="thumbs"><?php for ($i = 0; $i < 4; $i++) echo product_img(['id' => $p['id'] + $i, 'category' => $p['category'], 'name' => $p['name']], 'mini'); ?></div></div>
  <div class="info">
    <a class="brand" href="/search.php?q=<?= urlencode($p['brand']) ?>"><?= h($p['brand']) ?> 브랜드관 ›</a>
    <h1><?= h($p['name']) ?></h1>
    <div class="meta"><?= stars((float)$p['rating']) ?> <b><?= number_format((float)$p['rating'], 1) ?></b> <a href="#reviews">상품평 <?= number_format((int)$p['review_count']) ?>개</a> · 누적 판매 <?= number_format((int)$p['sold']) ?>개</div>
    <div class="pricebox">
      <?php if ((int)$p['discount'] > 0): ?><div class="orig"><del><?= won($p['price']) ?></del></div><?php endif; ?>
      <div class="now"><?php if ((int)$p['discount'] > 0): ?><em><?= (int)$p['discount'] ?>%</em><?php endif; ?><b><?= won($sale) ?></b></div>
      <div class="card-benefit">카드 결제 시 최대 12개월 무이자 · 적립 <?= number_format((int)($sale * 0.01)) ?>P</div>
    </div>
    <dl class="spec">
      <dt>배송</dt><dd><b class="arrive"><?= $arrive ?> 도착 예정</b> · <?= $ship ?></dd>
      <dt>판매자</dt><dd>바이트마트 직매입</dd>
      <dt>재고</dt><dd><?= (int)$p['stock'] > 0 ? ((int)$p['stock'] < 10 ? '<span class="warn">품절 임박 · ' . (int)$p['stock'] . '개 남음</span>' : '구매 가능') : '<span class="warn">일시품절</span>' ?></dd>
    </dl>
    <form method="post" action="/cart.php" class="buy">
      <input type="hidden" name="action" value="add"><input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
      <div class="qty"><button type="button" data-step="-1">−</button><input name="qty" value="1" inputmode="numeric" aria-label="수량"><button type="button" data-step="1">+</button></div>
      <div class="btns"><button class="btn line" <?= (int)$p['stock'] ? '' : 'disabled' ?>>장바구니</button><button class="btn" name="buynow" value="1" <?= (int)$p['stock'] ? '' : 'disabled' ?>>바로구매</button></div>
    </form>
  </div>
</section>

<nav class="tabs"><a href="#detail" class="on">상품정보</a><a href="#reviews">상품평 (<?= count($reviews) ?>)</a><a href="#shipping">배송/교환/반품</a></nav>
<section id="detail" class="detail card">
  <h3>상품 설명</h3><p><?= h($p['description']) ?></p>
  <table class="kv"><tr><th>브랜드</th><td><?= h($p['brand']) ?></td><th>카테고리</th><td><?= h(cat_name($p['category'])) ?></td></tr>
  <tr><th>모델명</th><td><?= h($p['name']) ?></td><th>상품번호</th><td>BM-<?= str_pad((string)$p['id'], 7, '0', STR_PAD_LEFT) ?></td></tr>
  <tr><th>A/S 안내</th><td>제조사 1년 무상</td><th>원산지</th><td>중국 (OEM)</td></tr></table>
</section>

<section id="reviews" class="card">
  <div class="shead"><h3>상품평</h3><span><?= stars((float)$p['rating']) ?> <?= number_format((float)$p['rating'], 1) ?> / 5</span></div>
  <?php if (!$reviews): ?><p class="muted">아직 등록된 상품평이 없습니다. 첫 상품평을 남겨 주세요.</p><?php endif; ?>
  <?php foreach ($reviews as $r): ?>
  <div class="review"><div><?= stars((float)$r['rating']) ?> <b><?= h($r['author']) ?></b> <span class="muted"><?= h($r['created_at']) ?></span></div><p><?= h($r['body']) ?></p></div>
  <?php endforeach; ?>
  <form method="post" action="/review.php" class="review-form">
    <input type="hidden" name="product_id" value="<?= (int)$p['id'] ?>">
    <div class="row"><input name="author" placeholder="작성자" maxlength="40" required>
    <select name="rating" aria-label="별점"><option value="5">★★★★★ 아주 좋아요</option><option value="4">★★★★ 좋아요</option><option value="3">★★★ 보통이에요</option><option value="2">★★ 그저 그래요</option><option value="1">★ 별로예요</option></select></div>
    <textarea name="body" rows="3" maxlength="500" placeholder="상품에 대한 솔직한 후기를 남겨 주세요. (최대 500자)" required></textarea>
    <button class="btn">상품평 등록</button>
  </form>
</section>

<section id="shipping" class="card">
  <h3>배송 / 교환 / 반품 안내</h3>
  <ul class="dots-list"><li>평일 오후 2시 이전 결제 완료 시 당일 출고됩니다. (주말·공휴일 제외)</li><li>단순 변심에 의한 교환·반품은 상품 수령 후 7일 이내 가능하며, 왕복 배송비 6,000원이 부과됩니다.</li><li>제품 하자의 경우 배송비는 바이트마트가 부담합니다.</li><li>포장 개봉 및 사용 흔적이 있는 경우 반품이 제한될 수 있습니다.</li></ul>
</section>

<section class="shelf"><div class="shead"><h2>함께 많이 본 상품</h2></div><div class="grid five"><?php foreach ($rel as $r) echo product_card($r); ?></div></section>
<?php footer_html();

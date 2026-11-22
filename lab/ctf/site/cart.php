<?php
// 장바구니·주문서. 세션에만 담고, 주문 저장은 바인딩(안전). 실제 결제는 없다.
require __DIR__ . '/_init.php';
$db = db();
$cart = cart();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = (string)($_POST['action'] ?? '');
    $id = (int)($_POST['id'] ?? 0);
    $qty = min(99, max(1, (int)($_POST['qty'] ?? 1)));
    if ($act === 'add' && $id > 0) {
        $st = $db->prepare("SELECT id FROM products WHERE id = ? AND stock > 0");
        $st->execute([$id]);
        if ($st->fetch()) {
            $cart[$id] = min(99, ($cart[$id] ?? 0) + $qty);
            $_SESSION['cart'] = $cart;
            if (!empty($_POST['buynow'])) { header('Location: /cart.php?step=order', true, 302); exit; }
            flash('장바구니에 담았습니다.');
        }
        header('Location: /cart.php', true, 302); exit;
    }
    if ($act === 'update' && isset($cart[$id])) { $cart[$id] = $qty; $_SESSION['cart'] = $cart; }
    if ($act === 'remove') { unset($cart[$id]); $_SESSION['cart'] = $cart; }
    if ($act === 'order' && $cart) {
        $name = trim(mb_substr((string)($_POST['name'] ?? ''), 0, 30));
        $phone = trim(mb_substr((string)($_POST['phone'] ?? ''), 0, 20));
        $addr = trim(mb_substr((string)($_POST['address'] ?? ''), 0, 120));
        if ($name === '' || $phone === '' || $addr === '') { flash('받는 분 정보를 모두 입력해 주세요.'); header('Location: /cart.php?step=order', true, 302); exit; }
        [$items, $sum] = cart_items($db, $cart);
        $first = $items[0]['name'] . (count($items) > 1 ? ' 외 ' . (count($items) - 1) . '건' : '');
        $u = current_user();
        $st = $db->prepare("INSERT INTO orders(user_id,name,address,phone,item,qty,total,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
        $st->execute([$u['id'] ?? null, $name, $addr, $phone, $first, array_sum($cart), $sum + ($sum >= 30000 ? 0 : 3000), '결제완료', date('Y-m-d H:i:s')]);
        $oid = (int)$db->lastInsertId();
        $_SESSION['cart'] = [];
        flash('주문이 완료되었습니다. 주문번호 ' . $oid);
        header('Location: /order.php?id=' . $oid, true, 302); exit;
    }
    header('Location: /cart.php', true, 302); exit;
}

function cart_items(PDO $db, array $cart): array {
    if (!$cart) return [[], 0];
    $ids = array_map('intval', array_keys($cart));
    $st = $db->prepare("SELECT * FROM products WHERE id IN (" . implode(',', array_fill(0, count($ids), '?')) . ")");
    $st->execute($ids);
    $items = []; $sum = 0;
    foreach ($st as $p) { $p['qty'] = (int)$cart[$p['id']]; $p['sale'] = sale_price($p); $sum += $p['sale'] * $p['qty']; $items[] = $p; }
    return [$items, $sum];
}

[$items, $sum] = cart_items($db, $cart);
$shipfee = ($sum >= 30000 || !$items) ? 0 : 3000;
$step = ($_GET['step'] ?? '') === 'order' && $items ? 'order' : 'cart';
header_html($step === 'order' ? '주문/결제' : '장바구니');
$u = current_user();
?>
<div class="steps"><span class="<?= $step === 'cart' ? 'on' : '' ?>">01 장바구니</span><span class="<?= $step === 'order' ? 'on' : '' ?>">02 주문/결제</span><span>03 주문완료</span></div>
<?php if (!$items): ?>
<section class="empty"><h2>장바구니에 담긴 상품이 없습니다.</h2><p>마음에 드는 상품을 담아 보세요.</p><a class="btn" href="/category.php?sort=best">베스트 상품 보기</a></section>
<?php else: ?>
<div class="cartlayout">
  <div>
  <?php if ($step === 'cart'): ?>
    <div class="card"><table class="carttable"><thead><tr><th colspan="2">상품정보</th><th>수량</th><th>상품금액</th><th></th></tr></thead><tbody>
    <?php foreach ($items as $p): ?>
      <tr><td class="ci"><?= product_img($p, 'mini') ?></td><td><a href="/product.php?id=<?= (int)$p['id'] ?>"><?= h($p['name']) ?></a><div class="muted"><?= h($p['brand']) ?> · <?= won($p['sale']) ?></div></td>
      <td><form method="post" class="inline"><input type="hidden" name="action" value="update"><input type="hidden" name="id" value="<?= (int)$p['id'] ?>"><input name="qty" value="<?= $p['qty'] ?>" size="2" class="qtyin"><button class="btn small line">변경</button></form></td>
      <td><b><?= won($p['sale'] * $p['qty']) ?></b></td>
      <td><form method="post"><input type="hidden" name="action" value="remove"><input type="hidden" name="id" value="<?= (int)$p['id'] ?>"><button class="x" aria-label="삭제">×</button></form></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
  <?php else: ?>
    <form method="post" class="card orderform" id="orderform"><input type="hidden" name="action" value="order">
      <h3>배송지 정보</h3><p class="muted">가상 주문입니다. 실제 이름·연락처·주소 대신 지어낸 값을 넣어 주세요.</p>
      <label>받는 분<input name="name" value="<?= h($u['name'] ?? '') ?>" required></label>
      <label>휴대폰 번호<input name="phone" placeholder="010-0000-0000" required></label>
      <label>주소<input name="address" placeholder="도로명 주소와 상세 주소" required></label>
      <label>배송 요청사항<select name="memo"><option>문 앞에 놓아 주세요</option><option>경비실에 맡겨 주세요</option><option>배송 전 연락 바랍니다</option></select></label>
      <h3>결제 수단</h3>
      <div class="pay"><label><input type="radio" name="pay" checked> 신용/체크카드</label><label><input type="radio" name="pay"> 계좌이체</label><label><input type="radio" name="pay"> 간편결제</label></div>
      <p class="muted">※ CTF 실습용 가상 결제 화면입니다. 카드 정보는 받지 않으며 결제가 이루어지지 않습니다.</p>
    </form>
  <?php endif; ?>
  </div>
  <aside class="card summary">
    <h3>결제 예정 금액</h3>
    <dl><dt>상품금액</dt><dd><?= won($sum) ?></dd><dt>배송비</dt><dd><?= $shipfee ? won($shipfee) : '무료' ?></dd></dl>
    <div class="total"><span>총 결제금액</span><b><?= won($sum + $shipfee) ?></b></div>
    <?php if ($step === 'cart'): ?><a class="btn block" href="/cart.php?step=order">주문하기 (<?= array_sum($cart) ?>개)</a>
    <?php else: ?><button class="btn block" form="orderform"><?= won($sum + $shipfee) ?> 결제하기</button><?php endif; ?>
    <?php if (!$u): ?><p class="muted">회원으로 주문하면 적립금과 쿠폰 혜택을 받을 수 있어요. <a href="/login.php">로그인</a></p><?php endif; ?>
  </aside>
</div>
<?php endif; footer_html();

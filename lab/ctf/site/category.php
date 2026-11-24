<?php
// 카테고리 목록: 정렬·페이지. SQL 은 모두 바인딩, 정렬은 허용 목록으로만 고른다.
require __DIR__ . '/_init.php';
$c = (string)($_GET['c'] ?? '');
if ($c !== '' && !isset(categories()[$c])) not_found('없는 카테고리입니다.');
$sorts = ['best' => ['판매량순', 'sold DESC'], 'new' => ['신상품순', 'id DESC'], 'low' => ['낮은 가격순', 'price ASC'], 'high' => ['높은 가격순', 'price DESC'], 'discount' => ['할인율순', 'discount DESC, sold DESC'], 'review' => ['리뷰 많은순', 'review_count DESC']];
$sort = isset($sorts[$_GET['sort'] ?? '']) ? $_GET['sort'] : 'best';
$page = max(1, (int)($_GET['page'] ?? 1));
$per = 20;
$db = db();
$where = $c !== '' ? 'WHERE category = ?' : '';
$args = $c !== '' ? [$c] : [];
$cnt = $db->prepare("SELECT COUNT(*) FROM products $where");
$cnt->execute($args);
$total = (int)$cnt->fetchColumn();
$pages = max(1, (int)ceil($total / $per));
$page = min($page, $pages);
$st = $db->prepare("SELECT * FROM products $where ORDER BY {$sorts[$sort][1]} LIMIT $per OFFSET " . (($page - 1) * $per));
$st->execute($args);
$title = $c !== '' ? cat_name($c) : ($sort === 'discount' ? '특가' : '전체 상품');
header_html($title, $c !== '' ? $c : ($sort === 'discount' ? 'deal' : 'all'));
$base = array_filter(['c' => $c, 'sort' => $sort, 'page' => $page], fn($v) => $v !== '');
$qs = fn(array $o) => '/category.php?' . http_build_query(array_merge($base, $o));
?>
<nav class="crumb"><a href="/">홈</a> › <?= h($title) ?></nav>
<div class="listhead">
  <h1><?= h($title) ?> <small><?= number_format($total) ?>개 상품</small></h1>
  <div class="sorts"><?php foreach ($sorts as $k => [$label]): ?><a href="<?= h($qs(['sort' => $k, 'page' => 1])) ?>" class="<?= $k === $sort ? 'on' : '' ?>"><?= $label ?></a><?php endforeach; ?></div>
</div>
<div class="grid four"><?php foreach ($st as $p) echo product_card($p); ?></div>
<nav class="pager">
<?php if ($page > 1): ?><a href="<?= h($qs(['page' => $page - 1])) ?>">‹ 이전</a><?php endif; ?>
<?php for ($i = max(1, $page - 4); $i <= min($pages, $page + 5); $i++): ?><a href="<?= h($qs(['page' => $i])) ?>" class="<?= $i === $page ? 'on' : '' ?>"><?= $i ?></a><?php endfor; ?>
<?php if ($page < $pages): ?><a href="<?= h($qs(['page' => $page + 1])) ?>">다음 ›</a><?php endif; ?>
</nav>
<?php footer_html();

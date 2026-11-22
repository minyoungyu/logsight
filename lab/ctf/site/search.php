<?php
// 검색: 매개변수 바인딩(안전), 출력 이스케이프(안전). 3-3: 로그인 외 페이지의 SQL은 매개변수화.
require __DIR__ . '/_init.php';
$q = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
header_html($q !== '' ? $q . ' 검색 결과' : '검색');
$rows = [];
if ($q !== '') {
    $st = db()->prepare("SELECT * FROM products WHERE name LIKE ? OR brand LIKE ? ORDER BY sold DESC LIMIT 40");
    $st->execute(['%' . $q . '%', '%' . $q . '%']);
    $rows = $st->fetchAll();
}
?>
<nav class="crumb"><a href="/">홈</a> › 검색</nav>
<div class="listhead"><h1><?= $q !== '' ? '‘' . h($q) . '’ 검색 결과' : '상품 검색' ?> <small><?= count($rows) ?>개</small></h1></div>
<?php if (!$rows): ?>
<section class="empty"><h2><?= $q !== '' ? '검색 결과가 없습니다.' : '검색어를 입력해 주세요.' ?></h2>
<p>철자를 확인하거나 더 짧은 검색어로 다시 찾아보세요.</p>
<div class="chips"><?php foreach (['노바북', '게이밍', 'SSD', '무선', '4K', '허브'] as $s): ?><a href="/search.php?q=<?= urlencode($s) ?>"><?= h($s) ?></a><?php endforeach; ?></div></section>
<?php else: ?>
<div class="grid four"><?php foreach ($rows as $p) echo product_card($p); ?></div>
<?php endif; footer_html();

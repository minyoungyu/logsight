<?php
// 프런트 컨트롤러. nginx 가 없는 경로를 여기로 보낸다(try_files ... /index.php).
// 두 가지 특수 경로를 처리한다:
//   /robots.txt        → 숨은 F1 경로를 Disallow 로 적어 준다(정찰 단서)
//   /<무작위 토큰>      → F1 값을 돌려준다. 토큰은 SSM 이 넣은 /var/lib/ctf/f1_path 와 같아야 한다.
require __DIR__ . '/_init.php';

$uri  = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$path = rtrim($uri, '/');            // "/abc/" → "/abc"
$seg  = ltrim($path, '/');           // "abc"

$f1_path = ctf_read('f1_path');      // 무작위 토큰(팀마다 다름)

// robots.txt: 숨은 경로를 흘려 준다. 무작위 대입이 아니라 이 파일을 읽어야 F1 경로를 안다.
if ($uri === '/robots.txt') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "User-agent: *\n";
    echo "Disallow: /admin/\n";
    echo "Disallow: /internal/\n";
    echo "Disallow: /cart.php\n";
    echo "Disallow: /mypage.php\n";
    if ($f1_path !== null && $f1_path !== '') {
        // 내부 점검용 경로 — 색인에서 빼기만 하고 접근 제어는 걸지 않은 상태(의도한 F1 노출)
        echo "Disallow: /{$f1_path}/\n";
    }
    exit;
}

// 숨은 F1 경로
if ($f1_path !== null && $f1_path !== '' && hash_equals($f1_path, $seg)) {
    $f1 = ctf_read('f1');
    header('Content-Type: text/plain; charset=utf-8');
    echo "내부 점검 엔드포인트. 외부에 노출하지 말 것.\n\n";
    echo "flag: " . ($f1 ?? '(준비되지 않음 — 운영진 주입 대기)') . "\n";
    exit;
}

// 그 외 알 수 없는 경로(실제 파일은 nginx 가 직접 처리하므로 여기 오지 않는다)
if ($uri !== '/' && $uri !== '/index.php') not_found();

// 홈
$db = db();
header_html('홈');
?>
<section class="hero">
  <div class="slides" data-slider>
    <div class="slide s1 on"><div><span class="eyebrow">BLACK WEEK · ~11.30</span><h1>연말 최대 할인<br><b>노트북 최대 32%</b></h1><p>카드사 즉시할인 + 무이자 할부 최대 12개월</p><a class="btn white" href="/category.php?c=laptop&amp;sort=discount">기획전 보러가기</a></div><img src="/static/img/laptop.svg" alt=""></div>
    <div class="slide s2"><div><span class="eyebrow">WORK FROM HOME</span><h1>재택근무 세팅<br><b>모니터·웹캠 특가</b></h1><p>2대 이상 구매 시 추가 5% 할인</p><a class="btn white" href="/category.php?c=monitor">모니터 보러가기</a></div><img src="/static/img/monitor.svg" alt=""></div>
    <div class="slide s3"><div><span class="eyebrow">NEW ARRIVAL</span><h1>타건감이 다른<br><b>무접점 키보드 입고</b></h1><p>신상품 리뷰 작성 시 포인트 2,000P</p><a class="btn white" href="/category.php?c=keyboard&amp;sort=new">신상품 보러가기</a></div><img src="/static/img/keyboard.svg" alt=""></div>
    <div class="dots"><i class="on"></i><i></i><i></i></div>
  </div>
  <div class="side-banners">
    <a href="/signup.php" class="sb sb1"><b>첫 구매 3,000원</b><span>신규 회원 전용 쿠폰</span></a>
    <a href="/support.php#notice" class="sb sb2"><b>오늘출발</b><span>오후 2시 전 주문 시 당일 발송</span></a>
  </div>
</section>

<section class="catrow">
<?php foreach (categories() as $slug => [$name, $icon]): ?>
  <a href="/category.php?c=<?= $slug ?>"><span><img src="/static/img/<?= $icon ?>.svg" alt=""></span><?= h($name) ?></a>
<?php endforeach; ?>
</section>

<section class="benefits">
  <div><b>무료배송</b><span>3만원 이상 구매 시</span></div>
  <div><b>오늘출발</b><span>평일 오후 2시 마감</span></div>
  <div><b>정품 보증</b><span>공식 수입·제조사 A/S</span></div>
  <div><b>안심 반품</b><span>수령 후 7일 이내</span></div>
</section>

<?php
$sections = [
    ['오늘의 특가', '지금 가장 많이 할인하는 상품', "SELECT * FROM products WHERE stock > 0 ORDER BY discount DESC, sold DESC LIMIT 10", '/category.php?sort=discount'],
    ['베스트 상품', '이번 주 가장 많이 팔린 상품', "SELECT * FROM products ORDER BY sold DESC LIMIT 10", '/category.php?sort=best'],
    ['신상품', '새로 들어온 상품을 만나보세요', "SELECT * FROM products ORDER BY id DESC LIMIT 10", '/category.php?sort=new'],
];
foreach ($sections as [$t, $sub, $sql, $more]):
?>
<section class="shelf">
  <div class="shead"><h2><?= h($t) ?> <small><?= h($sub) ?></small></h2><a href="<?= h($more) ?>">더보기 ›</a></div>
  <div class="grid five"><?php foreach ($db->query($sql) as $p) echo product_card($p); ?></div>
</section>
<?php endforeach; ?>

<section class="promo-strip">
  <div><h3>기업 고객이신가요?</h3><p>대량 구매 견적, 세금계산서, 전담 매니저 배정까지. 기업 전용 상담을 신청하세요.</p></div>
  <a class="btn" href="/support.php#b2b">기업 구매 상담</a>
</section>
<?php footer_html();

<?php
// ===========================================================================
// LogSight CTF 문제 사이트("바이트마트" 전자제품 쇼핑몰). 대회 서버에서만 쓴다.
// 설계: "LogSight 검증용 CTF 형식안" 2장(플래그), 3-3장(의도하지 않은 경로 점검).
// shopmall 원본에서 설계 밖 취약점(LFI view.php, include lang.php, XXE import.php,
// 기본 관리자 계정, 웹 루트 DB·backup.sql, file:// SSRF)을 모두 걷어냈다.
// 남긴 취약점은 설계한 것뿐이다:
//   F1 숨은 경로(robots.txt 단서) · F2 관리자 로그인 SQLi · F3 업로드 웹셸 실행 · F5 SSRF.
// 그 밖의 화면(카테고리·장바구니·회원가입·마이페이지·고객센터)은 실제 쇼핑몰처럼 보이게 하려는
// 것이며, SQL은 모두 매개변수 바인딩, 출력은 모두 이스케이프한다(새 취약점을 만들지 않는다).
// 플래그 값은 이 코드·DB·웹 루트 어디에도 하드코딩하지 않는다.
//   F1/F2 → /var/lib/ctf 의 파일(SSM이 넣음, nginx 그룹만 읽음)
//   F3   → /usr/local/bin/proof 실행 출력(읽을 수 없는 0711 바이너리)
//   F5   → 인스턴스 역할 이름(IMDS)   F6 → S3
// ===========================================================================
session_start();

const SHOP_NAME = '바이트마트';

function ctf_dir(): string { return getenv('CTF_DIR') ?: '/var/lib/ctf'; }
function db_path(): string { return getenv('CTF_DB') ?: '/var/lib/ctf/app/shop.sqlite'; }

// /var/lib/ctf 아래의 값을 읽는다. 웹에서 직접 못 읽고, 앱만 읽는다.
function ctf_read(string $name): ?string {
    $p = ctf_dir() . '/' . $name;
    if (!is_readable($p)) return null;
    return trim((string)file_get_contents($p));
}

function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function won($n): string { return number_format((int)$n) . '원'; }

// 카테고리: 슬러그 => [이름, 아이콘 파일]
function categories(): array {
    return [
        'laptop'   => ['노트북', 'laptop'],
        'monitor'  => ['모니터', 'monitor'],
        'keyboard' => ['키보드', 'keyboard'],
        'mouse'    => ['마우스', 'mouse'],
        'headset'  => ['헤드셋', 'headset'],
        'webcam'   => ['웹캠', 'webcam'],
        'storage'  => ['저장장치', 'storage'],
        'cable'    => ['케이블·허브', 'cable'],
    ];
}
function cat_name(string $slug): string { return categories()[$slug][0] ?? '기타'; }

// 상품 이미지(로컬 SVG) + 상품마다 다른 배경 톤
function product_img(array $p, string $cls = 'thumb'): string {
    $tones = ['#eef2ff', '#ecfdf5', '#fff7ed', '#f0f9ff', '#fdf2f8', '#f5f5f4'];
    $tone = $tones[((int)$p['id']) % count($tones)];
    $icon = categories()[$p['category']][1] ?? 'laptop';
    return '<div class="' . $cls . '" style="background:' . $tone . '"><img src="/static/img/' . $icon . '.svg" alt="' . h($p['name']) . '" loading="lazy"></div>';
}

function stars(float $r): string {
    $full = (int)round($r);
    return '<span class="stars" aria-label="별점 ' . number_format($r, 1) . '">' . str_repeat('★', $full) . '<i>' . str_repeat('★', 5 - $full) . '</i></span>';
}

function sale_price(array $p): int { return (int)(round($p['price'] * (100 - (int)$p['discount']) / 100 / 100) * 100); }

// 상품 카드(목록용)
function product_card(array $p): string {
    $sale = sale_price($p);
    $badge = '';
    if ((int)$p['stock'] === 0) $badge = '<span class="badge gray">일시품절</span>';
    elseif ((int)$p['id'] % 7 === 0) $badge = '<span class="badge">오늘출발</span>';
    elseif ((int)$p['id'] % 11 === 0) $badge = '<span class="badge blue">NEW</span>';
    return '<a class="pcard" href="/product.php?id=' . (int)$p['id'] . '">'
        . product_img($p) . $badge
        . '<div class="pbody"><div class="brand">' . h($p['brand']) . '</div>'
        . '<div class="pname">' . h($p['name']) . '</div>'
        . '<div class="price">' . ((int)$p['discount'] > 0 ? '<em>' . (int)$p['discount'] . '%</em>' : '') . won($sale)
        . ((int)$p['discount'] > 0 ? ' <del>' . won($p['price']) . '</del>' : '') . '</div>'
        . '<div class="meta">' . stars((float)$p['rating']) . ' <span>(' . number_format((int)$p['review_count']) . ')</span>'
        . ($sale >= 30000 ? ' · <span class="ship">무료배송</span>' : '') . '</div></div></a>';
}

// 결정적 시드 데이터 생성용 이름 표
function seed_catalog(): array {
    return [
        'laptop'   => [['노바북', '크로마 스튜디오', '에어라이트', '프로엣지'], ['13', '14', '15.6', '16'], ['i5/16GB/512GB', 'i7/16GB/1TB', 'R5/8GB/256GB', 'R7/32GB/1TB', 'Ultra5/16GB/512GB'], [549000, 2390000]],
        'monitor'  => [['뷰라인', '클리어뷰', '게이밍 플렉스', '오피스 와이드'], ['24', '27', '32', '34'], ['FHD 100Hz IPS', 'QHD 165Hz', '4K UHD HDR400', 'WQHD 커브드 144Hz'], [139000, 899000]],
        'keyboard' => [['타입로직', '키크래프트', '사일런트 프로', '로우 프로파일'], ['TKL', '풀배열', '75%', '65%'], ['갈축', '적축', '저소음 적축', '무접점 45g', '블루투스 멀티페어링'], [29000, 289000]],
        'mouse'    => [['에임 라이트', '오피스 무선', '버티컬 에르고', '트래블 미니'], ['M1', 'M3', 'G5', 'V2'], ['무선 2.4GHz', '블루투스 5.3', '유무선 겸용', '초경량 58g'], [12900, 159000]],
        'headset'  => [['사운드코어', '튠웨이브', '게이밍 7.1', '콜센터 프로'], ['H2', 'H5', 'X7', 'Z9'], ['노이즈캔슬링', '무선 저지연', 'USB 7.1채널', '양귀형 마이크'], [19900, 399000]],
        'webcam'   => [['클리어캠', '스트림뷰', '미팅캠'], ['C1', 'C4', 'C9'], ['FHD 30fps', 'QHD 오토포커스', '4K HDR'], [29900, 249000]],
        'storage'  => [['스피드 SSD', '포터블 SSD', '에버디스크', 'USB 메모리'], ['256GB', '512GB', '1TB', '2TB'], ['NVMe Gen4', 'USB-C 10Gbps', 'SATA3', 'USB 3.2'], [15900, 459000]],
        'cable'    => [['링크허브', 'C to C 케이블', 'HDMI 2.1 케이블', '멀티 어댑터'], ['1m', '2m', '7in1', '11in1'], ['100W PD', '8K 60Hz', '기가비트 랜', '썬더볼트 호환'], [6900, 129000]],
    ];
}

function db(): PDO {
    static $db = null;
    if ($db) return $db;
    $path = db_path();
    $fresh = !file_exists($path);
    if ($fresh) @mkdir(dirname($path), 0750, true);
    $db = new PDO('sqlite:' . $path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    if ($fresh) seed_db($db);
    return $db;
}

function seed_db(PDO $db): void {
    $db->exec("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, role TEXT, name TEXT, created_at TEXT)");
    $db->exec("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, brand TEXT, price INTEGER, discount INTEGER, category TEXT, stock INTEGER, rating REAL, review_count INTEGER, sold INTEGER, description TEXT)");
    $db->exec("CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, rating INTEGER, body TEXT, created_at TEXT)");
    $db->exec("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, address TEXT, phone TEXT, item TEXT, qty INTEGER, total INTEGER, status TEXT, created_at TEXT)");
    $db->exec("CREATE INDEX idx_products_cat ON products(category)");
    $db->exec("CREATE INDEX idx_reviews_pid ON reviews(product_id)");

    // 관리자·회원: 기본 계정을 두지 않는다. 비밀번호는 서버마다 무작위로 해시 저장한다.
    // F2는 비밀번호를 맞히는 문제가 아니라 로그인 쿼리를 SQL 인젝션으로 우회하는 문제다.
    $mk = fn() => password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT);
    $us = $db->prepare("INSERT INTO users(username,password,email,role,name,created_at) VALUES(?,?,?,?,?,?)");
    $us->execute(['admin', $mk(), 'owner@bytemart.example', 'admin', '운영관리자', '2025-03-02 09:00:00']);
    foreach ([['minji', '김민지'], ['dohyun', '이도현'], ['seoyeon', '박서연'], ['jiho', '최지호'], ['guest', '게스트']] as $i => $u) {
        $us->execute([$u[0], $mk(), $u[0] . '@example.com', 'user', $u[1], sprintf('2026-%02d-%02d 10:%02d:00', 3 + $i, 5 + $i * 3, $i * 7)]);
    }

    mt_srand(20261126); // 팀마다 같은 상품 목록(채점·지원이 쉽도록)
    $cat = seed_catalog();
    $slugs = array_keys($cat);
    $brands = ['NOVIX', 'KAIRO', 'LUMEN', 'ORBITA', 'HANSOL TECH', 'ARCLINE', 'PEBBLE', 'VELOCE'];
    $descs = [
        '매일 쓰는 기본기에 충실한 제품입니다. 1년 무상 A/S와 전국 서비스센터 지원을 받을 수 있습니다.',
        '얇고 가벼운 디자인에 오래가는 배터리로 이동이 잦은 분께 추천합니다.',
        '사무실·재택근무용으로 인기 있는 스테디셀러입니다. 대량 구매 시 세금계산서 발행이 가능합니다.',
        '게이밍과 크리에이티브 작업을 모두 고려한 고성능 라인업입니다.',
        '정품 인증 제품이며, 수령 후 7일 이내 단순 변심 반품이 가능합니다.',
    ];
    $stmt = $db->prepare("INSERT INTO products(name,brand,price,discount,category,stock,rating,review_count,sold,description) VALUES(?,?,?,?,?,?,?,?,?,?)");
    $db->beginTransaction();
    for ($i = 1; $i <= 2000; $i++) {
        $slug = $slugs[$i % count($slugs)];
        [$lines, $sizes, $specs, $range] = $cat[$slug];
        $name = $lines[mt_rand(0, count($lines) - 1)] . ' ' . $sizes[mt_rand(0, count($sizes) - 1)] . ' ' . $specs[mt_rand(0, count($specs) - 1)];
        $price = (int)(round(mt_rand($range[0], $range[1]) / 1000) * 1000 - 100);
        $discount = [0, 0, 5, 8, 10, 12, 15, 20, 25, 32][mt_rand(0, 9)];
        $stock = ($i % 23 === 0) ? 0 : mt_rand(3, 180);
        $rating = round(mt_rand(36, 50) / 10, 1);
        $stmt->execute([$name, $brands[mt_rand(0, count($brands) - 1)], $price, $discount, $slug, $stock, $rating, mt_rand(0, 2400), mt_rand(10, 9000), $descs[mt_rand(0, count($descs) - 1)]]);
    }
    $db->commit();

    // 후기(앞쪽 상품 위주)
    $authors = ['kim***', 'lee***', 'park**', 'choi***', 'jung**', 'han***', 'yoon**', 'kang***'];
    $bodies = [
        [5, '배송이 하루 만에 왔어요. 포장도 꼼꼼하고 제품 상태 아주 좋습니다.'],
        [5, '회사에서 쓰려고 샀는데 동료들도 따라 샀어요. 가성비 최고입니다.'],
        [4, '전체적으로 만족합니다. 설명서가 조금 부실한 것만 빼면요.'],
        [4, '디자인이 사진보다 실물이 더 예뻐요. 마감도 깔끔합니다.'],
        [3, '무난합니다. 가격 생각하면 괜찮은데 기대만큼은 아니었어요.'],
        [5, '두 번째 구매입니다. 이전 제품도 2년 넘게 문제없이 썼어요.'],
        [2, '초기 불량이 있어서 교환했는데, 교환 처리는 빨랐습니다.'],
        [4, '세일할 때 사서 만족도가 더 높네요. 추천합니다.'],
    ];
    $rv = $db->prepare("INSERT INTO reviews(product_id,author,rating,body,created_at) VALUES(?,?,?,?,?)");
    $db->beginTransaction();
    for ($pid = 1; $pid <= 240; $pid++) {
        $n = mt_rand(1, 6);
        for ($k = 0; $k < $n; $k++) {
            $b = $bodies[mt_rand(0, count($bodies) - 1)];
            $rv->execute([$pid, $authors[mt_rand(0, count($authors) - 1)], $b[0], $b[1], sprintf('2026-%02d-%02d', mt_rand(6, 11), mt_rand(1, 28))]);
        }
    }
    $db->commit();

    // 주문(가짜 데이터). order.php 는 IDOR 노이즈용이다(플래그 아님).
    $os = $db->prepare("INSERT INTO orders(user_id,name,address,phone,item,qty,total,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
    $pq = $db->prepare("SELECT name, price FROM products WHERE id = ?");
    $last = ['김', '이', '박', '최', '정', '강', '조', '윤', '장', '임'];
    $first = ['민준', '서연', '도윤', '하은', '지호', '수아', '예준', '지유', '시우', '서윤'];
    $roads = ['서울시 강남구 테헤란로', '서울시 마포구 월드컵북로', '경기도 성남시 분당구 판교역로', '부산시 해운대구 센텀중앙로', '대전시 유성구 대학로', '인천시 연수구 송도과학로'];
    $status = ['배송완료', '배송완료', '배송완료', '배송중', '상품준비중', '구매확정'];
    $db->beginTransaction();
    for ($i = 1; $i <= 300; $i++) {
        $pq->execute([mt_rand(1, 2000)]);
        $p = $pq->fetch();
        $qty = mt_rand(1, 3);
        $os->execute([null, $last[$i % 10] . $first[($i * 3) % 10], $roads[$i % 6] . ' ' . ($i * 7) . ', ' . (100 + $i % 20) . '동 ' . (200 + $i) . '호',
            sprintf('010-%04d-%04d', 1000 + $i * 13 % 9000, 2000 + $i * 29 % 8000), $p['name'], $qty, $p['price'] * $qty,
            $status[$i % 6], sprintf('2026-%02d-%02d %02d:%02d:00', 9 + intdiv($i, 101), 1 + $i % 28, 8 + $i % 14, $i % 60)]);
    }
    $db->commit();
}

function is_admin(): bool { return !empty($_SESSION['admin']); }
function require_admin(): void {
    if (!is_admin()) { header('Location: /admin/login.php', true, 302); exit; }
}
function current_user(): ?array {
    if (empty($_SESSION['uid'])) return null;
    $st = db()->prepare("SELECT id, username, name, email FROM users WHERE id = ? AND role = 'user'");
    $st->execute([(int)$_SESSION['uid']]);
    return $st->fetch() ?: null;
}
function cart(): array { return is_array($_SESSION['cart'] ?? null) ? $_SESSION['cart'] : []; }
function cart_count(): int { return array_sum(cart()); }

function flash(?string $msg = null): ?string {
    if ($msg !== null) { $_SESSION['flash'] = $msg; return null; }
    $m = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return $m;
}

function header_html($title, string $active = '') {
    $user = current_user();
    $q = isset($_GET['q']) ? (string)$_GET['q'] : '';
    echo '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>' . h($title) . ' | ' . SHOP_NAME . '</title>'
       . '<meta name="description" content="' . SHOP_NAME . ' - 노트북, 모니터, 주변기기 전문 온라인 쇼핑몰">'
       . '<link rel="icon" href="/static/img/favicon.svg" type="image/svg+xml">'
       . '<link rel="stylesheet" href="/static/style.css"></head><body>'
       // 정찰 단서: 로봇 배제 파일에 공개하지 않은 경로가 적혀 있다(F1).
       . '<!-- TODO(보안점검): 아래 관리/비공개 경로는 robots.txt 로만 가린 상태. 검색엔진 차단만 걸려 있음. -->'
       . '<div class="ctfbar">LogSight 보안 교육용 CTF 대회 환경입니다 · 실제 쇼핑몰이 아니며 판매·결제·배송이 이루어지지 않습니다</div>'
       . '<div class="topbar"><div class="wrap"><span>CTF 실습용 가상 쇼핑몰</span><span class="tlinks">'
       . ($user
           ? '<b>' . h($user['name'] ?: $user['username']) . '</b>님 · <a href="/mypage.php">마이페이지</a> · <a href="/logout.php">로그아웃</a>'
           : '<a href="/login.php">로그인</a> · <a href="/signup.php">회원가입</a>')
       . ' · <a href="/support.php">고객센터</a></span></div></div>'
       . '<header class="site"><div class="wrap hrow">'
       . '<a class="logo" href="/"><img src="/static/img/logo.svg" alt="" width="34" height="34"><span>' . SHOP_NAME . '</span><small class="ctftag">CTF</small></a>'
       . '<form class="search" action="/search.php" method="get" role="search"><input name="q" value="' . h($q) . '" placeholder="찾으시는 상품을 검색해 보세요" aria-label="상품 검색">'
       . '<button aria-label="검색"><svg viewBox="0 0 24 24" width="20" height="20"><circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="2.4"/><path d="M20 20l-4-4" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg></button></form>'
       . '<nav class="icons"><a href="/mypage.php"><svg viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6" fill="none" stroke="currentColor" stroke-width="2"/></svg><span>마이</span></a>'
       . '<a href="/cart.php" class="cartlink"><svg viewBox="0 0 24 24" width="24" height="24"><path d="M3 4h2l2.4 11h10.8L21 7H6.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><circle cx="9" cy="20" r="1.6" fill="currentColor"/><circle cx="18" cy="20" r="1.6" fill="currentColor"/></svg><span>장바구니</span>'
       . (cart_count() ? '<i class="cnt">' . cart_count() . '</i>' : '') . '</a></nav>'
       . '</div><nav class="gnb"><div class="wrap"><a href="/category.php" class="' . ($active === 'all' ? 'on' : '') . '">☰ 전체 카테고리</a>';
    foreach (categories() as $slug => [$name]) {
        echo '<a href="/category.php?c=' . $slug . '" class="' . ($active === $slug ? 'on' : '') . '">' . h($name) . '</a>';
    }
    echo '<a href="/category.php?sort=discount" class="hot ' . ($active === 'deal' ? 'on' : '') . '">특가</a></div></nav></header><main class="wrap">';
    if ($m = flash()) echo '<div class="flash">' . h($m) . '</div>';
}

function footer_html() {
    echo '</main><footer class="site"><div class="wrap">'
       . '<div class="fcols"><div><b class="flogo">' . SHOP_NAME . '</b><p>노트북·모니터·PC 주변기기 전문몰</p></div>'
       . '<div><h4>고객센터</h4><p>대회 중 문의는 운영진에게 해 주세요.</p></div>'
       . '<div><h4>쇼핑 안내</h4><p><a href="/support.php#notice">공지사항</a><br><a href="/support.php#faq">자주 묻는 질문</a><br><a href="/order.php">주문/배송 조회</a></p></div>'
       . '<div><h4>정책</h4><p><a href="/support.php#terms">이용약관</a><br><a href="/support.php#privacy"><b>개인정보처리방침</b></a></p></div></div>'
       . '<p class="biz">이 사이트는 LogSight 보안 교육용 CTF 대회를 위해 만든 가상 쇼핑몰입니다. 회사·연락처·상품은 모두 지어낸 것이며 실제 판매·결제가 이루어지지 않습니다. 개인정보를 입력하지 마세요.</p>'
       . '<p class="copy">© 2026 LogSight CTF · 가상 쇼핑몰 바이트마트</p></div></footer>'
       . '<script src="/static/app.js" defer></script></body></html>';
}

function not_found(string $msg = '요청하신 페이지를 찾을 수 없습니다.'): void {
    http_response_code(404);
    header_html('페이지 없음');
    echo '<section class="empty"><div class="big">404</div><h2>' . h($msg) . '</h2><p>주소가 바뀌었거나 삭제된 페이지일 수 있어요.</p><a class="btn" href="/">홈으로 가기</a></section>';
    footer_html();
    exit;
}

// ---------------------------------------------------------------- 관리자 화면 틀
function admin_header(string $title, string $active = ''): void {
    $items = ['index' => ['대시보드', '/admin/index.php'], 'upload' => ['상품 이미지 업로드', '/admin/upload.php'], 'fetch' => ['외부 이미지 가져오기', '/admin/fetch.php']];
    echo '<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>' . h($title) . ' | ' . SHOP_NAME . ' 파트너센터 (CTF)</title><link rel="icon" href="/static/img/favicon.svg" type="image/svg+xml">'
       . '<link rel="stylesheet" href="/static/admin.css"></head><body class="admin"><div class="ctfbar">LogSight 보안 교육용 CTF 대회 환경 · 가상 관리자 화면</div>'
       . '<aside><a class="alogo" href="/admin/index.php"><img src="/static/img/logo.svg" alt="" width="28" height="28"> 파트너센터</a><nav>';
    foreach ($items as $k => [$label, $href]) echo '<a href="' . $href . '" class="' . ($active === $k ? 'on' : '') . '">' . $label . '</a>';
    echo '<span class="sep">운영</span><a class="dim">주문 관리</a><a class="dim">정산</a><a class="dim">쿠폰·프로모션</a><a class="dim">고객 문의</a>'
       . '</nav><a class="back" href="/">← 쇼핑몰로 가기</a></aside><div class="amain"><div class="abar"><h1>' . h($title) . '</h1><span>운영관리자 · ' . date('Y-m-d') . '</span></div>';
}
function admin_footer(): void { echo '</div></body></html>'; }

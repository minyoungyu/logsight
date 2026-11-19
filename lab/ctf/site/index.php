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

// 그 외 알 수 없는 경로는 홈으로(단, 실제 파일은 nginx 가 직접 처리하므로 여기 오지 않는다)
if ($uri !== '/' && $uri !== '/index.php') {
    http_response_code(404);
    header_html('없음');
    echo '<p>페이지를 찾을 수 없습니다.</p>';
    footer_html();
    exit;
}

// 홈
$db = db();
header_html('홈');
echo '<h2>추천 상품</h2><div class="grid">';
foreach ($db->query("SELECT id,name,price FROM products ORDER BY id LIMIT 12") as $r) {
    echo '<a class="card" style="text-decoration:none;color:inherit" href="/product.php?id=' . (int)$r['id'] . '">'
       . htmlspecialchars($r['name']) . '<br><b>' . number_format($r['price']) . '원</b></a>';
}
echo '</div>';
footer_html();

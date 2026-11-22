<?php
// 외부 이미지 가져오기 — F5 경로(관리자 전용). 설계한 취약점: 내부 주소를 막지 않는다(SSRF).
// http/https 만 허용(file://·gopher:// 등은 거부, 3-3). 내부망·메타데이터(169.254.169.254)는 막지 않는다.
// SSRF 로 메타데이터의 인스턴스 역할 이름(F5)을 읽는다.
require __DIR__ . '/../_init.php';
require_admin();
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['url'])) {
    $url = (string)($_POST['url'] ?? $_GET['url'] ?? '');
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        http_response_code(400); header('Content-Type: text/plain; charset=utf-8');
        echo 'http/https 주소만 가져올 수 있습니다.'; exit;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'follow_location' => 0]]);
    $body = @file_get_contents($url, false, $ctx);
    header('Content-Type: text/plain; charset=utf-8');
    if ($body === false) { http_response_code(502); echo '가져오기 실패'; exit; }
    echo substr($body, 0, 200000); exit;
}
// F5 단서(입문자용). 난이도를 낮추려고 메타데이터/내부 주소로 이어지는 힌트를 남긴다.
// 리허설에서 너무 쉬우면 아래 안내 문구를 지우거나, 169.254.169.254 예시만 빼면 된다.
admin_header('외부 이미지 가져오기', 'fetch');
?>
<section class="panel"><h2>이미지 주소로 가져오기</h2>
  <p>제조사·공급사 사이트의 이미지 URL을 넣으면 서버가 대신 내려받아 미리 보여 줍니다.</p>
  <form method="post" class="urlrow"><input name="url" placeholder="https://..."><button class="abtn">가져오기</button></form>
</section>
<section class="panel"><h2>도움말</h2>
  <p>이미지 URL을 넣으면 서버가 대신 내려받아 미리 보여 줍니다.</p>
  <p class="muted">※ 서버 내부 점검용 주소도 이 기능으로 확인할 수 있습니다.
  예) 인스턴스 메타데이터 <code>http://169.254.169.254/latest/meta-data/</code>,
  내부 통계 <code>http://127.0.0.1/internal/stats.php</code></p>
</section>
<?php admin_footer();

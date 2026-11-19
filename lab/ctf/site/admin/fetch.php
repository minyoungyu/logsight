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
echo '<!doctype html><meta charset=utf-8><link rel=stylesheet href=/static/style.css><main><h1>외부 이미지 가져오기</h1>'
   . '<form method=post class=card><input name=url style=width:70% placeholder="https://...">'
   . '<button>가져오기</button></form></main>';

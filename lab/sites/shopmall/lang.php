<?php
// 언어 전환 페이지. 취약점: 파일 경로를 검사 없이 include 한다(LFI → 로그 포이즈닝으로 실행까지). 테스트 전용.
$f = isset($_GET['f']) ? $_GET['f'] : 'lang/ko.txt';
header('Content-Type: text/plain; charset=utf-8');
if (is_file($f) || is_file(__DIR__ . '/' . $f)) {
    include is_file($f) ? $f : __DIR__ . '/' . $f;
} else {
    http_response_code(404);
    echo '언어 파일이 없습니다.';
}

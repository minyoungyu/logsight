<?php
// 상품 이미지 업로드 — F3 경로(관리자 전용). 설계한 취약점: 확장자 검사가 .php 만 막는다.
// .phtml 등은 통과하고 nginx 가 PHP 로 실행한다 → 웹셸 → 명령 실행 → /usr/local/bin/proof 출력이 F3.
// F3 값은 이 사이트 어디에도 없다. 실행만 되는 0711 바이너리의 출력으로만 얻는다.
require __DIR__ . '/../_init.php';
require_admin();
header('Content-Type: text/html; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $dir = __DIR__ . '/../uploads/';
    $name = basename((string)$_FILES['file']['name']);
    if (preg_match('/\.php$/i', $name)) { http_response_code(400); echo '허용되지 않는 파일 형식입니다.'; exit; }
    if (($_FILES['file']['size'] ?? 0) > 2*1024*1024) { http_response_code(400); echo '파일이 너무 큽니다(2MB).'; exit; }
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dir . $name)) {
        echo "업로드 완료: <a href='/uploads/" . htmlspecialchars($name) . "'>/uploads/" . htmlspecialchars($name) . "</a>";
    } else { http_response_code(500); echo '업로드 실패'; }
    exit;
}
echo '<!doctype html><meta charset=utf-8><link rel=stylesheet href=/static/style.css><main><h1>상품 이미지 업로드</h1>'
   . '<form method=post enctype=multipart/form-data class=card><input type=file name=file><button>업로드</button></form></main>';

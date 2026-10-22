<?php
// 상품 이미지 업로드. 취약점: 확장자 검사가 .php 만 막는다(.phtml·.php5 등은 통과). 테스트 전용.
header('Content-Type: text/html; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $dir = __DIR__ . '/uploads/';
    @mkdir($dir, 0777, true);
    $name = basename($_FILES['file']['name']);
    if (preg_match('/\.php$/i', $name)) { http_response_code(400); echo '허용되지 않는 파일 형식입니다.'; exit; }
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dir . $name)) {
        echo "업로드 완료: <a href='/uploads/" . htmlspecialchars($name) . "'>/uploads/" . htmlspecialchars($name) . "</a>";
    } else {
        http_response_code(500); echo '업로드 실패';
    }
    exit;
}
echo '<!doctype html><meta charset=utf-8><h1>상품 이미지 업로드</h1>
<form method=post enctype=multipart/form-data><input type=file name=file><button>업로드</button></form>';

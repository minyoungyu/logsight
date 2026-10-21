<?php
// 취약점: 업로드 파일 확장자·내용 검사 없음 → 웹셸 업로드 가능. 테스트 전용.
header('Content-Type: text/html; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $dir = __DIR__ . '/uploads/';
    @mkdir($dir, 0777, true);
    $name = basename($_FILES['file']['name']); // 취약: 원래 이름 그대로
    $dest = $dir . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo "업로드 완료: <a href='/uploads/" . htmlspecialchars($name) . "'>/uploads/" . htmlspecialchars($name) . "</a>";
    } else {
        http_response_code(500);
        echo "업로드 실패";
    }
    exit;
}
echo '<!doctype html><meta charset=utf-8><h1>이미지 업로드</h1>
<form method=post enctype=multipart/form-data><input type=file name=file><button>업로드</button></form>';

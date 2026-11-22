<?php
// 상품 이미지 업로드 — F3 경로(관리자 전용). 설계한 취약점: 확장자 검사가 .php 만 막는다.
// .phtml 등은 통과하고 nginx 가 PHP 로 실행한다 → 웹셸 → 명령 실행 → /usr/local/bin/proof 출력이 F3.
// F3 값은 이 사이트 어디에도 없다. 실행만 되는 0711 바이너리의 출력으로만 얻는다.
require __DIR__ . '/../_init.php';
require_admin();
header('Content-Type: text/html; charset=utf-8');
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $dir = __DIR__ . '/../uploads/';
    $name = basename((string)$_FILES['file']['name']);
    if (preg_match('/\.php$/i', $name)) { http_response_code(400); echo '허용되지 않는 파일 형식입니다.'; exit; }
    if (($_FILES['file']['size'] ?? 0) > 2*1024*1024) { http_response_code(400); echo '파일이 너무 큽니다(2MB).'; exit; }
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dir . $name)) {
        $msg = "업로드 완료: <a href='/uploads/" . htmlspecialchars($name) . "'>/uploads/" . htmlspecialchars($name) . "</a>";
    } else { http_response_code(500); echo '업로드 실패'; exit; }
}
admin_header('상품 이미지 업로드', 'upload');
?>
<?php if ($msg): ?><div class="ok"><?= $msg ?></div><?php endif; ?>
<section class="panel"><h2>이미지 파일 올리기</h2>
  <form method="post" enctype="multipart/form-data" class="drop">
    <div><b>파일을 선택해 주세요</b><span>JPG, PNG, GIF, WEBP · 최대 2MB · 권장 1000×1000px</span></div>
    <input type="file" name="file"><button class="abtn">업로드</button>
  </form>
  <ul class="hint"><li>올린 이미지는 <code>/uploads/파일명</code> 주소로 바로 공개됩니다.</li><li>같은 이름의 파일을 올리면 기존 파일을 덮어씁니다.</li></ul>
</section>
<?php admin_footer();

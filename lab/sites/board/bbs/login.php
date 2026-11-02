<?php
// 취약점: 로그인 시도 제한 없음. 테스트 전용.
require __DIR__ . '/../_init.php';
header('Content-Type: text/html; charset=utf-8');
if ($_SERVER['REQUEST_METHOD']==='POST') {
    $db=db(); $st=$db->prepare("SELECT id FROM members WHERE uid=? AND pw=?");
    $st->execute([$_POST['uid']??'', $_POST['pw']??'']);
    if ($st->fetch()) { header('Location: /admin/tools.php',true,302); exit; }
    http_response_code(401); echo "로그인 실패"; exit;
}
echo '<!doctype html><meta charset=utf-8><h1>회원 로그인</h1>
<form method=post><input name=uid><input name=pw type=password><button>로그인</button></form>';

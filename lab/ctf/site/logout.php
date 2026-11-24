<?php
require __DIR__ . '/_init.php';
unset($_SESSION['uid']);
session_regenerate_id(true);
flash('로그아웃되었습니다.');
header('Location: /', true, 302);

<?php
// ===========================================================================
// 의도적으로 취약하게 만든 로컬 테스트 사이트 (LogSight 검증용).
// 절대 공개 서버에 올리지 마세요. 공격 테스트는 이 로컬 서버에만 하세요.
// INTENTIONALLY VULNERABLE TEST FIXTURE — LOCAL USE ONLY, DO NOT DEPLOY.
// ===========================================================================
// 작은 쇼핑몰: 상품 검색(SQLi), 로그인(무차별 대입), 파일 보기(LFI), 업로드(웹셸).
function db() {
    $path = __DIR__ . '/runtime.sqlite';
    $fresh = !file_exists($path);
    $db = new PDO('sqlite:' . $path);
    if ($fresh) {
        $db->exec("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        $db->exec("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER)");
        $db->exec("INSERT INTO users(username,password) VALUES('admin','S3cretPass!'),('guest','guest')");
        $db->exec("INSERT INTO products(name,price) VALUES('노트북',1200000),('마우스',20000),('키보드',45000)");
    }
    return $db;
}

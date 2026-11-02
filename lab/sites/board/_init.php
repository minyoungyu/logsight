<?php
// 의도적 취약 테스트 사이트 B (게시판형). LOCAL TEST FIXTURE ONLY — DO NOT DEPLOY.
// 변형 포인트: 경로 구조(/bbs, /admin)와 업로드 폴더(/data)가 A와 다름 → 프로필로만 설정.
function db() {
    $path = __DIR__ . '/runtime.sqlite';
    $fresh = !file_exists($path);
    $db = new PDO('sqlite:' . $path);
    if ($fresh) {
        $db->exec("CREATE TABLE members(id INTEGER PRIMARY KEY, uid TEXT, pw TEXT)");
        $db->exec("CREATE TABLE posts(id INTEGER PRIMARY KEY, title TEXT, body TEXT)");
        $db->exec("INSERT INTO members(uid,pw) VALUES('sysop','Adm!n2024'),('tester','1234')");
        $db->exec("INSERT INTO posts(title,body) VALUES('공지','환영합니다'),('질문','배송 문의')");
    }
    return $db;
}

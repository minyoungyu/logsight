<?php
// ===========================================================================
// 의도적으로 취약하게 만든 로컬 테스트 사이트 (LogSight 검증용).
// 절대 공개 서버에 올리지 마세요. 공격 테스트는 이 로컬 서버에만 하세요.
// INTENTIONALLY VULNERABLE TEST FIXTURE — LOCAL USE ONLY, DO NOT DEPLOY.
// ===========================================================================
// 실제 소형 쇼핑몰처럼 보이도록 만든 샘플몰. 기능: 상품 목록·상세, 검색, 로그인,
// 관리자 페이지(기본 비밀번호 그대로), 언어 전환, 이미지 업로드.
// 취약점은 실제 소형 사이트에서 자주 나오는 것만 골랐다(SQLi, 반사형 XSS, LFI, 업로드, 기본 계정).

function db() {
    $path = __DIR__ . '/runtime.sqlite';
    $fresh = !file_exists($path);
    $db = new PDO('sqlite:' . $path);
    if ($fresh) {
        $db->exec("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)");
        $db->exec("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER, category TEXT, stock INTEGER)");
        $db->exec("CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT)");
        $db->exec("INSERT INTO users(username,password,email,role) VALUES
            ('admin','S3cretPass!','owner@sample-mall.kr','admin'),
            ('shopadmin','admin','ops@sample-mall.kr','admin'),
            ('guest','guest','guest@example.com','user'),
            ('minji','minji1234','minji@example.com','user'),
            ('dohyun','dh!2024','dohyun@example.com','user')");
        // 상품 2,000개: 실제 쇼핑몰 목록처럼 많아야 검색·덤프 응답이 현실적인 크기가 된다.
        $cats = ['노트북', '마우스', '키보드', '모니터', '헤드셋', '웹캠', '케이블', '저장장치'];
        $stmt = $db->prepare("INSERT INTO products(name,price,category,stock) VALUES(?,?,?,?)");
        $db->beginTransaction();
        for ($i = 1; $i <= 2000; $i++) {
            $c = $cats[$i % count($cats)];
            $stmt->execute(["$c 모델 " . str_pad((string)$i, 4, '0', STR_PAD_LEFT), 10000 + ($i * 137) % 900000, $c, $i % 50]);
        }
        $db->commit();
    }
    return $db;
}

// 모든 페이지 공통 머리말(실제 사이트처럼 같은 틀을 쓴다)
function header_html($title) {
    echo '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>' . $title . ' | 샘플몰</title>'
       . '<link rel="stylesheet" href="/static/style.css"></head><body>'
       . '<header><a class="logo" href="/">샘플몰</a>'
       . '<form class="search" action="/search.php" method="get"><input name="q" placeholder="상품 검색">'
       . '<button>검색</button></form>'
       . '<nav><a href="/login.php">로그인</a> <a href="/lang.php?f=lang/ko.txt">KO</a></nav></header><main>';
}

function footer_html() {
    echo '</main><footer>© 샘플몰 · 사업자등록번호 000-00-00000 · 고객센터 1500-0000</footer></body></html>';
}

<?php
// ===========================================================================
// LogSight CTF 문제 사이트(shopmall CTF 버전). 대회 서버에서만 쓴다.
// 설계: "LogSight 검증용 CTF 형식안" 2장(플래그), 3-3장(의도하지 않은 경로 점검).
// shopmall 원본에서 설계 밖 취약점(LFI view.php, include lang.php, XXE import.php,
// 기본 관리자 계정, 웹 루트 DB·backup.sql, file:// SSRF)을 모두 걷어냈다.
// 남긴 취약점은 설계한 것뿐이다:
//   F1 숨은 경로(robots.txt 단서) · F2 관리자 로그인 SQLi · F3 업로드 웹셸 실행 · F5 SSRF.
// 플래그 값은 이 코드·DB·웹 루트 어디에도 하드코딩하지 않는다.
//   F1/F2 → /var/lib/ctf 의 파일(SSM이 넣음, nginx 그룹만 읽음)
//   F3   → /usr/local/bin/proof 실행 출력(읽을 수 없는 0711 바이너리)
//   F5   → 인스턴스 역할 이름(IMDS)   F6 → S3
// ===========================================================================
session_start();

function ctf_dir(): string { return getenv('CTF_DIR') ?: '/var/lib/ctf'; }
function db_path(): string { return getenv('CTF_DB') ?: '/var/lib/ctf/app/shop.sqlite'; }

// /var/lib/ctf 아래의 값을 읽는다. 웹에서 직접 못 읽고, 앱만 읽는다.
function ctf_read(string $name): ?string {
    $p = ctf_dir() . '/' . $name;
    if (!is_readable($p)) return null;
    return trim((string)file_get_contents($p));
}

function db(): PDO {
    $path = db_path();
    $fresh = !file_exists($path);
    if ($fresh) @mkdir(dirname($path), 0750, true);
    $db = new PDO('sqlite:' . $path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    if ($fresh) {
        $db->exec("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)");
        $db->exec("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER, category TEXT, stock INTEGER)");
        $db->exec("CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT)");
        $db->exec("CREATE TABLE orders(id INTEGER PRIMARY KEY, name TEXT, address TEXT, phone TEXT, item TEXT)");

        // 관리자·회원: 기본 계정을 두지 않는다. 비밀번호는 서버마다 무작위로 해시 저장한다.
        // F2는 비밀번호를 맞히는 문제가 아니라 로그인 쿼리를 SQL 인젝션으로 우회하는 문제다.
        $mk = fn() => password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT);
        $us = $db->prepare("INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)");
        $us->execute(['admin', $mk(), 'owner@sample-mall.kr', 'admin']);
        foreach ([['minji','minji@example.com'],['dohyun','dohyun@example.com'],['guest','guest@example.com']] as $u) {
            $us->execute([$u[0], $mk(), $u[1], 'user']);
        }

        $os = $db->prepare("INSERT INTO orders(name,address,phone,item) VALUES(?,?,?,?)");
        for ($i = 1; $i <= 300; $i++) {
            $os->execute(["고객" . $i, "서울시 강남구 테헤란로 " . ($i * 7), "010-" . (1000 + $i) . "-" . (2000 + $i), "마우스 모델 " . str_pad((string)$i, 4, '0', STR_PAD_LEFT)]);
        }
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

function is_admin(): bool { return !empty($_SESSION['admin']); }
function require_admin(): void {
    if (!is_admin()) { header('Location: /admin/login.php', true, 302); exit; }
}

function header_html($title) {
    echo '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>' . htmlspecialchars($title) . ' | 샘플몰</title>'
       . '<link rel="stylesheet" href="/static/style.css"></head><body>'
       // 정찰 단서: 로봇 배제 파일에 공개하지 않은 경로가 적혀 있다(F1).
       . '<!-- TODO(보안점검): 아래 관리/비공개 경로는 robots.txt 로만 가린 상태. 검색엔진 차단만 걸려 있음. -->'
       . '<header><a class="logo" href="/">샘플몰</a>'
       . '<form class="search" action="/search.php" method="get"><input name="q" placeholder="상품 검색">'
       . '<button>검색</button></form>'
       . '<nav><a href="/login.php">로그인</a></nav></header><main>';
}

function footer_html() {
    echo '</main><footer>© 샘플몰 · 사업자등록번호 000-00-00000 · 고객센터 1500-0000</footer></body></html>';
}

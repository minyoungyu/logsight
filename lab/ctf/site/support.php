<?php
// 고객센터(정적 안내). DB 를 쓰지 않는다.
require __DIR__ . '/_init.php';
header_html('고객센터');
$notices = [
    ['2026-11-20', '[안내] 블랙위크 기간 배송 지연 안내 (11/24~11/30)'],
    ['2026-11-14', '[이벤트] 노트북 구매 고객 대상 정품 파우치 증정'],
    ['2026-11-03', '[공지] 개인정보처리방침 개정 안내 (시행일 2026-11-10)'],
    ['2026-10-21', '[안내] 시스템 점검으로 인한 서비스 일시 중단 (10/25 02:00~05:00)'],
    ['2026-10-02', '[공지] 추석 연휴 고객센터 운영 시간 안내'],
];
$faq = [
    ['주문 후 배송까지 얼마나 걸리나요?', '평일 오후 2시 이전 결제 시 당일 출고되며, 보통 출고 다음 날 받아 보실 수 있습니다. 도서·산간 지역은 1~2일 더 걸릴 수 있습니다.'],
    ['교환·반품은 어떻게 신청하나요?', '마이페이지 › 주문 내역에서 신청하거나 운영진에게 문의해 주세요. 단순 변심은 수령 후 7일 이내 가능합니다.'],
    ['세금계산서 발행이 가능한가요?', '사업자 회원은 결제 완료 후 마이페이지에서 발행을 신청할 수 있습니다. 기업 대량 구매는 기업 구매 상담을 이용해 주세요.'],
    ['아이디·비밀번호를 잊어버렸어요.', '가입하신 이메일로 본인 확인 후 재설정할 수 있습니다. 현재 대회 환경에서는 재설정 메일이 발송되지 않으니 새로 가입해 주세요.'],
    ['A/S는 어디서 받나요?', '제품별 제조사 서비스센터에서 1년 무상 A/S를 받을 수 있습니다. 바이트마트로 보내 주셔도 대신 접수해 드립니다.'],
];
?>
<nav class="crumb"><a href="/">홈</a> › 고객센터</nav>
<section class="cs-hero card"><div><h1>무엇을 도와드릴까요?</h1><p class="muted">가상 쇼핑몰의 안내 페이지입니다. 대회 문의는 운영진에게 해 주세요.</p></div>
<div class="cs-quick"><a href="/order.php">주문/배송 조회</a><a href="#faq">교환/반품</a><a href="#b2b">기업 구매</a><a href="#notice">공지사항</a></div></section>
<div class="cols2">
<section id="notice" class="card"><h3>공지사항</h3><ul class="notice"><?php foreach ($notices as [$d, $t]): ?><li><span><?= h($t) ?></span><time><?= $d ?></time></li><?php endforeach; ?></ul></section>
<section id="faq" class="card"><h3>자주 묻는 질문</h3><?php foreach ($faq as [$q, $a]): ?><details><summary><?= h($q) ?></summary><p><?= h($a) ?></p></details><?php endforeach; ?></section>
</div>
<section id="b2b" class="card"><h3>기업 구매 상담</h3><p>임직원 PC 일괄 구매, 교육기관 납품, 정기 소모품 구매를 상담해 드립니다. <b>b2b@bytemart.example</b> 로 회사명·품목·수량을 보내 주시면 1영업일 안에 견적을 드립니다.</p></section>
<section id="terms" class="card"><h3>이용약관</h3><p class="muted">제1조(목적) 이 약관은 (주)바이트마트가 운영하는 온라인 쇼핑몰에서 제공하는 서비스의 이용 조건 및 절차에 관한 사항을 규정합니다. …</p></section>
<section id="privacy" class="card"><h3>개인정보처리방침</h3><p class="muted">회사는 주문 처리와 배송을 위해 이름, 연락처, 주소를 수집하며, 관계 법령에 따른 보존 기간이 지나면 지체 없이 파기합니다. 개인정보 보호책임자: 정보보호팀 (privacy@bytemart.example)</p></section>
<?php footer_html();

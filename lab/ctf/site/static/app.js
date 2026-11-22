// 홈 슬라이드, 수량 버튼. 외부 스크립트 없음.
(function () {
  var s = document.querySelector('[data-slider]');
  if (s) {
    var slides = s.querySelectorAll('.slide'), dots = s.querySelectorAll('.dots i'), i = 0;
    setInterval(function () {
      slides[i].classList.remove('on'); dots[i].classList.remove('on');
      i = (i + 1) % slides.length;
      slides[i].classList.add('on'); dots[i].classList.add('on');
    }, 4500);
  }
  document.querySelectorAll('.qty button').forEach(function (b) {
    b.addEventListener('click', function () {
      var inp = b.parentNode.querySelector('input');
      inp.value = Math.min(99, Math.max(1, (parseInt(inp.value, 10) || 1) + parseInt(b.dataset.step, 10)));
    });
  });
})();

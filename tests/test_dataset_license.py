"""비영리 데이터셋(AIT-LDS, CC BY-NC-SA)이 배포 이미지·제품 코드에 섞이지 않는지 검사한다.

원칙은 docs/공개데이터셋_독립측정.md 3절 "데이터 취급 원칙"을 본다.
실행: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# 측정 자료가 있는 곳. 이미지에도, 제품 코드·샘플에도 들어가면 안 된다.
MEASUREMENT_DIRS = ("docs", "reports", "scripts", "data")
# 데이터셋 고유 표지(테스트베드 호스트 이름). 제품 쪽 파일에 나오면 데이터가 복사된 것이다.
MARKERS = ("russellmitchell", "172.19.131.174")


class DatasetLicenseTest(unittest.TestCase):
    def test_image_uses_allowlist_without_measurement_dirs(self):
        lines = [l.strip() for l in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]
        self.assertEqual(lines[0], "*", ".dockerignore는 전부 빼고 시작하는 허용 목록이어야 함")
        allowed = [l[1:].strip("/") for l in lines if l.startswith("!")]
        for d in MEASUREMENT_DIRS:
            self.assertFalse(any(a == d or a.startswith(d + "/") for a in allowed), f"{d}/가 이미지에 들어감")

    def test_dockerfile_does_not_copy_measurement_dirs(self):
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
            if line.strip().upper().startswith(("COPY", "ADD")):
                srcs = line.split()[1:-1]
                for d in MEASUREMENT_DIRS:
                    self.assertFalse(any(s.strip("./") == d or s.strip("./").startswith(d + "/") for s in srcs), line)
                self.assertNotIn(".", srcs, f"전체 복사는 허용 목록을 우회함: {line}")

    def test_product_files_have_no_dataset_content(self):
        for top in ("logsight", "samples", "tests/fixtures", "app.py"):
            p = ROOT / top
            files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
            for f in files:
                text = f.read_text(encoding="utf-8", errors="ignore")
                for m in MARKERS:
                    self.assertNotIn(m, text, f"{f.relative_to(ROOT)}에 데이터셋 내용({m})이 있음")


if __name__ == "__main__":
    unittest.main()

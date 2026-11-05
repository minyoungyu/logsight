"""LogSight: 흩어진 AWS 로그를 하나의 공격 흐름으로 엮어 설명하고 방화벽 수정안을 제안한다."""
import sys

__version__ = "0.4.0"

if sys.version_info < (3, 10):  # Amazon Linux 2023 기본 python3는 3.9
    raise SystemExit(
        f"LogSight는 Python 3.10 이상이 필요합니다(현재 {sys.version.split()[0]}). "
        "Amazon Linux 2023: sudo dnf install -y python3.11 후 python3.11로 실행, "
        "Windows/macOS: python.org에서 3.12 설치.")

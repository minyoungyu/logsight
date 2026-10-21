"""
사이트 프로필 — 실제 사이트에 맞게 바꾸는 설정.

지금은 로컬 테스트 사이트를 가리키지만, 나중에 실제 사이트를 검사할 때는 이 파일(또는
profile.json) 하나만 바꾸면 된다. 코드에는 경로·IP를 박아 두지 않는다.

필드:
  name          사이트 이름(보고서 표시용)
  stack         "nginx+php" 등 설명 문자열(판단에는 쓰지 않음)
  webroot       웹 루트 경로(웹셸·파일 점검 대상). None이면 파일 점검 생략
  log_paths     {종류: [경로...]}  종류 = access | weberror | auth | sshauth
  trusted_ips   관리자/사내 IP(CIDR 가능) — 이 IP의 활동은 경보를 낮춘다
  admin_paths   관리자 로그인 경로 목록(예: /admin, /wp-login.php) — 무차별 대입 판단용
  login_paths   로그인 처리 경로(POST) — 로그인 성공/실패 판단용
  upload_dirs   업로드가 저장되는 URL 접두사(예: /uploads) — 업로드 뒤 실행 탐지용
  since/until   분석 시간 범위(ISO, 선택) — 큰 로그에서 사고 구간만 보고 싶을 때
  year          연도 없는 syslog 형식(auth.log)에 붙일 연도
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class SiteProfile:
    name: str = "웹서버"
    stack: str = ""
    webroot: str | None = None
    log_paths: dict[str, list[str]] = field(default_factory=dict)
    trusted_ips: list[str] = field(default_factory=list)
    admin_paths: list[str] = field(default_factory=lambda: [
        "/admin", "/administrator", "/wp-login.php", "/wp-admin",
        "/user/login", "/login", "/bbs/login.php", "/manager/html"])
    login_paths: list[str] = field(default_factory=list)
    upload_dirs: list[str] = field(default_factory=lambda: ["/uploads", "/upload", "/files", "/data"])
    sensitive_files: list[str] = field(default_factory=lambda: [
        ".env", "config.php", "wp-config.php", "database.yml", "settings.py",
        "id_rsa", ".git/config", "composer.json"])
    since: str | None = None
    until: str | None = None
    year: int = 2026

    @classmethod
    def load(cls, path: str | Path) -> "SiteProfile":
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)

    def resolved_logs(self) -> dict[str, list[Path]]:
        """존재하는 로그 파일만 글롭으로 펼쳐 돌려준다."""
        out: dict[str, list[Path]] = {}
        for kind, patterns in self.log_paths.items():
            files: list[Path] = []
            for pat in patterns:
                p = Path(pat)
                if any(ch in pat for ch in "*?["):
                    files += sorted(p.parent.glob(p.name))
                elif p.is_file():
                    files.append(p)
            if files:
                out[kind] = files
        return out

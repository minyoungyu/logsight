"""
LogSight 데모 웹앱 (FastAPI).
로그 파일을 올리면 형식 자동 판별 → 정규화 → 마스킹 → 탐지 → 사건 묶기 → 설정 점검 → 분석 → 보고서.
실행: uvicorn app:app --reload  →  http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import os
from html import escape
from pathlib import Path

from fastapi import FastAPI, File, Form, Request
from fastapi import UploadFile as FUploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.datastructures import UploadFile

from logsight import normalize
from logsight.normalize import PARSERS, load_uploads, parse_tz, parse_when
from logsight.pipeline import run, run_paths
from logsight.report import render
from logsight.web.webprofile import SiteProfile
from logsight.web.webpipeline import assess
from logsight.web.webreport import render as render_web

# 안전한 데모 모드: LOGSIGHT_DEMO=1 이면 로그 업로드를 받지 않고 샘플 보고서만 보여 준다.
# 공개 배포본은 이 모드로만 띄운다(외부 사용자가 올린 로그를 서버에 받지 않기 위함).
# 데모에서는 API 문서(/docs, /openapi.json)도 끈다(내부 경로·매개변수 구조를 주지 않기 위함).
DEMO = os.environ.get("LOGSIGHT_DEMO") == "1"
DEMO_MSG = "데모 모드에서는 파일 업로드를 받지 않습니다. 샘플 보고서를 확인하세요."
app = FastAPI(title="LogSight",
              docs_url=None if DEMO else "/docs",
              redoc_url=None if DEMO else "/redoc",
              openapi_url=None if DEMO else "/openapi.json")
ROOT = Path(__file__).parent / "samples"
WEB_SAMPLE = ROOT / "web" / "profile.json"
SAMPLES = {
    "demo": ("AWS 로그 4종(CloudTrail, VPC Flow, ALB, SSH)", ROOT / "demo"),
    "free": ("무료 대안 로그만(서버 방화벽, nginx)", ROOT / "free"),
    "combined": ("8종을 한곳에(GuardDuty, WAF 포함)", ROOT / "combined"),
}
MAX_UPLOAD_MB = int(os.environ.get("LOGSIGHT_MAX_UPLOAD_MB", "200"))
KINDS_KO = "CloudTrail, VPC Flow Logs, AWS WAF, ALB, GuardDuty, SSH auth.log, 서버 방화벽(kern.log), nginx/apache"

CONSOLE_CSS = """:root{--bg:#0e1013;--p1:#15181c;--p2:#1b1f24;--ln:#2a2f36;--fg:#d7dbe0;--sub:#8b939d;--dim:#79818c;
--red:#ff5a4e;--amb:#e6a23c;--grn:#3fb97a;--cy:#5fb3d9;
--sans:"IBM Plex Sans KR","Pretendard","Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif;
--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:13.5px/1.6 var(--sans)}
a{color:var(--cy)}.m{font-family:var(--mono)}.sub{color:var(--sub)}.dim{color:var(--dim)}
.bar{display:flex;align-items:center;gap:22px;min-height:40px;padding:0 16px;border-bottom:1px solid var(--ln);
background:var(--p1);font-size:12px;color:var(--sub);flex-wrap:wrap}
.bar .logo{color:var(--fg);font-weight:700;letter-spacing:.04em;text-decoration:none}
.bar .logo i{display:inline-block;width:8px;height:8px;background:var(--red);margin-right:8px}
.bar b{color:var(--fg);font-weight:500}.bar .sp{flex:1}.bar a{color:var(--sub);text-decoration:none}.bar a:hover{color:var(--fg)}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 380px;min-height:calc(100vh - 40px)}
@media (max-width:900px){.grid{grid-template-columns:1fr}}
.pane{border-right:1px solid var(--ln)}.pane:last-child{border-right:0}
.sh{display:flex;justify-content:space-between;padding:8px 16px;font-size:11px;color:var(--dim);letter-spacing:.06em;
background:var(--p1);border-bottom:1px solid var(--ln)}
.hero{padding:22px 16px 18px;border-bottom:1px solid var(--ln)}
.hero h1{font-size:20px;font-weight:600;margin:0 0 6px;letter-spacing:-.01em}.hero p{margin:0;color:var(--sub);max-width:640px}
.pipe{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid var(--ln)}
.pipe div{padding:10px 16px;border-left:1px solid var(--ln);font-size:12.5px;color:var(--sub)}.pipe div:first-child{border-left:0}
.pipe b{display:block;font-family:var(--mono);font-size:11px;color:var(--fg);font-weight:500}
form{padding:16px}
.drop{display:block;border:1px dashed var(--dim);padding:18px;background:var(--p1);cursor:pointer}
.drop:hover{border-color:var(--cy)}.drop b{font-weight:600}.drop input{display:block;margin-top:10px;color:var(--sub);max-width:100%}
label{display:block;margin:10px 0;font-size:13px}
input,select{font:inherit;font-size:13px;padding:4px 8px;border:1px solid var(--ln);background:var(--bg);color:var(--fg);max-width:100%}
input[type=checkbox]{padding:0;accent-color:var(--red)}
details{margin-top:12px;border-top:1px solid var(--ln);padding-top:8px}summary{cursor:pointer;color:var(--sub);font-size:12.5px}
.row{display:flex;gap:14px;flex-wrap:wrap}
button{margin-top:14px;padding:9px 20px;font:600 13px var(--mono);letter-spacing:.04em;border:1px solid var(--red);
background:var(--red);color:#111;cursor:pointer}button:hover{background:transparent;color:var(--red)}
.list a{display:grid;grid-template-columns:4px 1fr;border-bottom:1px solid var(--ln);text-decoration:none;color:var(--fg)}
.list a:hover{background:var(--p2)}.list a>i{background:var(--dim)}.list a:hover>i{background:var(--red)}
.list a>div{padding:10px 14px}.list .k{font-family:var(--mono);font-size:12px;display:flex;justify-content:space-between}
.list .k span{color:var(--dim)}.list small{display:block;color:var(--sub);font-size:12px}
.note{padding:10px 16px;font-size:12px;color:var(--dim);border-bottom:1px solid var(--ln)}
.demo{padding:12px 16px;color:var(--amb);border-bottom:1px solid var(--ln);font-size:13px}
"""
CONSOLE_BAR = ("<div class=bar><a class=logo href='/'><i></i>LOGSIGHT</a><span>AWS 침해사고 초동 분석</span>"
               "<span class=sp></span><a href='/'>로그 분석</a><a href='/web'>웹서버 점검</a><a href='/compare'>규칙 vs Claude</a>"
               "{docs}</div>")

PAGE = """<!doctype html><html lang=ko><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>LogSight</title>
<style>{css}</style>{bar}
<div class=grid><div class=pane>
<div class=hero><h1>로그를 올리면, 무슨 일이 있었고 무엇을 고칠지 알려 드립니다</h1>
<p>AWS·서버 로그를 하나의 공격 흐름으로 엮어 한국어로 설명하고, 원인이 된 방화벽·권한 설정과 고치는 명령을 제안합니다.
수정안은 자동으로 적용되지 않습니다.</p></div>
<div class=pipe><div><b>01 올리기</b>로그 파일을 폴더째 고르기</div><div><b>02 엮기</b>8종 로그를 사건 단위로 묶기</div>
<div><b>03 설명</b>판정·공격 흐름·알 수 없는 것</div><div><b>04 고치기</b>수정·되돌리기 명령(사람이 적용)</div></div>
<div class=sh><span>새 분석</span><span>올린 파일은 저장하지 않음</span></div>
<form action=/analyze method=post enctype=multipart/form-data>
<label class=drop><b>로그 파일 고르기</b><div class='sub' style='font-size:12.5px'>여러 개를 한꺼번에 고르면 종류를 자동으로 알아봅니다: {kinds}. .gz도 됩니다.<br>
environment.json(설정 스냅샷)을 같이 올리면 원인 설정과 수정 명령, 정상 작업 목록까지 씁니다.</div>
<input type=file name=logs multiple required></label>
<details><summary>옵션: 시간대·기간·AI <span class=dim>(모르면 그대로 두세요)</span></summary>
<label>auth.log·kern.log의 시간대 <select name=syslog_tz>
<option value="UTC">UTC(AWS 서버 기본)</option><option value="+09:00">한국 시간(+09:00)</option></select></label>
<label>연도가 없는 줄의 연도 <input name=year type=number min=2000 max=2100 placeholder="비우면 올해" style="width:9em"></label>
<div class=row><label>시작일 <input name=since type=date></label><label>종료일 <input name=until type=date></label></div>
<label><input type=checkbox name=no_ai value=1 {noai}> AI 없이 규칙 기반으로만(로그가 밖으로 나가지 않음)</label>
<div class='sub' style='font-size:12px'>{aikey}</div></details>
<button>분석 실행</button></form>
</div><div class=pane>
<div class=sh><span>샘플 보고서</span><span>AI 끔</span></div>
<div class=list>{samples}</div>
<div class=note>합성 데이터입니다. IP는 문서용 예약 대역만 씁니다.</div>
<div class=sh><span>설명 방식 비교</span><span>공방전 로그</span></div>
<div class=list><a href=/compare><i></i><div><div class=k>규칙 vs Claude<span>→</span></div><small>실제 클라우드 공방전 로그에서 같은 사건을 AI 없이, 정상 작업 목록을 넣고,
Claude로 판정한 결과를 나란히 봅니다(블루팀 보고서가 정답).</small></div></a></div>
</div></div></html>"""


def _page() -> str:
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    return (PAGE.replace("{css}", CONSOLE_CSS).replace("{bar}", _bar()).replace("{kinds}", escape(KINDS_KO))
            .replace("{noai}", "" if has_key else "checked")
            .replace("{aikey}", "Claude API 키가 설정되어 있습니다." if has_key else
                     "Claude API 키가 없어 규칙 기반 보고서를 만듭니다(서버에 ANTHROPIC_API_KEY 설정 시 AI 설명).")
            .replace("{samples}", "".join(f"<a href='/demo?sample={k}'><i></i><div><div class=k>{escape(k)}<span>→</span></div>"
                                          f"<small>{escape(v[0])}</small></div></a>" for k, v in SAMPLES.items())))


def _bar() -> str:
    return CONSOLE_BAR.replace("{docs}", "" if DEMO else "<a href='/docs'>API 문서</a>")


def _page_with_back(html: str) -> str:
    """보고서·비교 화면 위에 콘솔과 같은 상단 막대를 붙여 앱 안에서 연 것임을 보여 준다."""
    bar = (f"<style>.lsbar{{{BAR_CSS}}}.lsbar a{{color:#8b939d;text-decoration:none}}.lsbar a:hover{{color:#d7dbe0}}"
           ".lsbar b{color:#d7dbe0;letter-spacing:.04em}.lsbar i{display:inline-block;width:8px;height:8px;background:#ff5a4e;"
           "margin-right:8px}</style><div class=lsbar><a href='/'><b><i></i>LOGSIGHT</b></a>"
           "<a href='/'>← 다른 로그 분석하기</a></div>")
    i = html.find("</style>")
    return html[:i + 8] + bar + html[i + 8:] if i >= 0 else bar + html


BAR_CSS = ("display:flex;gap:22px;align-items:center;height:40px;padding:0 16px;background:#15181c;"
           "border-bottom:1px solid #2a2f36;font:12px/1 'IBM Plex Sans KR','Malgun Gothic',sans-serif")
COMPARE = ROOT.parent / "reports" / "ctf" / "compare_gongbang.html"


def _error(msg: str, code: int = 400) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><p>{escape(msg)}</p><p><a href=/>돌아가기</a></p>",
                        status_code=code)


class _Syslog:
    """요청마다 syslog 해석 설정(연도·시간대)을 바꾸고 끝나면 되돌린다(다른 요청에 새지 않게)."""
    def __init__(self, year=None, tz=None):
        self.new = {k: v for k, v in (("year", year), ("tz", tz)) if v is not None}

    def __enter__(self):
        self.saved = dict(normalize.SYSLOG)
        normalize.SYSLOG.update(self.new)

    def __exit__(self, *a):
        normalize.SYSLOG.clear()
        normalize.SYSLOG.update(self.saved)


@app.get("/healthz")
def healthz():
    """배포 플랫폼(Lightsail·App Runner 등)의 상태 확인용. 외부 의존성 없이 200만 돌려준다."""
    return {"status": "ok", "demo": DEMO}


@app.get("/", response_class=HTMLResponse)
def home():
    if DEMO:  # 업로드 칸을 숨기고 샘플만
        p = _page()
        return p[:p.index("<form")] + f"<div class=demo>{DEMO_MSG}</div>" + p[p.index("</form>") + 7:]
    return _page()


@app.get("/compare", response_class=HTMLResponse)
def compare():
    """규칙만 / 규칙+정상 작업 목록 / Claude 판정을 나란히 보는 발표용 화면(미리 만든 파일)."""
    if not COMPARE.is_file():
        return _error("비교 화면 파일이 없습니다. scripts/compare_modes.py로 만드세요.", 404)
    return _page_with_back(COMPARE.read_text(encoding="utf-8"))


@app.get("/demo", response_class=HTMLResponse)
def demo(sample: str = "demo"):
    if sample not in SAMPLES:
        return _error("없는 샘플입니다.", 404)
    label, path = SAMPLES[sample]
    with _Syslog(year=2026):  # 샘플은 2026년 기준 합성 데이터. 보는 사람이 돈을 쓰지 않게 AI는 끈다
        res = run_paths([str(path)], use_ai=False)
    return _page_with_back(render(res, f"LogSight 샘플 분석: {label}"))


@app.post("/analyze", response_class=HTMLResponse)
async def do_analyze(request: Request):
    if DEMO:
        return HTMLResponse(DEMO_MSG, status_code=403)
    form = await request.form()
    try:
        return await _analyze(form)
    finally:
        await form.close()  # 업로드 임시 파일 정리


async def _analyze(form) -> HTMLResponse:
    try:
        tz = parse_tz(str(form.get("syslog_tz") or "UTC"))
        year = int(form["year"]) if form.get("year") else None
        since = parse_when(str(form.get("since") or "") or None)
        until = parse_when(str(form.get("until") or "") or None, end=True)
    except ValueError:
        return _error("옵션 형식이 올바르지 않습니다(시간대 +09:00, 날짜 2026-10-01).")

    files: list[tuple[str, str, bytes]] = []  # (종류 또는 auto, 파일명, 내용)
    env: dict = {}
    total = 0
    # 'logs' 한 칸에 여러 파일을 받는다. 예전 방식(cloudtrail, vpcflow 등 종류별 칸)도 받는다
    for field, up in form.multi_items():
        if not isinstance(up, UploadFile):
            continue
        data = await up.read()
        if not data:
            continue
        total += len(data)
        if total > MAX_UPLOAD_MB * 1024 * 1024:
            return _error(f"올린 파일이 {MAX_UPLOAD_MB}MB를 넘습니다. 기간을 나눠 올리거나 명령줄 도구를 쓰세요.", 413)
        name = up.filename or field
        if field == "environment" or Path(name).name.lower() == "environment.json":
            try:
                env = json.loads(data.decode("utf-8-sig"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return _error("environment.json 형식이 올바르지 않습니다.")
            continue
        files.append((field if field in PARSERS else "auto", name, data))
    if not files:
        return _error("로그 파일을 하나 이상 올려 주세요.")

    with _Syslog(year=year, tz=tz):
        events, stats = [], []
        for kind, name, data in files:
            evs, st = load_uploads({kind: (name, data)})
            events += evs
            stats += st
        if since or until:
            events = [e for e in events if (not since or e.ts >= since) and (not until or e.ts <= until)]
        if not events:
            bad = [s["file"] for s in stats if not s.get("kind")]
            return _error("읽을 수 있는 로그가 없습니다."
                          + (f" 형식을 알 수 없는 파일: {', '.join(bad)}" if bad else " 기간을 확인하세요."))
        res = run(events, env, file_stats=stats, use_ai=not form.get("no_ai"))
    return _page_with_back(render(res))


@app.get("/api/demo")
def api_demo(sample: str = "demo"):
    if sample not in SAMPLES:
        return JSONResponse({"error": "unknown sample"}, status_code=404)
    with _Syslog(year=2026):
        return JSONResponse(run_paths([str(SAMPLES[sample][1])], use_ai=False))


# --------------------------------------------------------------- 웹서버 침해 점검
# 미래의 일반 사용자용 UI가 그대로 붙을 수 있게, 백엔드는 assess() 하나만 부른다.
WEB_PAGE = """<!doctype html><html lang=ko><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>LogSight 웹서버 점검</title>
<style>{css}</style>{bar}
<div class=grid><div class=pane>
<div class=hero><h1>웹서버, 이미 뚫렸나요?</h1>
<p>서버에 쌓인 로그를 올리면 공격 흔적과 침입 흐름을 분석해 판정합니다.
비워 둔 칸은 건너뜁니다. .gz 파일도 됩니다. 로그는 분석에만 쓰고 저장하지 않습니다.</p></div>
<div class=sh><span>새 점검</span><span>올린 파일은 저장하지 않음</span></div>
<form action=/web/scan method=post enctype=multipart/form-data>
<label>접속 로그 (nginx/Apache access.log) <input type=file name=access multiple></label>
<label>오류 로그 (error.log) <input type=file name=weberror multiple></label>
<label>인증 로그 (auth.log / secure) <input type=file name=auth multiple></label>
<button>점검</button></form>
</div><div class=pane>
<div class=sh><span>샘플</span><span>AI 끔</span></div>
<div class=list><a href=/web/demo><i></i><div><div class=k>web demo<span>→</span></div><small>샘플 웹서버 로그로 바로 보기</small></div></a></div>
</div></div></html>"""


def _web_page() -> str:
    return WEB_PAGE.replace("{css}", CONSOLE_CSS).replace("{bar}", _bar())


@app.get("/web", response_class=HTMLResponse)
def web_home():
    if DEMO:
        return _web_page().replace("<form action=/web/scan", "<form action=/web/scan hidden").replace(
            "<button>점검</button>", "<p>" + DEMO_MSG + "</p>").replace(
            "<div class=sh><span>새 점검</span>", f"<div class=demo>{DEMO_MSG}</div><div class=sh hidden><span>새 점검</span>")
    return _web_page()


@app.get("/web/demo", response_class=HTMLResponse)
def web_demo():
    return _page_with_back(render_web(assess(SiteProfile.load(WEB_SAMPLE), use_ai=False)))


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
    access: list[FUploadFile] | None = File(None),
    weberror: list[FUploadFile] | None = File(None),
    auth: list[FUploadFile] | None = File(None),
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
        return _page_with_back(render_web(assess(profile, use_ai=not no_ai)))


@app.post("/api/web/scan")
async def api_web_scan(
    access: list[FUploadFile] | None = File(None),
    weberror: list[FUploadFile] | None = File(None),
    auth: list[FUploadFile] | None = File(None),
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

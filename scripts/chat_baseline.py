"""'그냥 채팅 AI'로 공방전 사건 풀기(채팅 AI 기준선)를 스크립트로 재현하고 채점한다.

docs/채팅AI_기준선_실험.md(2026-11-03)는 사람이 대화를 손으로 주고받아 대화 기록이 남지 않았다.
이 스크립트는 같은 조건을 기계로 다시 만들고, 대화 전문·사용자 쪽 실행 명령·채점을 모두 파일로 남긴다.

조건
- 채팅 AI: 도구 없는 새 Claude 대화(시스템 프롬프트 없음). 사용자가 붙여 준 글만 읽는다.
- 사용자: 다른 Claude가 '보안을 모르는 백엔드 개발자' 역할을 맡는다. 가명 로그 3개
  (cloudtrail.json, waf.jsonl, alb.log)에 읽기 전용 셸 명령만 돌릴 수 있다. 채팅 AI가 시킨 것만
  뽑아 주고, 로그에 없는 것은 '확인 못 함'으로 답한다. 해석이나 보안 판단을 덧붙이지 않는다.
- 사용자가 아는 사실(원래 실험과 같음): blue-team-1·2는 팀원 계정이고 대응 작업도 팀원이 했다,
  PatchSignal은 원래 있던 서비스다, 이 계정은 공방전 환경이다. 물어보면 답한다.
- 주고받기 3번: 첫 질문 → AI 답 → 결과 1 → AI 답 → 결과 2 → AI 답 → 결과 3 + '최종 보고서를 써 달라'
  → AI 최종 보고서. 채점은 최종 보고서만 본다.
- 채점: 다른 Claude가 정답지 단계(G1~G6)마다 '잡음/놓침'과 보고서에서 그대로 옮긴 인용을 낸다.
  '가능성'으로만 언급한 것은 놓침이다(원래 실험의 기준). 인용이 보고서에 실제로 있는지 스크립트가 확인한다.

    ANTHROPIC_API_KEY=... python scripts/chat_baseline.py --data data/gongbang \\
        --out reports/remeasure_2026-11-26/chat_baseline/run1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

MODEL = os.environ.get("LOGSIGHT_CHAT_BASELINE_MODEL", "claude-opus-5-5")
FIRST_MESSAGE = ("오늘 13:30 이후에 우리 AWS 계정이 공격받았을 수 있다는 연락을 받았어요. "
                 "저는 백엔드 개발자라 보안은 잘 모릅니다. 무슨 일이 있었는지, 뭘 고쳐야 하는지 알려 주세요. "
                 "로그는 제가 뽑아 드릴 수 있어요.")
FINAL_REQUEST = "\n\n이제 더 뽑아 드리기는 어려워요. 지금까지 본 것으로 최종 보고서를 써 주세요(무슨 일이 있었는지, 뭘 고쳐야 하는지)."
EXCHANGES = 3
OUT_LIMIT = 12000  # 명령 하나의 결과를 붙일 때 최대 글자 수(채팅창에 붙이는 분량)

USER_SYSTEM = """너는 작은 회사의 백엔드 개발자다. 보안은 잘 모른다. 회사 AWS 계정이 공격받았을 수 있다는 연락을 받고
채팅 AI에게 도움을 청하는 중이다. 채팅 AI가 로그를 보여 달라거나 명령을 실행해 달라고 하면 run 도구로 뽑아서 붙여 준다.

네가 가진 것은 내려받아 둔 로그 파일 3개뿐이다(현재 디렉터리, 시각은 UTC, 한국 시간은 +9시간).
- cloudtrail.json: CloudTrail 기록 {"Records":[...]} (ap-northeast-2, KST 13:30~16:25 무렵)
- waf.jsonl: WAF 로그(한 줄에 하나)
- alb.log: ALB 접근 로그
AWS 콘솔·CLI에는 지금 접속할 수 없다. 그래서 AI가 aws CLI 명령을 주면 같은 내용을 이 파일에서 jq·grep·python3 등으로
뽑는다. AI가 jq 같은 명령을 주면 그대로 실행한다. 위 파일에 없는 것(인스턴스·IAM·보안그룹 설정, 다른 리전,
GuardDuty 탐지 결과, 비용, VPC Flow Logs, 애플리케이션 로그 등)은 '확인 못 함(그 로그는 없어요)'이라고 답한다.

결과를 보내는 방법
- run 도구의 send=true로 실행한 명령은 명령과 결과가 네 답장 뒤에 원문 그대로 자동으로 붙는다. 결과를 네가 다시 옮겨 적지 마라.
- 파일 구조를 살피는 등 AI에게 보내지 않을 확인용 실행은 send=false로 한다.
- 답장 본문에는 짧은 설명만 쓴다: AI의 질문에 대한 답, 어떤 요청을 어떻게 바꿔 뽑았는지, 뽑을 수 없는 것.

지켜야 할 것
- 이번 메시지에서 요청받은 것은 이번 답장에 모두 보낸다. '다음 메시지로 보내겠다'고 미루지 않는다.
- 어떤 로그 파일이 있는지는 AI가 물을 때만 답한다. 묻지 않은 로그를 먼저 권하거나 소개하지 않는다.
- AI가 요청한 것만 뽑는다. 요청하지 않은 로그나 다른 파일 내용을 스스로 찾아 붙이지 않는다.
- 결과는 고치지 말고 그대로 붙인다. 해석, 보안 판단, 추측을 덧붙이지 않는다(너는 보안을 모른다).
- 결과가 아주 길면 스크립트가 앞 12,000자만 붙인다. 필요하면 head 등으로 줄여 실행해도 된다.
- AI가 질문하면 아래 사실 안에서만 답하고, 모르면 모른다고 한다.
  * blue-team-1, blue-team-2는 우리 팀원 계정이다. 사고 뒤 대응 작업(조회, 설정 변경)도 팀원이 했다.
  * PatchSignal은 원래 있던 우리 서비스다.
  * 이 계정은 보안 공방전(연습) 환경이다.
- 마지막 답에는 채팅 AI에게 보낼 메시지 본문만 쓴다."""

JUDGE_SYSTEM = """너는 보안 사고 보고서 채점자다. 정답지의 공격 단계마다, 아래 '최종 보고서'가 그 단계를 잡았는지 판단한다.
- 잡음(caught=true): 보고서가 그 단계를 일어난 일로 적었고, 무엇이 언제·어디서 일어났는지 로그 근거(경로, IP, API 이름, 횟수, 시각 중 하나 이상)가 정답과 맞는다.
- 놓침(caught=false): 언급이 없거나, '가능성', '~일 수 있다', '확인 필요'처럼 추측으로만 적었거나, 내용이 정답과 다르다.
- quote에는 판단 근거가 된 보고서 문장을 한 글자도 바꾸지 말고 그대로 옮긴다(놓침이고 관련 문장이 없으면 빈 문자열).
정답지 밖의 내용은 채점하지 않는다. reason은 한국어로 쓴다."""

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {"stages": {"type": "array", "items": {
        "type": "object",
        "properties": {"id": {"type": "string"}, "caught": {"type": "boolean"},
                       "quote": {"type": "string"}, "reason": {"type": "string"}},
        "required": ["id", "caught", "quote", "reason"], "additionalProperties": False}}},
    "required": ["stages"], "additionalProperties": False,
}

RUN_TOOL = {
    "name": "run",
    "description": ("로그 파일이 있는 디렉터리에서 셸 명령을 실행하고 표준 출력·오류를 돌려준다(읽기 전용, 60초 제한). "
                    "send=true면 명령과 결과가 채팅 AI에게 보내는 답장 뒤에 원문 그대로 붙는다."),
    "input_schema": {"type": "object", "properties": {"command": {"type": "string"},
                                                     "send": {"type": "boolean"}},
                     "required": ["command", "send"]},
}

# 정답지 단계 설명(채점자에게 주는 것). 값은 reports/ctf/gongbang_ground_truth.json의 가명이다.
STAGE_DETAIL = {
    "G1": "WAF 로그: 공격자 IP 198.18.7.1(·198.18.7.2)이 웹앱 POST /api/subscriptions 로 내부 주소(메타데이터) 조회를 시도했고 WAF가 막았다(KST 14:10~).",
    "G2": "WAF 로그: 공격자 IP가 서명 없는 토큰으로 EKS 지원 API(/api/support/...)에 접근했다.",
    "G3": "ALB 로그: 공격자 IP가 PageSnap 결과 PDF를 /download 로 내려받았다(KST 14:52~14:54, 성공 응답).",
    "G4": "CloudTrail: EC2(portal) 인스턴스 역할 임시 키 ASIA71C21DC25EA495CF가 외부 IP(198.18.50.1, 198.18.7.1)에서 쓰였다.",
    "G5": "CloudTrail: 그 키로 states:StartExecution(워크플로 실행)이 성공했다(KST 15:36~16:08).",
    "G6": "CloudTrail: 그 키로 SSM(SendCommand·StartSession) 원격 명령·세션을 시도했고 거부(AccessDenied)됐다.",
}


def _safe_env(home: str) -> dict:
    # 모델이 만든 명령이 키를 읽지 못하게 환경 변수를 비운다
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def run_command(cmd: str, workdir: str) -> str:
    try:
        p = subprocess.run(["bash", "-c", cmd], cwd=workdir, env=_safe_env(workdir),
                           capture_output=True, text=True, timeout=60)
        out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        out = "[60초 안에 끝나지 않아 멈춤]"
    if len(out) > OUT_LIMIT:
        out = out[:OUT_LIMIT] + f"\n[... 출력 {len(out):,}자 중 앞 {OUT_LIMIT:,}자만]"
    return out


def _create(client, **kw):
    """긴 생각으로 출력 한도를 다 써서 빈 답이 오지 않게 한도를 넉넉히 두고 스트리밍으로 받는다.
    한도에서 잘리거나 빈 답이면 실험을 멈춘다(빈 답을 그대로 대화에 넣지 않는다)."""
    with client.messages.stream(max_tokens=64000, **kw) as st:
        resp = st.get_final_message()
    if resp.stop_reason == "refusal":
        raise RuntimeError("모델이 응답을 거절함")
    if resp.stop_reason == "max_tokens":
        raise RuntimeError("출력이 max_tokens에서 잘림")
    if resp.stop_reason != "tool_use" and not _text(resp).strip():
        raise RuntimeError(f"빈 답(stop_reason={resp.stop_reason})")
    return resp


def _text(resp) -> str:
    return "".join(b.text for b in resp.content if b.type == "text")


def _usage(acc: dict, resp) -> None:
    acc["input_tokens"] += resp.usage.input_tokens
    acc["output_tokens"] += resp.usage.output_tokens
    acc.setdefault("served_by", set()).add(resp.model)


def chat_ai_turn(client, history: list[dict], usage: dict) -> str:
    resp = _create(client, model=MODEL, messages=history)
    _usage(usage, resp)
    return _text(resp)


def user_turn(client, ai_message: str, convo_for_user: list[dict], workdir: str,
              usage: dict, log: list[dict], final: bool) -> str:
    """사용자 역할: 채팅 AI의 메시지를 읽고 도구로 로그를 뽑아 답장을 만든다."""
    convo_for_user.append({"role": "user", "content":
                           "채팅 AI가 보낸 메시지:\n\n" + ai_message +
                           "\n\n요청한 것을 run 도구로 뽑고, 채팅 AI에게 보낼 답장을 써라."})
    for _ in range(25):
        resp = _create(client, model=MODEL, system=USER_SYSTEM,
                                      tools=[RUN_TOOL], messages=convo_for_user)
        _usage(usage, resp)
        convo_for_user.append({"role": "assistant", "content": [b.model_dump() for b in resp.content]})
        calls = [b for b in resp.content if b.type == "tool_use"]
        if not calls:
            break
        results = []
        for c in calls:
            out = run_command(c.input["command"], workdir)
            send = bool(c.input.get("send"))
            log.append({"command": c.input["command"], "send": send,
                        "output_chars": len(out), "output": out})
            results.append({"type": "tool_result", "tool_use_id": c.id, "content": out})
        convo_for_user.append({"role": "user", "content": results})
    reply = _text(resp).strip()
    # 결과는 모델이 옮겨 적지 않고 스크립트가 원문 그대로 붙인다(옮겨 적다 잘리거나 바뀌지 않게)
    for x in log:
        if x["send"]:
            reply += f"\n\n실행한 명령:\n```\n{x['command']}\n```\n결과:\n```\n{x['output'].rstrip()}\n```"
    return reply + (FINAL_REQUEST if final else "")


def judge(client, report: str, usage: dict) -> list[dict]:
    stages = "\n".join(f"- {k}: {v}" for k, v in STAGE_DETAIL.items())
    resp = _create(
        client, model=MODEL, system=JUDGE_SYSTEM,
        messages=[{"role": "user", "content": f"정답지 단계:\n{stages}\n\n최종 보고서:\n\n{report}"}],
        output_config={"format": {"type": "json_schema", "schema": JUDGE_SCHEMA}},
    )
    _usage(usage, resp)
    rows = json.loads(_text(resp))["stages"]
    norm = lambda s: " ".join(s.split())  # noqa: E731
    for r in rows:
        r["quote_found_in_report"] = (not r["quote"]) or norm(r["quote"]) in norm(report)
    return rows


def run_once(data: Path, out: Path) -> dict:
    import anthropic

    client = anthropic.Anthropic()
    out.mkdir(parents=True, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="chatbase_")
    for name in ("cloudtrail.json", "waf.jsonl", "alb.log"):
        shutil.copy(data / name, workdir)
        os.chmod(Path(workdir) / name, 0o444)
    usage = {"chat_ai": {"input_tokens": 0, "output_tokens": 0},
             "user_role": {"input_tokens": 0, "output_tokens": 0},
             "judge": {"input_tokens": 0, "output_tokens": 0}}
    t0 = time.time()
    history = [{"role": "user", "content": FIRST_MESSAGE}]
    user_ctx: list[dict] = []
    commands: list[list[dict]] = []
    for i in range(EXCHANGES):
        ai = chat_ai_turn(client, history, usage["chat_ai"])
        history.append({"role": "assistant", "content": ai})
        log: list[dict] = []
        reply = user_turn(client, ai, user_ctx, workdir, usage["user_role"], log,
                          final=(i == EXCHANGES - 1))
        commands.append(log)
        history.append({"role": "user", "content": reply})
    report = chat_ai_turn(client, history, usage["chat_ai"])
    history.append({"role": "assistant", "content": report})
    stages = judge(client, report, usage["judge"])
    shutil.rmtree(workdir, ignore_errors=True)
    for u in usage.values():
        u["served_by"] = sorted(u.get("served_by", []))

    caught = sum(r["caught"] for r in stages)
    result = {
        "model": MODEL, "exchanges": EXCHANGES, "seconds": round(time.time() - t0, 1),
        "score": f"{caught}/{len(stages)}", "caught": caught, "n_stages": len(stages),
        "quotes_all_found": all(r["quote_found_in_report"] for r in stages),
        "stages": stages, "usage": usage,
        "n_user_commands": sum(len(c) for c in commands),
        "n_user_commands_sent": sum(1 for c in commands for x in c if x["send"]),
        "sources_sent": sorted({f for c in commands for x in c if x["send"]
                                for f in ("cloudtrail.json", "waf.jsonl", "alb.log")
                                if f in x["command"]}),
    }
    (out / "transcript.json").write_text(mask_keys(json.dumps(
        {"chat": history, "user_role_commands": commands}, ensure_ascii=False, indent=1)), encoding="utf-8")
    md = []
    for m in history:
        who = "사용자" if m["role"] == "user" else "채팅 AI"
        md.append(f"## {who}\n\n{m['content']}\n")
    (out / "transcript.md").write_text(mask_keys("\n".join(md)), encoding="utf-8")
    (out / "score.json").write_text(mask_keys(json.dumps(result, ensure_ascii=False, indent=1)), encoding="utf-8")
    return result


KEY_RE = re.compile(r"\b((?:ASIA|AKIA)[0-9A-Z]{4})[0-9A-Z]{8}([0-9A-Z]{4})\b")


def mask_keys(text: str) -> str:
    """가명 액세스 키도 앞 8자·뒤 4자만 남긴다(LogFinder 화면과 같은 모양, 비밀값 검사 통과)."""
    return KEY_RE.sub(r"\1…\2", text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/gongbang")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY가 없다")
    r = run_once(Path(a.data), Path(a.out))
    print(json.dumps({k: r[k] for k in ("score", "quotes_all_found", "n_user_commands_sent",
                                         "sources_sent", "seconds")}, ensure_ascii=False))


if __name__ == "__main__":
    main()

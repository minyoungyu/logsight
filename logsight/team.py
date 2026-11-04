"""
우리 팀 알아보기: 로그에서 '우리 팀 사람으로 보이는 계정'을 찾아 제안하고, 사람이 한 번 확인하면 정상 작업 목록이 된다.

왜: 작은 팀의 가장 흔한 오탐은 자기 팀의 작업이다(공방전에서 1위 사건이 블루팀의 조회 작업이었다).
GuardDuty나 채팅 AI는 누가 우리 팀인지 모른다. LogSight는 로그만 보고 후보를 고르고, 확인은 사람에게 받는다.

후보 조건(모두 만족):
  1. 사람 계정: IAM 사용자 또는 SSO 역할(AWSReservedSSO_). 루트·EC2 역할·서비스 역할은 제외
  2. 콘솔로 직접 작업한 흔적: 콘솔 로그인, CloudShell, 또는 IAM 사용자의 임시 키(ASIA, 콘솔 세션)
  3. 로그 기간 대부분에 걸쳐 활동했거나, 설정 스냅샷의 기존 IAM 사용자
  4. 키 유출에서 흔한 모습(인스턴스 키 외부 사용, 거부 폭주, 허용 밖 IP)이 그 계정에 없음

자동으로 정상 처리하지 않는다. 비밀번호를 훔친 공격자도 콘솔로 들어오므로, 확인 없이 넣으면 공격을 숨길 수 있다.
확인된 목록은 environment.json의 known_activity 형식으로 저장한다(analyze --env, --team).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .explain import KEY_MISUSE_RULES

SUSPECT_RULES = KEY_MISUSE_RULES | {"CT_UNTRUSTED_IP"}
CONSOLE_ACTIONS = {"signin:ConsoleLogin", "signin:GetSigninToken"}
LABEL = "우리 팀(확인됨)"


def _short(actor: str) -> str:
    return actor.rsplit("/", 1)[-1]


def _human(actor: str | None) -> bool:
    if not actor or not actor.startswith("arn:"):
        return False
    if ":user/" in actor:
        return True
    return ":assumed-role/AWSReservedSSO_" in actor


def _env_users(env: dict) -> set[str]:
    out = set()
    for u in (env.get("iam") or {}).get("users", []) or env.get("iam_users", []) or []:
        name = u.get("UserName") or u.get("name") if isinstance(u, dict) else u
        if name:
            out.add(str(name).lower())
    return out


def propose(events: list, env: dict | None = None, *, min_span: float = 0.5) -> list[dict]:
    """우리 팀 후보 목록. 각 항목: actor, name, reasons, n_events, n_ips, first, last."""
    env = env or {}
    ct = [e for e in events if e.source == "cloudtrail"]
    if not ct:
        return []
    t0, t1 = min(e.ts for e in ct), max(e.ts for e in ct)
    total = max((t1 - t0).total_seconds(), 1.0)
    known_users = _env_users(env)
    st: dict[str, dict] = defaultdict(lambda: {"n": 0, "ips": set(), "first": None, "last": None,
                                                "console": 0, "cloudshell": 0, "session_key": 0, "suspect": set()})
    for e in ct:
        if not _human(e.actor):
            continue
        s = st[e.actor]
        s["n"] += 1
        if e.src_ip:
            s["ips"].add(e.src_ip)
        s["first"] = e.ts if s["first"] is None or e.ts < s["first"] else s["first"]
        s["last"] = e.ts if s["last"] is None or e.ts > s["last"] else s["last"]
        if e.action in CONSOLE_ACTIONS and e.status == "success":
            s["console"] += 1
        if (e.action or "").startswith("cloudshell:"):
            s["cloudshell"] += 1
        if ":user/" in e.actor and (e.access_key or "").startswith("ASIA"):
            s["session_key"] += 1
        s["suspect"].update(r for r in e.findings if r in SUSPECT_RULES)
    out = []
    for actor, s in st.items():
        name = _short(actor)
        interactive = []
        if s["console"]:
            interactive.append(f"콘솔 로그인 {s['console']}회")
        if s["cloudshell"]:
            interactive.append(f"CloudShell 사용 {s['cloudshell']}건")
        if s["session_key"] and not s["console"]:
            interactive.append("콘솔 세션 임시 키 사용")
        span = (s["last"] - s["first"]).total_seconds() / total
        presence = []
        if span >= min_span:
            presence.append(f"로그 기간의 {round(span * 100)}% 동안 활동")
        if name.lower() in known_users:
            presence.append("설정 스냅샷의 기존 IAM 사용자")
        if not interactive or not presence:
            continue
        if s["suspect"]:
            continue  # 키 유출에서 흔한 모습이 있으면 후보에서 뺀다(공격자를 숨기지 않게)
        out.append({"actor": actor, "name": name, "reasons": interactive + presence,
                    "n_events": s["n"], "n_ips": len(s["ips"]),
                    "first": s["first"].isoformat(), "last": s["last"].isoformat()})
    return sorted(out, key=lambda x: -x["n_events"])


def excluded(events: list) -> list[dict]:
    """사람 계정이지만 수상한 모습 때문에 후보에서 뺀 것(보고서에서 '왜 안 넣었나'를 보여 준다)."""
    bad: dict[str, set] = defaultdict(set)
    for e in events:
        if e.source == "cloudtrail" and _human(e.actor):
            bad[e.actor].update(r for r in e.findings if r in SUSPECT_RULES)
    return [{"actor": a, "name": _short(a), "rules": sorted(r)} for a, r in bad.items() if r]


def to_env(names: list[str], label: str = LABEL) -> dict:
    """확인된 이름을 known_activity 형식으로. 이름은 정확히 일치(와일드카드 없음)."""
    return {"known_activity": [{"label": label, "actors": sorted(set(names)),
                                "confirmed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}]}


def merge(env: dict, team: dict) -> dict:
    """설정 스냅샷에 확인된 팀 목록을 더한다(원본은 바꾸지 않음)."""
    out = dict(env)
    out["known_activity"] = list(env.get("known_activity", [])) + list(team.get("known_activity", []))
    return out


def load(path: str | Path) -> dict:
    d = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    for ent in d.get("known_activity", []):
        if any(ch in "*?[" for a in ent.get("actors", []) for ch in a):
            raise ValueError("팀 목록에는 와일드카드를 쓰지 않는다(공격자 계정까지 덮을 수 있음)")
    return d

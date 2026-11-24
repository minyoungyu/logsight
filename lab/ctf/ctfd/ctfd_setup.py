#!/usr/bin/env python3
"""CTFd에 F1~F6 문제·플래그·힌트를 등록하고, 대회 뒤 남의 팀 플래그 제출을 찾는다.

  # 1) CTFd 관리자 화면 → Settings → Access Tokens 에서 토큰을 만든다
  # 2) 팀별 정답(저장소 밖에 보관)
  cd lab/ctf/terraform && terraform output -json flags > ~/ctf-flags.json
  # 3) 등록(같은 이름의 문제가 있으면 내용·점수·플래그·힌트를 다시 맞춘다)
  python lab/ctf/ctfd/ctfd_setup.py setup --url http://<CTFd IP> --token <토큰> --flags ~/ctf-flags.json
  #    먼저 보기만: --dry-run
  # 4) 대회 뒤: 다른 팀의 플래그를 낸 제출 찾기
  python lab/ctf/ctfd/ctfd_setup.py check-sharing --url ... --token ... --flags ~/ctf-flags.json

힌트 차감: CTFd 기본 동작으로 팀이 힌트를 열면 cost만큼 점수가 깎인다(점수가 0 아래로 갈 수 있다).
2단계 힌트는 1단계를 연 팀만 열 수 있게 걸어 둔다.

플래그는 팀마다 다르다. CTFd 문제 하나에 모든 팀의 플래그를 등록하므로, 다른 팀의 플래그를 내도
CTFd는 정답으로 받는다. 그래서 check-sharing으로 제출 팀과 플래그 주인을 대조한다.
CTFd 팀 이름은 t01, t02 … 처럼 terraform의 팀 키와 같게 만든다(다르면 --team-map 으로 대응).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


class CTFd:
    def __init__(self, url: str, token: str, dry: bool = False):
        self.base = url.rstrip("/") + "/api/v1"
        self.token = token
        self.dry = dry

    def call(self, method: str, path: str, body: dict | None = None):
        if self.dry and method != "GET":
            print(f"  [dry-run] {method} {path} {json.dumps(body, ensure_ascii=False)[:120] if body else ''}")
            return {"id": -1}
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Token {self.token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path} 실패: HTTP {e.code} {e.read()[:300]!r}")
        if isinstance(out, dict) and out.get("success") is False:
            raise SystemExit(f"{method} {path} 실패: {out}")
        return out.get("data") if isinstance(out, dict) and "data" in out else out

    def pages(self, path: str) -> list:
        items, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            req = urllib.request.Request(f"{self.base}{path}{sep}page={page}",
                                         headers={"Authorization": f"Token {self.token}",
                                                  "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read())
            items += out.get("data", [])
            nxt = (out.get("meta") or {}).get("pagination", {}).get("next")
            if not nxt:
                return items
            page = nxt


def team_flags(flags: dict, key: str) -> dict[str, str]:
    """{팀: 정답}. F5는 역할 이름이 정답이다."""
    return {t: str(v[key]) for t, v in flags.items() if v.get(key)}


def setup(api: CTFd, spec: dict, flags: dict) -> None:
    existing = {c["name"]: c for c in api.call("GET", "/challenges?view=admin") or []}
    for ch in spec["challenges"]:
        body = {"name": ch["name"], "category": ch["category"], "description": ch["description"],
                "value": ch["value"], "type": "standard", "state": "visible"}
        if ch["name"] in existing:
            cid = existing[ch["name"]]["id"]
            api.call("PATCH", f"/challenges/{cid}", body)
            # 다시 맞추기: 예전 플래그·힌트는 지우고 새로 넣는다
            for f in api.call("GET", f"/challenges/{cid}/flags") or []:
                api.call("DELETE", f"/flags/{f['id']}")
            for h in api.call("GET", f"/challenges/{cid}/hints") or []:
                api.call("DELETE", f"/hints/{h['id']}")
            print(f"[갱신] {ch['name']} (id {cid}, {ch['value']}점)")
        else:
            cid = api.call("POST", "/challenges", body)["id"]
            print(f"[추가] {ch['name']} (id {cid}, {ch['value']}점)")
        tf = team_flags(flags, ch["key"])
        if not tf:
            print(f"  경고: {ch['key']} 정답이 flags 파일에 없음")
        for content in sorted(set(tf.values())):
            api.call("POST", "/flags", {"challenge": cid, "challenge_id": cid, "content": content,
                                        "type": "static", "data": ""})
        prev = None
        for i, h in enumerate(ch.get("hints", []), 1):
            hb = {"challenge": cid, "challenge_id": cid, "content": h["content"], "cost": h["cost"],
                  "title": f"힌트 {i} (-{h['cost']}점)"}
            if prev:
                hb["requirements"] = {"prerequisites": [prev]}
            prev = api.call("POST", "/hints", hb)["id"]
        print(f"  플래그 {len(set(tf.values()))}개 · 힌트 {len(ch.get('hints', []))}개 "
              f"(차감 {'/'.join(str(h['cost']) for h in ch.get('hints', []))})")


def check_sharing(api: CTFd, spec: dict, flags: dict, team_map: dict[str, str]) -> int:
    """정답 제출 중 플래그 주인 팀과 제출 팀이 다른 것을 출력한다. 찾은 건수를 돌려준다."""
    owner: dict[tuple[str, str], str] = {}
    for ch in spec["challenges"]:
        for t, v in team_flags(flags, ch["key"]).items():
            owner[(ch["name"], v)] = t
    names = {c["id"]: c["name"] for c in api.call("GET", "/challenges?view=admin") or []}
    teams = {t["id"]: t["name"] for t in api.pages("/teams")}
    n = 0
    for s in api.pages("/submissions?type=correct"):
        cname = names.get(s.get("challenge_id"))
        tname = teams.get(s.get("team_id"), str(s.get("team_id")))
        own = owner.get((cname, s.get("provided", "")))
        if own and team_map.get(tname, tname) != own:
            n += 1
            print(f"[공유 의심] {s.get('date')} 팀 {tname} → {cname} 에 {own} 팀의 플래그 제출")
    print(f"공유 의심 {n}건")
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CTFd 문제·힌트 등록, 플래그 공유 점검")
    ap.add_argument("cmd", choices=["setup", "check-sharing"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--flags", required=True, help="terraform output -json flags 결과 파일")
    ap.add_argument("--spec", default=str(HERE / "challenges.json"))
    ap.add_argument("--team-map", default="", help="CTFd팀=tNN,... (팀 이름이 t01 형식이 아닐 때)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    spec = json.loads(Path(a.spec).read_text(encoding="utf-8"))
    flags = json.loads(Path(a.flags).expanduser().read_text(encoding="utf-8"))
    api = CTFd(a.url, a.token, a.dry_run)
    if a.cmd == "setup":
        setup(api, spec, flags)
        return 0
    tm = dict(p.split("=", 1) for p in a.team_map.split(",") if "=" in p)
    return 1 if check_sharing(api, spec, flags, tm) else 0


if __name__ == "__main__":
    sys.exit(main())

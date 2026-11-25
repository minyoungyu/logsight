"""CAM-LDS(Landauer 외, 2026, CC BY 4.0) 시나리오 하나를 단계별로 잰다.
라벨: attacker/logs/attackmate.log의 'Executing ...' 줄(시각)과 바로 뒤 'Metadata'(ATT&CK 기법·전술).
단계 탐지: 피해 서버 로그(웹 접근 로그 + auth.log)에서 LogFinder가 표시한 이벤트가 그 단계 시작 5초 전 ~ 다음 단계 시작 30초 뒤 사이에 있으면 탐지.
오탐 후보: 첫 공격 단계보다 앞선 시각의 표시."""
import json, re, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from logsight.web.webdetect import run_web_detections
from logsight.web.webpipeline import load_events
from logsight.web.webprofile import SiteProfile

root = Path(sys.argv[1]); victim = sys.argv[2]; out = sys.argv[3]
_raw = (root / "attacker/logs/attackmate.log").read_text(errors="replace").splitlines()
log = []  # 여러 줄에 걸친 명령은 다음 시각 줄 전까지 한 줄로 붙인다
for l in _raw:
    if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", l) or not log:
        log.append(l)
    else:
        log[-1] += " " + l.strip()
steps = []
for i, l in enumerate(log):
    m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) INFO - Executing (.+?): '(.*)'\s*$", l)
    if not m or m.group(2) in ("a msf-command",):
        continue
    meta = {}
    if i + 1 < len(log) and "Metadata:" in log[i + 1]:
        try:
            meta = json.loads(log[i + 1].split("Metadata: ", 1)[1].replace('"technique_name:\\"', '"technique_name": "'))
        except Exception:
            meta = {"techniques": re.findall(r"T\d{4}(?:\.\d{3})?", log[i + 1])[0] if re.findall(r"T\d{4}", log[i + 1]) else ""}
    if not meta.get("techniques"):
        continue
    ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    steps.append({"ts": ts, "kind": m.group(2), "cmd": m.group(3)[:120], "tech": meta.get("techniques", ""),
                  "tactic": meta.get("tactics", "")})
logs = root / victim / "logs"
prof = SiteProfile(name=f"CAM-LDS {root.name}/{victim}",
                   log_paths={"access": [str(logs / "access.log*"), str(logs / "log/apache2/*access.log*")],
                              "weberror": [str(logs / "error.log*")],
                              "auth": [str(logs / "log/auth.log*")]},
                   own_hosts=["127.0.0.1", "localhost"], year=steps[0]["ts"].year if steps else 2025)
events, stats = load_events(prof)
fs = run_web_detections(events, prof)
flagged = sorted({(e.ts, f.rule) for f in fs for e in f.events if e.ts}, key=lambda x: x[0])
# 흔적이 남는 단계: 그 시간 창에 공격자 IP의 웹 요청이나 sudo·su·sshd 줄이 있다(흔적이 없는 단계는 이 로그로 잡을 수 없다)
atk_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", (root / "attacker/logs/attackmate.log").read_text(errors="replace")))
trace = sorted(e.ts for e in events if e.ts and ((e.src_ip in atk_ips) or e.source in ("auth", "sshauth")))
for j, s in enumerate(steps):
    end = steps[j + 1]["ts"] if j + 1 < len(steps) else s["ts"] + timedelta(minutes=5)
    lo, hi = s["ts"] - timedelta(seconds=2), max(end, s["ts"] + timedelta(seconds=10)) + timedelta(seconds=2)
    s["rules"] = sorted({r for t, r in flagged if lo <= t < hi})
    s["visible"] = any(lo <= t < hi for t in trace)
first = steps[0]["ts"] if steps else None
pre = [(t.isoformat(), r) for t, r in flagged if first and t < first - timedelta(seconds=5)]
res = {"scenario": root.name, "victim": victim, "n_events": len(events), "files": stats if isinstance(stats, (dict, list)) else str(stats),
       "steps": [{**s, "ts": s["ts"].isoformat()} for s in steps], "flag_before_attack": len(pre),
       "flag_before_attack_rules": sorted({r for _, r in pre})}
json.dump(res, open(out, "w"), ensure_ascii=False, indent=1, default=str)
det = sum(1 for s in steps if s["rules"]); vis = [s for s in steps if s["visible"]]
res["summary"] = {"steps": len(steps), "detected": det, "visible": len(vis), "visible_detected": sum(1 for s in vis if s["rules"])}
json.dump(res, open(out, "w"), ensure_ascii=False, indent=1, default=str)
print(f"{root.name}: events {len(events)}  steps {det}/{len(steps)} detected, visible {res['summary']['visible_detected']}/{len(vis)}  pre-attack flags {len(pre)} {res['flag_before_attack_rules']}")
for s in steps:
    print(("  탐지 " if s["rules"] else ("  놓침 " if s["visible"] else "  흔적없음 ")) + s["ts"].strftime("%H:%M:%S"), s["tactic"][:28].ljust(28), s["tech"][:22].ljust(22), s["cmd"][:60], s["rules"][:4])

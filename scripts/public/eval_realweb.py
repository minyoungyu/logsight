"""라벨 없는 실제 웹서버 로그(Zenodo 20001206): 무엇을 얼마나 표시하는지, 상위 IP와 예시 줄."""
import collections, json, sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from logsight.web.webdetect import run_web_detections
from logsight.web.webpipeline import load_events
from logsight.web.webprofile import SiteProfile
d = sys.argv[1]
p = SiteProfile(name="real", log_paths={"access": [d + "/apache2/*access.log*"], "weberror": [d + "/apache2/*error.log*"],
                                        "auth": [d + "/auth.log*"]}, own_hosts=["127.0.0.1", "localhost"], year=2025)
ev, st = load_events(p)
fs = run_web_detections(ev, p)
by_rule = collections.Counter(); ips = collections.defaultdict(set); ex = {}
flag_ev = set()
for f in fs:
    by_rule[f.rule] += len(f.events); ips[f.rule].add(f.key)
    for e in f.events:
        flag_ev.add(id(e))
    ex.setdefault(f.rule, [e.extra.get("raw", "")[:200] or (e.action or "")[:200] for e in f.events[:2]])
src = collections.Counter(e.source for e in ev)
print("events", len(ev), dict(src), "flagged events", len(flag_ev), f"({len(flag_ev)/max(1,len(ev)):.2%})", "findings", len(fs))
for r, n in by_rule.most_common():
    print(f"  {r:28s} events {n:6d}  keys {len(ips[r]):4d}  e.g. {ex[r][0][:150]}")
json.dump({"events": len(ev), "sources": dict(src), "flagged_events": len(flag_ev), "findings": len(fs),
           "by_rule": dict(by_rule), "keys_per_rule": {r: len(v) for r, v in ips.items()}}, open(sys.argv[2], "w"), indent=1)

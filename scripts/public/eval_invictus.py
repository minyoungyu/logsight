"""Invictus aws_dataset(Stratus 공격 재현 CloudTrail) 측정.
라벨: userAgent에 stratus-red-team_<id>가 있고 Terraform이 아닌 호출 = 공격 실행(detonation). 같은 id의 Terraform 호출 = 준비(warmup).
실행 단위(id)마다 LogFinder가 공격 호출 중 하나라도 표시했는지, 무슨 규칙인지 센다. 정상 호출(라벨 없음)에 붙은 표시는 오탐 후보로 센다."""
import collections, glob, json, sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from logsight.normalize import parse_cloudtrail
from logsight.detect import run_detections

recs = []
for f in sorted(glob.glob(sys.argv[1] + "/*.json")):
    recs += json.load(open(f))["Records"]
recs.sort(key=lambda r: r["eventTime"])
for i, r in enumerate(recs):
    r["_i"] = i
evs = parse_cloudtrail(json.dumps({"Records": recs}), "invictus.json")
fs = run_detections(evs, {})
flag = collections.defaultdict(set)
for f in fs:
    for e in f.events:
        flag[e.raw_ref].add(f.rule)
# raw_ref → 레코드 순서 매핑: parse 순서가 레코드 순서와 같다고 가정하지 않고 eventID로 맞춘다
by_id = {r["eventID"]: r for r in recs}
ref_rules = {}
for e in evs:
    eid = e.extra.get("eventID") or e.extra.get("event_id")
    ref_rules[e.raw_ref] = (eid, flag.get(e.raw_ref, set()), e)
runs = collections.defaultdict(lambda: {"attack": [], "setup": 0, "rules": set()})
benign_flag = collections.Counter(); n_benign = 0; n_benign_flag = 0
for ref, (eid, rules, e) in ref_rules.items():
    ua = recs[int(ref.rsplit(":", 1)[1]) - 1].get("userAgent", "")
    if "stratus-red-team_" in ua:
        rid = ua.split("stratus-red-team_")[1][:36]
        if "terraform" in ua.lower():
            runs[rid]["setup"] += 1
        else:
            runs[rid]["attack"].append(e.action)
            runs[rid]["rules"] |= rules
    else:
        n_benign += 1
        if rules:
            n_benign_flag += 1
            benign_flag.update(rules)
out = []
for rid, x in runs.items():
    if not x["attack"]:
        continue
    out.append({"run": rid[:8], "attack_calls": sorted(collections.Counter(x["attack"]).items()),
                "detected": bool(x["rules"]), "rules": sorted(x["rules"])})
out.sort(key=lambda o: o["attack_calls"][0][0])
det = sum(o["detected"] for o in out)
print(f"events {len(evs)} | stratus runs with attack calls {len(out)} | detected {det}")
for o in out:
    print(("탐지 " if o["detected"] else "놓침 ") + o["run"], o["attack_calls"][:4], o["rules"])
print("unlabeled events", n_benign, "flagged", n_benign_flag, dict(benign_flag))
json.dump({"runs": out, "unlabeled": n_benign, "unlabeled_flagged": n_benign_flag, "unlabeled_rules": dict(benign_flag)},
          open(sys.argv[2], "w"), ensure_ascii=False, indent=1)

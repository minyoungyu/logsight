"""
공격 흐름 그림: 사건의 근거 이벤트만으로 "누가 → 어디로 들어와 → 어떤 권한으로 → 무엇을 했나"를 그린다.

원칙(객관성)
- 점(노드)과 선(엣지)은 모두 입력 이벤트에서 나온다. 추측으로 잇지 않는다.
  예: WAF 로그에 대상 서버 정보가 없으면 "웹 서비스"를 서버와 잇지 않는다.
- 선마다 건수·결과(성공/실패/차단)와 근거 ref를 붙이고, verify()가 근거가 사건 안에 있는지,
  모든 이벤트가 그림에 한 번씩 들어갔는지 다시 센다.
- 이벤트가 아닌 연결은 하나뿐이다: CloudTrail 역할 세션 이름이 인스턴스 ID와 같을 때
  "이 서버에 붙은 역할"을 점선으로 잇는다(로그에 적힌 사실).
- GuardDuty 결과는 행위가 아니라 판단이므로 선이 아니라 해당 점의 표시로 붙인다.

열: 출발지 → 들어온 곳(서버·웹) → 권한(역할·사용자) → AWS 서비스
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from html import escape

KST = timezone(timedelta(hours=9))
COLS = ["src", "entry", "cred", "svc"]
COL_KO = {"src": "출발지", "entry": "들어온 곳", "cred": "쓴 권한", "svc": "건드린 AWS 서비스"}
SVC_KO = {"s3": "S3(저장소)", "iam": "IAM(계정·권한)", "sts": "STS(신원 확인)", "ec2": "EC2(서버)",
          "ssm": "SSM(원격 명령)", "states": "Step Functions", "lambda": "Lambda", "kms": "KMS(암호 키)",
          "cloudtrail": "CloudTrail(감사 로그)", "guardduty": "GuardDuty", "logs": "CloudWatch Logs",
          "secretsmanager": "Secrets Manager", "rds": "RDS", "dynamodb": "DynamoDB", "eks": "EKS"}
NET = {"vpcflow", "hostfw"}
SRC_LOG = {"waf": "WAF", "alb": "ALB", "weblog": "웹서버 로그"}
WEB = {"waf", "alb", "weblog"}
GD_KO = {"SSHBruteForce": "SSH 무차별 대입", "InstanceCredentialExfiltration": "역할 키가 서버 밖에서 사용됨",
         "PortProbe": "포트 탐색", "Recon": "정찰"}


def _public(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return not any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                            "127.0.0.0/8"))


def _role(actor: str | None) -> tuple[str, str | None] | None:
    """ARN에서 (권한 이름, 세션 이름)을 뽑는다."""
    if not actor:
        return None
    if ":assumed-role/" in actor:
        rest = actor.split(":assumed-role/", 1)[1].split("/")
        return f"역할 {rest[0]}", (rest[1] if len(rest) > 1 else None)
    if ":user/" in actor:
        return f"사용자 {actor.rsplit('/', 1)[-1]}", None
    if actor.endswith(":root"):
        return "루트 계정", None
    return actor.rsplit("/", 1)[-1], None


def _src(e: dict) -> tuple[str, str]:
    ip = e.get("src_ip")
    if ip:
        return f"ip:{ip}", (ip if _public(ip) else f"{ip}(내부)")
    return "src:unknown", "출발지 기록 없음"


def build(incidents: list[dict]) -> dict:
    """사건 하나 이상의 근거 이벤트로 그림 자료를 만든다(여러 사건이면 같은 공격으로 묶인 것)."""
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    marks: dict[str, list] = defaultdict(list)
    used: dict[str, str] = {}  # ref -> 쓰인 곳(edge key 또는 mark)

    def node(nid, col, label, *lines):
        n = nodes.setdefault(nid, {"id": nid, "col": col, "label": label, "lines": [], "first": None})
        for ln in lines:
            if ln and ln not in n["lines"]:
                n["lines"].append(ln)
        return n

    def edge(a, b, kind, label, e):
        k = (a, b, kind)
        ed = edges.setdefault(k, {"src": a, "dst": b, "kind": kind, "label": label, "n": 0, "ok": 0, "fail": 0,
                                  "blocked": 0, "refs": [], "first": e["ts"], "last": e["ts"], "acts": defaultdict(int)})
        ed["n"] += 1
        if e.get("disposition") == "blocked":
            ed["blocked"] += 1
        elif e.get("status") == "success":
            ed["ok"] += 1
        elif e.get("status") == "failure":
            ed["fail"] += 1
        ed["refs"].append(e["ref"])
        ed["first"], ed["last"] = min(ed["first"], e["ts"]), max(ed["last"], e["ts"])
        ed["acts"][str(e.get("action") or "")] += 1
        for nid in (a, b):
            n = nodes[nid]
            n["first"] = min(n["first"] or e["ts"], e["ts"])
        used[e["ref"]] = "edge"

    inst_of_role: dict[str, str] = {}
    evs = sorted((e for inc in incidents for e in inc["events"]), key=lambda e: e["ts"])
    for e in evs:
        src = e["source"]
        if src == "guardduty":
            target = e.get("instance_id") or e.get("target_instance")
            tid = f"inst:{target}" if target else None
            actor = e.get("actor") or ""
            if actor and (e.get("access_key") or "Credential" in str(e.get("action"))):
                name = _role(actor)[0] if actor.startswith("arn:") else f"역할 {actor}"
                tid = f"cred:{name}"
                title, _, nm = name.partition(" ")
                node(tid, "cred", title, nm, f"{target} 서버의 키" if target else "")
            elif tid:
                node(tid, "entry", "서버", target)
            name = next((v for k, v in GD_KO.items() if k in str(e.get("action"))), str(e.get("action")).split("/")[-1])
            if tid:
                marks[tid].append({"text": f"GuardDuty: {name}", "ref": e["ref"]})
                used[e["ref"]] = "mark"
            continue
        sid, slabel = _src(e)
        node(sid, "src", slabel, "외부 IP" if sid.startswith("ip:") and _public(e.get("src_ip")) else "")
        if src == "cloudtrail":
            r = _role(e.get("actor"))
            if not r:
                continue
            cid = f"cred:{r[0]}"
            sess = r[1]
            inst = e.get("instance_id") or (sess if sess and sess.startswith("i-") else None)
            title, _, nm = r[0].partition(" ")
            node(cid, "cred", title, nm, f"{inst} 서버의 키" if inst else ("키 " + e["access_key"][:8] + "…"
                                                                       if e.get("access_key") else ""))
            if inst:
                inst_of_role[cid] = inst
            action = str(e.get("action") or "")
            svc = action.split(":", 1)[0] if ":" in action else "기타"
            vid = f"svc:{svc}"
            node(vid, "svc", SVC_KO.get(svc, svc.upper()))
            edge(sid, cid, "use", "키 사용", dict(e, ref=e["ref"] + "#use"))  # 같은 이벤트를 두 선이 나눠 그린다
            edge(cid, vid, "call", "API 호출", e)
        elif src in NET or src == "sshauth":
            t = e.get("target_instance") or e.get("instance_id") or e.get("dst_ip") or "서버"
            tid = f"inst:{t}"
            node(tid, "entry", "서버", t)
            if src == "sshauth":
                edge(sid, tid, "ssh", "SSH 로그인", e)
            else:
                edge(sid, tid, "net", "네트워크 접속", e)  # 포트마다 선을 나누지 않는다(포트 스캔이면 수십 개)
        elif src in WEB:
            host = e.get("http_host") or e.get("host") or ""
            t = e.get("target_instance") or e.get("instance_id")
            tid = f"inst:{t}" if t else f"web:{host or 'web'}"
            if t:
                node(tid, "entry", "서버", t)
            else:
                node(tid, "entry", "웹 서비스", host, f"{SRC_LOG.get(src, src)} 기록 · 대상 서버 정보 없음")
            edge(sid, tid, "web", "웹 요청", e)
        else:
            continue
    # 역할 → 서버: 세션 이름이 인스턴스 ID(로그에 적힌 사실)
    links = []
    for cid, inst in inst_of_role.items():
        tid = f"inst:{inst}"
        if tid in nodes:
            links.append({"src": tid, "dst": cid, "label": "이 서버에 붙은 역할"})
    order = sorted(edges.values(), key=lambda x: x["first"])
    for i, ed in enumerate(order, 1):
        ed["no"] = i
    return {"nodes": list(nodes.values()), "edges": order, "links": links, "marks": dict(marks),
            "incident_ids": [i["id"] for i in incidents],
            "n_events": sum(len(i["events"]) for i in incidents),
            "omitted": sum(i.get("omitted_events", 0) for i in incidents)}


def verify(g: dict, incidents: list[dict]) -> dict:
    """그림이 근거와 맞는지 다시 센다. 반환: {passed, edges, events_drawn, events_total, missing, unknown_refs}"""
    refs = {e["ref"] for i in incidents for e in i["events"]}
    drawn = set()
    unknown = []
    for ed in g["edges"]:
        for r in ed["refs"]:
            base = r.removesuffix("#use")
            if base not in refs:
                unknown.append(r)
            drawn.add(base)
    for ms in g["marks"].values():
        for m in ms:
            drawn.add(m["ref"])
            if m["ref"] not in refs:
                unknown.append(m["ref"])
    missing = sorted(refs - drawn)
    return {"passed": not unknown and not missing, "edges": len(g["edges"]), "events_drawn": len(drawn & refs),
            "events_total": len(refs), "missing": missing[:10], "unknown_refs": unknown[:10]}


# ------------------------------------------------------------------ 그리기(SVG)
def _w(text: str, size: float = 12.5) -> float:
    """대략의 글자 폭(한글은 넓게)."""
    return sum(size * (1.0 if ord(c) > 0x2E80 else 0.58) for c in text)


def _fit(text: str, width: float, size: float = 12.5) -> str:
    if _w(text, size) <= width:
        return text
    out = ""
    for c in text:
        if _w(out + c + "…", size) > width:
            return out + "…"
        out += c
    return out


def _hm(iso: str) -> str:
    d = datetime.fromisoformat(iso)
    return f"{d.astimezone(timezone.utc):%H:%M}"


def _result(ed: dict) -> tuple[str, str]:
    parts = []
    if ed["ok"]:
        parts.append(f"성공 {ed['ok']}")
    if ed["fail"]:
        parts.append(f"실패 {ed['fail']}")
    if ed["blocked"]:
        parts.append(f"차단 {ed['blocked']}")
    rest = ed["n"] - ed["ok"] - ed["fail"] - ed["blocked"]
    if rest:
        parts.append(f"결과 없음 {rest}")
    cls = "ok" if ed["ok"] else "no"
    return " · ".join(parts), cls


def _edge_title(ed: dict) -> str:
    if ed["kind"] == "call":
        acts = sorted(ed["acts"].items(), key=lambda kv: -kv[1])
        return ", ".join(f"{a.split(':', 1)[-1]}" + (f" {n}" if n > 1 else "") for a, n in acts[:2]) + \
            (f" 외 {len(acts) - 2}" if len(acts) > 2 else "")
    if ed["kind"] == "web":
        return f"웹 요청 {ed['n']}건"
    if ed["kind"] == "ssh":
        return f"SSH 로그인 {ed['n']}번"
    if ed["kind"] == "use":
        return f"역할 키로 API {ed['n']}번"
    if ed["kind"] == "net":
        ports = sorted({a.split()[0] for a in ed["acts"]})
        return (f"{ports[0]} 접속 {ed['n']}건" if len(ports) == 1 else f"포트 {len(ports)}개에 접속 {ed['n']}건")
    return f"{ed['label']} {ed['n']}건"


def _bez(p0, p1, p2, p3, t):
    u = 1 - t
    return tuple(u ** 3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t ** 3 * d for a, b, c, d in zip(p0, p1, p2, p3))


def svg(g: dict, width: int = 1000) -> str:
    """그림 자료를 SVG로. 선에는 번호만 달고 자세한 내용은 아래 표(steps_table)에 둔다(이름표 겹침 방지)."""
    cols = [c for c in COLS if any(n["col"] == c for n in g["nodes"])]
    if not cols:
        return ""
    nw, gap, top, pad = 200, 26, 40, 8
    span = (width - 2 * pad - nw) / max(1, len(cols) - 1)
    colx = {c: pad + i * span for i, c in enumerate(cols)} if len(cols) > 1 else {cols[0]: (width - nw) / 2}
    ci = {c: i for i, c in enumerate(cols)}

    def nh(n):
        return 34 + 17 * len(n["lines"]) + 17 * len(g["marks"].get(n["id"], [])) + 8

    pos = {}
    bottom = {}
    for c in cols:
        y = top
        for n in sorted((n for n in g["nodes"] if n["col"] == c), key=lambda n: n["first"] or ""):
            pos[n["id"]] = [colx[c], y, nh(n)]
            y += nh(n) + gap
        bottom[c] = y - gap
    # 선 끝점을 점의 옆면에 고르게 나눈다
    outs, ins = defaultdict(list), defaultdict(list)
    for ed in g["edges"]:
        outs[ed["src"]].append(ed)
        ins[ed["dst"]].append(ed)
    port = {}
    for nid, lst in outs.items():
        lst.sort(key=lambda e: pos[e["dst"]][1])
        x, y, h = pos[nid]
        for k, ed in enumerate(lst):
            port[(id(ed), "s")] = (x + nw, y + h * (k + 1) / (len(lst) + 1))
    for nid, lst in ins.items():
        lst.sort(key=lambda e: pos[e["src"]][1])
        x, y, h = pos[nid]
        for k, ed in enumerate(lst):
            port[(id(ed), "e")] = (x, y + h * (k + 1) / (len(lst) + 1))
    lane_y = max(bottom.values()) + 26
    lanes = 0
    paths, badges = [], []
    for ed in g["edges"]:
        (sx, sy), (ex, ey) = port[(id(ed), "s")], port[(id(ed), "e")]
        ex -= 4
        _, cls = _result(ed)
        skip = ci[g_col(g, ed["dst"])] - ci[g_col(g, ed["src"])] > 1
        if skip:  # 사이 열을 지나지 않도록 아래 길로 돌아간다(서버를 거치지 않았다는 뜻이기도 하다)
            k = lanes
            ly = lane_y + k * 18
            lanes += 1
            r = 10
            ax, bx2 = sx + 16 + 9 * k, ex - 16 - 9 * k  # 세로 구간이 겹치지 않게 길마다 조금씩 비킨다
            d = (f"M{sx:.0f},{sy:.0f} H{ax - r:.0f} Q{ax:.0f},{sy:.0f} {ax:.0f},{sy + r:.0f} "
                 f"V{ly - r:.0f} Q{ax:.0f},{ly:.0f} {ax + r:.0f},{ly:.0f} H{bx2 - r:.0f} "
                 f"Q{bx2:.0f},{ly:.0f} {bx2:.0f},{ly - r:.0f} V{ey + r:.0f} Q{bx2:.0f},{ey:.0f} {bx2 + r:.0f},{ey:.0f} "
                 f"H{ex:.0f}")
            bx, by = sx + (ex - sx) * (0.35 + 0.18 * k), ly
        else:
            dx = (ex - sx) / 2
            p = ((sx, sy), (sx + dx, sy), (ex - dx, ey), (ex, ey))
            d = f"M{sx:.0f},{sy:.0f} C{sx + dx:.0f},{sy:.0f} {ex - dx:.0f},{ey:.0f} {ex:.0f},{ey:.0f}"
            bx, by = _bez(*p, 0.5)
        paths.append(f"<path d='{d}' class='edge {cls}' marker-end='url(#ah-{cls})' />")
        badges.append((bx, by, ed, cls))
    # 번호표가 겹치면 조금씩 민다
    placed = []
    for i, (bx, by, ed, cls) in enumerate(badges):
        while any(abs(bx - px) < 26 and abs(by - py) < 26 for px, py in placed):
            by += 24
        placed.append((bx, by))
        badges[i] = (bx, by, ed, cls)
    H = int(max(lane_y + lanes * 16 if lanes else max(bottom.values()), max(b[1] for b in badges)) + 20)
    out = [f"<svg class=flowgraph viewBox='0 0 {width} {H}' width='100%' role=img aria-label='공격 흐름 그림' "
           "xmlns='http://www.w3.org/2000/svg'><defs>"
           + "".join(f"<marker id=ah-{c} viewBox='0 0 10 10' refX=8 refY=5 markerWidth=7 markerHeight=7 "
                     f"orient=auto><path d='M0,0 L10,5 L0,10 z' class='ahp {c}' /></marker>" for c in ("ok", "no"))
           + "</defs>"]
    for c in cols:
        out.append(f"<text x='{colx[c] + nw / 2:.0f}' y='18' class=colh text-anchor=middle>{COL_KO[c]}</text>")
    for lk in g["links"]:
        (x1, y1, h1), (x2, y2, h2) = pos[lk["src"]], pos[lk["dst"]]
        out.append(f"<path d='M{x1 + nw:.0f},{y1 + 16:.0f} C{x1 + nw + 60:.0f},{y1 + 16:.0f} {x2 - 60:.0f},{y2 + 16:.0f} "
                   f"{x2:.0f},{y2 + 16:.0f}' class=link><title>{escape(lk['label'])}</title></path>")
    out += paths
    for n in g["nodes"]:
        x, y, h = pos[n["id"]]
        out.append(f"<g class='node {n['col']}'><rect x='{x:.0f}' y='{y:.0f}' width='{nw}' height='{h:.0f}' rx=10 />"
                   f"<text x='{x + 12:.0f}' y='{y + 23:.0f}' class=nt>{escape(_fit(n['label'], nw - 24, 14))}</text>")
        yy = y + 23
        for ln in n["lines"]:
            yy += 17
            out.append(f"<text x='{x + 12:.0f}' y='{yy:.0f}' class=ns>{escape(_fit(ln, nw - 24, 12))}</text>")
        for m in g["marks"].get(n["id"], []):
            yy += 17
            out.append(f"<text x='{x + 12:.0f}' y='{yy:.0f}' class=nm>{escape(_fit(m['text'], nw - 24, 11.5))}</text>")
        out.append("</g>")
    for bx, by, ed, cls in badges:
        out.append(f"<g class='badge {cls}'><title>{escape(_edge_title(ed))} · {escape(_result(ed)[0])}</title>"
                   f"<circle cx='{bx:.0f}' cy='{by:.0f}' r=11 /><text x='{bx:.0f}' y='{by + 4:.0f}' "
                   f"text-anchor=middle>{ed['no']}</text></g>")
    out.append("</svg>")
    return "".join(out)


def g_col(g: dict, nid: str) -> str:
    return next(n["col"] for n in g["nodes"] if n["id"] == nid)


def _nlabel(g: dict, nid: str) -> str:
    n = next(n for n in g["nodes"] if n["id"] == nid)
    if nid.startswith("web:"):
        first = n["lines"][0] if n["lines"] else ""
        return "웹 서비스" + (f" {first}" if first and "기록" not in first else f"({first.split(' ')[0]})" if first else "")
    return n["label"] + (f" {n['lines'][0]}" if n["lines"] and n["col"] in ("entry", "cred") else "")


def steps_table(g: dict, ref2inc: dict[str, str] | None = None) -> str:
    """그림의 번호별 내용: 언제, 어디서 어디로, 무엇을, 결과, 근거."""
    rows = []
    for ed in g["edges"]:
        res, cls = _result(ed)
        d = datetime.fromisoformat(ed["first"])
        when = f"{d.astimezone(timezone.utc):%m-%d %H:%M}" + (
            f"~{_hm(ed['last'])}" if ed["last"] != ed["first"] else "") + f" UTC<br><span class=faint>한국 {d.astimezone(KST):%H:%M}</span>"
        refs = [r.removesuffix("#use") for r in ed["refs"]]
        links = " ".join((f"<a class=ref href='#{escape(ref2inc[r])}-{escape(r)}'>{escape(r)}</a>" if ref2inc and r in ref2inc
                          else f"<span class=ref>{escape(r)}</span>") for r in refs[:3]) + (f" <span class=faint>외 {len(refs) - 3}</span>"
                                                                                  if len(refs) > 3 else "")
        acts = sorted(ed["acts"].items(), key=lambda kv: -kv[1])
        what = ", ".join(f"{a}" + (f" ×{n}" if n > 1 else "") for a, n in acts[:3]) + (f" 외 {len(acts) - 3}종" if len(acts) > 3 else "")
        rows.append(f"<tr><td><span class='bn {cls}'>{ed['no']}</span></td><td class=nw>{when}</td>"
                    f"<td><b>{escape(_nlabel(g, ed['src']))}</b> → <b>{escape(_nlabel(g, ed['dst']))}</b>"
                    f"<div class='small muted'>{escape(_edge_title(ed))}: {escape(what)}</div></td>"
                    f"<td class='res {cls}'>{escape(res)}</td><td class=act>{links}</td></tr>")
    return ("<div class=tablewrap><table class=steps><tr><th></th><th>시각</th><th>누가 → 어디로, 무엇을</th><th>결과</th>"
            "<th>근거</th></tr>" + "".join(rows) + "</table></div>")


GRAPH_CSS = """
.flowgraph{display:block;max-width:100%;height:auto;font-family:inherit}
.flowgraph .colh{font-size:12px;font-weight:700;fill:var(--faint);letter-spacing:.04em}
.flowgraph .node rect{fill:var(--card);stroke:var(--line);stroke-width:1.5}
.flowgraph .node.src rect{stroke:var(--high);fill:var(--high-soft)}
.flowgraph .node.entry rect{stroke:var(--accent)}.flowgraph .node.cred rect{stroke:var(--medium);fill:var(--medium-soft)}
.flowgraph .node.svc rect{stroke:var(--gray)}
.flowgraph .nt{font-size:14px;font-weight:700;fill:var(--fg)}.flowgraph .ns{font-size:12px;fill:var(--muted)}
.flowgraph .nm{font-size:11.5px;font-weight:600;fill:var(--high)}
.flowgraph .edge{fill:none;stroke-width:2}.flowgraph .edge.ok{stroke:var(--high)}.flowgraph .edge.no{stroke:var(--faint);stroke-dasharray:5 4}
.flowgraph .ahp.ok{fill:var(--high)}.flowgraph .ahp.no{fill:var(--faint)}
.flowgraph .badge circle{stroke-width:2;fill:var(--card)}.flowgraph .badge.ok circle{stroke:var(--high)}
.flowgraph .badge.no circle{stroke:var(--faint)}.flowgraph .badge text{font-size:12px;font-weight:800;fill:var(--fg)}
.graphwrap{overflow-x:auto}.graphwrap svg{min-width:640px}table.steps{min-width:680px}
span.ref{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:var(--soft);border-radius:5px;
padding:0 6px;margin:0 4px 4px 0;display:inline-block}
table.steps td{vertical-align:middle}table.steps .res.ok{color:var(--high);font-weight:600}table.steps .res.no{color:var(--muted)}
.bn{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;border:2px solid var(--faint);font-size:12px;font-weight:800}
.bn.ok{border-color:var(--high)}.flowgraph .link{fill:none;stroke:var(--medium);stroke-width:1.5;stroke-dasharray:2 4}
.flowgraph .linkt{font-size:11px;fill:var(--medium)}
.flowgraph .lab{fill:var(--card);stroke-width:1.2}.flowgraph .lab.ok{stroke:var(--high)}.flowgraph .lab.no{stroke:var(--line)}
.flowgraph .labt{font-size:12.5px;font-weight:600;fill:var(--fg)}.flowgraph .labs{font-size:11.5px;fill:var(--muted)}
.flowgraph .labs.ok{fill:var(--high);font-weight:600}.flowgraph a{cursor:pointer}
.graphnote{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12.5px;color:var(--muted);margin-top:8px}
.graphnote i{display:inline-block;width:22px;height:0;border-top:2px solid var(--high);vertical-align:middle;margin-right:5px}
.graphnote i.no{border-top:2px dashed var(--faint)}.graphnote i.lk{border-top:2px dotted var(--medium)}
"""


def figure(incidents: list[dict], link: bool = True, width: int = 1000) -> str:
    """보고서에 넣을 그림 + 범례 + 번호별 표 + 검증 문장."""
    g = build(incidents)
    if not g["edges"]:
        return ""
    v = verify(g, incidents)
    note = (f"그림의 선 {v['edges']}개를 근거 이벤트와 다시 대조했습니다. 이 사건의 이벤트 {v['events_total']}건 중 "
            f"{v['events_drawn']}건이 그림에 들어갔습니다"
            + (f"(비슷한 이벤트 {g['omitted']}건은 생략된 대표 이벤트 기준)" if g["omitted"] else "")
            + ("." if v["passed"] else f". 확인 필요: {', '.join(v['missing'] + v['unknown_refs'])}"))
    return (f"<div class=graphwrap>{svg(g, width)}</div><div class=graphnote>"
            "<span><i></i>성공·허용이 있음</span><span><i class=no></i>모두 실패·차단</span>"
            "<span><i class=lk></i>로그에 적힌 소속(서버에 붙은 역할)</span><span>번호는 처음 일어난 순서</span></div>"
            + steps_table(g, {e["ref"]: i["id"] for i in incidents for e in i["events"]} if link else None)
            + f"<div class='small {'ok' if v['passed'] else 'warn'}' style='margin-top:6px'>{escape(note)}</div>")

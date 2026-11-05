"""
자동 격리(구상 3단계, 방안 A): 경보 뒤 5분 안에 아무도 확인하지 않으면, 도입 이후 외부에서 만들어진
키·사용자·역할·보안그룹 규칙만 **되돌릴 수 있게** 막는다. 삭제는 하지 않는다(사람이 보고서를 보고 한다).

    기준선(baseline.json)   도입한 날의 IAM 사용자·역할·액세스 키·보안그룹 규칙. 여기 있는 것은 절대 건드리지 않음
    허용 목록(allowlist.json) 기준선 뒤에 만들어졌지만 내부에서 만든 것. CloudTrail 생성 기록으로 자동 추가:
                              배포 주체(CI/Terraform)가 만들었거나,
                              관리자 주체가 관리 IP에서 MFA로 만들었을 때만(세 조건을 함께 본다: 관리자 키를
                              훔친 공격자도 '내부 사용자'로 찍히기 때문)
    후보                    둘 다 아닌 것. 경보가 높음이고 5분 동안 확인이 없으면 격리한다

격리 조치(모두 되돌리기 짝이 있다):
    액세스 키      → 비활성(Inactive)              되돌리기: Active
    IAM 사용자·역할 → AWSDenyAll 관리형 정책 부착   되돌리기: 떼기
    보안그룹 규칙   → 그 규칙만 닫기                되돌리기: 같은 규칙 다시 열기

AI는 조치를 고르지 않는다. 대상은 위 규칙으로만 정하고, 실행할 수 있는 조치는 이 파일의 세 가지뿐이다.
기본은 시험 모드(mode=dry-run): 무엇을 했을지만 기록한다. 실제 실행은 설정에서 mode=enforce로 바꿔야 한다.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

DENY_ALL = "arn:aws:iam::aws:policy/AWSDenyAll"
# 기준선 대상에 대한 변경은 격리하면 서비스가 깨질 수 있어 사람에게만 알린다
HUMAN_ONLY = {"CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy", "PutUserPolicy",
              "AttachRolePolicy", "PutRolePolicy", "UpdateAssumeRolePolicy", "CreatePolicyVersion",
              "AddUserToGroup"}
ORDER = {"access_key": 0, "user": 1, "role": 1, "sg_rule": 2}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(s: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _load(path: str | Path | None, default):
    if not path:
        return default
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default


def _save(path: str | Path, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)


def rule_key(group: str, proto: Any, frm: Any, to: Any, cidr: str) -> str:
    proto = str(proto)
    if proto == "-1":
        frm = to = -1
    return f"{group}|{proto}|{frm}|{to}|{cidr}"


# ------------------------------------------------------------------ 설정
@dataclass
class Config:
    mode: str = "dry-run"                 # dry-run | enforce
    deadline_min: float = 5.0
    min_severity: str = "high"
    max_per_incident: int = 5
    max_per_day: int = 20
    deploy_principals: list[str] = field(default_factory=list)  # 예: arn:aws:iam::123:role/github-deploy
    admin_principals: list[str] = field(default_factory=list)   # 예: arn:aws:iam::123:user/alice
    trusted_ips: list[str] = field(default_factory=list)        # 관리 IP(CIDR)
    require_mfa: bool = True
    baseline: str = "baseline.json"
    allowlist: str = "allowlist.json"
    stop_file: str = "STOP"               # 이 파일이 있으면 모든 실행을 멈춘다(끄는 스위치)
    deny_policy_arn: str = DENY_ALL       # 사용자·역할에 붙일 거부 정책(실행 역할 권한도 이 정책으로만 제한)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        d = _load(path, {})
        base = Path(path).parent
        c = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        for k in ("baseline", "allowlist", "stop_file"):  # 상대 경로는 설정 파일 기준
            v = getattr(c, k)
            if v and not Path(v).is_absolute():
                setattr(c, k, str(base / v))
        if c.mode not in ("dry-run", "enforce"):
            raise ValueError("mode는 dry-run 또는 enforce")
        return c

    def stopped(self) -> str | None:
        if os.environ.get("LOGSIGHT_RESPOND_STOP"):
            return "환경변수 LOGSIGHT_RESPOND_STOP"
        if self.stop_file and Path(self.stop_file).exists():
            return f"끄는 스위치 파일 {self.stop_file}"
        return None


# ------------------------------------------------------------------ 기준선
def take_baseline(session=None, region: str | None = None) -> dict:
    """도입하는 날 실행한다(읽기 전용). 이후 이 목록의 자원은 자동 격리 대상에서 영원히 빠진다."""
    import boto3
    s = session or boto3.Session(region_name=region)
    iam, ec2 = s.client("iam"), s.client("ec2", region_name=region or s.region_name)
    out: dict[str, Any] = {"taken_at": _iso(_now()), "users": [], "roles": [], "access_keys": [], "sg_rules": []}
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            out["users"].append(u["UserName"])
            for k in iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []):
                out["access_keys"].append(k["AccessKeyId"])
    for page in iam.get_paginator("list_roles").paginate():
        out["roles"].extend(r["RoleName"] for r in page["Roles"])
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for g in page["SecurityGroups"]:
            for p in g.get("IpPermissions", []):
                for r in p.get("IpRanges", []):
                    out["sg_rules"].append(rule_key(g["GroupId"], p.get("IpProtocol"), p.get("FromPort"),
                                                    p.get("ToPort"), r["CidrIp"]))
                for r in p.get("Ipv6Ranges", []):
                    out["sg_rules"].append(rule_key(g["GroupId"], p.get("IpProtocol"), p.get("FromPort"),
                                                    p.get("ToPort"), r["CidrIpv6"]))
    return out


# ------------------------------------------------------------------ CloudTrail 생성 기록 읽기
def iter_records(paths: Iterable[str | Path], since: datetime | None = None,
                 until: datetime | None = None) -> Iterator[dict]:
    """CloudTrail 원본 레코드(정규화 전). responseElements(새 키 ID 등)가 필요해서 따로 읽는다."""
    from .normalize import _walk, detect_kind, read_text
    for p in _walk([Path(x) for x in paths]):
        try:
            text = read_text(p)
        except OSError:
            continue
        if detect_kind(p.name, text) != "cloudtrail":
            continue
        try:
            docs = [json.loads(text)]
        except json.JSONDecodeError:
            docs = []
            for line in text.splitlines():
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        for d in docs:
            recs = d.get("Records") if isinstance(d, dict) and "Records" in d else [d]
            for r in recs or []:
                if not isinstance(r, dict) or "eventName" not in r:
                    continue
                t = _ts(r.get("eventTime"))
                if t and ((since and t < since) or (until and t > until)):
                    continue
                yield r


@dataclass
class Created:
    kind: str           # access_key | user | role | sg_rule | baseline_change
    id: str             # 키 ID, 사용자 이름, 역할 이름, 규칙 키
    event: str
    time: str
    creator: str
    ip: str
    mfa: bool
    detail: dict = field(default_factory=dict)


def _creator(r: dict) -> tuple[str, list[str], bool]:
    ui = r.get("userIdentity") or {}
    sc = ui.get("sessionContext") or {}
    names = [x for x in (ui.get("arn"), (sc.get("sessionIssuer") or {}).get("arn")) if x]
    mfa = str((sc.get("attributes") or {}).get("mfaAuthenticated", "")).lower() == "true"
    return (names[-1] if names else ui.get("type", "?")), names, mfa


def creations(records: Iterable[dict]) -> Iterator[tuple[Created, list[str]]]:
    for r in records:
        if r.get("errorCode"):
            continue  # 실패한 호출은 아무것도 만들지 않았다
        name = r.get("eventName", "")
        req, resp = r.get("requestParameters") or {}, r.get("responseElements") or {}
        who, names, mfa = _creator(r)
        base = dict(event=name, time=r.get("eventTime", ""), creator=who, ip=r.get("sourceIPAddress", ""), mfa=mfa)
        if name == "CreateAccessKey":
            ak = resp.get("accessKey") or {}
            if ak.get("accessKeyId"):
                yield Created("access_key", ak["accessKeyId"], detail={"user": ak.get("userName") or req.get("userName")},
                              **base), names
        elif name == "CreateUser" and req.get("userName"):
            yield Created("user", req["userName"], **base), names
        elif name == "CreateRole" and req.get("roleName"):
            yield Created("role", req["roleName"], detail={"path": req.get("path", "/")}, **base), names
        elif name == "AuthorizeSecurityGroupIngress":
            g = req.get("groupId", "")
            for p in ((req.get("ipPermissions") or {}).get("items") or []):
                for rng, key in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
                    for x in ((p.get(rng) or {}).get("items") or []):
                        k = rule_key(g, p.get("ipProtocol"), p.get("fromPort"), p.get("toPort"), x.get(key))
                        yield Created("sg_rule", k, detail={"group": g, "proto": str(p.get("ipProtocol")),
                                                            "from": p.get("fromPort"), "to": p.get("toPort"),
                                                            "cidr": x.get(key), "v6": key == "cidrIpv6"}, **base), names
        elif name in HUMAN_ONLY:
            target = req.get("userName") or req.get("roleName") or req.get("policyArn") or req.get("groupName") or "?"
            yield Created("baseline_change", f"{name}:{target}", detail={"target": target}, **base), names


# ------------------------------------------------------------------ 분류
class Responder:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.baseline = _load(cfg.baseline, {})
        self.allow = _load(cfg.allowlist, {"items": []})
        self._nets = []
        for c in cfg.trusted_ips:
            try:
                self._nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    # 기준선·허용 목록
    def in_baseline(self, c: Created) -> bool:
        b = self.baseline
        return {"access_key": c.id in b.get("access_keys", []), "user": c.id in b.get("users", []),
                "role": c.id in b.get("roles", []), "sg_rule": c.id in b.get("sg_rules", [])}.get(c.kind, False)

    def allowed(self, kind: str, rid: str) -> bool:
        return any(i.get("kind") == kind and i.get("id") == rid for i in self.allow.get("items", []))

    def _ip_trusted(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._nets)

    def approved(self, c: Created, names: list[str]) -> str | None:
        """내부에서 만든 것으로 볼 이유. 없으면 None(후보)."""
        if any(n in self.cfg.deploy_principals for n in names):
            return f"배포 주체 {c.creator}"
        if any(n in self.cfg.admin_principals for n in names):
            if not self._ip_trusted(c.ip):
                return None  # 관리자 계정이라도 관리 IP 밖이면 훔친 키일 수 있다
            if self.cfg.require_mfa and not c.mfa:
                return None
            return f"관리자 {c.creator}, 관리 IP {c.ip}" + (", MFA" if c.mfa else "")
        return None

    def observe(self, records: Iterable[dict]) -> list[dict]:
        """생성 기록을 보고 내부에서 만든 것을 허용 목록에 더한다(계속 갱신). 추가된 항목을 돌려준다."""
        added = []
        for c, names in creations(records):
            if c.kind == "baseline_change" or self.in_baseline(c) or self.allowed(c.kind, c.id):
                continue
            why = self.approved(c, names)
            if why:
                item = {"kind": c.kind, "id": c.id, "why": why, "event": c.event, "at": c.time}
                self.allow.setdefault("items", []).append(item)
                added.append(item)
        if added:
            _save(self.cfg.allowlist, self.allow)
        return added

    def allow_manual(self, kind: str, rid: str, why: str = "사람이 추가") -> None:
        if not self.allowed(kind, rid):
            self.allow.setdefault("items", []).append({"kind": kind, "id": rid, "why": why, "at": _iso(_now())})
            _save(self.cfg.allowlist, self.allow)

    # 계획
    def plan(self, records: Iterable[dict]) -> dict:
        """후보 → 격리 조치 목록. 범위 제한을 넘는 것은 held, 사람이 정할 것은 human_only."""
        recs = list(records)
        self.observe(recs)  # 같은 기록 안의 내부 생성은 먼저 허용 목록으로
        seen, cands, human, skipped = set(), [], [], []
        for c, names in creations(recs):
            if (c.kind, c.id) in seen:
                continue
            seen.add((c.kind, c.id))
            if c.kind == "baseline_change":
                human.append({"what": c.id, "by": c.creator, "ip": c.ip, "at": c.time,
                              "why": "기존 자원의 권한·로그인 변경: 자동으로 막으면 서비스가 깨질 수 있어 사람이 판단"})
                continue
            if self.in_baseline(c):
                skipped.append({"kind": c.kind, "id": c.id, "why": "기준선(도입 전부터 있음)"})
                continue
            if self.allowed(c.kind, c.id):
                skipped.append({"kind": c.kind, "id": c.id, "why": "허용 목록"})
                continue
            if c.kind == "role" and (str(c.detail.get("path", "")).startswith("/aws-service-role/")
                                     or c.id.startswith("AWSServiceRole") or "logsight" in c.id.lower()):
                skipped.append({"kind": c.kind, "id": c.id, "why": "AWS 서비스 역할 또는 LogSight 자신"})
                continue
            cands.append(action_for(c, self.cfg.deny_policy_arn))
        cands.sort(key=lambda a: ORDER.get(a["kind"], 9))
        n = self.cfg.max_per_incident
        return {"actions": cands[:n], "held": [dict(a, why=f"사건당 {n}개 한도 초과") for a in cands[n:]],
                "human_only": human, "skipped": skipped}


def action_for(c: Created, deny: str = DENY_ALL) -> dict:
    base = {"kind": c.kind, "id": c.id, "created_by": c.creator, "created_ip": c.ip, "created_at": c.time,
            "event": c.event}
    if c.kind == "access_key":
        u = c.detail.get("user") or "?"
        return {**base, "op": "deactivate_key", "user": u,
                "undo_cli": f"aws iam update-access-key --user-name {u} --access-key-id {c.id} --status Active"}
    if c.kind == "user":
        return {**base, "op": "deny_user", "policy": deny,
                "undo_cli": f"aws iam detach-user-policy --user-name {c.id} --policy-arn {deny}"}
    if c.kind == "role":
        return {**base, "op": "deny_role", "policy": deny,
                "undo_cli": f"aws iam detach-role-policy --role-name {c.id} --policy-arn {deny}"}
    d = c.detail
    rng = f"Ipv6Ranges=[{{CidrIpv6={d['cidr']}}}]" if d.get("v6") else f"IpRanges=[{{CidrIp={d['cidr']}}}]"
    ports = "" if d["proto"] == "-1" else f",FromPort={d['from']},ToPort={d['to']}"
    return {**base, "op": "revoke_ingress", "group": d["group"], "rule": d,
            "undo_cli": f"aws ec2 authorize-security-group-ingress --group-id {d['group']} "
                        f"--ip-permissions IpProtocol={d['proto']}{ports},{rng}"}


# ------------------------------------------------------------------ 실행·되돌리기
def _perm(rule: dict) -> dict:
    p: dict[str, Any] = {"IpProtocol": rule["proto"]}
    if rule["proto"] != "-1":
        p["FromPort"], p["ToPort"] = int(rule["from"]), int(rule["to"])
    if rule.get("v6"):
        p["Ipv6Ranges"] = [{"CidrIpv6": rule["cidr"]}]
    else:
        p["IpRanges"] = [{"CidrIp": rule["cidr"]}]
    return p


def apply(action: dict, iam, ec2) -> dict:
    """조치 하나. 대상이 이미 없으면 gone. 바꾸기 전 상태를 before에 남긴다."""
    op = action["op"]
    try:
        if op == "deactivate_key":
            keys = iam.list_access_keys(UserName=action["user"]).get("AccessKeyMetadata", [])
            before = next((k["Status"] for k in keys if k["AccessKeyId"] == action["id"]), None)
            if before is None:
                return {"result": "gone"}
            iam.update_access_key(UserName=action["user"], AccessKeyId=action["id"], Status="Inactive")
            return {"result": "done", "before": before}
        if op in ("deny_user", "deny_role"):
            # 대상이 없는 것(gone)과 정책을 못 붙인 것(error)을 구별하려고 목록을 먼저 읽는다
            if op == "deny_user":
                pol = iam.list_attached_user_policies(UserName=action["id"])["AttachedPolicies"]
            else:
                pol = iam.list_attached_role_policies(RoleName=action["id"])["AttachedPolicies"]
            try:
                if op == "deny_user":
                    iam.attach_user_policy(UserName=action["id"], PolicyArn=action["policy"])
                else:
                    iam.attach_role_policy(RoleName=action["id"], PolicyArn=action["policy"])
            except Exception as exc:  # noqa: BLE001
                code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", type(exc).__name__)
                return {"result": "error", "error": code}
            return {"result": "done", "before": [p["PolicyArn"] for p in pol]}
        if op == "revoke_ingress":
            ec2.revoke_security_group_ingress(GroupId=action["group"], IpPermissions=[_perm(action["rule"])])
            return {"result": "done"}
    except Exception as exc:  # noqa: BLE001
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", type(exc).__name__)
        if code in ("NoSuchEntity", "InvalidGroup.NotFound", "InvalidPermission.NotFound"):
            return {"result": "gone", "error": code}
        return {"result": "error", "error": code}
    return {"result": "error", "error": f"모르는 조치 {op}"}


def revert(action: dict, iam, ec2) -> dict:
    op = action["op"]
    try:
        if op == "deactivate_key":
            iam.update_access_key(UserName=action["user"], AccessKeyId=action["id"],
                                  Status=action.get("outcome", {}).get("before") or "Active")
        elif op == "deny_user":
            if action["policy"] not in (action.get("outcome", {}).get("before") or []):
                iam.detach_user_policy(UserName=action["id"], PolicyArn=action["policy"])
        elif op == "deny_role":
            if action["policy"] not in (action.get("outcome", {}).get("before") or []):
                iam.detach_role_policy(RoleName=action["id"], PolicyArn=action["policy"])
        elif op == "revoke_ingress":
            ec2.authorize_security_group_ingress(GroupId=action["group"], IpPermissions=[_perm(action["rule"])])
        return {"result": "reverted"}
    except Exception as exc:  # noqa: BLE001
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", type(exc).__name__)
        return {"result": "error", "error": code}


# ------------------------------------------------------------------ 5분 타이머
def prepare(responder: Responder, alert_summary: dict, records: Iterable[dict], out_dir: Path,
            now: datetime | None = None) -> dict:
    """경보 처리 직후: 계획을 만들어 response.json(대기 중)으로 남긴다. 실행은 tick()이 마감 뒤에 한다."""
    now = now or _now()
    p = responder.plan(records)
    resp = {"status": "pending" if p["actions"] else "nothing", "mode": responder.cfg.mode,
            "alert": alert_summary, "created": _iso(now),
            "deadline": _iso(now + timedelta(minutes=responder.cfg.deadline_min)), **p}
    _save(out_dir / "response.json", resp)
    return resp


def summary_lines(resp: dict, out_dir: Path) -> list[str]:
    if resp["status"] == "nothing" and not resp["human_only"]:
        return []
    lines = []
    if resp["actions"]:
        test = " (시험 모드: 실제로 바꾸지 않고 기록만)" if resp["mode"] == "dry-run" else ""
        lines.append(f"{resp['deadline'][11:16]} UTC까지 확인하지 않으면 외부에서 만든 {len(resp['actions'])}개를 "
                     f"격리합니다{test}. 확인: logsight respond ack {out_dir}")
    if resp["human_only"]:
        lines.append(f"사람이 판단할 기존 자원 변경 {len(resp['human_only'])}건(자동으로 막지 않음)")
    return lines


def ack(out_dir: str | Path, who: str = "") -> bool:
    p = Path(out_dir) / "response.json"
    resp = _load(p, None)
    if not resp:
        return False
    if resp["status"] == "pending":
        resp["status"] = "acknowledged"
    resp["ack"] = {"at": _iso(_now()), "by": who or os.environ.get("USER", "")}
    _save(p, resp)
    return True


def _day_count(root: Path, now: datetime, add: int = 0) -> int:
    p = root / ".respond_count.json"
    d = _load(p, {})
    k = now.strftime("%Y-%m-%d")
    if add:
        d = {k: d.get(k, 0) + add}
        _save(p, d)
    return d.get(k, 0)


def tick(cfg: Config, out_root: str | Path, *, session=None, iam=None, ec2=None,
         now: datetime | None = None) -> list[dict]:
    """대기 중인 응답 중 마감이 지난 것을 처리한다. watch가 20초마다 부르고, cron으로도 돌릴 수 있다."""
    now = now or _now()
    root = Path(out_root)
    done = []
    responder = None
    for p in sorted(root.glob("*/response.json")):
        resp = _load(p, None)
        if not resp or resp.get("status") != "pending":
            continue
        if (_ts(resp["deadline"]) or now) > now:
            continue
        stop = cfg.stopped()
        if stop:
            resp.update(status="stopped", stopped_by=stop, finished=_iso(now))
            _save(p, resp)
            done.append(resp)
            continue
        responder = responder or Responder(cfg)  # 5분 동안 갱신된 허용 목록을 다시 읽는다
        enforce = cfg.mode == "enforce"
        if enforce and (iam is None or ec2 is None):
            import boto3
            s = session or boto3.Session()
            iam = iam or s.client("iam")
            ec2 = ec2 or s.client("ec2", region_name=(resp.get("alert") or {}).get("region") or s.region_name)
        for a in resp["actions"]:
            if responder.allowed(a["kind"], a["id"]):
                a["outcome"] = {"result": "skipped", "why": "마감 전에 허용 목록에 추가됨"}
            elif _day_count(root, now) >= cfg.max_per_day:
                a["outcome"] = {"result": "held", "why": f"하루 {cfg.max_per_day}개 한도"}
            elif not enforce:
                a["outcome"] = {"result": "would-do"}
            else:
                a["outcome"] = apply(a, iam, ec2)
                if a["outcome"]["result"] == "done":
                    _day_count(root, now, add=1)
        resp.update(status="executed" if enforce else "dry-run", finished=_iso(now))
        _save(p, resp)
        _write_undo(p.parent, resp)
        done.append(resp)
    return done


def _write_undo(out_dir: Path, resp: dict) -> None:
    lines = ["# LogSight 자동 격리 되돌리기. 한 번에: python -m logsight respond undo " + str(out_dir), ""]
    for a in resp["actions"]:
        r = (a.get("outcome") or {}).get("result")
        lines.append(f"# {a['op']} {a['id']} → {r}")
        if r == "done":
            lines.append(a["undo_cli"])
    (out_dir / "undo.sh").write_text("\n".join(lines) + "\n", encoding="utf-8")


def undo(out_dir: str | Path, *, session=None, iam=None, ec2=None) -> list[dict]:
    p = Path(out_dir) / "response.json"
    resp = _load(p, None)
    if not resp or resp.get("status") != "executed":
        return []
    if iam is None or ec2 is None:
        import boto3
        s = session or boto3.Session()
        iam = iam or s.client("iam")
        ec2 = ec2 or s.client("ec2", region_name=(resp.get("alert") or {}).get("region") or s.region_name)
    out = []
    for a in reversed(resp["actions"]):
        if (a.get("outcome") or {}).get("result") == "done":
            a["undo"] = revert(a, iam, ec2)
            out.append(a)
    resp["status"] = "reverted"
    resp["reverted"] = _iso(_now())
    _save(p, resp)
    return out

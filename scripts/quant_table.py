"""멘토링용 정량 결과 표: 규칙 수, 테스트 케이스 수, 정답 데이터 분포를 저장소 파일에서만 계산한다.

    python scripts/quant_table.py           # docs/정량_결과표.md 와 reports/quant/quant_table.json 을 다시 만든다
    python scripts/quant_table.py --check   # 다시 계산한 값이 커밋된 두 파일과 다르면 차이를 출력하고 1로 끝난다(CI)

원칙
- 숫자는 손으로 적지 않는다. 모든 값은 아래 SOURCES의 코드·결과 파일을 읽어 계산한다.
- 표의 칸마다 근거 파일 경로를 붙이고, 읽은 결과·라벨 파일의 sha256 앞 12자리를 함께 적는다.
  결과 파일이 바뀌면 해시가 바뀌므로, 표를 다시 만들지 않으면 --check가 실패한다.
- 테스트 수는 pytest가 실제로 모으는 수(--collect-only)다. 테스트를 더하거나 빼면 표를 다시 만들어야 한다.
- 결과 파일이 없는 숫자(문서에만 있는 숫자)는 표에 넣지 않고 '표에 넣지 않은 것'에 이유와 함께 적는다.
"""
from __future__ import annotations

import argparse
import difflib
import glob
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_MD = ROOT / "docs" / "정량_결과표.md"
OUT_JSON = ROOT / "reports" / "quant" / "quant_table.json"

# 규칙 id 앞부분 → 읽는 로그(표시용 이름). 앞부분이 여기에 없으면 실패해서 새 종류를 빠뜨리지 않게 한다.
PREFIX_NAME = {
    "CT": "CloudTrail",
    "WEBLOG": "웹서버 접근 로그(ALB·WAF 포함)",
    "VPC": "VPC Flow Logs·서버 방화벽 로그",
    "WAF": "AWS WAF",
    "SSH": "SSH 인증 로그",
    "HOST": "서버 인증 로그(auth.log·secure)",
    "FILE": "웹 루트 파일 검사",
    "GD": "GuardDuty 결과",
}

AIT_TESTBEDS = ["russellmitchell", "fox", "santos", "wheeler", "harrison", "shaw", "wardbeck", "wilson"]

_used: dict[str, str] = {}


def doc_note(doc: str, quote: str, text: str) -> dict:
    """결과 파일에 없는 정정 내용은 문서 문구로만 단다. 문구가 문서에 그대로 있어야 한다."""
    body = (ROOT / doc).read_text(encoding="utf-8")
    if quote not in body:
        raise SystemExit(f"{doc}에 '{quote}' 문구가 없다(정정 메모의 근거가 사라짐)")
    _used[doc] = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
    return {"text": text, "doc": doc, "quote": quote}


def rel(p: Path) -> str:
    return p.resolve().relative_to(ROOT).as_posix()


def load(relpath: str):
    p = ROOT / relpath
    _used[relpath] = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
    return json.loads(p.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ 1. 규칙
def rules_section() -> dict:
    sys.path.insert(0, str(ROOT))
    from logsight import detect, rulespec

    rules = detect.RULES
    spec = rulespec.SPEC
    if set(rules) != set(spec):
        raise SystemExit(f"detect.RULES와 rulespec.SPEC의 규칙이 다르다: {sorted(set(rules) ^ set(spec))}")

    by_prefix = Counter(k.split("_")[0] for k in rules)
    unknown = set(by_prefix) - set(PREFIX_NAME)
    if unknown:
        raise SystemExit(f"PREFIX_NAME에 없는 규칙 앞부분: {sorted(unknown)} — scripts/quant_table.py에 이름을 더할 것")
    status = Counter(spec[k].get("status", "stable") for k in rules)
    experimental = sorted(k for k in rules if spec[k].get("status") == "experimental")

    # 규칙 검증 예: tests/test_rule_validation.py 의 CASES = {규칙: (양성, 음성)}
    sys.path.insert(0, str(ROOT / "tests"))
    import test_rule_validation as trv

    cases = trv.CASES
    pos = sum(1 for v in cases.values() if v[0] is not None)
    neg = sum(1 for v in cases.values() if len(v) > 1 and v[1] is not None)

    return {
        "total": len(rules),
        "status": {"stable": status.get("stable", 0), "experimental": status.get("experimental", 0)},
        "experimental_ids": experimental,
        "by_log": [{"prefix": p, "log": PREFIX_NAME[p], "n": n}
                   for p, n in sorted(by_prefix.items(), key=lambda x: (-x[1], x[0]))],
        "by_severity": dict(sorted(Counter(v[3] for v in rules.values()).items(),
                                   key=lambda x: ["high", "medium", "low"].index(x[0]))),
        "attack_techniques": len({v[0] for v in rules.values()}),
        "by_tactic": dict(Counter(v[1] for v in rules.values()).most_common()),
        "validation_cases": {"rules": len(cases), "positive": pos, "negative": neg},
        "sources": ["logsight/detect.py (RULES)", "logsight/rulespec.py (SPEC, status)",
                    "tests/test_rule_validation.py (CASES)"],
    }


# ------------------------------------------------------------------ 2. 테스트
def tests_section() -> dict:
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"],
                       cwd=ROOT, capture_output=True, text=True)
    per_file = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^(tests/\S+\.py): (\d+)$", line.strip())
        if m:
            per_file[m.group(1)] = int(m.group(2))
    if r.returncode != 0 or not per_file:
        sys.stderr.write(r.stdout[-3000:] + r.stderr[-3000:])
        raise SystemExit("pytest --collect-only 실패(테스트 의존성 설치: pip install -r requirements.txt httpx pytest "
                         "pytest-cov \"moto[ec2,s3,cloudtrail,iam,wafv2,elbv2,guardduty,sts,sqs]>=5\")")
    top = sorted(per_file.items(), key=lambda x: (-x[1], x[0]))[:5]

    # 사양서 기반 테스트 체크리스트(docs/테스트_체크리스트.md): TC마다 방법(자동·수동·스크립트)이 적혀 있다
    sys.path.insert(0, str(ROOT / "scripts"))
    from spec_trace import CHECK, read_checklist

    body = CHECK.read_text(encoding="utf-8")
    _used[rel(CHECK)] = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
    tcs = read_checklist(body)
    how = Counter(r["method"].split()[0] if r["method"] else "(빈칸)" for r in tcs)
    return {
        "spec_checklist": {"total": len(tcs), "by_method": dict(how.most_common()),
                           "auto_linked_to_pytest": sum(1 for r in tcs if r["auto"])},
        "total": sum(per_file.values()),
        "files": len(per_file),
        "top_files": [{"file": f, "n": n} for f, n in top],
        "sources": ["python -m pytest --collect-only -q tests"],
    }


# ------------------------------------------------------------------ 3. 정답 데이터 분포
def gt_section() -> list[dict]:
    rows: list[dict] = []

    # 공방전(PR 62 재라벨): 이벤트 단위 + 사건 단위
    gl = load("reports/relabel/gongbang_labels_summary.json")["by_class"]
    gi = load("reports/relabel/gongbang_score.json")["incidents"]["truth"]
    gic = Counter(gi.values())
    rows.append({
        "dataset": "공방전(교내 AWS 공방전 로그)",
        "truth_from": "블루팀 보고서 → 원본 로그 근거로 줄마다 다시 라벨(탐지 코드 안 읽음)",
        "unit": "이벤트(CloudTrail·WAF·ALB 줄)",
        "attack": gl["attack"], "normal": gl["normal"], "other": {"불확실": gl["uncertain"]},
        "extra": f"사건 {len(gi)}개: 공격 {gic['attack']} · 공격 아님 {gic['not_attack']} · 불확실 {gic['uncertain']}",
        "files": ["reports/relabel/gongbang_labels_summary.json (by_class)",
                  "reports/relabel/gongbang_score.json (incidents.truth)"],
    })

    # BOTSv3(PR 62 재라벨)
    bl = load("reports/relabel/botsv3_labels_summary.json")["by_class"]
    bi = load("reports/relabel/botsv3_score_no_list.json")["incidents"]
    tc = bi["truth_counts"]
    rows.append({
        "dataset": "Splunk BOTSv3(AWS 부분)",
        "truth_from": "공식 질문의 답 → 원본 로그 근거로 줄마다 다시 라벨",
        "unit": "이벤트(줄)",
        "attack": bl["attack"], "normal": bl["normal"],
        "other": {"위험 설정": bl.get("risky", 0), "라벨 없음": bl.get("unlabeled", 0)},
        "extra": (f"사건 {bi['n']}개: 공격 {tc.get('attack', 0)} · 위험 설정 {tc.get('risky', 0)} · "
                  f"공격 아님 {tc.get('not_attack', 0)} · 라벨 없음 {tc.get('unlabeled', 0)}"),
        "files": ["reports/relabel/botsv3_labels_summary.json (by_class)",
                  "reports/relabel/botsv3_score_no_list.json (incidents.truth_counts)"],
    })

    # EClog(실제 온라인 상점 접근 로그 1일)
    el = load("reports/relabel/eclog_labels_summary.json")
    ec = el["by_class"]
    rows.append({
        "dataset": "EClog 1일(실제 온라인 상점 웹 로그)",
        "truth_from": "사전 등록한 A1~A3 기준(holdout_plan S7)으로 줄 라벨. 기준에 안 걸린 줄은 '라벨 없음'",
        "unit": "접근 로그 줄",
        "attack": ec["attack"], "normal": None,
        "other": {"불확실": ec.get("uncertain", 0), "해석 못 함": ec.get("unparsed", 0),
                  "라벨 없음(정상으로 가정)": ec.get("unlabeled", 0)},
        "extra": f"전체 {el['n_lines']:,}줄",
        "files": ["reports/relabel/eclog_labels_summary.json (by_class, n_lines)"],
    })

    # lab(우리가 만든 실습 웹서버)
    ll = load("reports/relabel/lab_lines.json")["lines"]
    gt = load("reports/remeasure_2026-11-26/lab/logs/ground_truth.json")["scenarios"]
    mal_det = sum(1 for s in gt if s["malicious"] and s["detectable"])
    mal_nodet = sum(1 for s in gt if s["malicious"] and not s["detectable"])
    benign = sum(1 for s in gt if not s["malicious"])
    exp_rules = sum(len(s["expected_rules"]) for s in gt if s["detectable"])
    rows.append({
        "dataset": "자체 웹서버 실습(lab)",
        "truth_from": "lab/attack.py가 공격하면서 남긴 정답(IP → 시나리오). 시나리오를 우리가 만듦",
        "unit": "접근 로그 줄",
        "attack": ll["attack"], "normal": ll["normal"], "other": {"불확실": ll.get("uncertain", 0)},
        "extra": (f"시나리오 {len(gt)}개: 공격·로그로 탐지 가능 {mal_det} · 공격·로그로 탐지 불가 {mal_nodet} · "
                  f"정상 {benign}, 기대 규칙 {exp_rules}개"),
        "files": ["reports/relabel/lab_lines.json (lines)",
                  "reports/remeasure_2026-11-26/lab/logs/ground_truth.json (scenarios)"],
    })

    # AIT-LDS 8개 테스트베드: 데이터셋 줄 라벨 + PR 62에서 찾은 라벨 빈틈
    lab_sum, gaps, per_tb = 0, Counter(), {}
    for tb in AIT_TESTBEDS:
        a = load(f"reports/relabel/ait_audit_{tb}.json")
        per_tb[tb] = sum(h["labeled"] for h in a["summary"].values())
        for host, h in a["summary"].items():
            lab_sum += h["labeled"]
            gaps[host] += h["gap_candidates"]
    rows.append({
        "dataset": f"AIT-LDS v2 ({len(AIT_TESTBEDS)}개 테스트베드)",
        "truth_from": "데이터셋 제공 줄 라벨(공격자 실행 기록에서 만듦). 라벨은 인트라넷 서버에만 있음",
        "unit": "로그 줄",
        "attack": lab_sum, "normal": None,
        "other": {"라벨 빠진 공격 줄(빈틈)": sum(gaps.values())},
        "extra": ("테스트베드별 라벨 줄: " + " · ".join(f"{tb} {n:,}" for tb, n in per_tb.items())
                  + ". 빈틈: " + " · ".join(f"{h} {n}" for h, n in sorted(gaps.items()))
                  + ". 정상 줄 수는 감사 파일에 없음"),
        "note": doc_note("docs/데이터_전수_라벨검증_2026-11-26.md", "라벨 빠진 공격 줄 92줄",
                         "빈틈은 데이터셋 라벨에 없는 공격 줄이다. 예전 계산은 이 줄을 오탐으로 셌다"),
        "files": [f"reports/relabel/ait_audit_<{len(AIT_TESTBEDS)}곳>.json (summary.*.labeled, gap_candidates)"],
    })

    # 처음 보는 데이터: 표본 단위 정답
    s = load("reports/public/splunk_attack_data.json")
    datasets = {tuple(r["data"]) for r in s["rows"]}
    rows.append({
        "dataset": "Splunk attack_data (AWS 탐지 표본)",
        "truth_from": "데이터 제공자가 '이 로그에 이 행동이 있다'고 붙인 표본",
        "unit": "탐지 항목(표본)",
        "attack": s["n_detections"], "normal": 0, "other": {},
        "extra": f"서로 다른 표본 파일 묶음 {len(datasets)}개(같은 표본을 쓰는 탐지 {sum(1 for r in s['rows'] if r['duplicate_data'])}개)",
        "files": ["reports/public/splunk_attack_data.json (n_detections, rows[].data)"],
    })

    for half in ("A", "B"):
        p = load(f"reports/public/panther_ct_{half}.json")
        ex = Counter(bool(i["expected"]) for i in p["items"])
        rows.append({
            "dataset": f"Panther CloudTrail 시험 이벤트 {half} 반",
            "truth_from": "Panther 규칙 시험 이벤트의 ExpectedResult(Panther가 붙임)",
            "unit": "시험 이벤트",
            "attack": ex[True], "normal": ex[False], "other": {},
            "extra": f"Panther 규칙 {len(p['per_rule'])}개(양성 시험이 있는 규칙)",
            "files": [f"reports/public/panther_ct_{half}.json (items[].expected, per_rule)"],
        })

    inv = load("reports/public/invictus_aws_after.json")
    rows.append({
        "dataset": "Invictus(Stratus Red Team 실행 CloudTrail)",
        "truth_from": "CloudTrail 원문 userAgent의 stratus-red-team_<id> 문자열",
        "unit": "공격 실행(run)",
        "attack": len(inv["runs"]), "normal": None,
        "other": {"라벨 없는 이벤트": inv["unlabeled"]},
        "extra": "",
        "files": ["reports/public/invictus_aws_after.json (runs, unlabeled)"],
    })

    cam = []
    for f in sorted(glob.glob("reports/public/camlds_*.json", root_dir=ROOT)):
        f = f.replace("\\", "/")
        c = load(f)
        cam.append((c["scenario"], c["victim"], c["summary"]["steps"], c["summary"]["visible"]))
    scen = {}
    for sc, _, steps, _ in cam:
        scen[sc] = steps
    rows.append({
        "dataset": f"CAM-LDS (시나리오 {len(scen)}개, 호스트별 {len(cam)}개 파일)",
        "truth_from": "AttackMate 공격 실행 기록(시각·ATT&CK)",
        "unit": "공격 단계",
        "attack": sum(scen.values()), "normal": None, "other": {},
        "extra": ("시나리오별 단계 " + " · ".join(f"{k} {v}" for k, v in scen.items())
                  + ". 로그에 흔적 있는 단계(호스트별): "
                  + " · ".join(f"{sc.split('_')[1]}/{v} {vis}" for sc, v, _, vis in cam)),
        "files": ["reports/public/camlds_*.json (summary.steps, summary.visible)"],
        "note": doc_note("docs/데이터_전수_라벨검증_2026-11-26.md", "흔적 있는 단계 중 탐지 7/13 → 5/11",
                         "시나리오 1의 흔적 있는 단계 13은 결과 파일 값이다. 채점 시간 창이 옆 단계 줄을 끌어온 것이라 "
                         "문서에서 11로 정정했다(결과 파일은 다시 만들지 않음)"),
    })
    return rows


def excluded_section() -> list[dict]:
    pre = load("reports/public/ctf_main_precheck.json")
    ct = load("reports/public/ctf_cloudtrail.json")
    return [
        {"what": "CTF 본대회(11/25)",
         "why": (f"외부 참가자 접속이 없어 측정 대상이 아님. 접근 로그 사전 확인 measured={pre['measured']}, "
                 f"CloudTrail 공격 세션 {ct['attack_sessions']}건"),
         "files": ["reports/public/ctf_main_precheck.json", "reports/public/ctf_cloudtrail.json"]},
        {"what": "CTF 리허설(11/23) 정답표 F1~F6",
         "why": "줄 단위 정답지·결과 파일이 저장소에 없음(원본 대조는 docs/데이터_전수_라벨검증_2026-11-26.md 4절)",
         "files": []},
        {"what": "Zenodo 20001206 웹 로그",
         "why": "기준 목록을 표시된 줄을 본 뒤 늘려서 판정에 쓰지 않기로 한 데이터",
         "files": []},
        {"what": "회의 요약에 있던 정확도 변화 숫자",
         "why": "저장소에 대응하는 결과 파일이 없고, 회의 요약에 잘못 들어간 숫자로 확인됨(2026-11-26). 쓰지 않음",
         "files": []},
    ]


# ------------------------------------------------------------------ 출력
def build() -> dict:
    _used.clear()
    data = {
        "rules": rules_section(),
        "tests": tests_section(),
        "ground_truth": gt_section(),
        "excluded": excluded_section(),
    }
    data["inputs_sha256_12"] = dict(sorted(_used.items()))
    return data


def fmt(n) -> str:
    return "—" if n is None else f"{n:,}"


def render_md(d: dict) -> str:
    r, t = d["rules"], d["tests"]
    L = [
        "# 정량 결과 표 (규칙 · 테스트 · 정답 데이터)",
        "",
        "> 이 문서는 `python scripts/quant_table.py`가 저장소 파일만 읽어 만든다. **손으로 고치지 않는다.**",
        "> CI가 `python scripts/quant_table.py --check`로 다시 계산해, 코드·테스트·결과 파일이 바뀌었는데 이 문서를",
        "> 다시 만들지 않았으면 실패한다. 같은 값은 `reports/quant/quant_table.json`에도 있다.",
        "",
        "## 1. 탐지 규칙",
        "",
        "| 항목 | 값 | 근거 |",
        "|---|---|---|",
        f"| 탐지 규칙 수 | **{r['total']}** | `logsight/detect.py` RULES |",
        f"| 정식 / 시험 중(경보에서 뺌) | {r['status']['stable']} / {r['status']['experimental']} | `logsight/rulespec.py` status |",
        f"| 대응 MITRE ATT&CK 기법(서로 다른 것) | {r['attack_techniques']} | `logsight/detect.py` RULES[0] |",
        f"| 심각도 high / medium / low | {' / '.join(str(v) for v in r['by_severity'].values())} | `logsight/detect.py` RULES[3] |",
        f"| 규칙마다 양성·음성 검증 예 | 규칙 {r['validation_cases']['rules']}개 × (양성 {r['validation_cases']['positive']} + 음성 {r['validation_cases']['negative']}) | `tests/test_rule_validation.py` CASES |",
        "",
        "읽는 로그별 규칙 수:",
        "",
        "| 규칙 id 앞부분 | 읽는 로그 | 규칙 수 |",
        "|---|---|---|",
    ]
    L += [f"| `{x['prefix']}_` | {x['log']} | {x['n']} |" for x in r["by_log"]]
    L += [
        "",
        f"시험 중 규칙: {', '.join('`' + x + '`' for x in r['experimental_ids'])}",
        "",
        "## 2. 테스트",
        "",
        "| 항목 | 값 | 근거 |",
        "|---|---|---|",
        f"| 자동 테스트 케이스 수 | **{t['total']}** | `python -m pytest --collect-only -q tests` |",
        f"| 테스트 파일 수 | {t['files']} | 같은 명령 |",
        f"| 사양서 기반 테스트 체크리스트 TC 수 | **{t['spec_checklist']['total']}** "
        f"({' · '.join(f'{k} {v}' for k, v in t['spec_checklist']['by_method'].items())}) | "
        "`docs/테스트_체크리스트.md` (`scripts/spec_trace.py` read_checklist) |",
        f"| 그중 pytest 테스트를 가리키는 TC | {t['spec_checklist']['auto_linked_to_pytest']} | 같은 파일의 `tests/...::이름` |",
        f"| pytest 중 규칙 검증 예(양성+음성) | {r['validation_cases']['positive'] + r['validation_cases']['negative']} | `tests/test_rule_validation.py` CASES (하나의 테스트 함수가 모든 규칙을 돈다) |",
        "",
        "테스트가 많은 파일: " + ", ".join(f"`{x['file']}` {x['n']}" for x in t["top_files"]),
        "",
        "## 3. 정답 데이터 분포",
        "",
        "'공격'·'정상'은 정답지 기준이다(탐지 결과가 아님). '—'는 그 데이터의 정답지가 정상 수를 세지 않는다는 뜻이다.",
        "",
        "| 데이터 | 단위 | 공격 | 정상 | 그 밖 | 추가 | 정답지 출처 | 근거 파일 |",
        "|---|---|---:|---:|---|---|---|---|",
    ]
    for g in d["ground_truth"]:
        other = " · ".join(f"{k} {fmt(v)}" for k, v in g["other"].items()) or "—"
        files = "<br>".join(f"`{f}`" for f in g["files"])
        L.append(f"| {g['dataset']} | {g['unit']} | {fmt(g['attack'])} | {fmt(g['normal'])} | {other} | "
                 f"{g['extra'] or '—'} | {g['truth_from']} | {files} |")
    notes = [g for g in d["ground_truth"] if g.get("note")]
    if notes:
        L += ["", "정정 메모(결과 파일이 아니라 문서에만 있는 내용. 스크립트가 문서에 그 문구가 있는지 확인한다):", ""]
        L += [f"- **{g['dataset']}**: {g['note']['text']}. 근거: `{g['note']['doc']}` \"{g['note']['quote']}\""
              for g in notes]
    L += [
        "",
        "## 4. 표에 넣지 않은 것",
        "",
        "| 무엇 | 이유 | 근거 |",
        "|---|---|---|",
    ]
    for e in d["excluded"]:
        L.append(f"| {e['what']} | {e['why']} | {'<br>'.join('`' + f + '`' for f in e['files']) or '—'} |")
    L += [
        "",
        "## 5. 입력 파일 해시",
        "",
        "표를 만들 때 읽은 결과·라벨 파일과 sha256 앞 12자리. 하나라도 바뀌면 `--check`가 실패한다. 규칙·테스트 수는 코드에서 바로 세므로 해시 대신 수 자체를 비교한다.",
        "",
        "| 파일 | sha256[:12] |",
        "|---|---|",
    ]
    L += [f"| `{k}` | `{v}` |" for k, v in d["inputs_sha256_12"].items()]
    L += ["", "## 다시 만들기", "", "```", "python scripts/quant_table.py          # 다시 만들기",
          "python scripts/quant_table.py --check  # 커밋된 표와 같은지 확인(CI)", "```", ""]
    return "\n".join(L)


# 지금 상태를 말하는 문서 문구(날짜가 붙은 예전 기록 문서는 보지 않는다). (파일, 정규식, 비교할 값 경로)
DOC_CLAIMS = [
    ("README.md", r"테스트 ([0-9,]+)개", ("tests", "total")),
    ("README.md", r"탐지 규칙 ([0-9]+)개", ("rules", "total")),
    ("docs/README.md", r"탐지 규칙 ([0-9]+)개", ("rules", "total")),
    ("docs/README.md", r"테스트 케이스 ([0-9,]+)개", ("tests", "spec_checklist", "total")),
]


def check_docs(d: dict) -> list[str]:
    errs = []
    for f, pat, path in DOC_CLAIMS:
        want = d
        for k in path:
            want = want[k]
        text = (ROOT / f).read_text(encoding="utf-8")
        found = list(re.finditer(pat, text))
        if not found:
            errs.append(f"{f}에 '{pat}' 문구가 없음(문구를 바꿨다면 scripts/quant_table.py DOC_CLAIMS도 고칠 것)")
        for m in found:
            if int(m.group(1).replace(",", "")) != want:
                errs.append(f"{f} '{m.group(0)}' ≠ 다시 계산한 값 {want}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="다시 만들지 않고 커밋된 파일과 비교만 한다")
    args = ap.parse_args()
    d = build()
    js = json.dumps(d, ensure_ascii=False, indent=1) + "\n"
    md = render_md(d)
    if args.check:
        bad = 0
        for path, new in ((OUT_JSON, js), (OUT_MD, md)):
            old = path.read_text(encoding="utf-8") if path.exists() else ""
            if old != new:
                bad += 1
                print(f"{rel(path)}가 다시 계산한 값과 다르다:")
                sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                           "커밋된 파일", "다시 계산", n=0))
        readme = check_docs(d)
        for e in readme:
            print(e)
        bad += len(readme)
        if bad:
            print("\n고치는 법: python scripts/quant_table.py 를 돌려 두 파일을 함께 커밋한다. "
                  "README·docs/README의 숫자는 다시 계산한 값으로 손으로 고친다.")
            return 1
        print(f"정량 결과 표가 최신이다(규칙 {d['rules']['total']}, 테스트 {d['tests']['total']}, "
              f"정답 데이터 {len(d['ground_truth'])}종)")
        return 0
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(js, encoding="utf-8")
    OUT_MD.write_text(md, encoding="utf-8")
    print(f"{rel(OUT_MD)}, {rel(OUT_JSON)} 다시 만듦")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""실제 로그 오탐률 측정 도구(scripts/public/eval_reallog.py)와 EClog 변환기. 로그는 직접 만든 합성 줄만 쓴다."""
import csv
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "public" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _profile(tmp_path, lines):
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    p = tmp_path / "profile.json"
    p.write_text(json.dumps({"name": "합성", "log_paths": {"access": [str(log)]}, "year": 2026}), encoding="utf-8")
    return p


NORMAL = '203.0.113.{i} - - [22/Oct/2026:03:00:{s:02d} +0000] "GET /products?page={i} HTTP/1.1" 200 1200 "-" "Mozilla/5.0"'
ATTACK = '198.51.100.9 - - [22/Oct/2026:03:01:00 +0000] "GET /index.php?id=1%27%20union%20select%201,2-- HTTP/1.1" 200 900 "-" "sqlmap/1.7"'


def test_counts_and_label_correction(tmp_path):
    m = _load("eval_reallog")
    prof = _profile(tmp_path, [NORMAL.format(i=i, s=i) for i in range(1, 41)] + [ATTACK])
    out, review = tmp_path / "o.json", tmp_path / "r.tsv"
    assert m.main(["--profile", str(prof), "--out", str(out), "--review", str(review)]) == 0
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["access_lines"] == 41
    assert res["flagged_lines"] >= 1
    assert "sqlmap" not in out.read_text(encoding="utf-8")  # 결과 JSON에 원본 줄 없음
    rows = list(csv.DictReader(open(review, encoding="utf-8"), delimiter="\t"))
    assert any("sqlmap" in r["line"] for r in rows)
    for r in rows:
        r["class"], r["reason"] = ("attack", "sqlmap UA와 union select") if "sqlmap" in r["line"] else ("fp", "")
    with open(review, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=m.REVIEW_COLS, delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    assert m.main(["--profile", str(prof), "--out", str(out), "--labels", str(review), "--review", str(review)]) == 0
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["confirmed_attack_lines"] >= 1 and res["unclassified_flagged"] == 0
    assert res["fp_lines"] == res["flagged_lines"] - res["confirmed_attack_lines"]
    # 다시 쓴 분류표가 사람이 적은 분류를 지우지 않음
    assert any(r["class"] for r in csv.DictReader(open(review, encoding="utf-8"), delimiter="\t"))


def test_attack_needs_reason(tmp_path):
    m = _load("eval_reallog")
    t = tmp_path / "l.tsv"
    t.write_text("ref\trules\tsrc_ip\tclass\treason\tline\na.log:1\tX\t1.2.3.4\tattack\t\tx\n", encoding="utf-8")
    try:
        m.load_labels(t)
    except SystemExit as e:
        assert "reason" in str(e)
    else:
        raise AssertionError("근거 없는 attack 분류를 받아들임")


def test_eclog_converter_keeps_ip_identity(tmp_path):
    m = _load("eclog_to_combined")
    src = tmp_path / "e.csv"
    src.write_text("IpId,UserId,TimeStamp,HttpMethod,Uri,HttpVersion,ResponseCode,Bytes,Referrer,UserAgent\n"
                   '7,1,2019-12-11 10:00:00,GET,/a?x=1,HTTP/1.1,200,10,-,"Mozilla/5.0 (X11)"\n'
                   "7,1,2019-12-11 10:00:01,GET,/b,HTTP/1.1,404,0,,curl/8\n"
                   "8,2,2019-12-11 10:00:02,POST,/c,1.1,302,0,-,UA\n", encoding="utf-8")
    dst = tmp_path / "access.log"
    assert m.convert(src, dst) == 3
    lines = dst.read_text(encoding="utf-8").splitlines()
    ips = [ln.split()[0] for ln in lines]
    assert ips[0] == ips[1] != ips[2] and ips[0].startswith("100.")
    assert '"GET /a?x=1 HTTP/1.1" 200 10' in lines[0] and "[11/Dec/2019:10:00:00 +0000]" in lines[0]
    assert '"POST /c HTTP/1.1" 302' in lines[2]

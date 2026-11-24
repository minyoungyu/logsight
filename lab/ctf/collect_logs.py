#!/usr/bin/env python3
"""CTF 대회 로그를 내려받아 LogFinder가 바로 읽는 폴더로 만든다.

  python lab/ctf/collect_logs.py --logs-bucket <logs 버킷> --waf-bucket <waf 버킷> \
      --region ap-southeast-2 --out data/ctf-2026-11

  (lab/ctf/terraform 에서 `terraform output -json buckets` 로 버킷 이름을 본다)

왜 필요한가: 팀 서버는 1분마다 새로 쌓인 부분만 `hosts/<팀>/<로그>/<epoch>-<시작바이트>.log` 로 올린다.
이 조각 이름에는 로그 종류가 없어서, 그대로 넣으면 LogFinder가 내용만 보고 종류를 짐작한다.
그러면 SSH 줄이 없는 auth.log(sudo만 있는 F4 흔적)를 알아보지 못하고 버린다.
그래서 조각을 원래 순서대로 이어 붙여 `hosts/<팀>-<로그>.log` 처럼 종류가 드러나는 이름으로 만든다.

결과 폴더:
  raw/                 버킷에서 받은 원본(손대지 않음) + SHA256SUMS
  analyze/aws/         CloudTrail·VPC Flow·ALB·WAF (원래 이름 그대로, 이름에 종류가 들어 있다)
  analyze/hosts/       팀별 nginx 접속·오류, auth.log (조각을 이어 붙인 것)
  extra/               LogFinder가 읽지 않는 호스트 로그(messages, php-fpm). 사람이 볼 때만
  pieces.json          이어 붙인 조각 목록과 끊김(중간에 처음부터 다시 보낸 곳)

분석:  python -m logsight analyze data/ctf-2026-11/analyze --no-ai --env lab/ctf/environment.json \
           --out data/ctf-2026-11/report_rules
       (environment.json: 운영진 계정 ctf-deployer의 배포·SSM·점검 조회를 정상 작업으로 표시)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# 조각 이름 → 이어 붙인 파일 이름. LogFinder 판별(normalize.detect_kind)은 파일 이름의 낱말을 본다.
HOST_LOGS = {
    "nginx-access": ("analyze", "nginx-access.log"),   # weblog
    "nginx-error": ("analyze", "nginx-error.log"),     # weberror
    "auth": ("analyze", "auth.log"),                   # sshauth (sudo·su·SSH)
    "secure": ("analyze", "secure.log"),               # sshauth (RHEL 계열 기본 경로)
    "messages": ("extra", "messages.log"),
    "php-fpm": ("extra", "php-fpm.log"),
    "nginx-body": ("extra", "nginx-body.log"),   # 관리자 로그인·fetch POST 본문(사람이 F2·F5 근거로 볼 때)
    "audit": ("extra", "audit.log"),             # 웹 계정의 명령 실행(auditd, key=ctf_webexec)
}
_PIECE = re.compile(r"^(?P<epoch>\d+)-(?P<off>\d+)\.log$")


def assemble_hosts(hosts_dir: Path, out: Path) -> dict:
    """hosts/<팀>/<로그>/<epoch>-<off>.log 조각을 팀·로그별로 이어 붙인다. 조각 목록을 돌려준다."""
    report: dict = {}
    if not hosts_dir.is_dir():
        return report
    for team_dir in sorted(p for p in hosts_dir.iterdir() if p.is_dir()):
        team = team_dir.name
        for log_dir in sorted(p for p in team_dir.iterdir() if p.is_dir()):
            name = log_dir.name
            where, fname = HOST_LOGS.get(name, ("extra", f"{name}.log"))
            pieces = []
            for f in log_dir.iterdir():
                m = _PIECE.match(f.name)
                if m:
                    pieces.append((int(m["epoch"]), int(m["off"]), f))
            if not pieces:
                continue
            # 보낸 시각 순서. 같은 초에 두 조각이면 시작 바이트 순서.
            pieces.sort(key=lambda x: (x[0], x[1]))
            dest = out / where / "hosts" / f"{team}-{fname}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            restarts = []
            expected = 0
            with dest.open("wb") as w:
                for epoch, off, f in pieces:
                    data = f.read_bytes()
                    if off != expected:
                        # 0으로 돌아가면 서버 쪽 파일이 잘리거나 바뀐 것(로그 회전·삭제 시도). 그대로 이어 붙이고 기록만.
                        restarts.append({"epoch": epoch, "offset": off, "expected": expected})
                    # 조각이 줄 중간에서 끊겨도 다음 조각이 그 줄의 뒷부분이라 줄바꿈을 넣지 않는다.
                    w.write(data)
                    expected = off + len(data)
            report[f"{team}/{name}"] = {"file": str(dest.relative_to(out)), "pieces": len(pieces),
                                        "bytes": dest.stat().st_size, "restarts": restarts}
    _dedupe_secure(out, report)
    return report


def _dedupe_secure(out: Path, report: dict) -> None:
    """Amazon Linux 2023은 같은 줄을 auth.log와 secure에 똑같이 남긴다. 둘 다 분석에 넣으면 sudo·계정 생성이
    두 번씩 세진다(리허설: ec2-user 계정 생성 2대 → 4건). 내용이 같으면 secure를 extra/로 옮긴다."""
    for key in [k for k in report if k.endswith("/secure")]:
        team = key.split("/", 1)[0]
        auth = report.get(f"{team}/auth")
        if not auth:
            continue
        sec_p, auth_p = out / report[key]["file"], out / auth["file"]
        if "analyze" in sec_p.relative_to(out).parts and sec_p.read_bytes() == auth_p.read_bytes():
            moved = out / "extra" / "hosts" / sec_p.name
            moved.parent.mkdir(parents=True, exist_ok=True)
            sec_p.replace(moved)
            report[key]["file"] = str(moved.relative_to(out))
            report[key]["note"] = "auth.log와 내용이 같아 분석에서 뺌(중복 집계 방지)"


def _sync(src: str, dest: Path, region: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["aws", "s3", "sync", src, str(dest), "--region", region, "--only-show-errors"], check=True)


def _sha256sums(root: Path) -> None:
    lines = []
    for p in sorted(x for x in root.rglob("*") if x.is_file() and x.name != "SHA256SUMS"):
        lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root)}")
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CTF 로그를 내려받아 LogFinder 분석용 폴더로 정리")
    ap.add_argument("--logs-bucket", help="logs 버킷(cloudtrail/ vpcflow/ alb/ hosts/)")
    ap.add_argument("--waf-bucket", help="aws-waf-logs-… 버킷")
    ap.add_argument("--region", default="ap-southeast-2")
    ap.add_argument("--out", required=True, help="결과 폴더(data/ 아래, 저장소에 올리지 않는다)")
    ap.add_argument("--skip-download", action="store_true", help="raw/가 이미 있으면 내려받지 않고 정리만")
    a = ap.parse_args(argv)

    out = Path(a.out)
    raw = out / "raw"
    if not a.skip_download:
        if not a.logs_bucket:
            ap.error("--logs-bucket 이 필요하다(정리만 하려면 --skip-download)")
        if shutil.which("aws") is None:
            print("aws CLI가 없다", file=sys.stderr)
            return 2
        _sync(f"s3://{a.logs_bucket}/", raw / "logs", a.region)
        if a.waf_bucket:
            _sync(f"s3://{a.waf_bucket}/", raw / "waf", a.region)
        _sha256sums(raw)

    aws_out = out / "analyze" / "aws"
    for sub in ("cloudtrail", "vpcflow", "alb"):
        src = raw / "logs" / sub
        if src.is_dir():
            shutil.copytree(src, aws_out / sub, dirs_exist_ok=True)
    if (raw / "waf").is_dir():
        shutil.copytree(raw / "waf", aws_out / "waf", dirs_exist_ok=True)

    report = assemble_hosts(raw / "logs" / "hosts", out)
    (out / "pieces.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[완료] 호스트 로그 {len(report)}개 이어 붙임 → {out / 'analyze'}")
    for k, v in report.items():
        flag = f"  끊김 {len(v['restarts'])}곳" if v["restarts"] else ""
        print(f"  {k}: 조각 {v['pieces']}개, {v['bytes']}바이트{flag}")
    print(f"분석: python -m logsight analyze {out / 'analyze'} --no-ai --out {out / 'report_rules'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

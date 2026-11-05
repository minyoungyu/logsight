#!/usr/bin/env bash
# Stratus Red Team(DataDog, Apache-2.0)으로 실습 계정에서 AWS 공격 기법을 하나씩 일으키고 시각을 적는다.
# 반드시 이 실습 전용 계정에서만 돌린다. 각 기법은 준비(warmup) → 실행(detonate) → 정리(cleanup) 순서다.
#
# 사용: bash lab/aws/stratus/run.sh [기법ID ...]   (없으면 expected.tsv의 기법 전부)
# 결과: data/stratus/<날짜>/times.tsv  (technique, start, end, status)
set -euo pipefail
command -v stratus >/dev/null || { echo "stratus 설치 필요: https://github.com/DataDog/stratus-red-team"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="data/stratus/$(date -u +%Y%m%d_%H%M)"
mkdir -p "$OUT"
if [[ $# -gt 0 ]]; then TECHS=("$@"); else mapfile -t TECHS < <(grep -v '^#' "$HERE/expected.tsv" | cut -f1); fi
printf 'technique\tstart\tend\tstatus\n' > "$OUT/times.tsv"
for t in "${TECHS[@]}"; do
  echo "[*] $t"
  stratus warmup "$t" >/dev/null 2>&1 || { printf '%s\t-\t-\twarmup_failed\n' "$t" >> "$OUT/times.tsv"; continue; }
  s=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if stratus detonate "$t" >"$OUT/$t.log" 2>&1; then st=ok; else st=detonate_failed; fi
  e=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '%s\t%s\t%s\t%s\n' "$t" "$s" "$e" "$st" >> "$OUT/times.tsv"
  stratus cleanup "$t" >/dev/null 2>&1 || echo "  (정리 실패: stratus cleanup $t 를 다시 실행)"
  sleep 60   # 기법끼리 시간이 겹치지 않게 1분 띄운다
done
echo "[*] 끝. CloudTrail 전달까지 15분쯤 기다린 뒤: bash lab/aws/collect.sh ... 로 로그를 받고"
echo "    python lab/aws/stratus/score.py $OUT/times.tsv <분석 결과 report.json>"

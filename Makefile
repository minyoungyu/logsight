# 한 줄 실행 진입점. 자세한 설명은 README 참고.
.PHONY: test lint regress smoke run

test:
	python -m pytest --cov --cov-report=term

lint:
	ruff check .

# 처음 보는 데이터에서 한 번 잡은 것을 계속 잡는지(Splunk 표본을 data/에 내려받는다)
regress:
	python scripts/regress_samples.py
	python scripts/public/regress_splunk.py --cache data/public/attack_data

# 샘플로 AWS·웹 두 파이프라인이 끝까지 도는지 빠르게 확인한다
smoke:
	python -m logsight analyze samples/demo --out reports/ci --no-ai
	python -m logsight scan --profile samples/web/profile.json --no-ai --out reports/ci-web

# 공개 데모 모드로 웹 앱 실행(업로드·API 문서·AI 호출 없음)
run:
	LOGSIGHT_DEMO=1 uvicorn app:app --port 8000

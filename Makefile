# 한 줄 실행 진입점. 자세한 설명은 README 참고.
.PHONY: test smoke run

test:
	python -m unittest discover -s tests -v

# 샘플로 AWS·웹 두 파이프라인이 끝까지 도는지 빠르게 확인한다
smoke:
	python -m logsight analyze samples/demo --out reports/ci --no-ai
	python -m logsight scan --profile samples/web/profile.json --no-ai --out reports/ci-web

# 공개 데모 모드로 웹 앱 실행(업로드·API 문서·AI 호출 없음)
run:
	LOGSIGHT_DEMO=1 uvicorn app:app --port 8000

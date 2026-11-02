# 공개 데모 이미지. 실행 시 LOGSIGHT_DEMO=1 로 고정되어 업로드·API 문서·AI 호출이 꺼진다.
# 취약 테스트 사이트(lab/)와 테스트 코드는 .dockerignore 로 이미지에서 뺀다.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOGSIGHT_DEMO=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY logsight ./logsight
COPY samples ./samples
COPY reports/ctf/compare_gongbang.html ./reports/ctf/compare_gongbang.html

RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000
# App Runner/ECS 등은 PORT 환경변수를 줄 수 있다. 없으면 8000.
CMD ["sh", "-c", "exec uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]

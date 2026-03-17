FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TRIAGE_RUNTIME_MODE=docker \
    TRIAGE_LOG_FILE_ENABLED=1 \
    TRIAGE_LOG_FILE_PATH=/app/data/triage-engine.log

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip && \
    python -m pip install -r /app/requirements.txt

COPY . /app

RUN python -m pip install ".[server,sigma]" && \
    mkdir -p /app/data /app/cases /app/uploads

EXPOSE 8000

VOLUME ["/app/data", "/app/cases"]

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]

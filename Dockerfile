FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CORROBORA_RUNTIME_MODE=docker \
    CORROBORA_LOG_FILE_ENABLED=1 \
    CORROBORA_LOG_FILE_PATH=/app/data/corrobora.log

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip && \
    python -m pip install -r /app/requirements.txt

COPY . /app

RUN python -m pip install ".[server,sigma]" && \
    groupadd --gid 10001 triage && \
    useradd --uid 10001 --gid triage --no-create-home triage && \
    mkdir -p /app/data /app/cases /app/uploads && \
    chown -R triage:triage /app/data /app/cases /app/uploads

USER 10001:10001

EXPOSE 8000

VOLUME ["/app/data", "/app/cases"]

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]

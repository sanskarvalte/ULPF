FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend \
    ULPF_DB_PATH=/app/data/ulpf.duckdb \
    ULPF_EXPORTS_DIR=/app/exports

WORKDIR /app

RUN mkdir -p /app/data /app/exports /app/offline_packages

COPY requirements.txt /app/requirements.txt
COPY offline_packages /app/offline_packages

RUN pip install --no-cache-dir --no-index --find-links=/app/offline_packages -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

COPY backend /app/backend
COPY frontend /app/frontend
COPY mappings /app/mappings
COPY integrations /app/integrations
COPY datasets /app/datasets

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--app-dir", "/app/backend", "--host", "0.0.0.0", "--port", "8000"]

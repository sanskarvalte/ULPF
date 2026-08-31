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

# Install dependencies using local offline packages first
RUN pip install --no-cache-dir --no-index --find-links=/app/offline_packages -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY backend /app/backend
COPY frontend /app/frontend
COPY mappings /app/mappings
COPY integrations /app/integrations
COPY datasets /app/datasets
COPY docker/entrypoint.sh /app/docker/entrypoint.sh

RUN chmod +x /app/docker/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]

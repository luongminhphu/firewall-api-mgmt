FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Ho_Chi_Minh

WORKDIR /srv

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl tzdata && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY backend /srv/backend
COPY frontend /srv/frontend

ENV FRONTEND_DIR=/srv/frontend \
    PYTHONPATH=/srv/backend

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD curl -fsS http://localhost:8080/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--app-dir", "/srv/backend"]

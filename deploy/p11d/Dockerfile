FROM python:3.14.7-alpine3.23@sha256:6b8f06d04d5305c1d1288435388df9165ab41e681fae6439d6349d8053cc3f83
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY apps ./apps
RUN pip install --no-cache-dir fastapi==0.141.1 httpx==0.28.1 uvicorn==0.52.1 cryptography==50.0.0
USER 10001:10001

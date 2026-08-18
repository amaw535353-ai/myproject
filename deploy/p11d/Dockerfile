FROM python:3.12.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY apps ./apps
RUN pip install --no-cache-dir fastapi==0.141.1 httpx==0.28.1 uvicorn==0.52.1 cryptography==50.0.0
USER 10001:10001

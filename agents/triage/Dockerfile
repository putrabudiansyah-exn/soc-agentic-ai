# Triage Agent — Lightweight Stack Dockerfile
# SAO migration: change FROM line to SAO ECR base image
FROM python:3.11-slim

WORKDIR /app

# Install deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY core/           ./core/
COPY agents/triage/  ./agents/triage/
COPY policies/       ./policies/

# Non-root user
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent

ENV PYTHONPATH=/app
CMD ["uvicorn", "agents.triage.main:app", "--host", "0.0.0.0", "--port", "8080"]

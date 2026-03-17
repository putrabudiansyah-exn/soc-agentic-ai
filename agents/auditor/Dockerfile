FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY core/ ./core/
COPY agents/auditor/ ./agents/auditor/
COPY policies/ ./policies/
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent
ENV PYTHONPATH=/app
CMD ["uvicorn", "agents.auditor.main:app", "--host", "0.0.0.0", "--port", "8081"]

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY core/ ./core/
COPY agents/remediation/ ./agents/remediation/
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent
ENV PYTHONPATH=/app
CMD ["uvicorn", "agents.remediation.main:app", "--host", "0.0.0.0", "--port", "8083"]

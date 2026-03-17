FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY core/ ./core/
COPY agents/compliance/ ./agents/compliance/
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent
ENV PYTHONPATH=/app
CMD ["uvicorn", "agents.compliance.main:app", "--host", "0.0.0.0", "--port", "8082"]

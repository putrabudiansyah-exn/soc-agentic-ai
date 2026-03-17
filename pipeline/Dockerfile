FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir redis[hiredis] httpx asyncpg python-dotenv
COPY core/     ./core/
COPY pipeline/ ./pipeline/
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent
ENV PYTHONPATH=/app
CMD ["python", "-m", "pipeline.event_consumer"]

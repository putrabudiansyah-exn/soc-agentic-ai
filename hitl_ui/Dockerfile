FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] asyncpg jinja2 python-dotenv
COPY hitl_ui/ ./hitl_ui/
RUN addgroup --system sao && adduser --system --ingroup sao saoagent
USER saoagent
ENV PYTHONPATH=/app
CMD ["uvicorn", "hitl_ui.main:app", "--host", "0.0.0.0", "--port", "8090"]

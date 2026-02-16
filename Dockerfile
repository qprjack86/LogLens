FROM python:3.9.18-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -r appgroup && \
    useradd -r -d /home/appuser -m appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup . .
RUN chown -R appuser:appgroup /app /home/appuser

USER appuser

EXPOSE 8501

CMD ["python", "app.py"]

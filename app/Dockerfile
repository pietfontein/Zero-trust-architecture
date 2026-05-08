FROM python:3.13-slim

WORKDIR /app
RUN apt-get update \
    && apt-get upgrade -y \
    && addgroup --system --gid 1001 app \
    && adduser --system --uid 1001 --gid 1001 --home /app app \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R app:app /app

USER 1001:1001

CMD ["gunicorn", "--chdir", "/tmp", "--pythonpath", "/app", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "30", "--worker-tmp-dir", "/tmp", "--access-logfile", "-", "--error-logfile", "-", "main_fixed:app"]


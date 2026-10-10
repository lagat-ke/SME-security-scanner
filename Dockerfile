FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m app && chown -R app /app
USER app
ENV PORT=8000
EXPOSE 8000
# Scans take up to ~40s, so allow a generous worker timeout.
CMD gunicorn app:app --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120

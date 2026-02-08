FROM python:3.11-slim

WORKDIR /app

# Install dependencies (minimal)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache/pip

# Copy app
COPY app.py .
COPY static/ static/

# Create persistent data dir (HF Spaces mounts /data)
RUN mkdir -p /data

# HF Spaces uses port 7860
EXPOSE 7860

# Single worker, minimal memory
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1", "--limit-max-requests", "1000"]

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py .
COPY static/ static/

# HF Spaces uses port 7860
EXPOSE 7860

# Create persistent data dir (HF Spaces mounts /data)
RUN mkdir -p /data

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]

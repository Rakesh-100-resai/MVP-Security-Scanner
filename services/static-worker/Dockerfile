FROM python:3.11-slim

# Install ClamAV + YARA system libs
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    libyara-dev \
    libmagic1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV signatures (ignore failure in offline builds)
RUN freshclam || true

# Create log dir
RUN mkdir -p /var/log/mvp-scanner

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy rules and worker
COPY rules /app/rules
COPY worker.py /app/

# Expose clamd TCP port (optional)
EXPOSE 3310

# Start clamd then run worker
CMD service clamav-daemon start && \
    python worker.py

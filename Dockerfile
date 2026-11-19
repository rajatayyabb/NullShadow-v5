# NullShadow v5.0 image — Python base with the scanning CLI tools.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1

# System scanning tools used by the scan engine (Phase D) + nmap for core scans.
# (Nikto/WhatWeb/Dirb are best on Kali; here we install what Debian ships so the
# container still runs the core pipeline. On a Kali host, run natively instead.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        whatweb \
        dirb \
        john \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

COPY . /app

# Dashboard port (localhost-bound by the app itself).
EXPOSE 8077

# Default: show help. Compose overrides this per-service (core/dash).
CMD ["python3", "main.py"]

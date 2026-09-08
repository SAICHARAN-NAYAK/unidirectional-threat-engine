# Multi-stage production container for CYBERSHIELD Threat Detection Engine
FROM python:3.13-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime container
FROM python:3.13-slim

WORKDIR /app

# Copy installed python wheels from builder stage
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8080

# Copy application source code
COPY engine/ /app/engine/
COPY web/ /app/web/
COPY samples/ /app/samples/
COPY run_server.py /app/run_server.py
COPY benchmark.py /app/benchmark.py

# Pre-generate sample PCAP for offline demonstrations
RUN python samples/generate_sample_pcap.py

# Expose HTTP & WebSocket port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + str(os.environ.get('PORT', 8080)) + '/api/telemetry')" || exit 1

# Launch the SOC operations enclave
ENTRYPOINT ["python", "run_server.py"]

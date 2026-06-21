# DeceptiNet-AI honeypot image.
# Runs as a non-root user with a read-only root filesystem (see docker-compose).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first for layer caching. All deps ship as wheels, so no compiler
# toolchain is needed in the image (keeps it small and reduces attack surface).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code + default config.
COPY deceptinet/ ./deceptinet/
COPY config.yaml ./config.yaml

# Non-root runtime user; /data holds generated host keys (mounted volume).
RUN useradd -r -u 10001 -m -d /home/app app \
    && mkdir -p /data \
    && chown -R app:app /data /app
USER app

# In-container overrides (compose can override further). The datastore URL is
# injected by compose (Postgres). /tmp is a tmpfs and writable for the kill file.
ENV DECEPTINET_HOSTKEY_DIR=/data/hostkeys \
    DECEPTINET_KILL_SWITCH_FILE=/tmp/deceptinet.stop \
    DECEPTINET_HEALTH_LISTEN=0.0.0.0:8000

EXPOSE 2222 8000

CMD ["python", "-m", "deceptinet"]

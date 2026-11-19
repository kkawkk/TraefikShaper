# Pinned by digest so Dependabot opens a PR whenever the base image is rebuilt
# (e.g. Debian security fixes); merging it updates :edge, the next release ships it.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt \
    && pip uninstall -y pip setuptools wheel || true

COPY update_whitelist.py .

USER 1000:1000
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).status == 200 else 1)"]

CMD ["python", "update_whitelist.py"]

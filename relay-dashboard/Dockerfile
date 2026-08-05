FROM hashicorp/terraform:1.15.8 AS python-dependencies

RUN apk add --no-cache \
      py3-pip \
      python3

COPY requirements.txt /tmp/relay-dashboard-requirements.txt
RUN python3 -m pip install \
      --no-cache-dir \
      --no-deps \
      --require-hashes \
      --target /opt/relay-python \
      -r /tmp/relay-dashboard-requirements.txt

FROM hashicorp/terraform:1.15.8

RUN apk add --no-cache \
      bash \
      openssh-client \
      python3

COPY --from=python-dependencies /opt/relay-python/ /opt/relay-python/

WORKDIR /app

COPY dashboard/ /app/dashboard/
COPY static/ /app/static/
COPY entrypoint.sh /app/entrypoint.sh

RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod 0755 /app/entrypoint.sh
RUN mkdir -p /workspace/scripts /data

ENV DASHBOARD_BIND=0.0.0.0 \
    DASHBOARD_PORT=8080 \
    DASHBOARD_DATA_DIR=/data \
    DASHBOARD_STATIC_DIR=/app/static \
    PYTHONPATH=/opt/relay-python \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERRAFORM_WORKSPACE=/workspace

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

ENTRYPOINT ["/app/entrypoint.sh"]

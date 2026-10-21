FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.21.2
ARG OPA_VERSION=0.70.0
ARG COSIGN_VERSION=2.4.1
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
    && goarch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo amd64)" \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && opa_suffix="$([ "$goarch" = "amd64" ] && echo amd64_static || echo arm64_static)" \
    && curl -fsSL -o /usr/local/bin/opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${opa_suffix}" \
    && curl -fsSL -o /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${goarch}" \
    && chmod +x /usr/local/bin/opa /usr/local/bin/cosign \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --create-home --uid 1000 app && mkdir -p /data/cosign && chown -R app /app /data/cosign
USER app

EXPOSE 8000
CMD ["uvicorn", "detection.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

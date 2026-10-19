FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.21.2
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --create-home --uid 1000 app && chown -R app /app
USER app

EXPOSE 8000
CMD ["uvicorn", "detection.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

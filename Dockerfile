# syntax=docker/dockerfile:1.6

ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=3.8.0
ARG SUBFINDER_VERSION=2.14.0
ARG HTTPX_VERSION=1.9.0
ARG TRIVY_VERSION=0.70.0
ARG GITLEAKS_VERSION=8.30.1

# ---------- Stage 1: download Go-based tool binaries ----------
FROM debian:bookworm-slim AS tools

ARG TARGETARCH
ARG NUCLEI_VERSION
ARG SUBFINDER_VERSION
ARG HTTPX_VERSION
ARG TRIVY_VERSION
ARG GITLEAKS_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/dl
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) PD_ARCH=amd64; TRIVY_ARCH=64bit; GITLEAKS_ARCH=x64 ;; \
        arm64) PD_ARCH=arm64; TRIVY_ARCH=ARM64; GITLEAKS_ARCH=arm64 ;; \
        *) echo "Unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${PD_ARCH}.zip" -o nuclei.zip; \
    unzip -q -o nuclei.zip nuclei -d /out/; \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${PD_ARCH}.zip" -o subfinder.zip; \
    unzip -q -o subfinder.zip subfinder -d /out/; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${PD_ARCH}.zip" -o httpx.zip; \
    unzip -q -o httpx.zip httpx -d /out/; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
        | tar -xz -C /out trivy; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
        | tar -xz -C /out gitleaks; \
    chmod +x /out/*

# ---------- Stage 2: runtime image ----------
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl nmap git tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE requirements.txt ./
COPY secscan/ ./secscan/

RUN pip install --no-cache-dir . semgrep

# Copy Go binaries last so they win the PATH race against pip-installed CLIs
# (notably python's httpx package ships a `httpx` console script).
COPY --from=tools /out/nuclei /usr/local/bin/nuclei
COPY --from=tools /out/subfinder /usr/local/bin/subfinder
COPY --from=tools /out/httpx /usr/local/bin/httpx
COPY --from=tools /out/trivy /usr/local/bin/trivy
COPY --from=tools /out/gitleaks /usr/local/bin/gitleaks

RUN mkdir -p /app/reports
VOLUME ["/app/reports"]

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8765/ >/dev/null || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["secscan", "serve", "--host", "0.0.0.0", "--port", "8765"]

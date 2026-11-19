# syntax=docker/dockerfile:1.7

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/sentinela
COPY pyproject.toml README.md ./
COPY src ./src
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -f /run/secrets/build_ca ]; then \
        install -m 0644 /run/secrets/build_ca /usr/local/share/ca-certificates/sentinela-build-ca.crt && \
        update-ca-certificates; \
    fi && \
    python -m pip install --no-cache-dir '.[analysis]' && \
    if [ -f /run/secrets/build_ca ]; then \
        rm -f /usr/local/share/ca-certificates/sentinela-build-ca.crt && \
        update-ca-certificates --fresh; \
    fi

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["sentinela"]
CMD ["review", ".", "--format", "markdown"]

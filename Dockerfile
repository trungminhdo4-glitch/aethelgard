FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY examples ./examples

RUN python -m pip install --no-cache-dir -e ".[pdf]" \
    && groupadd --system --gid 10001 aethelgard \
    && useradd --system --uid 10001 --gid aethelgard --create-home \
        --home-dir /home/aethelgard aethelgard \
    && mkdir -p /workspace/reports \
    && chown -R aethelgard:aethelgard /workspace /home/aethelgard

USER 10001:10001
WORKDIR /workspace

ENTRYPOINT ["python", "-m", "aethelgard.cli"]
CMD ["--help"]

FROM python:3.13.9-slim-trixie@sha256:0222b795db95bf7412cede36ab46a266cfb31f632e64051aac9806dabf840a61 AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Disable Python downloads, because we want to use the system interpreter
# across both images. If using a managed Python version, it needs to be
# copied from the build image into the final image; see `standalone.Dockerfile`
# for an example.
ENV UV_PYTHON_DOWNLOADS=0

# Install build dependencies
RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
    build-essential

# Copy the uv binaries from the distroless image
COPY --from=ghcr.io/astral-sh/uv:0.9.7@sha256:ba4857bf2a068e9bc0e64eed8563b065908a4cd6bfb66b531a9c424c8e25e142 /uv /uvx /bin/

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev


# Then, use a final image without uv
FROM python:3.13.9-slim-trixie@sha256:0222b795db95bf7412cede36ab46a266cfb31f632e64051aac9806dabf840a61
# It is important to use the image that matches the builder, as the path to the
# Python executable must be the same, e.g., using `python:3.11-slim-bookworm`
# will fail.

RUN apt-get update \
    && apt-get --no-install-recommends --yes install \
    curl \
    libcap2-bin \
    libpcap-dev \
    && setcap cap_net_raw+ep /usr/local/bin/python3.13 \
    && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

# Copy the application from the builder
COPY --from=builder --chown=app:app /app /app

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Run the application
WORKDIR /app
CMD ["python", "main.py"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsSL http://127.0.0.1:8000/health | grep 'ok'

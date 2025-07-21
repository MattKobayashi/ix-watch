FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

# renovate: datasource=repology depName=alpine_3_22/curl
ENV CURL_VERSION="8.14.1-r1"
# renovate: datasource=repology depName=alpine_3_22/libcap
ENV LIBCAP_VERSION="2.76-r0"
# renovate: datasource=repology depName=alpine_3_22/libpcap
ENV LIBPCAP_VERSION="1.10.5-r1"
# renovate: datasource=repology depName=alpine_3_22/uv
ENV UV_VERSION="0.7.22-r0"

RUN apk --no-cache add \
    curl="${CURL_VERSION}" \
    libcap="${LIBCAP_VERSION}" \
    libpcap="${LIBPCAP_VERSION}" \
    uv="${UV_VERSION}"

RUN adduser --disabled-password ix-watch
USER ix-watch
WORKDIR /opt/ix-watch
COPY main.py /opt/ix-watch/
COPY templates/index.html /opt/ix-watch/templates/
ENTRYPOINT [ "uv", "run", "main.py" ]
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsSL http://127.0.0.1:8000/health | grep 'ok'

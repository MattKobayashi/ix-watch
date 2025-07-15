FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
RUN adduser --disabled-password ix-watch \
    && apk --no-cache add curl libcap libpcap python3 uv \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.12
USER ix-watch
WORKDIR /opt/ix-watch
COPY main.py /opt/ix-watch/
COPY templates/index.html /opt/ix-watch/templates/
ENTRYPOINT [ "uv", "run", "main.py" ]
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsSL http://127.0.0.1:8000/health | grep 'ok'

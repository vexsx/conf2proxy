# syntax=docker/dockerfile:1.7

ARG DEBIAN_VERSION=bookworm-slim
FROM debian:${DEBIAN_VERSION}

ARG V2RAY_VERSION=5.49.0

# TARGETARCH and TARGETVARIANT are build-time args.
# Docker BuildKit/buildx can set them automatically.
# docker compose can also pass them from .env/build.args.
ARG TARGETARCH=amd64
ARG TARGETVARIANT=

ENV DEBIAN_FRONTEND=noninteractive \
    V2RAY_LOCATION_ASSET=/usr/local/share/v2ray \
    V2RAY_LOCATION_CONFIG=/etc/v2ray \
    V2RAY_CONFIG_FILE=/etc/v2ray/config.json \
    V2RAY_LINK_FILE=/etc/v2ray/link.txt \
    ACTIVE_CONFIG=/work/active-config.json \
    LOGLEVEL=warning \
    LOCAL_PROXY_PROTOCOL=socks5 \
    INBOUND_LISTEN=0.0.0.0 \
    PROXY_PORT=1080 \
    SOCKS_PORT=1080 \
    HTTP_PORT=1081 \
    ENABLE_SNIFFING=true \
    ENABLE_SOCKS_UDP=true \
    ROUTE_PRIVATE_DIRECT=true \
    ENABLE_MUX=false \
    MUX_CONCURRENCY=8

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      unzip \
      tini \
      python3; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64) v2ray_asset="v2ray-linux-64.zip" ;; \
      arm64*) v2ray_asset="v2ray-linux-arm64-v8a.zip" ;; \
      armv7) v2ray_asset="v2ray-linux-arm32-v7a.zip" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH:-unknown}${TARGETVARIANT:-}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/v2ray.zip "https://github.com/v2fly/v2ray-core/releases/download/v${V2RAY_VERSION}/${v2ray_asset}"; \
    mkdir -p /tmp/v2ray /usr/local/share/v2ray /etc/v2ray /work; \
    unzip -q /tmp/v2ray.zip -d /tmp/v2ray; \
    install -m 0755 /tmp/v2ray/v2ray /usr/local/bin/v2ray; \
    if [ -f /tmp/v2ray/geoip.dat ]; then install -m 0644 /tmp/v2ray/geoip.dat /usr/local/share/v2ray/geoip.dat; fi; \
    if [ -f /tmp/v2ray/geosite.dat ]; then install -m 0644 /tmp/v2ray/geosite.dat /usr/local/share/v2ray/geosite.dat; fi; \
    rm -rf /tmp/v2ray /tmp/v2ray.zip; \
    groupadd --system --gid 10001 v2ray; \
    useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin v2ray; \
    chown -R v2ray:v2ray /etc/v2ray /work

COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chmod=0755 link2config.py /usr/local/bin/link2config.py

USER v2ray:v2ray
WORKDIR /work

EXPOSE 1080/tcp 1081/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import os,socket; proto=os.environ.get('LOCAL_PROXY_PROTOCOL','socks5').lower(); p=int((os.environ.get('PROXY_PORT') if proto in ('socks','socks5','http') else os.environ.get('SOCKS_PORT')) or '1080'); s=socket.create_connection(('127.0.0.1',p),3); s.close()"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

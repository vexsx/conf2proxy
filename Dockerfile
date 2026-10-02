# syntax=docker/dockerfile:1.7

ARG DEBIAN_VERSION=trixie-slim

# ---------------------------------------------------------------------------
# Stage 1: download and verify the Xray-core release (curl/unzip stay here).
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION} AS xray

ARG XRAY_VERSION=26.9.9

# TARGETARCH and TARGETVARIANT are build-time args.
# Docker BuildKit/buildx can set them automatically.
# docker compose can also pass them from .env/build.args.
ARG TARGETARCH=amd64
ARG TARGETVARIANT=

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64) asset="Xray-linux-64.zip" ;; \
      arm64*) asset="Xray-linux-arm64-v8a.zip" ;; \
      armv7) asset="Xray-linux-arm32-v7a.zip" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH:-unknown}${TARGETVARIANT:-}" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}"; \
    curl -fsSL --retry 3 -o /tmp/xray.zip "${base}/${asset}"; \
    curl -fsSL --retry 3 -o /tmp/xray.zip.dgst "${base}/${asset}.dgst"; \
    expected="$(sed -n 's/^SHA2-256= *//p' /tmp/xray.zip.dgst | tr -d '\r')"; \
    test -n "${expected}"; \
    echo "${expected}  /tmp/xray.zip" | sha256sum -c -; \
    mkdir -p /tmp/xray /out/share; \
    unzip -q /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /out/xray; \
    for f in geoip.dat geosite.dat; do \
      if [ -f "/tmp/xray/$f" ]; then install -m 0644 "/tmp/xray/$f" "/out/share/$f"; fi; \
    done

# ---------------------------------------------------------------------------
# Stage 2: runtime image.
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}

ENV XRAY_LOCATION_ASSET=/usr/local/share/xray \
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
      python3-minimal \
      tini \
      tzdata; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /usr/local/share/xray /etc/v2ray /work; \
    groupadd --system --gid 10001 xray; \
    useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin xray; \
    chown -R xray:xray /etc/v2ray /work

COPY --from=xray /out/xray /usr/local/bin/xray
COPY --from=xray /out/share/ /usr/local/share/xray/
COPY --chmod=0755 docker-entrypoint.sh link2config.py healthcheck.py /usr/local/bin/

# Strip CRLF in case the build context was checked out on Windows.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh /usr/local/bin/link2config.py /usr/local/bin/healthcheck.py

USER xray:xray
WORKDIR /work

EXPOSE 1080/tcp 1081/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python3", "/usr/local/bin/healthcheck.py"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

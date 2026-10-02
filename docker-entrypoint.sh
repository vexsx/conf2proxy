#!/usr/bin/env bash
set -Eeuo pipefail

log()  { printf '[entrypoint] %s\n' "$*" >&2; }
die()  { printf '[entrypoint] ERROR: %s\n' "$*" >&2; exit 1; }

CONFIG_IN="${V2RAY_CONFIG_FILE:-/etc/v2ray/config.json}"
LINK_IN="${V2RAY_LINK_FILE:-/etc/v2ray/link.txt}"
ACTIVE_CONFIG="${ACTIVE_CONFIG:-/work/active-config.json}"

export XRAY_LOCATION_ASSET="${XRAY_LOCATION_ASSET:-/usr/local/share/xray}"

mkdir -p "$(dirname "$ACTIVE_CONFIG")"

log "starting proxy gateway: $(xray version | head -n 1)"
log "local proxy protocol: ${LOCAL_PROXY_PROTOCOL:-socks5}"

if [ -n "${V2RAY_LINK:-}" ]; then
  log "using V2RAY_LINK from environment"
  printf '%s\n' "$V2RAY_LINK" | python3 /usr/local/bin/link2config.py - "$ACTIVE_CONFIG"
elif [ -s "$CONFIG_IN" ]; then
  log "using mounted native Xray config: ${CONFIG_IN}"
  cp "$CONFIG_IN" "$ACTIVE_CONFIG"
elif [ -s "$LINK_IN" ]; then
  log "using mounted link/subscription file: ${LINK_IN}"
  python3 /usr/local/bin/link2config.py "$LINK_IN" "$ACTIVE_CONFIG"
else
  die "no usable config found. Mount ${CONFIG_IN}, mount ${LINK_IN}, or set V2RAY_LINK."
fi

if ! xray run -test -c "$ACTIVE_CONFIG" >/tmp/xray-test.log 2>&1; then
  cat /tmp/xray-test.log >&2 || true
  die "Xray rejected the config"
fi

log "config validated; starting Xray"
exec xray run -c "$ACTIVE_CONFIG"

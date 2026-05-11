#!/usr/bin/env bash
set -Eeuo pipefail

log()  { printf '[entrypoint] %s\n' "$*" >&2; }
warn() { printf '[entrypoint] WARN: %s\n' "$*" >&2; }
die()  { printf '[entrypoint] ERROR: %s\n' "$*" >&2; exit 1; }

CONFIG_IN="${V2RAY_CONFIG_FILE:-/etc/v2ray/config.json}"
LINK_IN="${V2RAY_LINK_FILE:-/etc/v2ray/link.txt}"
ACTIVE_CONFIG="${ACTIVE_CONFIG:-/work/active-config.json}"

export V2RAY_LOCATION_ASSET="${V2RAY_LOCATION_ASSET:-/usr/local/share/v2ray}"
export V2RAY_LOCATION_CONFIG="${V2RAY_LOCATION_CONFIG:-/etc/v2ray}"

mkdir -p "$(dirname "$ACTIVE_CONFIG")"

validate_json() {
  python3 - "$1" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    json.load(f)
PY
}

run_v2ray_test() {
  if v2ray test -c "$ACTIVE_CONFIG" >/tmp/v2ray-test.log 2>&1; then
    return 0
  fi

  if v2ray -test -config="$ACTIVE_CONFIG" >/tmp/v2ray-test.log 2>&1; then
    return 0
  fi

  cat /tmp/v2ray-test.log >&2 || true
  return 1
}

exec_v2ray() {
  if v2ray help 2>&1 | grep -Eq '(^|[[:space:]])run([[:space:]]|$)'; then
    exec v2ray run -c "$ACTIVE_CONFIG"
  fi

  exec v2ray -config="$ACTIVE_CONFIG"
}

log "starting V2Ray proxy gateway"
log "local proxy protocol: ${LOCAL_PROXY_PROTOCOL:-socks5}"
log "assets: ${V2RAY_LOCATION_ASSET}"

if [ -n "${V2RAY_LINK:-}" ]; then
  log "using V2RAY_LINK from environment"
  printf '%s\n' "$V2RAY_LINK" > /tmp/proxy-link.txt
  python3 /usr/local/bin/link2config.py /tmp/proxy-link.txt "$ACTIVE_CONFIG"
elif [ -s "$CONFIG_IN" ]; then
  log "using mounted native config: ${CONFIG_IN}"
  cp "$CONFIG_IN" "$ACTIVE_CONFIG"
elif [ -s "$LINK_IN" ]; then
  log "using mounted link/subscription file: ${LINK_IN}"
  python3 /usr/local/bin/link2config.py "$LINK_IN" "$ACTIVE_CONFIG"
else
  die "no usable config found. Mount ${CONFIG_IN}, mount ${LINK_IN}, or set V2RAY_LINK."
fi

validate_json "$ACTIVE_CONFIG" || die "generated config is not valid JSON"
run_v2ray_test || die "V2Ray rejected the generated config"

log "config validated; starting core"
exec_v2ray

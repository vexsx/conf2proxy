# conf2proxy v4.1

`conf2proxy` converts a V2Ray-compatible client config or share link into a local SOCKS5/HTTP proxy container.

This version makes build-time and runtime values explicit in `.env`.

## Where TARGETARCH and TARGETVARIANT are set

`TARGETARCH` and `TARGETVARIANT` are Docker **build args**, not container runtime environment variables. They are used only while building the image to choose the correct V2Ray binary.

They are now defined in `.env` and passed through `compose.yaml`:

```yaml
build:
  args:
    V2RAY_VERSION: "${V2RAY_VERSION:-5.49.0}"
    TARGETARCH: "${TARGETARCH:-amd64}"
    TARGETVARIANT: "${TARGETVARIANT:-}"
```

Default `.env` values:

```env
TARGETARCH=amd64
TARGETVARIANT=
```

For ARM64:

```env
TARGETARCH=arm64
TARGETVARIANT=
```

For ARMv7:

```env
TARGETARCH=arm
TARGETVARIANT=v7
```

## Local proxy mode

Choose what this container exposes locally by changing `.env`:

```env
LOCAL_PROXY_PROTOCOL=socks5
PROXY_PORT=1080
```

or:

```env
LOCAL_PROXY_PROTOCOL=http
PROXY_PORT=1080
```

or:

```env
LOCAL_PROXY_PROTOCOL=both
SOCKS_PORT=1080
HTTP_PORT=1081
```

---


Containerized V2Ray-compatible config-to-proxy gateway. It accepts either a native `config.json`, a single V2Ray-compatible share link, an environment variable link, or a base64 subscription file. It then exposes a local proxy listener selected by environment variable.

## What changed in v4

- Removed upstream input support for `socks://`, `socks5://`, `http://`, and `https://` links.
- Local exposed proxy is now selected with `LOCAL_PROXY_PROTOCOL` in `compose.yaml`.
- Default local listener is SOCKS5 on `127.0.0.1:1080`.
- HTTP proxy mode can use the same exposed port, so you do not need two ports unless you choose `both`.

## Supported generated link inputs

- `vmess://`
- `vless://` with `security=tls` or `security=none`
- `trojan://` with `security=tls` or `security=none`
- `ss://` Shadowsocks SIP002 and legacy base64 body

## Not supported in this V2Ray-only image

- `socks://`, `socks5://`, `http://`, `https://` as upstream input links.
- `vless://...security=reality...` and most `flow=xtls-rprx-vision` configs: these are Xray-side patterns.
- `hy2://`, `hysteria2://`, `tuic://`, `wireguard://`: these are not V2Ray-core outbound share links.
- `ssr://`: ShadowsocksR is not normal Shadowsocks SIP002.

Use a native config with the correct core if you need these protocols.

## File layout

```text
.
├── compose.yaml
├── Dockerfile
├── docker-entrypoint.sh
├── link2config.py
├── v2ray/
    └── link.txt
```

## Run with SOCKS5 local proxy

This is the default mode.

```yaml
LOCAL_PROXY_PROTOCOL: "socks5"
PROXY_PORT: "1080"
```

Start:

```bash
nano v2ray/link.txt
docker compose up -d --build
```

Test:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

## Run with HTTP local proxy

Change only this in `compose.yaml`:

```yaml
environment:
  LOCAL_PROXY_PROTOCOL: "http"
  PROXY_PORT: "1080"
```

Keep the same port mapping:

```yaml
ports:
  - "127.0.0.1:${HOST_PROXY_PORT:-1080}:${PROXY_PORT:-1080}/tcp"
```

Start and test:

```bash
docker compose up -d --build
curl -x http://127.0.0.1:1080 https://ifconfig.me
```

## Run with both SOCKS5 and HTTP local proxies

Use this only if you really need both protocols at the same time.

```yaml
environment:
  LOCAL_PROXY_PROTOCOL: "both"
  SOCKS_PORT: "1080"
  HTTP_PORT: "1081"

ports:
  - "127.0.0.1:${HOST_PROXY_PORT:-1080}:${SOCKS_PORT:-1080}/tcp"
  - "127.0.0.1:${HOST_HTTP_PORT:-1081}:${HTTP_PORT:-1081}/tcp"
```

Test:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
curl -x http://127.0.0.1:1081 https://ifconfig.me
```

## Run with native config.json

Place your complete V2Ray client config at:

```text
v2ray/config.json
```

Then start:

```bash
docker compose up -d --build
```

When native `config.json` exists and is non-empty, it takes priority over `link.txt`.

## Run with environment variable

```bash
V2RAY_LINK='vless://...' docker compose up -d --build
```

`V2RAY_LINK` has the highest priority.

## Optional authentication

For LAN/public exposure, enable authentication first:

```yaml
environment:
  PROXY_AUTH: "password"
  PROXY_USER: "proxyuser"
  PROXY_PASS: "change-me"
ports:
  - "0.0.0.0:${HOST_PROXY_PORT:-1080}:${PROXY_PORT:-1080}/tcp"
```

For SOCKS5:

```bash
curl --socks5-hostname proxyuser:change-me@127.0.0.1:1080 https://ifconfig.me
```

For HTTP:

```bash
curl -x http://proxyuser:change-me@127.0.0.1:1080 https://ifconfig.me
```

## Important environment variables

| Variable | Default | Description |
|---|---:|---|
| `LOCAL_PROXY_PROTOCOL` | `socks5` | Local exposed protocol: `socks5`, `http`, or `both` |
| `PROXY_PORT` | `1080` | Main local inbound port for `socks5` or `http` mode |
| `SOCKS_PORT` | `1080` | SOCKS5 port when `LOCAL_PROXY_PROTOCOL=both` |
| `HTTP_PORT` | `1081` | HTTP proxy port when `LOCAL_PROXY_PROTOCOL=both` |
| `PROXY_AUTH` | `noauth` | Set to `password` to enable inbound auth |
| `PROXY_USER` | empty | Inbound auth username |
| `PROXY_PASS` | empty | Inbound auth password |
| `ENABLE_SOCKS_UDP` | `true` | Enable UDP on SOCKS inbound |
| `ENABLE_SNIFFING` | `true` | Enable V2Ray sniffing for HTTP/TLS/QUIC destination override |
| `ROUTE_PRIVATE_DIRECT` | `true` | Route private IP/domain ranges directly |
| `LOGLEVEL` | `warning` | V2Ray log level |
| `ENABLE_MUX` | `false` | Enable V2Ray mux on generated proxy outbound |
| `V2RAY_LINK` | empty | Direct link input without mounting a file |

## Production notes

The container runs as non-root, drops Linux capabilities, uses `no-new-privileges`, mounts `/etc/v2ray` read-only, and uses tmpfs for generated runtime config.

Keep the host binding as `127.0.0.1` unless this proxy is intentionally shared. If you expose it on LAN or public network, enable `PROXY_AUTH=password` and use a strong password.

## Validate parser locally

```bash
python3 -m py_compile link2config.py
python3 link2config.py v2ray/link.txt /tmp/active-config.json
python3 -m json.tool /tmp/active-config.json >/dev/null
```

If you have pytest installed:

```bash
pytest -q
```

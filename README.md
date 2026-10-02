# conf2proxy v5.0

`conf2proxy` turns a proxy share link (or a native Xray config) into a local **SOCKS5 / HTTP proxy** container.

Paste a `vless://` (including **REALITY** + **XTLS Vision**), `vmess://`, `trojan://` or `ss://` link into `v2ray/link.txt`, start the container, and point your apps at `127.0.0.1:1080`.

Since v5 the image runs **[Xray-core](https://github.com/XTLS/Xray-core) 26.9.9** instead of V2Ray (v2fly). V2Ray cannot connect to REALITY servers at all; Xray can, and it also handles every link type the old version accepted.

## What changed in v5

- **REALITY works.** `vless://...security=reality...` links (and XTLS Vision, XHTTP, uTLS `fp=`, VLESS encryption) are now supported. They used to fail with `security=reality is Xray-specific`.
- **No more stalls under heavy traffic:**
  - Upstream connections that stop getting acknowledged (dropped or blackholed paths) are closed after 30 s (`TCP_USER_TIMEOUT_MS`) instead of hanging for minutes.
  - gRPC links get health-check pings, so one dead connection no longer freezes every stream multiplexed on it (`GRPC_HEALTH_CHECK`).
  - The per-connection access log is off by default (`ACCESS_LOG`).
  - Docker logs are rotated (they used to grow until the disk filled).
  - The container gets a high open-file limit (`NOFILE_LIMIT`).
- **Faster and lighter.** With the same VMess link, the new core moved about 2× the data at about a third of the CPU in the VM benchmark below. REALITY+Vision uses kernel splice (zero-copy) on Linux.
- **Optional host networking** (`compose.host.yaml`) skips Docker's userland proxy and NAT, and makes SOCKS5 UDP usable from other machines.
- **Real healthcheck.** It completes a SOCKS5/HTTP exchange with Xray instead of a bare TCP connect, which succeeds even when the proxy is stuck. You can optionally add an end-to-end check through the tunnel (`HEALTHCHECK_URL`).
- **Image:**
  - Debian 13 slim with a multi-stage build.
  - The Xray zip is verified against the release's SHA-256 digest.
  - Uses `python3-minimal`; `curl`/`unzip` are not in the final image.
  - Scripts are forced to LF line endings, so building from a Windows checkout works.
- **Parser fixes:**
  - `+` in link parameters is no longer turned into a space (this broke base64 values).
  - Paths are no longer decoded twice.
  - VLESS IDs that are not UUID v1-v5 are accepted.
  - `ss://` user info containing `/` is handled.
  - A subscription that starts with an unsupported link no longer aborts before reaching a supported one.

### Breaking changes

- A mounted native `v2ray/config.json` must now be an **Xray** config. Classic V2Ray "v4" JSON mostly works; v2fly v5 `jsonv5` configs do not.
- Xray removed the `http`/`h2` and `quic` transports, so links using them are rejected. Ask your provider for an `xhttp` link.
- `allowInsecure=1` no longer disables certificate checks; current Xray removed it. For a self-signed server certificate, add `pcs=<sha256 of the certificate>` to the link (see Troubleshooting).
- Xray refuses VLESS/Trojan without TLS/REALITY to public IP addresses, and Shadowsocks `none`/stream ciphers.
- mKCP links with `headerType`/`seed` need a native config.

## Quick start

```bash
nano v2ray/link.txt            # paste one link, or a base64 subscription
docker compose up -d --build
docker compose logs -f         # look for "link2config: vless reality/raw flow=xtls-rprx-vision -> socks:1080"
```

Test:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

Use `socks5h`/`--socks5-hostname` (remote DNS) in your clients, so domain names are resolved by the server, not by a possibly poisoned local DNS.

## Supported links

| Link | Security | Transports |
|---|---|---|
| `vless://` | `reality`, `tls`, `none` (private addresses only) | `tcp`/`raw` (+ `flow=xtls-rprx-vision`), `xhttp`, `ws`, `httpupgrade`, `grpc`, `kcp` |
| `vmess://` (v2rayN base64 JSON) | `tls`, `none` | same as above |
| `trojan://` | `tls`, `reality` | same as above |
| `ss://` (SIP002, SIP022 `2022-blake3-*`, legacy base64) | none, or `tls` via `v2ray-plugin`/`xray-plugin` | `tcp`, `ws`/`grpc` through the plugin |

Recognized link parameters: `type`, `security`, `encryption`, `flow`, `sni`, `fp`, `alpn`, `pbk`, `sid`, `spx`, `pqv`, `pcs`, `vcn`, `ech`, `host`, `path`, `serviceName`, `mode`, `authority`, `extra` (XHTTP JSON), `headerType`.

If `fp` is missing on a TLS/REALITY link, the `TLS_FINGERPRINT` default (`chrome`) is used.

A subscription file can be a list of links or one base64 blob; the first supported link is used.

### Not supported

- `socks://`, `socks5://`, `http://`, `https://` as upstream links.
- `hysteria2://`, `hy2://`, `tuic://`, `wireguard://`, `ssr://`.
- The `http`/`h2` and `quic` transports (removed from Xray).

Mount a native Xray `config.json` if you need any of these.

## Local proxy mode

Choose what the container exposes by changing `.env`:

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

Test the HTTP proxy:

```bash
curl -x http://127.0.0.1:1080 https://ifconfig.me
```

## High throughput and stall protection

If the proxy "hangs" under heavy traffic, the usual causes are:

- **Dead upstream connections.** On filtered networks a long-running, high-traffic connection is often silently dropped. Without a limit, Linux keeps retransmitting for about 15 minutes, and your download sits frozen. `TCP_USER_TIMEOUT_MS=30000` closes such connections after 30 s so apps reconnect immediately.
- **Multiplexing.** gRPC transports (and Mux) carry many connections over one TCP stream. If that stream dies, everything on it freezes. `GRPC_HEALTH_CHECK=true` pings after 60 s of silence and replaces the connection if no answer arrives within 20 s. Keep `ENABLE_MUX=false`, which avoids head-of-line blocking, for bulk traffic.
- **Logging.** Writing one access-log line per connection is costly under load, and Docker never deleted old logs. Keep `ACCESS_LOG=false` and `LOGLEVEL=warning`; logs rotate at `LOG_MAX_SIZE` × `LOG_MAX_FILE`.
- **File descriptors.** Docker's default soft limit is 1024 open files; each proxied connection needs several. `NOFILE_LIMIT` raises it.
- **Small VPS memory.** Xray buffers up to 512 KB per connection on amd64. With thousands of connections on a 1 GB server, set `BUFFER_SIZE_KB=64` and/or `GOMEMLIMIT=256MiB`.

### Host networking (fastest path)

By default the port is published through Docker, which adds a userland proxy (`docker-proxy`) and NAT hop. For maximum throughput, add this to `.env`:

```env
COMPOSE_FILE=compose.yaml:compose.host.yaml
```

Xray then listens directly on `HOST_PROXY_BIND:PROXY_PORT` (default `127.0.0.1:1080`). This requires Docker Compose v2.24+ and a Linux host. Make sure the port is free on the host.

### Server side

For downloads, the **server's** TCP congestion control decides the speed, so enable BBR on the upstream server:

```bash
echo 'net.core.default_qdisc=fq' | sudo tee -a /etc/sysctl.d/99-bbr.conf
echo 'net.ipv4.tcp_congestion_control=bbr' | sudo tee -a /etc/sysctl.d/99-bbr.conf
sudo sysctl --system
```

`TCP_CONGESTION=bbr` in this container only affects uploads. It also requires `bbr` to be listed in the host's `net.ipv4.tcp_allowed_congestion_control`, otherwise every upstream connection fails.

### SOCKS5 UDP

Current Xray answers SOCKS5 `UDP ASSOCIATE` on a random UDP port, as RFC 1928 specifies, and Docker cannot publish random ports. In the default bridge mode, UDP therefore only works for clients running on the Docker host itself (Linux). Use host networking if other machines need UDP through the proxy. Set `ENABLE_SOCKS_UDP=false` to turn UDP off.

## Run with native config.json

Place a complete **Xray** client config at:

```text
v2ray/config.json
```

Then start:

```bash
docker compose up -d --build
```

When a non-empty `config.json` exists, it takes priority over `link.txt`. The `geoip.dat`/`geosite.dat` files from the Xray release are included in the image for configs that use them.

## Run with environment variable

```bash
V2RAY_LINK='vless://...' docker compose up -d --build
```

`V2RAY_LINK` has the highest priority.

## Optional authentication

For LAN/public exposure, enable authentication first:

```env
PROXY_AUTH=password
PROXY_USER=proxyuser
PROXY_PASS=change-me
HOST_PROXY_BIND=0.0.0.0
```

For SOCKS5:

```bash
curl --socks5-hostname proxyuser:change-me@127.0.0.1:1080 https://ifconfig.me
```

For HTTP:

```bash
curl -x http://proxyuser:change-me@127.0.0.1:1080 https://ifconfig.me
```

## Build architecture

`TARGETARCH` and `TARGETVARIANT` are Docker **build args** that pick the right Xray binary. They are set in `.env` and passed through `compose.yaml`:

| Server | `.env` |
|---|---|
| x86_64 (default) | `TARGETARCH=amd64`, `TARGETVARIANT=` |
| ARM64 | `TARGETARCH=arm64`, `TARGETVARIANT=` |
| ARMv7 | `TARGETARCH=arm`, `TARGETVARIANT=v7` |

`XRAY_VERSION` selects the Xray release. The build verifies the download against the release's SHA-256 digest.

## Environment variables

| Variable | Default | Description |
|---|---:|---|
| `LOCAL_PROXY_PROTOCOL` | `socks5` | Local exposed protocol: `socks5`, `http`, or `both` |
| `PROXY_PORT` | `1080` | Main local inbound port for `socks5` or `http` mode |
| `SOCKS_PORT` | `1080` | SOCKS5 port when `LOCAL_PROXY_PROTOCOL=both` |
| `HTTP_PORT` | `1081` | HTTP proxy port when `LOCAL_PROXY_PROTOCOL=both` |
| `HOST_PROXY_BIND` | `127.0.0.1` | Host address the proxy is published on |
| `PROXY_AUTH` | `noauth` | Set to `password` to enable inbound auth |
| `PROXY_USER` / `PROXY_PASS` | empty | Inbound auth credentials |
| `ENABLE_SOCKS_UDP` | `true` | Enable UDP on the SOCKS5 inbound |
| `ENABLE_SNIFFING` | `true` | Recover the real domain from TLS/HTTP/QUIC, which repairs apps that used a poisoned local DNS |
| `ROUTE_PRIVATE_DIRECT` | `true` | Send private IPs and local names (`localhost`, `*.lan`, dotless names) directly instead of through the tunnel |
| `LOGLEVEL` | `warning` | Xray log level: `debug`, `info`, `warning`, `error`, `none` |
| `ACCESS_LOG` | `false` | Log every connection |
| `ENABLE_MUX` | `false` | Xray Mux on the proxy outbound (not recommended for bulk traffic) |
| `MUX_CONCURRENCY` | `8` | Mux streams per connection |
| `TCP_USER_TIMEOUT_MS` | `30000` | Close upstream connections whose data stays unacknowledged this long; `0` = off |
| `CONN_IDLE` | `300` | Close connections idle in both directions after this many seconds |
| `GRPC_HEALTH_CHECK` | `true` | Health-check pings on gRPC transports |
| `BUFFER_SIZE_KB` | Xray default | Per-connection buffer |
| `TCP_CONGESTION` | empty | Per-socket congestion control for upstream sockets (see Server side) |
| `TLS_FINGERPRINT` | `chrome` | uTLS fingerprint when a link has no `fp=` |
| `GOMEMLIMIT` | empty | Soft memory limit for Xray, e.g. `256MiB` |
| `NOFILE_LIMIT` | `1048576` | Container open-file limit (lower it for rootless Docker) |
| `LOG_MAX_SIZE` / `LOG_MAX_FILE` | `10m` / `3` | Docker log rotation |
| `HEALTHCHECK_URL` | empty | Plain `http://` URL fetched through the tunnel by the healthcheck, e.g. `http://cp.cloudflare.com/generate_204` |
| `V2RAY_LINK` | empty | Direct link input without mounting a file |

## Production notes

The container runs as non-root, drops all Linux capabilities, uses `no-new-privileges`, mounts `/etc/v2ray` read-only, and keeps the generated config on a tmpfs.

Keep the host binding as `127.0.0.1` unless this proxy is intentionally shared. If you expose it on LAN or a public network, enable `PROXY_AUTH=password` and use a strong password.

The healthcheck reports `unhealthy` when Xray stops answering. If `HEALTHCHECK_URL` is set, it also reports `unhealthy` when the upstream server is unreachable. Docker does not restart unhealthy containers on its own; use a watchdog such as `autoheal` if you want that.

## Validate locally

```bash
python3 -m unittest discover -s tests -v
python3 link2config.py v2ray/link.txt /tmp/active-config.json
docker run --rm -v /tmp/active-config.json:/c.json:ro --entrypoint xray conf2proxy:v5.0 run -test -c /c.json
```

## Troubleshooting

| Message | Fix |
|---|---|
| `security=reality is Xray-specific` | You are running a v4 image. Rebuild: `docker compose up -d --build` |
| `x509: certificate signed by unknown authority` | The server uses a self-signed certificate and the link relied on `allowInsecure`. Add `&pcs=<hex sha256>` to the link; get the value with `openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \| openssl x509 -outform der \| sha256sum` |
| `vless without TLS or other encryption is prohibited` | Xray refuses unencrypted VLESS/Trojan to public addresses. Use a TLS/REALITY link |
| `The HTTP/2 (h2) transport was removed` / `QUIC transport was removed` | Ask your provider for an `xhttp` link |
| Container `unhealthy` | Run `docker compose logs --tail 50`, then set `LOGLEVEL=info` temporarily |

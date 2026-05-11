#!/usr/bin/env python3
"""
Convert common proxy share links into a V2Ray JSON client config.

The container exposes a local proxy listener selected by environment variable:
  - LOCAL_PROXY_PROTOCOL=socks5  -> SOCKS5 inbound
  - LOCAL_PROXY_PROTOCOL=http    -> HTTP proxy inbound
  - LOCAL_PROXY_PROTOCOL=both    -> SOCKS5 + HTTP proxy inbounds

Supported generated outbound configs:
  - vmess://
  - vless://              security=tls or none
  - trojan://             security=tls or none
  - ss://                 SIP002 + legacy base64 body

Not supported by this V2Ray-only helper:
  - socks://, socks5://, http://, https:// as upstream input links
  - VLESS REALITY / XTLS Vision: Xray-specific, use Xray or native config.
  - hysteria2 / hy2 / tuic / wireguard links: not V2Ray-core outbounds.
  - ssr://: ShadowsocksR is not normal Shadowsocks SIP002.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

SUPPORTED_PREFIXES = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
)

UNSUPPORTED_PREFIXES = (
    "socks://",
    "socks5://",
    "http://",
    "https://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "ssr://",
    "wireguard://",
)

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def env_csv(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def env_choice(*names: str, default: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def env_int_choice(*names: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    selected = None
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            selected = (name, value.strip())
            break
    if selected is None:
        raw = str(default)
        source = names[0] if names else "value"
    else:
        source, raw = selected
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{source} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{source} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{source} must be <= {maximum}")
    return value




def fail(message: str) -> None:
    raise ValueError(message)


def b64decode_relaxed(value: str) -> str:
    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * ((-len(value)) % 4)
    try:
        return base64.b64decode(value.encode("utf-8"), validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("Invalid base64 content") from exc


def read_link_or_subscription(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        fail("No proxy link found in file")

    candidates = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            candidates.append(line)

    for line in candidates:
        if line.startswith(SUPPORTED_PREFIXES):
            return line
        if line.startswith(UNSUPPORTED_PREFIXES):
            fail(f"Unsupported link type: {line.split('://', 1)[0]}://")

    # Many subscription files are a single base64 blob containing one link per line.
    try:
        decoded = b64decode_relaxed("".join(candidates))
    except ValueError:
        decoded = ""

    for line in decoded.splitlines():
        line = line.strip()
        if line.startswith(SUPPORTED_PREFIXES):
            return line
        if line.startswith(UNSUPPORTED_PREFIXES):
            fail(f"Unsupported link type inside subscription: {line.split('://', 1)[0]}://")

    fail("No supported proxy link found. Supported input links: vmess, vless, trojan, ss.")


def safe_port(parsed_url) -> int:
    try:
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError("Invalid port in proxy link") from exc
    if not port or not (1 <= int(port) <= 65535):
        fail("Missing or invalid port in proxy link")
    return int(port)


def qget(q: dict[str, list[str]], names: list[str], default: str = "") -> str:
    lowered = {k.lower(): v for k, v in q.items()}
    for name in names:
        values = lowered.get(name.lower())
        if values:
            return values[0]
    return default


def normalize_network(value: str) -> str:
    network = (value or "tcp").strip().lower()
    aliases = {
        "h2": "http",
        "http/2": "http",
        "websocket": "ws",
        "tcp": "tcp",
        "ws": "ws",
        "grpc": "grpc",
        "http": "http",
        "kcp": "kcp",
        "mkcp": "kcp",
        "quic": "quic",
        "httpupgrade": "httpupgrade",
        "splithttp": "splithttp",
        "xhttp": "splithttp",
    }
    if network not in aliases:
        fail(f"Unsupported network/transport {value!r}. Use native config.json for this transport.")
    return aliases[network]


def normalize_security(value: str, *, default: str) -> str:
    security = (value or default or "none").strip().lower()
    if security in {"", "none"}:
        return "none"
    if security == "tls":
        return "tls"
    if security in {"reality", "xtls"}:
        fail(
            f"security={security} is Xray-specific in common share links. "
            "Use an Xray-based image/native config instead of this V2Ray-only helper."
        )
    fail(f"Unsupported security {security!r}. This helper supports only tls or none.")


def sniffing_block() -> dict[str, Any]:
    if not env_bool("ENABLE_SNIFFING", True):
        return {"enabled": False}
    return {
        "enabled": True,
        "destOverride": env_csv("SNIFF_DEST_OVERRIDE", "http,tls,quic"),
    }


def inbound_auth_settings(kind: str) -> dict[str, Any]:
    """
    kind is the actual V2Ray inbound protocol: socks or http.

    New generic envs:
      PROXY_AUTH=noauth|password
      PROXY_USER=...
      PROXY_PASS=...

    Backward-compatible legacy envs still work:
      SOCKS_AUTH/SOCKS_USER/SOCKS_PASS
      HTTP_AUTH/HTTP_USER/HTTP_PASS
    """
    kind_upper = kind.upper()
    auth = env_choice("PROXY_AUTH", f"{kind_upper}_AUTH", default="noauth").lower()
    if auth in {"", "noauth", "none", "false"}:
        return {"auth": "noauth"} if kind == "socks" else {}

    if auth != "password":
        fail("PROXY_AUTH must be noauth or password")

    user = env_choice("PROXY_USER", f"{kind_upper}_USER", default="")
    password = env_choice("PROXY_PASS", f"{kind_upper}_PASS", default="")
    if not user or not password:
        fail("PROXY_USER and PROXY_PASS are required when PROXY_AUTH=password")

    return {"accounts": [{"user": user, "pass": password}], **({"auth": "password"} if kind == "socks" else {})}


def make_socks_inbound(*, listen: str, port: int) -> dict[str, Any]:
    settings = inbound_auth_settings("socks")
    settings["udp"] = env_bool("ENABLE_SOCKS_UDP", True)
    return {
        "tag": "socks-in",
        "listen": listen,
        "port": port,
        "protocol": "socks",
        "sniffing": sniffing_block(),
        "settings": settings,
    }


def make_http_inbound(*, listen: str, port: int) -> dict[str, Any]:
    return {
        "tag": "http-in",
        "listen": listen,
        "port": port,
        "protocol": "http",
        "sniffing": sniffing_block(),
        "settings": inbound_auth_settings("http"),
    }


def default_inbounds() -> list[dict[str, Any]]:
    listen = os.getenv("INBOUND_LISTEN", "0.0.0.0").strip() or "0.0.0.0"
    protocol = env_choice("LOCAL_PROXY_PROTOCOL", "INBOUND_PROTOCOL", default="socks5").lower()

    if protocol in {"socks", "socks5"}:
        port = env_int_choice("PROXY_PORT", "SOCKS_PORT", default=1080, minimum=1, maximum=65535)
        return [make_socks_inbound(listen=listen, port=port)]

    if protocol == "http":
        port = env_int_choice("PROXY_PORT", "HTTP_PORT", default=1080, minimum=1, maximum=65535)
        return [make_http_inbound(listen=listen, port=port)]

    if protocol == "both":
        socks_port = env_int_choice("SOCKS_PORT", default=1080, minimum=1, maximum=65535)
        http_port = env_int_choice("HTTP_PORT", default=1081, minimum=1, maximum=65535)
        if socks_port == http_port:
            fail("SOCKS_PORT and HTTP_PORT must be different when LOCAL_PROXY_PROTOCOL=both")
        return [
            make_socks_inbound(listen=listen, port=socks_port),
            make_http_inbound(listen=listen, port=http_port),
        ]

    fail("LOCAL_PROXY_PROTOCOL must be one of: socks5, http, both")

def maybe_stream_settings(
    *,
    network: str,
    security: str,
    host: str = "",
    path: str = "",
    sni: str = "",
    alpn: str = "",
    service_name: str = "",
    header_type: str = "",
    quic_security: str = "",
    quic_key: str = "",
    mode: str = "",
    authority: str = "",
) -> dict[str, Any]:
    network = normalize_network(network)
    security = normalize_security(security, default="none")

    out: dict[str, Any] = {"network": network}

    if security == "tls":
        out["security"] = "tls"
        tls_settings: dict[str, Any] = {}
        if sni:
            tls_settings["serverName"] = sni
        if alpn:
            tls_settings["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if tls_settings:
            out["tlsSettings"] = tls_settings

    if network == "ws":
        ws: dict[str, Any] = {}
        if path:
            ws["path"] = path
        if host:
            ws["headers"] = {"Host": host}
        if ws:
            out["wsSettings"] = ws

    elif network == "grpc":
        grpc: dict[str, Any] = {}
        service = service_name or path.lstrip("/")
        if service:
            grpc["serviceName"] = service
        if mode:
            grpc["multiMode"] = mode.lower() in {"multi", "multi-mode", "true", "1"}
        if authority:
            grpc["authority"] = authority
        if grpc:
            out["grpcSettings"] = grpc

    elif network == "http":
        http_settings: dict[str, Any] = {}
        if host:
            http_settings["host"] = [h.strip() for h in host.split(",") if h.strip()]
        if path:
            http_settings["path"] = path
        if http_settings:
            out["httpSettings"] = http_settings

    elif network == "tcp":
        if header_type and header_type.lower() != "none":
            out["tcpSettings"] = {"header": {"type": header_type}}

    elif network == "kcp":
        kcp: dict[str, Any] = {}
        if header_type:
            kcp["header"] = {"type": header_type}
        if kcp:
            out["kcpSettings"] = kcp

    elif network == "quic":
        quic: dict[str, Any] = {}
        if quic_security:
            quic["security"] = quic_security
        if quic_key:
            quic["key"] = quic_key
        if header_type:
            quic["header"] = {"type": header_type}
        if quic:
            out["quicSettings"] = quic

    elif network == "httpupgrade":
        httpupgrade: dict[str, Any] = {}
        if host:
            httpupgrade["host"] = host
        if path:
            httpupgrade["path"] = path
        if httpupgrade:
            out["httpupgradeSettings"] = httpupgrade

    elif network == "splithttp":
        splithttp: dict[str, Any] = {}
        if host:
            splithttp["host"] = host
        if path:
            splithttp["path"] = path
        if mode:
            splithttp["mode"] = mode
        if splithttp:
            out["splithttpSettings"] = splithttp

    return out


def apply_common_outbound_options(outbound: dict[str, Any]) -> dict[str, Any]:
    if env_bool("ENABLE_MUX", False):
        outbound["mux"] = {
            "enabled": True,
            "concurrency": env_int("MUX_CONCURRENCY", 8, minimum=1, maximum=1024),
        }
    return outbound


def build_base_config(proxy_outbound: dict[str, Any]) -> dict[str, Any]:
    config: dict[str, Any] = {
        "log": {"loglevel": os.getenv("LOGLEVEL", "warning")},
        "inbounds": default_inbounds(),
        "outbounds": [
            apply_common_outbound_options(proxy_outbound),
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
    }

    if env_bool("ROUTE_PRIVATE_DIRECT", True):
        config["routing"] = {
            "domainStrategy": os.getenv("ROUTING_DOMAIN_STRATEGY", "AsIs"),
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": ["geosite:private"],
                    "outboundTag": "direct",
                },
            ],
        }

    return config


def parse_vmess(link: str) -> dict[str, Any]:
    raw = link[len("vmess://") :]
    obj = json.loads(b64decode_relaxed(raw))

    address = obj.get("add")
    port = int(obj.get("port", 0))
    uuid = obj.get("id")
    if not address or not port or not uuid:
        fail("Invalid vmess link: missing add, port, or id")

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "alterId": int(obj.get("aid", 0) or 0),
                            "security": obj.get("scy", "auto") or "auto",
                        }
                    ],
                }
            ]
        },
    }

    stream = maybe_stream_settings(
        network=obj.get("net", "tcp"),
        security=obj.get("tls", "none"),
        host=obj.get("host", ""),
        path=unquote(obj.get("path", "")),
        sni=obj.get("sni", ""),
        alpn=obj.get("alpn", ""),
        header_type=obj.get("type", ""),
    )
    if stream:
        outbound["streamSettings"] = stream
    return build_base_config(outbound)


def parse_vless(link: str) -> dict[str, Any]:
    u = urlparse(link)
    port = safe_port(u)
    if not u.username or not u.hostname:
        fail("Invalid vless link: missing uuid, host, or port")

    uuid = unquote(u.username)
    if not UUID_RE.match(uuid):
        fail("Invalid vless link: username must be a UUID")

    q = parse_qs(u.query, keep_blank_values=True)
    security = qget(q, ["security"], "none")
    network = qget(q, ["type", "net"], "tcp")

    user: dict[str, Any] = {
        "id": uuid,
        "encryption": qget(q, ["encryption"], "none") or "none",
    }
    flow = qget(q, ["flow"], "")
    if flow:
        # This is safe to pass for V2Ray-supported flows; REALITY/XTLS links are blocked above by security.
        user["flow"] = flow

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": u.hostname,
                    "port": port,
                    "users": [user],
                }
            ]
        },
    }

    stream = maybe_stream_settings(
        network=network,
        security=security,
        host=qget(q, ["host", "peer"], ""),
        path=unquote(qget(q, ["path"], "")),
        sni=qget(q, ["sni", "servername"], ""),
        alpn=qget(q, ["alpn"], ""),
        service_name=qget(q, ["serviceName", "service", "servicename"], ""),
        header_type=qget(q, ["headerType"], ""),
        quic_security=qget(q, ["quicSecurity", "quicsecurity"], ""),
        quic_key=qget(q, ["key", "quicKey"], ""),
        mode=qget(q, ["mode"], ""),
        authority=qget(q, ["authority"], ""),
    )
    if stream:
        outbound["streamSettings"] = stream
    return build_base_config(outbound)


def parse_trojan(link: str) -> dict[str, Any]:
    u = urlparse(link)
    port = safe_port(u)
    if not u.username or not u.hostname:
        fail("Invalid trojan link: missing password, host, or port")

    q = parse_qs(u.query, keep_blank_values=True)
    network = qget(q, ["type", "net"], "tcp")
    security = qget(q, ["security"], "tls")

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": u.hostname,
                    "port": port,
                    "password": unquote(u.username),
                }
            ]
        },
    }

    stream = maybe_stream_settings(
        network=network,
        security=security,
        host=qget(q, ["host", "peer"], ""),
        path=unquote(qget(q, ["path"], "")),
        sni=qget(q, ["sni", "servername"], ""),
        alpn=qget(q, ["alpn"], ""),
        service_name=qget(q, ["serviceName", "service", "servicename"], ""),
        header_type=qget(q, ["headerType"], ""),
        mode=qget(q, ["mode"], ""),
        authority=qget(q, ["authority"], ""),
    )
    if stream:
        outbound["streamSettings"] = stream
    return build_base_config(outbound)


def parse_ss_userinfo(username: str, password: str | None = None) -> tuple[str, str]:
    if password is not None:
        decoded = f"{unquote(username)}:{unquote(password)}"
    else:
        token = unquote(username)
        decoded = token if ":" in token else b64decode_relaxed(token)

    if ":" not in decoded:
        fail("Invalid ss link: cannot read method/password")
    method, password = decoded.split(":", 1)
    if not method or not password:
        fail("Invalid ss link: empty method or password")
    return method, password


def parse_ss_legacy_body(link: str) -> dict[str, Any]:
    raw = link[len("ss://") :]
    raw = raw.split("#", 1)[0].split("?", 1)[0]
    decoded = b64decode_relaxed(raw)
    legacy = urlparse("ss://" + decoded)
    port = safe_port(legacy)
    if not legacy.username or not legacy.hostname:
        fail("Invalid legacy ss link")
    return {
        "method": unquote(legacy.username),
        "password": unquote(legacy.password or ""),
        "address": legacy.hostname,
        "port": port,
    }


def parse_ss_plugin_stream(plugin: str) -> dict[str, Any]:
    if not plugin:
        return {}

    plugin = unquote(plugin)
    parts = [p for p in plugin.split(";") if p]
    if not parts:
        return {}

    name = parts[0].lower()
    opts: dict[str, str] = {}
    flags: set[str] = set()
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            opts[k.strip().lower()] = v.strip()
        else:
            flags.add(part.strip().lower())

    if name not in {"v2ray-plugin", "xray-plugin"}:
        fail(
            f"Unsupported Shadowsocks plugin {name!r}. "
            "This helper supports v2ray-plugin/xray-plugin websocket/grpc mappings only."
        )

    mode = opts.get("mode", "websocket").lower()
    if mode in {"websocket", "ws"}:
        network = "ws"
    elif mode == "grpc":
        network = "grpc"
    elif mode == "quic":
        network = "quic"
    else:
        fail(f"Unsupported Shadowsocks plugin mode {mode!r}")

    tls_enabled = "tls" in flags or opts.get("tls", "").lower() in {"1", "true", "yes", "on"}
    host = opts.get("host", "")

    return maybe_stream_settings(
        network=network,
        security="tls" if tls_enabled else "none",
        host=host,
        path=unquote(opts.get("path", "")),
        sni=opts.get("sni", host),
        alpn=opts.get("alpn", ""),
        service_name=opts.get("servicename", "") or opts.get("service_name", ""),
    )


def parse_ss(link: str) -> dict[str, Any]:
    u = urlparse(link)
    q = parse_qs(u.query, keep_blank_values=True)
    plugin = qget(q, ["plugin"], "")

    if u.hostname and u.username:
        port = safe_port(u)
        method, password = parse_ss_userinfo(u.username, u.password)
        address = u.hostname
    else:
        legacy = parse_ss_legacy_body(link)
        method = legacy["method"]
        password = legacy["password"]
        address = legacy["address"]
        port = legacy["port"]

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "method": method,
                    "password": password,
                }
            ]
        },
    }

    stream = parse_ss_plugin_stream(plugin)
    if stream:
        outbound["streamSettings"] = stream
    return build_base_config(outbound)


def parse_link(link: str) -> dict[str, Any]:
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith(UNSUPPORTED_PREFIXES):
        fail(f"Unsupported link type: {link.split('://', 1)[0]}://")
    fail("Unsupported link type")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: link2config.py <link-file> <output-json>", file=sys.stderr)
        return 2

    link_file = sys.argv[1]
    output_json = sys.argv[2]

    try:
        link = read_link_or_subscription(link_file)
        config = parse_link(link)
        Path(output_json).write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI tool should print clean error
        print(f"link2config: ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

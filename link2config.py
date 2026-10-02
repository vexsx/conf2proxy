#!/usr/bin/env python3
"""
Convert a proxy share link (or a subscription) into an Xray-core client config.

The container exposes a local proxy listener selected by environment variable:
  - LOCAL_PROXY_PROTOCOL=socks5  -> SOCKS5 inbound
  - LOCAL_PROXY_PROTOCOL=http    -> HTTP proxy inbound
  - LOCAL_PROXY_PROTOCOL=both    -> SOCKS5 + HTTP proxy inbounds

Supported share links:
  - vmess://   v2rayN base64 JSON format
  - vless://   security=none|tls|reality, flow=xtls-rprx-vision, VLESS encryption
  - trojan://  security=tls|reality|none
  - ss://      SIP002, SIP022 (2022-blake3-*), legacy base64 body,
               v2ray-plugin/xray-plugin (websocket/grpc)

Supported transports: raw/tcp (incl. HTTP header), ws, httpupgrade,
xhttp/splithttp, grpc, kcp (without header/seed).

Not supported (mount a native Xray config.json instead):
  - socks://, http(s)://, hysteria2://, hy2://, tuic://, wireguard://, ssr://
  - transports Xray removed: http/h2, quic
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
from urllib.parse import unquote, urlsplit

SUPPORTED_SCHEMES = ("vmess", "vless", "trojan", "ss")

SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Same ranges Xray treats as private (common/geodata/consts.go). Inlined so the
# routing rules do not need geoip.dat/geosite.dat to be loaded at startup.
PRIVATE_IP_CIDRS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/127",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]
PRIVATE_DOMAINS = [
    "domain:lan",
    "domain:localdomain",
    "domain:example",
    "domain:invalid",
    "domain:localhost",
    "domain:test",
    "domain:local",
    "domain:home.arpa",
    "domain:internal",
    "regexp:^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$",  # dotless names such as "router"
]

SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
VMESS_SECURITIES = {"auto", "aes-128-gcm", "chacha20-poly1305"}
VISION_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name, "").strip() or str(default)
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
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return env_int(name, default, minimum=minimum, maximum=maximum)
    return default


def fail(message: str) -> None:
    raise ValueError(message)


def warn(message: str) -> None:
    print(f"link2config: WARN: {message}", file=sys.stderr)


def b64decode_relaxed(value: str) -> str:
    value = "".join(value.split())
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * ((-len(value)) % 4)
    try:
        return base64.b64decode(value.encode("utf-8"), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid base64 content") from exc


def link_scheme(line: str) -> str:
    match = SCHEME_RE.match(line)
    return match.group(1).lower() if match else ""


def read_link_or_subscription(text: str) -> str:
    """Return the first supported share link in a link list or base64 subscription."""
    candidates = [ln.strip() for ln in text.strip().splitlines()]
    candidates = [ln for ln in candidates if ln and not ln.startswith("#")]
    if not candidates:
        fail("No proxy link found")

    if not any(link_scheme(ln) for ln in candidates):
        # Many subscriptions are a single base64 blob holding one link per line.
        try:
            decoded = b64decode_relaxed("".join(candidates))
        except ValueError:
            fail("No proxy link found: input is neither share links nor a base64 subscription")
        candidates = [ln.strip() for ln in decoded.splitlines() if ln.strip()]

    unsupported: list[str] = []
    for line in candidates:
        scheme = link_scheme(line)
        if scheme in SUPPORTED_SCHEMES:
            return line
        if scheme and scheme not in unsupported:
            unsupported.append(scheme)

    if unsupported:
        fail(
            "Unsupported link type: " + ", ".join(f"{s}://" for s in unsupported)
            + ". Supported: vmess, vless, trojan, ss. Mount a native Xray config.json for other protocols."
        )
    fail("No supported proxy link found. Supported input links: vmess, vless, trojan, ss.")


class Params:
    """Case-insensitive view of share-link parameters.

    Values are percent-decoded exactly once and "+" is kept literally, because
    base64 values (ech, pbk, keys) may contain it.
    """

    def __init__(self, query: str = "", values: dict[str, Any] | None = None) -> None:
        self._values: dict[str, str] = {}
        for part in query.split("&"):
            if not part:
                continue
            key, _, value = part.partition("=")
            key = unquote(key).strip().lower()
            if key and key not in self._values:
                self._values[key] = unquote(value)
        for key, value in (values or {}).items():
            if value is not None and str(value) != "":
                self._values[key.lower()] = str(value)

    def get(self, *names: str, default: str = "") -> str:
        for name in names:
            value = self._values.get(name.lower(), "")
            if value.strip() != "":
                return value.strip()
        return default

    def flag(self, *names: str) -> bool:
        return self.get(*names).lower() in {"1", "true", "yes", "on"}


def split_list(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def safe_port(value: Any, what: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid port in {what} link") from exc
    if not 1 <= port <= 65535:
        fail(f"Missing or invalid port in {what} link")
    return port


def url_port(parsed, what: str) -> int:
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in {what} link") from exc
    return safe_port(port, what)


def normalize_network(value: str) -> str:
    network = (value or "tcp").strip().lower()
    aliases = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "ws",
        "websocket": "ws",
        "httpupgrade": "httpupgrade",
        "xhttp": "xhttp",
        "splithttp": "xhttp",
        "grpc": "grpc",
        "gun": "grpc",
        "kcp": "kcp",
        "mkcp": "kcp",
    }
    if network in {"h2", "http", "h3"}:
        fail("The HTTP/2 (h2) transport was removed from Xray; ask your provider for an xhttp link.")
    if network == "quic":
        fail("The QUIC transport was removed from Xray; ask your provider for an xhttp link.")
    if network not in aliases:
        fail(f"Unsupported network/transport {value!r}. Use a native Xray config.json for this transport.")
    return aliases[network]


def default_fingerprint() -> str:
    value = os.getenv("TLS_FINGERPRINT", "chrome").strip().lower()
    return "" if value in {"", "none", "off", "false"} else value


def build_security(security: str, p: Params) -> tuple[str, dict[str, Any] | None]:
    security = (security or "none").strip().lower()
    if security in {"", "none"}:
        return "none", None

    fingerprint = p.get("fp", "fingerprint").lower() or default_fingerprint()
    server_name = p.get("sni", "servername", "peer")

    if security == "tls":
        tls: dict[str, Any] = {}
        if server_name:
            tls["serverName"] = server_name
        alpn = split_list(p.get("alpn"))
        if alpn:
            tls["alpn"] = alpn
        if fingerprint:
            tls["fingerprint"] = fingerprint
        if p.get("pcs"):
            tls["pinnedPeerCertSha256"] = p.get("pcs")
        if p.get("vcn"):
            tls["verifyPeerCertByName"] = p.get("vcn")
        if p.get("ech"):
            tls["echConfigList"] = p.get("ech")
        if p.flag("allowinsecure", "insecure", "allow_insecure") and not p.get("pcs"):
            warn(
                "allowInsecure is not supported by current Xray; the server certificate will be verified. "
                "For a self-signed certificate add pcs=<sha256 of the certificate> to the link."
            )
        return "tls", tls

    if security == "reality":
        public_key = p.get("pbk", "publickey", "password")
        if not public_key:
            fail("REALITY link is missing pbk (server public key)")
        reality: dict[str, Any] = {
            "fingerprint": fingerprint or "chrome",
            "publicKey": public_key,
        }
        if server_name:
            reality["serverName"] = server_name
        if p.get("sid", "shortid"):
            reality["shortId"] = p.get("sid", "shortid")
        spider_x = p.get("spx", "spiderx")
        if spider_x:
            reality["spiderX"] = spider_x if spider_x.startswith("/") else "/" + spider_x
        if p.get("pqv", "mldsa65verify"):
            reality["mldsa65Verify"] = p.get("pqv", "mldsa65verify")
        return "reality", reality

    if security == "xtls":
        fail("security=xtls was removed from Xray; use flow=xtls-rprx-vision with tls or reality.")
    fail(f"Unsupported security {security!r}. Supported: none, tls, reality.")


def build_transport(network: str, p: Params) -> tuple[str, dict[str, Any] | None]:
    """Return (settings key, settings) for the transport."""
    host = p.get("host")
    path = p.get("path")

    if network == "raw":
        header_type = p.get("headertype").lower()
        if header_type in {"", "none"}:
            return "rawSettings", None
        if header_type != "http":
            fail(f"Unsupported raw/tcp headerType {header_type!r}")
        request: dict[str, Any] = {"path": split_list(path) or ["/"]}
        if host:
            request["headers"] = {"Host": split_list(host)}
        return "rawSettings", {"header": {"type": "http", "request": request}}

    if network == "ws":
        ws: dict[str, Any] = {"path": path or "/"}
        if host:
            ws["host"] = host
        return "wsSettings", ws

    if network == "httpupgrade":
        hu: dict[str, Any] = {"path": path or "/"}
        if host:
            hu["host"] = host
        return "httpupgradeSettings", hu

    if network == "xhttp":
        xhttp: dict[str, Any] = {"path": path or "/", "mode": p.get("mode") or "auto"}
        if host:
            xhttp["host"] = host
        extra = p.get("extra")
        if extra:
            try:
                xhttp["extra"] = json.loads(extra)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid xhttp extra parameter: not JSON") from exc
        return "xhttpSettings", xhttp

    if network == "grpc":
        grpc: dict[str, Any] = {}
        service = p.get("servicename", "service", "path")
        if service:
            grpc["serviceName"] = service
        if p.get("mode").lower() in {"multi", "multi-mode", "true", "1"}:
            grpc["multiMode"] = True
        if p.get("authority"):
            grpc["authority"] = p.get("authority")
        if env_bool("GRPC_HEALTH_CHECK", True):
            # Without pings a dead gRPC connection freezes every stream multiplexed
            # on it until the kernel gives up (minutes). Ping after 60s of silence
            # and drop the connection if no answer arrives within 20s.
            grpc["idle_timeout"] = 60
            grpc["health_check_timeout"] = 20
            grpc["permit_without_stream"] = False
        return "grpcSettings", grpc

    if network == "kcp":
        if p.get("headertype").lower() not in {"", "none"} or p.get("seed"):
            fail("mKCP with headerType/seed needs Xray finalmask settings; use a native config.json.")
        return "kcpSettings", None

    fail(f"Unsupported network {network!r}")


def build_sockopt() -> dict[str, Any] | None:
    sockopt: dict[str, Any] = {}
    user_timeout = env_int("TCP_USER_TIMEOUT_MS", 30000, minimum=0, maximum=600000)
    if user_timeout:
        # Close upstream connections whose data stays unacknowledged this long
        # (silently dropped/blackholed paths) instead of hanging for ~15 minutes.
        sockopt["tcpUserTimeout"] = user_timeout
    congestion = os.getenv("TCP_CONGESTION", "").strip()
    if congestion:
        sockopt["tcpCongestion"] = congestion
    return sockopt or None


def build_stream(network: str, security: str, p: Params) -> dict[str, Any]:
    network = normalize_network(network)
    stream: dict[str, Any] = {"network": network}

    security_name, security_settings = build_security(security, p)
    if security_name != "none":
        stream["security"] = security_name
        stream["tlsSettings" if security_name == "tls" else "realitySettings"] = security_settings

    key, transport = build_transport(network, p)
    if transport:
        stream[key] = transport

    sockopt = build_sockopt()
    if sockopt:
        stream["sockopt"] = sockopt
    return stream


def private_routing() -> dict[str, Any]:
    return {
        "domainStrategy": os.getenv("ROUTING_DOMAIN_STRATEGY", "AsIs").strip() or "AsIs",
        "rules": [
            {"type": "field", "ip": PRIVATE_IP_CIDRS, "outboundTag": "direct"},
            {"type": "field", "domain": PRIVATE_DOMAINS, "outboundTag": "direct"},
        ],
    }


def sniffing_block() -> dict[str, Any]:
    if not env_bool("ENABLE_SNIFFING", True):
        return {"enabled": False}
    return {
        "enabled": True,
        "destOverride": env_csv("SNIFF_DEST_OVERRIDE", "http,tls,quic"),
        "routeOnly": env_bool("SNIFF_ROUTE_ONLY", False),
    }


def inbound_accounts(kind: str) -> list[dict[str, str]] | None:
    """
    kind is the Xray inbound protocol: socks or http.

    Generic envs: PROXY_AUTH=noauth|password, PROXY_USER, PROXY_PASS.
    Legacy envs still work: SOCKS_AUTH/SOCKS_USER/SOCKS_PASS, HTTP_AUTH/HTTP_USER/HTTP_PASS.
    """
    kind_upper = kind.upper()
    auth = env_choice("PROXY_AUTH", f"{kind_upper}_AUTH", default="noauth").lower()
    if auth in {"", "noauth", "none", "false"}:
        return None
    if auth != "password":
        fail("PROXY_AUTH must be noauth or password")

    user = env_choice("PROXY_USER", f"{kind_upper}_USER", default="")
    password = env_choice("PROXY_PASS", f"{kind_upper}_PASS", default="")
    if not user or not password:
        fail("PROXY_USER and PROXY_PASS are required when PROXY_AUTH=password")
    return [{"user": user, "pass": password}]


def make_socks_inbound(*, listen: str, port: int) -> dict[str, Any]:
    accounts = inbound_accounts("socks")
    settings: dict[str, Any] = {
        "auth": "password" if accounts else "noauth",
        "udp": env_bool("ENABLE_SOCKS_UDP", True),
    }
    if accounts:
        settings["accounts"] = accounts
    udp_ip = os.getenv("SOCKS_UDP_IP", "").strip()
    if udp_ip:
        settings["ip"] = udp_ip
    return {
        "tag": "socks-in",
        "listen": listen,
        "port": port,
        "protocol": "socks",
        "settings": settings,
        "sniffing": sniffing_block(),
    }


def make_http_inbound(*, listen: str, port: int) -> dict[str, Any]:
    accounts = inbound_accounts("http")
    settings: dict[str, Any] = {"allowTransparent": False}
    if accounts:
        settings["accounts"] = accounts
    return {
        "tag": "http-in",
        "listen": listen,
        "port": port,
        "protocol": "http",
        "settings": settings,
        "sniffing": sniffing_block(),
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


def apply_mux(outbound: dict[str, Any], flow: str = "") -> None:
    if not env_bool("ENABLE_MUX", False):
        return
    mux: dict[str, Any] = {
        "enabled": True,
        "concurrency": env_int("MUX_CONCURRENCY", 8, minimum=1, maximum=1024),
        "xudpConcurrency": env_int("MUX_XUDP_CONCURRENCY", 16, minimum=1, maximum=1024),
    }
    if flow in VISION_FLOWS:
        # Vision carries TCP itself; only UDP (XUDP) may be multiplexed.
        mux["concurrency"] = -1
    outbound["mux"] = mux


def build_policy() -> dict[str, Any]:
    level: dict[str, Any] = {
        "connIdle": env_int("CONN_IDLE", 300, minimum=10, maximum=86400),
    }
    buffer_kb = os.getenv("BUFFER_SIZE_KB", "").strip()
    if buffer_kb:
        level["bufferSize"] = env_int("BUFFER_SIZE_KB", 0, minimum=0, maximum=65536)
    return {"levels": {"0": level}}


def build_base_config(proxy_outbound: dict[str, Any]) -> dict[str, Any]:
    loglevel = os.getenv("LOGLEVEL", "warning").strip().lower() or "warning"
    config: dict[str, Any] = {
        "log": {
            "loglevel": loglevel,
            # "" means stdout; one line per connection is costly under heavy load.
            "access": "" if env_bool("ACCESS_LOG", False) else "none",
            "dnsLog": False,
        },
        "policy": build_policy(),
        "inbounds": default_inbounds(),
        "outbounds": [
            proxy_outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
    }
    if env_bool("ROUTE_PRIVATE_DIRECT", True):
        config["routing"] = private_routing()
    return config


def parse_vmess(link: str) -> dict[str, Any]:
    raw = link[len("vmess://"):].split("#", 1)[0]
    try:
        obj = json.loads(b64decode_relaxed(raw))
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid vmess link: payload is not JSON") from exc
    if not isinstance(obj, dict):
        fail("Invalid vmess link: payload is not a JSON object")

    address = str(obj.get("add", "")).strip()
    port = safe_port(obj.get("port"), "vmess")
    uuid = str(obj.get("id", "")).strip()
    if not address or not uuid:
        fail("Invalid vmess link: missing add or id")

    aid = str(obj.get("aid", "0") or "0").strip()
    if aid not in {"", "0"}:
        warn("vmess alterId > 0 (legacy MD5 auth) is not supported by Xray; using VMess AEAD (alterId 0).")

    security = str(obj.get("scy", "auto") or "auto").lower()
    if security not in VMESS_SECURITIES:
        security = "auto"

    network = str(obj.get("net", "tcp") or "tcp")
    kind = str(obj.get("type", "") or "")
    # v2rayN keeps the transport details in generic fields; map them to link params.
    values: dict[str, Any] = {
        "host": obj.get("host", ""),
        "path": obj.get("path", ""),
        "sni": obj.get("sni", ""),
        "alpn": obj.get("alpn", ""),
        "fp": obj.get("fp", ""),
        "pbk": obj.get("pbk", ""),
        "sid": obj.get("sid", ""),
        "spx": obj.get("spx", ""),
    }
    net = network.strip().lower()
    if net in {"grpc", "gun"}:
        values["serviceName"] = obj.get("path", "")
        values["authority"] = obj.get("host", "")
        values["mode"] = kind
        values["host"] = ""
    elif net in {"xhttp", "splithttp"}:
        values["mode"] = kind
    else:
        values["headerType"] = kind
    p = Params(values=values)

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [{"id": uuid, "security": security}],
                }
            ]
        },
        "streamSettings": build_stream(network, str(obj.get("tls", "") or "none"), p),
    }
    apply_mux(outbound)
    return build_base_config(outbound)


def parse_vless(link: str) -> dict[str, Any]:
    u = urlsplit(link)
    port = url_port(u, "vless")
    if not u.username or not u.hostname:
        fail("Invalid vless link: missing id or host")

    uuid = unquote(u.username)
    if not UUID_RE.match(uuid) and not 1 <= len(uuid.encode("utf-8")) <= 30:
        fail("Invalid vless link: id must be a UUID or a 1-30 byte string")

    p = Params(u.query)
    user: dict[str, Any] = {"id": uuid, "encryption": p.get("encryption") or "none"}
    flow = p.get("flow")
    if flow:
        if flow not in VISION_FLOWS:
            fail(f"VLESS flow {flow!r} is not supported by Xray; only xtls-rprx-vision is.")
        user["flow"] = flow

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": u.hostname, "port": port, "users": [user]}]},
        "streamSettings": build_stream(p.get("type", "net") or "tcp", p.get("security") or "none", p),
    }
    apply_mux(outbound, flow)
    return build_base_config(outbound)


def parse_trojan(link: str) -> dict[str, Any]:
    u = urlsplit(link)
    port = url_port(u, "trojan")
    if not u.username or not u.hostname:
        fail("Invalid trojan link: missing password or host")
    password = unquote(u.username)
    if u.password is not None:
        password += ":" + unquote(u.password)

    p = Params(u.query)
    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [{"address": u.hostname, "port": port, "password": password}]},
        "streamSettings": build_stream(p.get("type", "net") or "tcp", p.get("security") or "tls", p),
    }
    apply_mux(outbound)
    return build_base_config(outbound)


def parse_ss_userinfo(userinfo: str) -> tuple[str, str]:
    token = unquote(userinfo)
    if ":" not in token:
        token = b64decode_relaxed(token)
    if ":" not in token:
        fail("Invalid ss link: cannot read method/password")
    method, password = token.split(":", 1)
    if not method or not password:
        fail("Invalid ss link: empty method or password")
    return method, password


def parse_ss_plugin_stream(plugin: str) -> dict[str, Any]:
    parts = [x for x in plugin.split(";") if x]
    name = parts[0].strip().lower()
    opts: dict[str, str] = {}
    flags: set[str] = set()
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            opts[k.strip().lower()] = v.strip()
        else:
            flags.add(part.strip().lower())

    if name not in {"v2ray-plugin", "xray-plugin"}:
        fail(f"Unsupported Shadowsocks plugin {name!r}. Only v2ray-plugin/xray-plugin (websocket/grpc) are supported.")

    mode = opts.get("mode", "websocket").lower()
    if mode in {"websocket", "ws"}:
        network = "ws"
    elif mode == "grpc":
        network = "grpc"
    else:
        fail(f"Unsupported Shadowsocks plugin mode {mode!r}")

    tls = "tls" in flags or opts.get("tls", "").lower() in {"1", "true", "yes", "on"}
    host = opts.get("host", "")
    p = Params(values={
        "host": host,
        "path": opts.get("path", ""),
        "sni": opts.get("sni", host),
        "alpn": opts.get("alpn", ""),
        "serviceName": opts.get("servicename", "") or opts.get("service_name", ""),
    })
    return build_stream(network, "tls" if tls else "none", p)


def parse_ss(link: str) -> dict[str, Any]:
    # Split by hand: standard-base64 user info may contain "/", which urlsplit
    # would treat as the start of the path.
    body = link[len("ss://"):].split("#", 1)[0]
    main, _, query = body.partition("?")
    p = Params(query)

    if "@" in main:
        userinfo, _, hostport = main.rpartition("@")
        method, password = parse_ss_userinfo(userinfo)
    else:
        # Legacy form: ss://BASE64(method:password@host:port)
        try:
            decoded = b64decode_relaxed(main)
        except ValueError:
            decoded = b64decode_relaxed(main.rstrip("/"))
        userinfo, _, hostport = decoded.rpartition("@")
        method, _, password = userinfo.partition(":")
        if not method or not password:
            fail("Invalid legacy ss link: cannot read method/password")
    parsed = urlsplit("//" + hostport.rstrip("/"))
    if not parsed.hostname:
        fail("Invalid ss link: missing host")
    port = url_port(parsed, "ss")

    method = method.strip().lower()
    if method in {"none", "plain"}:
        fail("Shadowsocks method none/plain was removed from Xray.")
    if method not in SS_METHODS:
        fail(f"Shadowsocks method {method!r} is not supported by Xray (AEAD and 2022 methods only).")

    outbound: dict[str, Any] = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": parsed.hostname, "port": port, "method": method, "password": password}]
        },
    }
    plugin = p.get("plugin")
    if plugin:
        outbound["streamSettings"] = parse_ss_plugin_stream(plugin)
    else:
        outbound["streamSettings"] = build_stream(p.get("type", "net") or "tcp", p.get("security") or "none", p)
    apply_mux(outbound)
    return build_base_config(outbound)


def parse_link(link: str) -> dict[str, Any]:
    scheme = link_scheme(link)
    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "vless":
        return parse_vless(link)
    if scheme == "trojan":
        return parse_trojan(link)
    if scheme == "ss":
        return parse_ss(link)
    if scheme:
        fail(f"Unsupported link type: {scheme}://")
    fail("Unsupported link type")


def describe(config: dict[str, Any]) -> str:
    """One-line summary for the container log; never includes secrets."""
    out = config["outbounds"][0]
    stream = out.get("streamSettings", {})
    parts = [out["protocol"], stream.get("security", "none") + "/" + stream.get("network", "raw")]
    users = out["settings"].get("vnext", [{}])[0].get("users", [{}])
    if users and users[0].get("flow"):
        parts.append("flow=" + users[0]["flow"])
    listeners = ", ".join(f"{i['protocol']}:{i['port']}" for i in config["inbounds"])
    return " ".join(parts) + " -> " + listeners


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: link2config.py <link-file|-> <output-json>", file=sys.stderr)
        return 2

    source, output_json = sys.argv[1], sys.argv[2]
    try:
        text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8-sig")
        config = parse_link(read_link_or_subscription(text))
        Path(output_json).write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"link2config: {describe(config)}", file=sys.stderr)
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI tool should print clean error
        print(f"link2config: ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

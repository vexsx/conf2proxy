#!/usr/bin/env python3
"""
Container healthcheck.

A bare TCP connect is not enough: the kernel keeps accepting connections into
the listen backlog even when the proxy process is stuck. This check completes a
real SOCKS5 / HTTP exchange with Xray, and optionally fetches HEALTHCHECK_URL
(plain http://) through the tunnel to verify the upstream server end to end.
"""
from __future__ import annotations

import base64
import os
import socket
import sys
from urllib.parse import urlsplit

TIMEOUT = float(os.getenv("HEALTHCHECK_TIMEOUT", "4"))


def env(name: str, default: str = "") -> str:
    value = os.getenv(name, "").strip()
    return value or default


def target_host() -> str:
    listen = env("INBOUND_LISTEN", "0.0.0.0")
    return "127.0.0.1" if listen in {"0.0.0.0", "::", "[::]"} else listen


def auth() -> tuple[str, str] | None:
    if env("PROXY_AUTH", "noauth").lower() != "password":
        return None
    return env("PROXY_USER"), env("PROXY_PASS")


def listeners() -> list[tuple[str, int]]:
    proto = env("LOCAL_PROXY_PROTOCOL", env("INBOUND_PROTOCOL", "socks5")).lower()
    if proto == "http":
        return [("http", int(env("PROXY_PORT", env("HTTP_PORT", "1080"))))]
    if proto == "both":
        return [("socks", int(env("SOCKS_PORT", "1080"))), ("http", int(env("HTTP_PORT", "1081")))]
    return [("socks", int(env("PROXY_PORT", env("SOCKS_PORT", "1080"))))]


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed by proxy")
        data += chunk
    return data


def socks_handshake(sock: socket.socket, creds: tuple[str, str] | None) -> None:
    sock.sendall(b"\x05\x01\x02" if creds else b"\x05\x01\x00")
    version, method = recv_exact(sock, 2)
    if version != 5:
        raise ConnectionError("not a SOCKS5 reply")
    if method == 2 and creds:
        user, password = (x.encode() for x in creds)
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if recv_exact(sock, 2)[1] != 0:
            raise ConnectionError("SOCKS5 authentication rejected")
    elif method != 0:
        raise ConnectionError(f"SOCKS5 method {method} not accepted")


def socks_connect(sock: socket.socket, host: str, port: int) -> None:
    name = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    reply = recv_exact(sock, 4)
    if reply[1] != 0:
        raise ConnectionError(f"SOCKS5 CONNECT failed (rep={reply[1]})")
    skip = {1: 4, 4: 16}.get(reply[3])
    if skip is None:
        skip = recv_exact(sock, 1)[0]
    recv_exact(sock, skip + 2)


def proxy_auth_header(creds: tuple[str, str] | None) -> str:
    if not creds:
        return ""
    token = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"


def check_listener(kind: str, host: str, port: int) -> None:
    """Prove Xray itself answers on the listener (no upstream traffic)."""
    with socket.create_connection((host, port), TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        if kind == "socks":
            sock.sendall(b"\x05\x01\x00")
            if recv_exact(sock, 1) != b"\x05":
                raise ConnectionError("not a SOCKS5 reply")
        else:
            # An empty Host makes Xray answer (407) or close at once; either
            # proves the request was read. A stuck process times out instead.
            sock.sendall(b"GET / HTTP/1.1\r\nHost:\r\n\r\n")
            sock.recv(1)


def check_url(url: str, kind: str, host: str, port: int) -> None:
    """Fetch a plain-http URL through the tunnel and require any HTTP status line."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("HEALTHCHECK_URL must be a plain http:// URL")
    dest_port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    creds = auth()
    with socket.create_connection((host, port), TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        if kind == "socks":
            socks_handshake(sock, creds)
            socks_connect(sock, parts.hostname, dest_port)
            request = f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n"
        else:
            request = (
                f"GET {url} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
                f"{proxy_auth_header(creds)}Connection: close\r\n\r\n"
            )
        sock.sendall(request.encode())
        status = sock.recv(64)
        if not status.startswith(b"HTTP/"):
            raise ConnectionError("no HTTP response through the tunnel")


def main() -> int:
    host = target_host()
    url = env("HEALTHCHECK_URL")
    try:
        for kind, port in listeners():
            check_listener(kind, host, port)
        if url:
            kind, port = listeners()[0]
            check_url(url, kind, host, port)
    except Exception as exc:  # noqa: BLE001 - report any failure as unhealthy
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1
    print("healthy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

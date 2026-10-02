"""Unit tests for link2config.py (run: python3 -m unittest discover -s tests -v)."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import link2config as l2c  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "R-HfzkHQ31tENLkk6Z-Jw4DUbX4hldqxaF6ixt5nwm8"
REALITY = (
    f"vless://{UUID}@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality"
    f"&sni=www.example.org&fp=firefox&pbk={PBK}&sid=6ba85179e30d4fc2&spx=%2F&type=tcp#my%20server"
)


def vmess_link(**fields):
    obj = {"v": "2", "ps": "t", "add": "vm.example.org", "port": "443", "id": UUID, "aid": "0",
           "scy": "auto", "net": "ws", "type": "none", "host": "", "path": "/", "tls": ""}
    obj.update(fields)
    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


def convert(link: str) -> dict:
    return l2c.parse_link(l2c.read_link_or_subscription(link))


def proxy(config: dict) -> dict:
    return config["outbounds"][0]


class EnvTestCase(unittest.TestCase):
    """Every test starts from an empty environment."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)


class RealityTests(EnvTestCase):
    def test_reality_vision(self):
        out = proxy(convert(REALITY))
        self.assertEqual(out["protocol"], "vless")
        user = out["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user, {"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"})
        stream = out["streamSettings"]
        self.assertEqual(stream["network"], "raw")
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(stream["realitySettings"], {
            "fingerprint": "firefox",
            "publicKey": PBK,
            "serverName": "www.example.org",
            "shortId": "6ba85179e30d4fc2",
            "spiderX": "/",
        })
        self.assertEqual(stream["sockopt"], {"tcpUserTimeout": 30000})

    def test_reality_defaults_fingerprint_and_requires_public_key(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=reality&pbk={PBK}"))
        self.assertEqual(out["streamSettings"]["realitySettings"]["fingerprint"], "chrome")
        with self.assertRaisesRegex(ValueError, "pbk"):
            convert(f"vless://{UUID}@h.example.org:443?security=reality&sni=a.org")

    def test_legacy_flows_rejected(self):
        with self.assertRaisesRegex(ValueError, "flow"):
            convert(f"vless://{UUID}@h.example.org:443?security=tls&flow=xtls-rprx-direct")


class TransportTests(EnvTestCase):
    def test_ws_path_decoded_once(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&type=ws&host=cdn.example.org"
                            "&path=%2Fws%3Fed%3D2048%2525"))
        ws = out["streamSettings"]["wsSettings"]
        self.assertEqual(ws, {"path": "/ws?ed=2048%25", "host": "cdn.example.org"})

    def test_plus_sign_is_preserved(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&ech=AB+CD/EF=="))
        self.assertEqual(out["streamSettings"]["tlsSettings"]["echConfigList"], "AB+CD/EF==")

    def test_tls_fields(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&sni=s.example.org"
                            "&alpn=h2%2Chttp%2F1.1&pcs=abcd&vcn=n.example.org"))
        self.assertEqual(out["streamSettings"]["tlsSettings"], {
            "serverName": "s.example.org",
            "alpn": ["h2", "http/1.1"],
            "fingerprint": "chrome",
            "pinnedPeerCertSha256": "abcd",
            "verifyPeerCertByName": "n.example.org",
        })

    def test_allow_insecure_is_dropped_with_warning(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&allowInsecure=1"))
        self.assertNotIn("allowInsecure", out["streamSettings"]["tlsSettings"])
        self.assertIn("pcs=", stderr.getvalue())

    def test_grpc_health_check(self):
        link = f"vless://{UUID}@h.example.org:443?security=tls&type=grpc&serviceName=svc&mode=multi"
        grpc = proxy(convert(link))["streamSettings"]["grpcSettings"]
        self.assertEqual(grpc["serviceName"], "svc")
        self.assertTrue(grpc["multiMode"])
        self.assertEqual((grpc["idle_timeout"], grpc["health_check_timeout"]), (60, 20))
        with mock.patch.dict(os.environ, {"GRPC_HEALTH_CHECK": "false"}):
            grpc = proxy(convert(link))["streamSettings"]["grpcSettings"]
        self.assertNotIn("idle_timeout", grpc)

    def test_xhttp_extra(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&type=xhttp&path=%2Fx"
                            "&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"))
        self.assertEqual(out["streamSettings"]["xhttpSettings"], {
            "path": "/x", "mode": "packet-up", "extra": {"xPaddingBytes": "100-1000"},
        })

    def test_raw_http_header(self):
        out = proxy(convert(f"vless://{UUID}@h.example.org:443?security=tls&type=tcp&headerType=http"
                            "&host=a.org%2Cb.org&path=%2Fp"))
        self.assertEqual(out["streamSettings"]["rawSettings"]["header"], {
            "type": "http", "request": {"path": ["/p"], "headers": {"Host": ["a.org", "b.org"]}},
        })

    def test_removed_transports(self):
        for network in ("h2", "http", "quic"):
            with self.subTest(network=network), self.assertRaisesRegex(ValueError, "removed"):
                convert(f"vless://{UUID}@h.example.org:443?security=tls&type={network}")

    def test_kcp_with_seed_rejected(self):
        with self.assertRaisesRegex(ValueError, "mKCP"):
            convert(f"vless://{UUID}@h.example.org:443?type=kcp&seed=abc")


class ProtocolTests(EnvTestCase):
    def test_vless_accepts_non_uuid_id(self):
        out = proxy(convert("vless://my-user@h.example.org:443?security=tls"))
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["id"], "my-user")
        with self.assertRaisesRegex(ValueError, "UUID"):
            convert("vless://" + "x" * 31 + "@h.example.org:443?security=tls")

    def test_vmess_ws_tls(self):
        out = proxy(convert(vmess_link(net="ws", host="cdn.example.org", path="/vm", tls="tls",
                                       sni="cdn.example.org", scy="none", aid="64")))
        user = out["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user, {"id": UUID, "security": "auto"})
        stream = out["streamSettings"]
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["wsSettings"], {"path": "/vm", "host": "cdn.example.org"})

    def test_vmess_grpc_uses_path_as_service_name(self):
        out = proxy(convert(vmess_link(net="grpc", path="svc", host="auth.example.org", type="multi", tls="tls")))
        grpc = out["streamSettings"]["grpcSettings"]
        self.assertEqual((grpc["serviceName"], grpc["authority"], grpc["multiMode"]), ("svc", "auth.example.org", True))

    def test_trojan_defaults_to_tls(self):
        out = proxy(convert("trojan://p%40ss@t.example.org:443?sni=t.example.org#x"))
        self.assertEqual(out["settings"]["servers"][0]["password"], "p@ss")
        self.assertEqual(out["streamSettings"]["security"], "tls")

    def test_ss_2022_plain_userinfo(self):
        out = proxy(convert("ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:8388#ss"))
        server = out["settings"]["servers"][0]
        self.assertEqual((server["method"], server["password"]), ("2022-blake3-aes-128-gcm", "YWJjZGVmZ2hpamtsbW5vcA=="))

    def test_ss_standard_base64_userinfo_with_slash(self):
        password = "ab?xyz"  # "?" at the end of a 3-byte group encodes to "/"
        userinfo = base64.b64encode(f"aes-256-gcm:{password}".encode()).decode()
        self.assertIn("/", userinfo)
        out = proxy(convert(f"ss://{userinfo}@ss.example.org:8388#x"))
        server = out["settings"]["servers"][0]
        self.assertEqual((server["address"], server["port"], server["password"]), ("ss.example.org", 8388, password))

    def test_ss_legacy_body(self):
        body = base64.b64encode(b"chacha20-ietf-poly1305:pw@[2001:db8::1]:8388").decode()
        server = proxy(convert(f"ss://{body}#legacy"))["settings"]["servers"][0]
        self.assertEqual((server["address"], server["port"]), ("2001:db8::1", 8388))

    def test_ss_plugin(self):
        userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:pw").decode().rstrip("=")
        out = proxy(convert(f"ss://{userinfo}@ss.example.org:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket"
                            "%3Btls%3Bhost%3Dcdn.example.org%3Bpath%3D%2Fp#x"))
        stream = out["streamSettings"]
        self.assertEqual((stream["network"], stream["security"]), ("ws", "tls"))
        self.assertEqual(stream["wsSettings"], {"path": "/p", "host": "cdn.example.org"})

    def test_ss_stream_cipher_rejected(self):
        userinfo = base64.urlsafe_b64encode(b"aes-256-cfb:pw").decode()
        with self.assertRaisesRegex(ValueError, "not supported"):
            convert(f"ss://{userinfo}@ss.example.org:8388")


class InputTests(EnvTestCase):
    def test_subscription_skips_unsupported_links(self):
        blob = base64.b64encode(f"hy2://x@1.1.1.1:443\n{REALITY}\n".encode()).decode()
        self.assertEqual(l2c.read_link_or_subscription(blob), REALITY)

    def test_unsupported_only(self):
        with self.assertRaisesRegex(ValueError, "hysteria2://"):
            l2c.read_link_or_subscription("# comment\nhysteria2://x@1.1.1.1:443\n")

    def test_empty(self):
        with self.assertRaisesRegex(ValueError, "No proxy link"):
            l2c.read_link_or_subscription("\n# only a comment\n")


class SettingsTests(EnvTestCase):
    def test_defaults(self):
        config = convert(REALITY)
        self.assertEqual(config["log"], {"loglevel": "warning", "access": "none", "dnsLog": False})
        self.assertEqual(config["policy"], {"levels": {"0": {"connIdle": 300}}})
        (inbound,) = config["inbounds"]
        self.assertEqual((inbound["protocol"], inbound["port"], inbound["listen"]), ("socks", 1080, "0.0.0.0"))
        self.assertEqual(inbound["settings"], {"auth": "noauth", "udp": True})
        self.assertTrue(inbound["sniffing"]["enabled"])
        self.assertEqual([o["tag"] for o in config["outbounds"]], ["proxy", "direct", "block"])
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "direct")

    def test_both_with_auth(self):
        env = {"LOCAL_PROXY_PROTOCOL": "both", "SOCKS_PORT": "2080", "HTTP_PORT": "2081",
               "PROXY_AUTH": "password", "PROXY_USER": "u", "PROXY_PASS": "p"}
        with mock.patch.dict(os.environ, env):
            socks, http = convert(REALITY)["inbounds"]
        self.assertEqual((socks["port"], http["port"]), (2080, 2081))
        self.assertEqual(socks["settings"]["auth"], "password")
        self.assertEqual(socks["settings"]["accounts"], [{"user": "u", "pass": "p"}])
        self.assertEqual(http["settings"]["accounts"], [{"user": "u", "pass": "p"}])

    def test_invalid_settings(self):
        cases = [
            ({"LOCAL_PROXY_PROTOCOL": "both", "SOCKS_PORT": "1080", "HTTP_PORT": "1080"}, "different"),
            ({"PROXY_AUTH": "password"}, "PROXY_USER"),
            ({"LOCAL_PROXY_PROTOCOL": "tun"}, "LOCAL_PROXY_PROTOCOL"),
            ({"PROXY_PORT": "70000"}, "PROXY_PORT"),
        ]
        for env, message in cases:
            with self.subTest(env=env), mock.patch.dict(os.environ, env), self.assertRaisesRegex(ValueError, message):
                convert(REALITY)

    def test_tuning_switches(self):
        env = {"ROUTE_PRIVATE_DIRECT": "false", "ACCESS_LOG": "true", "TCP_USER_TIMEOUT_MS": "0",
               "CONN_IDLE": "120", "BUFFER_SIZE_KB": "64", "TCP_CONGESTION": "bbr"}
        with mock.patch.dict(os.environ, env):
            config = convert(REALITY)
        self.assertNotIn("routing", config)
        self.assertEqual(config["log"]["access"], "")
        self.assertEqual(config["policy"]["levels"]["0"], {"connIdle": 120, "bufferSize": 64})
        self.assertEqual(proxy(config)["streamSettings"]["sockopt"], {"tcpCongestion": "bbr"})

    def test_mux_with_vision_only_muxes_udp(self):
        with mock.patch.dict(os.environ, {"ENABLE_MUX": "true"}):
            mux = proxy(convert(REALITY))["mux"]
        self.assertEqual(mux["concurrency"], -1)
        self.assertEqual(mux["xudpConcurrency"], 16)

    def test_summary_has_no_secrets(self):
        summary = l2c.describe(convert(REALITY))
        self.assertEqual(summary, "vless reality/raw flow=xtls-rprx-vision -> socks:1080")
        self.assertNotIn(UUID, summary)


if __name__ == "__main__":
    unittest.main()

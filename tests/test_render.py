"""Compatibility and boundary tests for generated public/private artifacts."""

import base64
import copy
import ipaddress
import json
import re
import unittest
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

from vpnkit.render import new_state, render, validate_state


def sample_state(**kwargs):
    # Deterministic nonproduction key-format fixtures. Never use these keys.
    return new_state(
        "8.8.8.8", private_key=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
        public_key=base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("="),
        **kwargs,
    )


class SubscriptionCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.state = sample_state(name="新加坡 & Friends/#?")
        self.files = render(self.state, with_monitor=True)

    def test_shadowrocket_standard_base64_and_vless_match_clash(self):
        uri = base64.b64decode(self.files["shadowrocket.txt"], validate=False).decode().strip()
        self.assertEqual(uri, self.files["direct-vless.txt"].strip())
        self.assertEqual(uri, json.loads(self.files["urls.json"])["direct_vless"])
        # Reject URL-safe substitutions or malformed padding in a subscription.
        self.assertEqual(base64.b64encode((uri + "\n").encode()).decode(), self.files["shadowrocket.txt"].strip())
        parts = urlsplit(uri)
        query = parse_qs(parts.query, strict_parsing=True)
        proxy = json.loads(self.files["clash.yaml"])["proxies"][0]
        self.assertEqual(parts.scheme, "vless")
        self.assertEqual(parts.hostname, proxy["server"])
        self.assertEqual(parts.port, proxy["port"])
        self.assertEqual(parts.username, proxy["uuid"])
        self.assertEqual(unquote(parts.fragment), proxy["name"])
        self.assertEqual(query["flow"], [proxy["flow"]])
        self.assertEqual(query["pbk"], [proxy["reality-opts"]["public-key"]])
        self.assertEqual(query["sid"], [proxy["reality-opts"]["short-id"]])
        self.assertEqual(query["sni"], [proxy["servername"]])
        self.assertEqual(query["fp"], [proxy["client-fingerprint"]])
        self.assertEqual(query["security"], ["reality"])
        self.assertEqual(query["encryption"], ["none"])
        self.assertEqual(query["type"], ["tcp"])
        self.assertEqual(query["spx"], ["/"])
        self.assertTrue(proxy["udp"])

    def test_clients_never_receive_server_or_monitor_credentials(self):
        client_files = ["clash.yaml", "shadowrocket.txt", "direct-vless.txt", "urls.json"]
        forbidden = [self.state[field] for field in (
            "reality_private_key", "api_secret", "monitor_password",
        )]
        for filename in client_files:
            payload = self.files[filename]
            if filename == "shadowrocket.txt":
                payload = base64.b64decode(payload).decode()
            for secret in forbidden:
                with self.subTest(file=filename):
                    self.assertNotIn(secret, payload)

    def test_ip_update_keeps_all_credentials_and_paths(self):
        before = copy.deepcopy(self.state)
        first = render(self.state, with_monitor=True)
        self.assertEqual(self.state, before, "render must not mutate persistent credentials")
        self.assertEqual(first, render(self.state, with_monitor=True))
        updated = {**self.state, "server_ip": "1.1.1.1", "local_addresses": ["10.2.3.4"]}
        second = render(updated, with_monitor=True)
        for field in before:
            if field not in {"server_ip", "local_addresses"}:
                self.assertEqual(updated[field], before[field])
        old_urls = json.loads(first["urls.json"])
        new_urls = json.loads(second["urls.json"])
        for field in ("clash", "shadowrocket", "monitor"):
            self.assertEqual(urlsplit(old_urls[field]).path, urlsplit(new_urls[field]).path)
            self.assertEqual(urlsplit(new_urls[field]).hostname, "1.1.1.1")
        proxy = json.loads(second["clash.yaml"])["proxies"][0]
        self.assertEqual(proxy["server"], "1.1.1.1")
        self.assertEqual(proxy["uuid"], before["uuid"])

    def test_new_state_independent_random_credentials(self):
        first, second = sample_state(), sample_state()
        self.assertEqual(uuid.UUID(first["uuid"]).version, 4)
        for field in ("uuid", "short_id", "clash_token", "sr_token", "api_secret", "monitor_password"):
            self.assertNotEqual(first[field], second[field])
        self.assertNotEqual(first["clash_token"], first["sr_token"])
        self.assertEqual(first["monitor_username"], "admin")

    def test_group_does_not_collide_with_node_name(self):
        config = json.loads(render(sample_state(name="VPN"))["clash.yaml"])
        self.assertNotEqual(config["proxies"][0]["name"], config["proxy-groups"][0]["name"])


class ServerBoundaryTests(unittest.TestCase):
    def test_resolved_destinations_reject_private_reserved_and_own_addresses(self):
        state = sample_state(local_addresses=["10.2.3.4", "2001:db8::1", "10.2.3.4"])
        config = json.loads(render(state)["sing-box.json"])
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"action": "resolve", "strategy": "ipv4_only"})
        self.assertTrue(rules[1]["ip_is_private"])
        blocked = [ipaddress.ip_network(cidr) for cidr in rules[2]["ip_cidr"]]
        for value in ("127.0.0.1", "10.2.3.4", "169.254.169.254", "100.100.100.200",
                      "168.63.129.16", "8.8.8.8", "192.0.2.1", "224.0.0.1", "2001:db8::1"):
            address = ipaddress.ip_address(value)
            self.assertTrue(any(address.version == net.version and address in net for net in blocked), value)
        address = ipaddress.ip_address("1.1.1.1")
        self.assertFalse(any(address.version == net.version and address in net for net in blocked))

    def test_monitor_is_opt_in_and_controller_is_local_only(self):
        state = sample_state()
        disabled = render(state)
        enabled = render(state, with_monitor=True)
        self.assertNotIn("experimental", json.loads(disabled["sing-box.json"]))
        self.assertNotIn("listen 8444", disabled["nginx.conf"])
        self.assertNotIn("monitor", json.loads(disabled["urls.json"]))
        api = json.loads(enabled["sing-box.json"])["experimental"]["clash_api"]
        self.assertEqual(api["external_controller"], "127.0.0.1:19090")
        self.assertEqual(api["secret"], state["api_secret"])
        self.assertNotIn("external_ui", api, "the server must never automatically fetch executable dashboard assets")

    def test_nginx_read_only_exact_api_allowlist_and_safe_websockets(self):
        config = render(sample_state(), with_monitor=True)["nginx.conf"]
        endpoints = re.findall(r"location = /api/([^ ]+) \{", config)
        self.assertEqual(set(endpoints), {
            "version", "connections", "traffic", "memory", "logs", "configs", "proxies",
            "rules", "providers/proxies", "providers/rules",
        })
        self.assertEqual(config.count("if ($request_method != GET) { return 405; }"), 2)
        self.assertIn("location /api/ { return 404; }", config)
        self.assertIn("location = /api { return 404; }", config)
        self.assertIn("proxy_pass http://127.0.0.1:19090/connections?interval=1000;", config)
        self.assertIn("proxy_pass http://127.0.0.1:19090/logs?level=warning;", config)
        self.assertNotIn("$args", config)
        self.assertNotIn("$request_uri", config)
        self.assertIn('auth_basic "VPN Monitor";', config)
        self.assertIn("auth_basic_user_file /etc/vpnkit/monitor.htpasswd;", config)
        self.assertIn("map $http_origin $vpnkit_monitor_origin_allowed", config)
        self.assertIn("'https://8.8.8.8:8444' 1;", config)
        self.assertIn("if ($vpnkit_monitor_origin_allowed = 0) { return 403; }", config)
        self.assertIn("proxy_set_header Upgrade $http_upgrade;", config)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", config)
        self.assertNotIn("sites-enabled", config)
        self.assertNotIn("autoindex on", config)
        self.assertIn("access_log off;", config)

    def test_subscriptions_have_exact_random_routes_and_no_plaintext_fallback(self):
        state = sample_state()
        files = render(state)
        nginx = files["nginx.conf"]
        urls = json.loads(files["urls.json"])
        for kind in ("clash", "shadowrocket"):
            self.assertEqual(urlsplit(urls[kind]).scheme, "https")
            self.assertIn(f"location = {urlsplit(urls[kind]).path} {{", nginx)
        initial = files["acme-nginx.conf"]
        self.assertIn("listen 80 default_server;", initial)
        self.assertIn("location ^~ /.well-known/acme-challenge/", initial)
        self.assertIn("location / { return 404; }", initial)
        self.assertNotIn("ssl_certificate", initial)
        self.assertNotIn("subscriptions/", initial)
        self.assertNotIn(state["clash_token"], initial)


class InputValidationTests(unittest.TestCase):
    def test_invalid_server_ips(self):
        state = sample_state()
        for value in ("", "localhost", "1.1.1.1; return 200;", "1.1.1.1\n", "127.0.0.1",
                      "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1",
                      "0.0.0.0", "224.0.0.1", "::1", "2606:4700:4700::1111", 123, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                render({**state, "server_ip": value})

    def test_injection_and_malformed_state_rejected(self):
        state = sample_state()
        bad = {
            "schema_version": [True, "1", 2, None],
            "name": ["", "DIRECT", "bad\nname", "bad\x00name", "leading ", "x" * 101],
            "handshake_host": ["localhost", "1.1.1.1", "example.com;evil", "example.com\n", "bad..com", "-bad.com", "example.COM"],
            "uuid": ["", "not-a-uuid", str(uuid.UUID(int=0)), "'\n;"],
            "short_id": ["00", "A" * 16, "f" * 16 + ";", "\n"],
            "reality_private_key": ["short", "x" * 43 + "=", "A" * 42 + "B"],
            "reality_public_key": ["short", '"; include /tmp/evil; #'],
            "clash_token": ["../secret", "A" * 42 + ";", "A" * 42 + "B"],
            "sr_token": ["?foo", "A" * 43 + "\n"],
            "api_secret": ['";return 200;#', "A" * 42 + "\\"],
            "monitor_username": ["admin:other", "admin\nother", ""],
            "monitor_password": ["short", "long-password\n", "\x00" * 20],
            "local_addresses": ["10.0.0.1", ["10.0.0.1/8"], ["bad"], ["fe80::1%eth0"]],
        }
        for field, values in bad.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    render({**state, field: value}, with_monitor=True)

    def test_required_fields_and_type(self):
        state = sample_state()
        for field in state:
            if field == "local_addresses":
                continue
            missing = {key: value for key, value in state.items() if key != field}
            with self.subTest(field=field), self.assertRaises(ValueError):
                render(missing)
        with self.assertRaises(ValueError):
            validate_state([])
        with self.assertRaises(ValueError):
            render(state, with_monitor="false")
        with self.assertRaises(ValueError):
            sample_state(uuid_value="")


if __name__ == "__main__":
    unittest.main()

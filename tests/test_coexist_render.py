"""Check independent listeners, TLS identity, and legacy-state compatibility."""

import base64
import copy
import json
import re
import unittest
from urllib.parse import urlsplit

from vpnkit.render import new_state, render, validate_state


OPTIONS = {
    "mode": "coexist", "public_host": "vpn.example.com", "vpn_port": 24443,
    "subscription_port": 28443, "monitor_port": 28444, "api_port": 29090,
}


def sample_state(**options):
    return new_state("8.8.8.8", private_key="A" * 43, public_key="A" * 43, **options)


class CoexistRenderTests(unittest.TestCase):
    def setUp(self):
        self.state = sample_state(**OPTIONS)
        self.files = render(self.state, with_monitor=True)

    def test_custom_ports_and_domain_are_consistent_across_clients_and_server(self):
        server = json.loads(self.files["sing-box.json"])
        client = json.loads(self.files["clash.yaml"])
        direct = urlsplit(self.files["direct-vless.txt"].strip())
        sr = base64.b64decode(self.files["shadowrocket.txt"]).decode().strip()
        self.assertEqual(server["inbounds"][0]["listen_port"], 24443)
        self.assertEqual(client["proxies"][0]["port"], 24443)
        self.assertEqual(client["proxies"][0]["server"], "8.8.8.8")
        self.assertEqual(client["rules"][0], "DOMAIN,vpn.example.com,DIRECT")
        self.assertEqual(direct.port, 24443)
        self.assertEqual(direct.hostname, "8.8.8.8")
        self.assertEqual(sr, self.files["direct-vless.txt"].strip())
        # The REALITY handshake still targets the actual TLS service on 443.
        self.assertEqual(server["inbounds"][0]["tls"]["reality"]["handshake"]["server_port"], 443)
        urls = json.loads(self.files["urls.json"])
        for name, port in (("clash", 28443), ("shadowrocket", 28443), ("monitor", 28444)):
            url = urlsplit(urls[name])
            self.assertEqual(url.scheme, "https")
            self.assertEqual(url.hostname, "vpn.example.com")
            self.assertEqual(url.port, port)
        api = server["experimental"]["clash_api"]
        self.assertEqual(api["external_controller"], "127.0.0.1:29090")
        self.assertEqual(api["access_control_allow_origin"], ["https://vpn.example.com:28444"])

    def test_nginx_uses_only_private_paths_and_nonwebsite_listeners(self):
        config = self.files["nginx.conf"]
        self.assertEqual(set(re.findall(r"^\s*listen (\d+)\b", config, re.M)), {"28443", "28444"})
        self.assertNotIn("acme-challenge", config)
        self.assertNotIn("/etc/letsencrypt", config)
        self.assertNotIn("/etc/nginx", config)
        self.assertIn("user vpnkit;", config)
        self.assertIn("worker_processes 1;", config)
        self.assertIn("pid /var/lib/vpnkit/nginx/nginx.pid;", config)
        for directive, path in (("client_body", "client_body"), ("proxy", "proxy"),
                                ("fastcgi", "fastcgi"), ("uwsgi", "uwsgi"), ("scgi", "scgi")):
            self.assertIn(f"{directive}_temp_path /var/lib/vpnkit/nginx/{path};", config)
        self.assertIn("ssl_certificate /etc/vpnkit/tls/fullchain.pem;", config)
        self.assertIn("ssl_certificate_key /etc/vpnkit/tls/privkey.pem;", config)
        self.assertIn("server_name vpn.example.com;", config)
        self.assertIn("text/css css;", config)
        self.assertIn("application/javascript js mjs;", config)
        self.assertIn("font/woff2 woff2;", config)
        # Accidentally selecting the old bootstrap artifact cannot bind port 80.
        self.assertEqual(self.files["acme-nginx.conf"], config)

    def test_monitor_origin_and_read_only_proxy_share_custom_controller_port(self):
        config = self.files["nginx.conf"]
        self.assertIn("'https://vpn.example.com:28444' 1;", config)
        self.assertIn("proxy_pass http://127.0.0.1:29090/connections?interval=1000;", config)
        self.assertIn("proxy_pass http://127.0.0.1:29090/logs?level=warning;", config)
        self.assertIn("auth_basic_user_file /etc/vpnkit/monitor.htpasswd;", config)
        self.assertIn("if ($vpnkit_monitor_origin_allowed = 0) { return 403; }", config)
        self.assertNotIn(":19090", config)
        self.assertNotIn("$args", config)
        self.assertNotIn("$request_uri", config)
        self.assertEqual(config.count("if ($request_method != GET) { return 405; }"), 2)

    def test_disabled_monitor_has_no_controller_or_monitor_listener(self):
        files = render(self.state)
        self.assertNotIn("experimental", json.loads(files["sing-box.json"]))
        self.assertNotIn("monitor", json.loads(files["urls.json"]))
        self.assertNotIn("listen 28444", files["nginx.conf"])
        self.assertNotIn("proxy_pass", files["nginx.conf"])

    def test_ip_change_preserves_https_domain_and_credentials(self):
        original = copy.deepcopy(self.state)
        changed = dict(self.state, server_ip="1.1.1.1")
        changed_files = render(changed, with_monitor=True)
        self.assertEqual(self.state, original)
        before = json.loads(self.files["urls.json"])
        after = json.loads(changed_files["urls.json"])
        for name in ("clash", "shadowrocket", "monitor"):
            self.assertEqual(after[name], before[name])
        proxy = json.loads(changed_files["clash.yaml"])["proxies"][0]
        self.assertEqual(proxy["server"], "1.1.1.1")
        self.assertEqual(proxy["uuid"], self.state["uuid"])


class CoexistValidationTests(unittest.TestCase):
    def test_invalid_ports_fail_before_rendering(self):
        state = sample_state(**OPTIONS)
        for field in ("vpn_port", "subscription_port", "monitor_port", "api_port"):
            for value in (True, False, "24443", "24443; return 200;", 1.5, None, 0, 80, 443, 1023, 65536):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    render(dict(state, **{field: value}), with_monitor=True)
        for field in ("subscription_port", "monitor_port", "api_port"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "distinct"):
                render(dict(state, **{field: state["vpn_port"]}))
        self.assertEqual(validate_state(dict(state, vpn_port=1024))["vpn_port"], 1024)
        self.assertEqual(validate_state(dict(state, vpn_port=65535))["vpn_port"], 65535)

    def test_hostname_mode_and_missing_values_cannot_inject_config(self):
        state = sample_state(**OPTIONS)
        for host in (None, "", "8.8.8.8", "localhost", "vpn.example.com:28443", "https://vpn.example.com",
                     "VPN.example.com", "vpn.example.com\n", "vpn.example.com; include /tmp/x;", "*.example.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                render(dict(state, public_host=host))
        for mode in (None, True, "coexist\n", "invalid", []):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                render(dict(state, mode=mode))
        with self.assertRaises(ValueError):
            sample_state(public_host="vpn.example.com")
        with self.assertRaises(ValueError):
            sample_state(mode="coexist", public_host="vpn.example.com")

    def test_legacy_state_uses_unchanged_defaults_and_ip_urls(self):
        state = sample_state()
        legacy = {name: value for name, value in state.items() if name not in OPTIONS}
        self.assertEqual(render(legacy, with_monitor=True), render(state, with_monitor=True))
        clean = validate_state(legacy)
        self.assertEqual(clean["mode"], "standalone")
        self.assertIsNone(clean["public_host"])
        self.assertEqual(clean["vpn_port"], 443)
        self.assertEqual(clean["subscription_port"], 8443)
        self.assertEqual(clean["monitor_port"], 8444)
        self.assertEqual(clean["api_port"], 19090)
        files = render(dict(legacy, server_ip="1.1.1.1"), with_monitor=True)
        self.assertIn("listen 80 default_server;", files["nginx.conf"])
        self.assertIn("ssl_certificate /etc/letsencrypt/live/vpnkit-ip/fullchain.pem;", files["nginx.conf"])
        urls = json.loads(files["urls.json"])
        self.assertEqual(urlsplit(urls["clash"]).hostname, "1.1.1.1")


if __name__ == "__main__":
    unittest.main()

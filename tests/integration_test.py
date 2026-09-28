#!/usr/bin/env python3
"""Destructive installer test for a disposable GitHub-hosted Linux VM only.

This installs real distribution packages, sing-box, Certbot, MetaCubeXD, and
systemd units. Only ACME issuance and public-IP detection are replaced: HTTPS
uses a locally generated test CA that curl explicitly trusts. Never run this
script on a workstation or an existing VPS.
"""
import argparse
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpnkit import system


def require_disposable_runner():
    if (sys.platform != "linux" or os.geteuid() != 0
            or os.environ.get("VPNKIT_DISPOSABLE_CI") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Refusing: this test requires an explicitly opted-in, disposable GitHub-hosted root runner.")
    for path in (system.ETC, system.APP, system.DATA, Path("/usr/local/bin/vpnkit")):
        if path.exists():
            raise SystemExit(f"Refusing to alter an existing installation: {path}")


def fake_issue_certificate(ip):
    """Generate a test-only certificate; no request is sent to an ACME CA."""
    system.CERT.mkdir(parents=True, exist_ok=True)
    system.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
        "-subj", f"/CN={ip}", "-addext", f"subjectAltName=IP:{ip}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-keyout", system.CERT / "privkey.pem", "-out", system.CERT / "fullchain.pem",
    ])
    os.chmod(system.CERT / "privkey.pem", 0o600)


def request(url, *, credentials=None, method="GET", headers=None):
    parsed = urlsplit(url)
    args = [
        "curl", "--silent", "--show-error", "--max-time", "15", "--noproxy", "*",
        "--cacert", str(system.CERT / "fullchain.pem"),
        "--resolve", f"{parsed.hostname}:{parsed.port}:127.0.0.1",
        "--request", method, "--write-out", "\n%{http_code}",
    ]
    if credentials:
        args += ["--user", credentials]
    for key, value in (headers or {}).items():
        args += ["--header", f"{key}: {value}"]
    result = system.run(args + [url])
    body, status = result.stdout.rsplit("\n", 1)
    return int(status), body


class InstalledStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contexts = contextlib.ExitStack()
        cls.addClassCleanup(cls.contexts.close)
        cls.contexts.enter_context(patch.object(system, "issue_certificate", side_effect=fake_issue_certificate))
        cls.contexts.enter_context(patch.object(system, "detect_public_ip", return_value="1.1.1.1"))
        cls.args = argparse.Namespace(
            accept_acme_tos=True, server_ip=None, name="CI VPN",
            handshake_host="dl.google.com", with_monitor=True,
        )
        # Output contains generated test credentials; keep CI logs concise.
        with contextlib.redirect_stdout(io.StringIO()):
            system.install(cls.args)
        cls.state = system.load_state()
        cls.urls = json.loads((system.ETC / "urls.json").read_text())
        cls.auth = f'{cls.state["monitor_username"]}:{cls.state["monitor_password"]}'

    def test_01_real_services_and_configuration_checks(self):
        system.check_configs()
        for unit in ("vpnkit.service", "vpnkit-web.service", "vpnkit-renew.timer"):
            self.assertEqual(system.run(["systemctl", "is-active", unit]).stdout.strip(), "active")
        self.assertIn("5.8.0", system.run([system.APP / "certbot/bin/certbot", "--version"]).stdout)
        for flag in ("--ip-address", "--required-profile", "--renew-with-new-domains"):
            self.assertIn(flag, system.run([system.APP / "certbot/bin/certbot", "--help", "all"]).stdout)

    def test_02_private_files_and_service_identity(self):
        for path in (system.ETC / "state.json", system.ETC / "install.json", system.ACCESS):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, str(path))
            self.assertEqual(path.stat().st_uid, 0)
        self.assertEqual(system.run(["systemctl", "show", "vpnkit.service", "-p", "User", "--value"]).stdout.strip(), "vpnkit")
        sockets = system.run(["ss", "-lntH", "sport = :19090"]).stdout.splitlines()
        self.assertTrue(sockets)
        for line in sockets:
            self.assertEqual(line.split()[3], "127.0.0.1:19090")

    def test_03_https_subscriptions_are_consistent(self):
        code, clash_text = request(self.urls["clash"])
        self.assertEqual(code, 200)
        clash = json.loads(clash_text)
        node = clash["proxies"][0]
        self.assertEqual(node["server"], self.state["server_ip"])
        self.assertEqual(node["uuid"], self.state["uuid"])
        self.assertEqual(node["reality-opts"]["public-key"], self.state["reality_public_key"])
        self.assertEqual(clash_text, (system.DATA / "subscriptions/clash.yaml").read_text())
        code, subscription = request(self.urls["shadowrocket"])
        self.assertEqual(code, 200)
        uri = base64.b64decode(subscription.strip(), validate=True).decode().strip()
        parsed = urlsplit(uri)
        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(parsed.hostname, node["server"])
        self.assertEqual(parsed.username, node["uuid"])
        self.assertEqual(parsed.port, node["port"])
        params = parse_qs(parsed.query)
        self.assertEqual(params["pbk"], [node["reality-opts"]["public-key"]])
        self.assertEqual(params["sid"], [node["reality-opts"]["short-id"]])
        self.assertEqual(params["flow"], ["xtls-rprx-vision"])
        for secret in (self.state["reality_private_key"], self.state["api_secret"], self.state["monitor_password"]):
            self.assertNotIn(secret, clash_text)
            self.assertNotIn(secret, uri)
        self.assertEqual(request("https://1.1.1.1:8443/sub/wrong/clash.yaml")[0], 404)

    def test_04_monitor_authentication_and_readonly_boundary(self):
        base = "https://1.1.1.1:8444"
        self.assertEqual(request(base + "/online")[0], 401)
        self.assertEqual(request(base + "/api/connections")[0], 401)
        self.assertEqual(request(base + "/online", credentials="wrong:wrong")[0], 401)
        code, page = request(base + "/online", credentials=self.auth)
        self.assertEqual(code, 200)
        self.assertIn("活跃", page)
        self.assertEqual(request(base + "/", credentials=self.auth)[0], 200)
        for endpoint in ("version", "configs", "connections", "proxies", "rules"):
            code, body = request(base + "/api/" + endpoint, credentials=self.auth)
            self.assertEqual(code, 200, endpoint)
            json.loads(body)
        self.assertEqual(request(base + "/api/connections", credentials=self.auth, method="DELETE")[0], 405)
        self.assertEqual(request(base + "/api/configs", credentials=self.auth, method="PATCH")[0], 405)
        self.assertEqual(request(base + "/api/proxies/DIRECT/delay", credentials=self.auth)[0], 404)
        # sing-box must not receive the caller's unsafe websocket interval.
        self.assertEqual(request(base + "/api/connections?interval=0", credentials=self.auth)[0], 200)
        self.assertEqual(request(base + "/api/version", credentials=self.auth)[0], 200)
        self.assertEqual(request(base + "/api/connections", credentials=self.auth,
                                 headers={"Origin": base})[0], 200)
        self.assertEqual(request(base + "/api/connections", credentials=self.auth,
                                 headers={"Origin": "https://example.net", "Upgrade": "websocket",
                                          "Connection": "Upgrade"})[0], 403)

    def test_04_tls_rejects_untrusted_certificates_and_wrong_ip(self):
        base_args = ["curl", "--silent", "--show-error", "--max-time", "15", "--noproxy", "*"]
        untrusted = system.run(base_args + [
            "--resolve", "1.1.1.1:8443:127.0.0.1", "https://1.1.1.1:8443/",
        ], check=False)
        self.assertEqual(untrusted.returncode, 60, "Self-signed test CA must not be trusted implicitly")
        wrong_ip = system.run(base_args + [
            "--cacert", system.CERT / "fullchain.pem",
            "--resolve", "8.8.8.8:8443:127.0.0.1", "https://8.8.8.8:8443/",
        ], check=False)
        self.assertEqual(wrong_ip.returncode, 60, "A trusted certificate must still match its IP SAN")

    def test_05_vless_reality_authenticated_proxy_works(self):
        client = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 17891}],
            "outbounds": [{
                "type": "vless", "server": "127.0.0.1", "server_port": 443,
                "uuid": self.state["uuid"], "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True, "server_name": self.state["handshake_host"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": self.state["reality_public_key"],
                                "short_id": self.state["short_id"]},
                },
            }],
        }
        with tempfile.TemporaryDirectory(prefix="vpnkit-client-test-") as temporary:
            path = Path(temporary) / "client.json"
            system.save_json(path, client)
            command = [str(system.APP / "bin/sing-box"), "run", "-c", str(path)]
            with open(Path(temporary) / "client.log", "w") as logfile:
                process = subprocess.Popen(command, stdout=logfile, stderr=logfile)
                try:
                    time.sleep(1)
                    self.assertIsNone(process.poll(), "Test client failed to start")
                    result = system.run([
                        "curl", "--fail", "--silent", "--show-error", "--max-time", "30",
                        "--noproxy", "", "--proxy", "http://127.0.0.1:17891",
                        "https://www.gstatic.com/generate_204", "--write-out", "%{http_code}",
                    ])
                    self.assertEqual(result.stdout, "204")
                    marker = "vpnkit-loopback-sentinel-" + secrets.token_hex(16)
                    challenge_dir = system.DATA / "acme/.well-known/acme-challenge"
                    challenge_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(challenge_dir.parent, 0o755)
                    os.chmod(challenge_dir, 0o755)
                    probe = challenge_dir / "ci-loopback-probe"
                    probe.write_text(marker)
                    os.chmod(probe, 0o644)
                    probe_url = "http://127.0.0.1/.well-known/acme-challenge/ci-loopback-probe"
                    try:
                        direct = system.run([
                            "curl", "--fail", "--silent", "--show-error", "--max-time", "10",
                            "--noproxy", "*", probe_url,
                        ])
                        self.assertEqual(direct.stdout, marker)
                        blocked = system.run([
                            "curl", "--fail", "--silent", "--show-error", "--max-time", "10",
                            "--noproxy", "", "--proxy", "http://127.0.0.1:17891", probe_url,
                        ], check=False)
                        self.assertNotEqual(blocked.returncode, 0, "Proxy must reject the reachable loopback destination")
                        self.assertNotIn(marker, blocked.stdout)
                    finally:
                        probe.unlink(missing_ok=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    def test_06_doctor_detects_wrong_certificate_ip(self):
        with contextlib.redirect_stdout(io.StringIO()):
            system.doctor()
        wrong_state = dict(self.state, server_ip="8.8.8.8")
        with patch.object(system, "load_state", return_value=wrong_state):
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                with self.assertRaisesRegex(RuntimeError, "health checks failed"):
                    system.doctor()
        self.assertIn("FAIL: certificate IP matches", captured.getvalue())
        self.assertEqual(system.load_state()["server_ip"], "1.1.1.1")

    def test_90_repeated_install_preserves_credentials_and_urls(self):
        saved_state = (system.ETC / "state.json").read_bytes()
        saved_urls = (system.ETC / "urls.json").read_bytes()
        with patch.object(system, "install_dependencies", side_effect=AssertionError("Replay must not reinstall")):
            with contextlib.redirect_stdout(io.StringIO()):
                system.install(self.args)
        self.assertEqual((system.ETC / "state.json").read_bytes(), saved_state)
        self.assertEqual((system.ETC / "urls.json").read_bytes(), saved_urls)
        self.assertEqual(request(self.urls["clash"])[0], 200)

    def test_99_ip_change_refreshes_certificate_and_subscriptions(self):
        args = argparse.Namespace(accept_acme_tos=True, server_ip="8.8.8.8")
        with contextlib.redirect_stdout(io.StringIO()):
            system.update_ip(args)
        state = system.load_state()
        self.assertEqual(state["server_ip"], "8.8.8.8")
        for key in self.state.keys() - {"server_ip", "local_addresses"}:
            self.assertEqual(state[key], self.state[key], key)
        urls = json.loads((system.ETC / "urls.json").read_text())
        for name in ("clash", "shadowrocket", "monitor"):
            self.assertEqual(urlsplit(urls[name]).hostname, "8.8.8.8")
            self.assertEqual(urlsplit(urls[name]).path, urlsplit(self.urls[name]).path)
        code, body = request(urls["clash"])
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["proxies"][0]["server"], "8.8.8.8")
        self.assertEqual(request(urls["shadowrocket"])[0], 200)
        self.assertEqual(request(urls["monitor"], credentials=self.auth)[0], 200)
        system.run(["openssl", "x509", "-in", system.CERT / "fullchain.pem", "-noout", "-checkip", "8.8.8.8"])


if __name__ == "__main__":
    require_disposable_runner()
    # The download bootstrap sets this; directories must still be traversable
    # by the dedicated VPN account and nginx workers after installation.
    os.umask(0o077)
    unittest.main(verbosity=2)

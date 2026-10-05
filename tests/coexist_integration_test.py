#!/usr/bin/env python3
"""Real coexist installation test, exclusively for disposable GitHub runners.

The fixture installs distribution packages and creates an existing HTTPS site
before the installer is observed. Coexist installation then runs under a
command guard that rejects package/firewall changes and website operations.
Only public-IP discovery and the test hostname's DNS check are substituted;
certificate chain, hostname, expiry, key, REALITY, and HTTPS checks are real.
Never execute this script on a workstation or an existing VPS.
"""

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpnkit import coexist, system
from integration_test import require_disposable_runner


HOST = "vpnkit-ci.example.test"
FIXTURE = Path("/etc/vpnkit-coexist-ci")
SOURCE_CERT = FIXTURE / "fullchain.pem"
SOURCE_KEY = FIXTURE / "privkey.pem"
PORTS = {"vpn_port": 25443, "subscription_port": 29443,
         "monitor_port": 29444, "api_port": 29990}
MARKER = "existing-website-" + secrets.token_hex(16)


def issue_external_certificate(serial):
    """Act as the website's external certificate manager, not the installer."""
    with tempfile.TemporaryDirectory(prefix="vpnkit-external-renewal-") as temporary:
        directory = Path(temporary)
        key, request, leaf = (directory / name for name in ("key.pem", "request.pem", "leaf.pem"))
        extensions = directory / "extensions.cnf"
        extensions.write_text(
            f"subjectAltName=DNS:{HOST}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        system.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={HOST}", "-keyout", key, "-out", request])
        system.run(["openssl", "x509", "-req", "-in", request,
                    "-CA", FIXTURE / "ca.pem", "-CAkey", FIXTURE / "ca.key",
                    "-set_serial", str(serial), "-days", "3", "-sha256",
                    "-extfile", extensions, "-out", leaf])
        # Both source paths belong to the simulated website certificate manager.
        system.atomic_write(SOURCE_CERT, leaf.read_text() + (FIXTURE / "ca.pem").read_text())
        system.atomic_write(SOURCE_KEY, key.read_text())


def prepare_existing_website():
    """Destructive fixture creation occurs before any preservation baseline."""
    if FIXTURE.exists():
        raise RuntimeError("Refusing to replace an existing coexist test fixture")
    system.run(["apt-get", "update"], timeout=900)
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="a")
    result = subprocess.run(
        ["apt-get", "install", "-y", "--no-install-recommends", "nginx", "curl",
         "openssl", "ca-certificates", "iproute2"], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900,
    )
    if result.returncode:
        raise RuntimeError("CI fixture dependency installation failed: " + result.stderr[-1800:])
    FIXTURE.mkdir(mode=0o700)
    system.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
                "-subj", "/CN=VPNKit disposable coexist test CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", FIXTURE / "ca.key", "-out", FIXTURE / "ca.pem"])
    issue_external_certificate(101)
    config = f"""user www-data;
worker_processes 1;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server {{
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name {HOST};
        ssl_certificate {SOURCE_CERT};
        ssl_certificate_key {SOURCE_KEY};
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {{ return 200 '{MARKER}'; }}
    }}
}}
"""
    system.atomic_write("/etc/nginx/nginx.conf", config, 0o644)
    system.run(["nginx", "-t"])
    system.run(["systemctl", "enable", "nginx.service"])
    system.run(["systemctl", "restart", "nginx.service"])
    # Retain public roots: the install still verifies the real Google handshake
    # and GitHub downloads; the local CA is added solely for fixture DNS TLS.
    bundle = FIXTURE / "combined-ca.pem"
    bundle.write_bytes(Path("/etc/ssl/certs/ca-certificates.crt").read_bytes()
                       + b"\n" + (FIXTURE / "ca.pem").read_bytes())
    return bundle


class CommandGuard:
    """Observe actual subprocess launches, including direct subprocess calls."""

    def __init__(self):
        self.trace = []
        self.original = subprocess.Popen

    def __call__(self, argv, *args, **kwargs):
        if kwargs.get("shell") or isinstance(argv, (str, bytes)):
            raise AssertionError("Coexist must execute explicit argv, never a shell")
        command = tuple(str(value) for value in argv)
        name = Path(command[0]).name
        self.trace.append(command)
        forbidden = {
            "apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "pacman", "apk",
            "pip", "pip3", "certbot", "ufw", "firewall-cmd", "iptables", "ip6tables",
            "iptables-restore", "ip6tables-restore", "nft", "sysctl", "service",
            "sh", "bash", "dash", "kill", "killall", "pkill",
        }
        if name in forbidden:
            raise AssertionError(f"Coexist attempted a forbidden host command: {name}")
        if name.startswith("python") and "pip" in command:
            raise AssertionError("Coexist must not install Python packages")
        if name == "nginx" and command[1:] != ("-V",):
            if ("-p" not in command or "-c" not in command
                    or command[command.index("-p") + 1] != str(system.DATA / "nginx") + "/"
                    or command[command.index("-c") + 1] != str(system.ETC / "nginx.conf")):
                raise AssertionError("Coexist attempted to operate the website nginx configuration")
        if name == "systemctl":
            if command[1:] != ("daemon-reload",) and command[1] not in {"show", "is-active", "status"}:
                if command[1] not in {"enable", "restart", "reload", "start", "stop", "disable"}:
                    raise AssertionError("Unexpected mutating systemctl operation")
                units = [item for item in command[2:] if not item.startswith("-")]
                if not units or any(not unit.startswith("vpnkit") for unit in units):
                    raise AssertionError("Coexist attempted to change an existing host service")
        return self.original(argv, *args, **kwargs)


def request(url, *, credentials=None, method="GET"):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    args = ["curl", "--silent", "--show-error", "--max-time", "5", "--noproxy", "*",
            "--cacert", FIXTURE / "ca.pem", "--resolve", f"{parsed.hostname}:{port}:127.0.0.1",
            "--request", method, "--write-out", "\n%{http_code}"]
    if credentials:
        args += ["--user", credentials]
    result = system.run(args + [url])
    body, status = result.stdout.rsplit("\n", 1)
    return int(status), body


def file_snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            value = ("symlink", os.readlink(path))
        elif path.is_file():
            value = ("file", path.read_bytes(), path.stat().st_mode & 0o777)
        else:
            continue
        result[str(path.relative_to(root))] = value
    return result


def service_pid(unit):
    return system.run(["systemctl", "show", unit, "-p", "MainPID", "--value"]).stdout.strip()


def served_fingerprint(port):
    context = ssl.create_default_context(cafile=str(FIXTURE / "ca.pem"))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as transport:
        with context.wrap_socket(transport, server_hostname=HOST) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


class WebsiteProbe:
    def __init__(self):
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.failures = []
        self.rounds = 0
        self.thread = threading.Thread(target=self.probe, daemon=True)

    def probe(self):
        while not self.stop.is_set():
            try:
                for scheme in ("http", "https"):
                    if request(f"{scheme}://{HOST}/") != (200, MARKER):
                        self.failures.append(f"Unexpected website {scheme} response")
                self.rounds += 1
            except Exception as error:
                # Website requests do not contain subscription credentials.
                self.failures.append(str(error))
            self.ready.set()
            self.stop.wait(0.1)

    def start(self):
        self.thread.start()
        if not self.ready.wait(timeout=15):
            raise RuntimeError("Existing website probe did not become ready")

    def close(self):
        self.stop.set()
        self.thread.join(timeout=15)
        if self.thread.is_alive():
            raise AssertionError("Website continuity probe failed to stop")
        if self.failures:
            raise AssertionError("Existing website was interrupted: " + repr(self.failures[:3]))


class CoexistStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Guard here as well as __main__, so importing this test cannot bypass it.
        require_disposable_runner()
        os.umask(0o077)
        cls.contexts = contextlib.ExitStack()
        cls.addClassCleanup(cls.contexts.close)
        bundle = prepare_existing_website()
        cls.contexts.enter_context(patch.dict(os.environ, {"SSL_CERT_FILE": str(bundle)}))
        cls.contexts.enter_context(patch.object(system, "detect_public_ip", return_value="1.1.1.1"))
        cls.contexts.enter_context(patch.object(coexist, "check_host", return_value=None))
        cls.website_files = file_snapshot(Path("/etc/nginx"))
        cls.source_files = (SOURCE_CERT.read_bytes(), SOURCE_KEY.read_bytes())
        cls.website_pid = service_pid("nginx.service")
        if cls.website_pid in {"", "0"}:
            raise RuntimeError("Website nginx did not start")
        cls.website_certificate = served_fingerprint(443)
        cls.website_workers = Path(f"/proc/{cls.website_pid}/task/{cls.website_pid}/children").read_text()
        cls.guard = CommandGuard()
        cls.contexts.enter_context(patch.object(subprocess, "Popen", side_effect=cls.guard))
        cls.probe = WebsiteProbe()
        cls.addClassCleanup(cls.probe.close)
        cls.probe.start()
        cls.args = argparse.Namespace(
            coexist=True, accept_acme_tos=False, server_ip=None, name="CI Coexist VPN",
            handshake_host="dl.google.com", with_monitor=True, tls_host=HOST,
            tls_cert=str(SOURCE_CERT), tls_key=str(SOURCE_KEY), nginx_binary=None, **PORTS,
        )
        # Do not publish generated subscription/admin credentials in CI logs.
        with contextlib.redirect_stdout(io.StringIO()):
            system.install(cls.args)
        cls.state = system.load_state()
        cls.urls = json.loads((system.ETC / "urls.json").read_text())
        cls.auth = f'{cls.state["monitor_username"]}:{cls.state["monitor_password"]}'

    def assert_website_unchanged(self):
        self.assertEqual(file_snapshot(Path("/etc/nginx")), self.website_files)
        self.assertEqual(service_pid("nginx.service"), self.website_pid)
        self.assertEqual(Path(f"/proc/{self.website_pid}/task/{self.website_pid}/children").read_text(),
                         self.website_workers, "The existing website workers must not be reloaded")
        self.assertEqual(system.run(["systemctl", "is-active", "nginx.service"]).stdout.strip(), "active")
        self.assertEqual(served_fingerprint(443), self.website_certificate)
        for scheme in ("http", "https"):
            self.assertEqual(request(f"{scheme}://{HOST}/"), (200, MARKER))
        self.assertGreater(self.probe.rounds, 0)
        self.assertEqual(self.probe.failures, [], "Website requests must succeed throughout installation")

    def tearDown(self):
        self.assert_website_unchanged()

    def test_01_existing_website_and_certificates_preserved(self):
        self.assertEqual((SOURCE_CERT.read_bytes(), SOURCE_KEY.read_bytes()), self.source_files)
        self.assert_website_unchanged()
        for unit in coexist.UNITS:
            self.assertEqual(system.run(["systemctl", "is-active", unit]).stdout.strip(), "active")
        for path in (system.ETC / "state.json", system.ETC / "install.json", system.ACCESS):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, str(path))
        self.assertFalse((system.APP / "certbot").exists())
        self.assertFalse(Path("/etc/systemd/system/vpnkit-renew.timer").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            system.doctor()
        api_sockets = system.run(["ss", "-lntH", f"sport = :{PORTS['api_port']}"]).stdout.splitlines()
        self.assertTrue(api_sockets)
        for line in api_sockets:
            self.assertEqual(line.split()[3], f"127.0.0.1:{PORTS['api_port']}")

    def test_02_https_profiles_use_custom_ports_and_same_credentials(self):
        for label in ("clash", "shadowrocket"):
            parsed = urlsplit(self.urls[label])
            self.assertEqual((parsed.scheme, parsed.hostname, parsed.port),
                             ("https", HOST, PORTS["subscription_port"]))
        code, clash_text = request(self.urls["clash"])
        self.assertEqual(code, 200)
        node = json.loads(clash_text)["proxies"][0]
        self.assertEqual(node["server"], "1.1.1.1")
        self.assertEqual(node["port"], PORTS["vpn_port"])
        self.assertEqual(node["uuid"], self.state["uuid"])
        code, encoded = request(self.urls["shadowrocket"])
        self.assertEqual(code, 200)
        uri = base64.b64decode(encoded.strip(), validate=True).decode().strip()
        parsed = urlsplit(uri)
        self.assertEqual((parsed.scheme, parsed.hostname, parsed.port, parsed.username),
                         ("vless", node["server"], node["port"], node["uuid"]))
        params = parse_qs(parsed.query)
        self.assertEqual(params["pbk"], [node["reality-opts"]["public-key"]])
        self.assertEqual(params["sid"], [node["reality-opts"]["short-id"]])
        self.assertEqual(params["sni"], [self.state["handshake_host"]])
        self.assertEqual(params["flow"], ["xtls-rprx-vision"])
        for secret in (self.state["reality_private_key"], self.state["api_secret"], self.state["monitor_password"]):
            self.assertNotIn(secret, clash_text)
            self.assertNotIn(secret, uri)
        self.assertEqual(request(f"https://{HOST}:{PORTS['subscription_port']}/sub/wrong/clash.yaml")[0], 404)

    def test_03_monitor_requires_auth_and_is_read_only(self):
        base = f"https://{HOST}:{PORTS['monitor_port']}"
        self.assertEqual(urlsplit(self.urls["monitor"]).port, PORTS["monitor_port"])
        self.assertEqual(request(base + "/online")[0], 401)
        self.assertEqual(request(base + "/api/connections")[0], 401)
        self.assertEqual(request(base + "/online", credentials="wrong:wrong")[0], 401)
        code, body = request(base + "/online", credentials=self.auth)
        self.assertEqual(code, 200)
        self.assertIn("活跃", body)
        self.assertEqual(request(base + "/", credentials=self.auth)[0], 200)
        code, body = request(base + "/api/connections", credentials=self.auth)
        self.assertEqual(code, 200)
        json.loads(body)
        self.assertEqual(request(base + "/api/connections", credentials=self.auth, method="DELETE")[0], 405)

    def test_04_real_vless_reality_proxy_on_custom_port(self):
        client = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 17892}],
            "outbounds": [{
                "type": "vless", "server": "127.0.0.1", "server_port": PORTS["vpn_port"],
                "uuid": self.state["uuid"], "flow": "xtls-rprx-vision",
                "tls": {"enabled": True, "server_name": self.state["handshake_host"],
                        "utls": {"enabled": True, "fingerprint": "chrome"},
                        "reality": {"enabled": True, "public_key": self.state["reality_public_key"],
                                    "short_id": self.state["short_id"]}},
            }],
        }
        with tempfile.TemporaryDirectory(prefix="vpnkit-coexist-client-") as temporary:
            directory = Path(temporary)
            system.save_json(directory / "client.json", client)
            with open(directory / "client.log", "w") as logfile:
                process = subprocess.Popen([str(system.APP / "bin/sing-box"), "run", "-c",
                                            str(directory / "client.json")], stdout=logfile, stderr=logfile)
                try:
                    time.sleep(1)
                    self.assertIsNone(process.poll(), "REALITY client did not start")
                    result = system.run([
                        "curl", "--fail", "--silent", "--show-error", "--max-time", "30",
                        "--noproxy", "", "--proxy", "http://127.0.0.1:17892",
                        "https://www.gstatic.com/generate_204", "--write-out", "%{http_code}",
                    ])
                    self.assertEqual(result.stdout, "204")
                    # The website remains directly reachable but is not exposed
                    # as a private destination through the authenticated proxy.
                    blocked = system.run([
                        "curl", "--silent", "--show-error", "--max-time", "5", "--noproxy", "",
                        "--proxy", "http://127.0.0.1:17892", "http://127.0.0.1/",
                    ], check=False)
                    self.assertNotEqual(blocked.returncode, 0)
                    self.assertNotIn(MARKER, blocked.stdout)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    def test_05_valid_external_renewal_reloads_only_vpn_web(self):
        previous = served_fingerprint(PORTS["subscription_port"])
        self.assertEqual(previous, self.website_certificate)
        issue_external_certificate(102)
        renewed_sources = file_snapshot(FIXTURE)
        vpn_pid = service_pid("vpnkit.service")
        web_pid = service_pid("vpnkit-web.service")
        trace_start = len(self.guard.trace)
        with contextlib.redirect_stdout(io.StringIO()):
            coexist.sync_certificate()
        deadline = time.monotonic() + 10
        while served_fingerprint(PORTS["subscription_port"]) == previous and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertNotEqual(served_fingerprint(PORTS["subscription_port"]), previous)
        self.assertEqual(file_snapshot(FIXTURE), renewed_sources, "Sync must not edit source certificate data")
        self.assertEqual(service_pid("vpnkit.service"), vpn_pid)
        self.assertEqual(service_pid("vpnkit-web.service"), web_pid, "Certificate renewal should reload, not restart")
        mutations = [command for command in self.guard.trace[trace_start:]
                     if Path(command[0]).name == "systemctl" and command[1] not in {"show", "is-active", "status"}]
        self.assertEqual(mutations, [("systemctl", "reload", "vpnkit-web.service")])
        self.assertEqual(request(self.urls["clash"])[0], 200)
        self.assertEqual(request(self.urls["shadowrocket"])[0], 200)

    def test_06_invalid_external_renewal_keeps_working_vpn_certificate(self):
        good_sources = (SOURCE_CERT.read_bytes(), SOURCE_KEY.read_bytes())
        active_link = os.readlink(system.ETC / "tls")
        active_certificate = (system.ETC / "tls/fullchain.pem").read_bytes()
        previous_fingerprint = served_fingerprint(PORTS["subscription_port"])
        # A partial/invalid external renewal must never replace the valid copy.
        SOURCE_CERT.write_text("invalid partially renewed certificate\n")
        invalid_sources = file_snapshot(FIXTURE)
        trace_start = len(self.guard.trace)
        try:
            with self.assertRaises(RuntimeError):
                coexist.sync_certificate()
            self.assertEqual(file_snapshot(FIXTURE), invalid_sources)
            self.assertEqual(os.readlink(system.ETC / "tls"), active_link)
            self.assertEqual((system.ETC / "tls/fullchain.pem").read_bytes(), active_certificate)
            self.assertEqual(served_fingerprint(PORTS["subscription_port"]), previous_fingerprint)
            self.assertFalse(any(Path(command[0]).name == "systemctl"
                                 for command in self.guard.trace[trace_start:]))
            self.assertEqual(request(self.urls["clash"])[0], 200)
            self.assertEqual(request(self.urls["monitor"], credentials=self.auth)[0], 200)
        finally:
            # Only this external-manager fixture repairs its source files.
            SOURCE_CERT.write_bytes(good_sources[0])
            SOURCE_KEY.write_bytes(good_sources[1])

    def test_90_repeated_install_preserves_credentials_urls_and_services(self):
        state = (system.ETC / "state.json").read_bytes()
        urls = (system.ETC / "urls.json").read_bytes()
        source_files = file_snapshot(FIXTURE)
        service_pids = {unit: service_pid(unit) for unit in coexist.UNITS[:2]}
        trace_start = len(self.guard.trace)
        with contextlib.redirect_stdout(io.StringIO()):
            system.install(self.args)
        self.assertEqual((system.ETC / "state.json").read_bytes(), state)
        self.assertEqual((system.ETC / "urls.json").read_bytes(), urls)
        self.assertEqual(file_snapshot(FIXTURE), source_files)
        self.assertFalse(any(Path(command[0]).name == "systemctl"
                             for command in self.guard.trace[trace_start:]))
        for unit, pid in service_pids.items():
            self.assertEqual(service_pid(unit), pid)
        self.assertEqual(request(self.urls["clash"])[0], 200)
        self.assertEqual(request(self.urls["shadowrocket"])[0], 200)


if __name__ == "__main__":
    require_disposable_runner()
    os.umask(0o077)
    unittest.main(verbosity=2)

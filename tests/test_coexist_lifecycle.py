"""Coexistence safety and real certificate checks without privileged changes."""

import argparse
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vpnkit import coexist, system


class CertificateFixture:
    """A private test CA and two independently keyed server certificates."""

    host = "vpn.example.test"

    def __init__(self, root):
        self.root = root
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise unittest.SkipTest("openssl is needed for certificate validation tests")
        self.ca = root / "ca.pem"
        ca_key = root / "ca-key.pem"
        ca_config = root / "ca.cnf"
        ca_config.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
            "[dn]\nCN=VPN Kit isolated test CA\n[ca]\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        )
        self.run("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt",
                 "ec_paramgen_curve:prime256v1", "-nodes", "-days", "7",
                 "-config", ca_config, "-keyout", ca_key, "-out", self.ca)
        extensions = root / "server.cnf"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{self.host}\n"
        )
        self.pairs = []
        for serial in (1, 2):
            key, csr, leaf, chain = [root / f"server-{serial}.{suffix}"
                                     for suffix in ("key", "csr", "pem", "fullchain.pem")]
            self.run("req", "-new", "-newkey", "ec", "-pkeyopt",
                     "ec_paramgen_curve:prime256v1", "-nodes", "-subj",
                     f"/CN={self.host}", "-keyout", key, "-out", csr)
            self.run("x509", "-req", "-in", csr, "-CA", self.ca, "-CAkey", ca_key,
                     "-set_serial", str(serial), "-days", "7", "-extfile", extensions,
                     "-out", leaf)
            chain.write_bytes(leaf.read_bytes() + self.ca.read_bytes())
            self.pairs.append((chain, key))

    def run(self, *args):
        return subprocess.run([self.openssl, *map(str, args)], check=True,
                              capture_output=True, text=True, timeout=15)


class CertificateSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vpnkit-test-certs-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = CertificateFixture(Path(cls.temporary.name))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpnkit-test-coexist-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(patch.dict(os.environ, {"SSL_CERT_FILE": str(self.fixture.ca)}))
        for name, path in {
            "ETC": self.root / "etc", "APP": self.root / "app",
            "DATA": self.root / "data", "ACCESS": self.root / "access.txt",
        }.items():
            self.contexts.enter_context(patch.object(system, name, path))

    def test_snapshot_accepts_a_matching_key_and_trusted_dns_certificate(self):
        cert, key = self.fixture.pairs[0]
        snapshot = coexist.certificate_snapshot(self.fixture.host, cert, key)
        self.assertEqual(snapshot, (cert.read_bytes(), key.read_bytes()))
        self.assertFalse(system.ETC.exists())

    def test_snapshot_rejects_a_certificate_for_another_host(self):
        cert, key = self.fixture.pairs[0]
        with self.assertRaises((RuntimeError, ValueError)):
            coexist.certificate_snapshot("another.example.test", cert, key)
        self.assertFalse(system.ETC.exists())

    def test_snapshot_rejects_a_private_key_that_does_not_match(self):
        cert, _ = self.fixture.pairs[0]
        _, different_key = self.fixture.pairs[1]
        with self.assertRaises((RuntimeError, ValueError)):
            coexist.certificate_snapshot(self.fixture.host, cert, different_key)
        self.assertFalse(system.ETC.exists())

    def live_certificate_files(self):
        live = system.ETC / "tls"
        self.assertTrue(live.is_symlink(), "The certificate pair needs one atomic activation point")
        return {path.name: path.read_bytes() for path in live.iterdir() if path.is_file()}

    def install_first_certificate(self):
        system.ETC.mkdir()
        cert, key = self.fixture.pairs[0]
        snapshot = coexist.certificate_snapshot(self.fixture.host, cert, key)
        self.assertTrue(coexist.install_certificate(*snapshot))
        files = self.live_certificate_files()
        self.assertIn(snapshot[0], files.values())
        self.assertIn(snapshot[1], files.values())
        for path in (system.ETC / "tls").iterdir():
            if path.is_file() and path.read_bytes() == snapshot[1]:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return snapshot

    def test_reinstalling_identical_certificate_does_not_switch_generations(self):
        snapshot = self.install_first_certificate()
        previous_target = (system.ETC / "tls").resolve()
        previous_files = self.live_certificate_files()
        with patch.object(system, "run") as process:
            self.assertFalse(coexist.install_certificate(*snapshot))
        self.assertEqual((system.ETC / "tls").resolve(), previous_target)
        self.assertEqual(self.live_certificate_files(), previous_files)
        process.assert_not_called()

    def test_failed_private_key_write_does_not_activate_a_partial_pair(self):
        self.install_first_certificate()
        previous_target = (system.ETC / "tls").resolve()
        previous_files = self.live_certificate_files()
        cert, key = self.fixture.pairs[1]
        replacement = coexist.certificate_snapshot(self.fixture.host, cert, key)
        actual_write = system.atomic_write

        def fail_key_write(path, *args, **kwargs):
            if Path(path).name == "privkey.pem":
                raise OSError("simulated full disk")
            return actual_write(path, *args, **kwargs)

        with patch.object(system, "atomic_write", side_effect=fail_key_write):
            with self.assertRaisesRegex(OSError, "full disk"):
                coexist.install_certificate(*replacement)
        self.assertEqual((system.ETC / "tls").resolve(), previous_target)
        self.assertEqual(self.live_certificate_files(), previous_files)
        self.assertEqual({path.resolve() for path in (system.ETC / "tls-revisions").iterdir()}, {previous_target})

    def test_invalid_external_renewal_preserves_live_certificate_pair(self):
        self.install_first_certificate()
        previous_target = (system.ETC / "tls").resolve()
        previous_files = self.live_certificate_files()
        new_cert, _ = self.fixture.pairs[1]
        _, old_key = self.fixture.pairs[0]
        metadata = {
            "mode": "coexist", "complete": True, "with_monitor": True,
            "nginx_binary": "/usr/sbin/nginx",
            "certificate_source": str(new_cert), "key_source": str(old_key),
        }
        with patch.object(system, "load_state", return_value={"mode": "coexist", "public_host": self.fixture.host}), \
                patch.object(system, "load_install", return_value=metadata), \
                patch.object(system, "run", wraps=system.run) as process:
            with self.assertRaises((RuntimeError, ValueError)):
                coexist.sync_certificate()
        self.assertEqual((system.ETC / "tls").resolve(), previous_target)
        self.assertEqual(self.live_certificate_files(), previous_files)
        self.assertFalse(any(str(call.args[0][0]) == "systemctl" for call in process.call_args_list))

    def test_failed_owned_web_reload_restores_previous_certificate_generation(self):
        self.install_first_certificate()
        previous_target = (system.ETC / "tls").resolve()
        previous_files = self.live_certificate_files()
        cert, key = self.fixture.pairs[1]
        replacement = coexist.certificate_snapshot(self.fixture.host, cert, key)
        calls = []
        reload_failed = False

        def owned_process(argv, **kwargs):
            nonlocal reload_failed
            argv = list(map(str, argv))
            calls.append(argv)
            if argv[:2] == ["systemctl", "reload"] and not reload_failed:
                reload_failed = True
                raise RuntimeError("simulated owned web reload failure")
            if Path(argv[0]).name == "nginx" or argv[0] == "systemctl":
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(f"Unexpected process during certificate reload: {argv}")

        with patch.object(system, "run", side_effect=owned_process):
            with self.assertRaisesRegex(RuntimeError, "previous certificate restored"):
                coexist.install_certificate(
                    *replacement, reload=True, metadata={"nginx_binary": "/usr/sbin/nginx"},
                )
        self.assertEqual((system.ETC / "tls").resolve(), previous_target)
        self.assertEqual(self.live_certificate_files(), previous_files)
        service_calls = [argv for argv in calls if argv[0] == "systemctl"]
        self.assertTrue(service_calls)
        for argv in service_calls:
            self.assertEqual(argv[-1], "vpnkit-web.service")


class ResourceOwnershipTests(unittest.TestCase):
    def test_loaded_unit_is_refused_even_when_no_unit_file_is_visible(self):
        def systemd_show(argv, **kwargs):
            self.assertEqual(argv[:2], ["systemctl", "show"])
            self.assertEqual(argv[-2:], ["--property=LoadState", "--value"])
            return subprocess.CompletedProcess(argv, 0, "loaded\n", "")

        with patch.object(coexist.Path, "exists", return_value=False), \
                patch.object(coexist.Path, "is_symlink", return_value=False), \
                patch.object(system, "run", side_effect=systemd_show) as process, \
                patch.object(coexist.pwd, "getpwnam") as account:
            with self.assertRaisesRegex(RuntimeError, "Refusing to replace existing or unverified unit"):
                coexist._refuse_existing_resources()
        self.assertEqual(process.call_count, 1)
        account.assert_not_called()


class CoexistInstallSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vpnkit-test-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(contextlib.redirect_stdout(io.StringIO()))
        for name, path in {
            "ETC": self.root / "etc", "APP": self.root / "app",
            "DATA": self.root / "data", "ACCESS": self.root / "access.txt",
        }.items():
            self.contexts.enter_context(patch.object(system, name, path))
        self.site_config = self.root / "existing-site.conf"
        self.site_config.write_text("existing website configuration\n")
        self.cert, self.key = self.root / "website.pem", self.root / "website.key"
        self.cert.write_bytes(b"external certificate snapshot")
        self.key.write_bytes(b"external private key snapshot")
        self.original_site = {path: path.read_bytes() for path in (self.site_config, self.cert, self.key)}
        self.args = argparse.Namespace(
            coexist=True, accept_acme_tos=False, server_ip="1.1.1.1",
            name="Coexisting VPN", handshake_host="dl.google.com", with_monitor=True,
            tls_host="vpn.example.test", tls_cert=str(self.cert), tls_key=str(self.key),
            nginx_binary=None, vpn_port=24443, subscription_port=28443,
            monitor_port=28444, api_port=29090,
        )
        self.actual_preflight = coexist.preflight
        self.preflight = self.contexts.enter_context(
            patch.object(coexist, "preflight", return_value="/usr/sbin/nginx"))
        self.contexts.enter_context(patch.object(system, "preflight", return_value="amd64"))
        self.contexts.enter_context(patch.object(coexist, "_refuse_existing_resources"))
        self.ports = self.contexts.enter_context(patch.object(coexist, "check_ports"))
        self.host = self.contexts.enter_context(patch.object(coexist, "check_host"))
        self.snapshot = self.contexts.enter_context(patch.object(
            coexist, "certificate_snapshot", return_value=(self.cert.read_bytes(), self.key.read_bytes())))
        self.handshake = self.contexts.enter_context(patch.object(system, "verify_handshake"))
        self.contexts.enter_context(patch.object(system, "local_addresses", return_value=["127.0.0.1"]))
        self.directories = self.contexts.enter_context(patch.object(coexist, "make_directories"))
        self.app = self.contexts.enter_context(patch.object(system, "install_app"))
        self.core = self.contexts.enter_context(patch.object(system, "install_core"))
        self.monitor = self.contexts.enter_context(patch.object(system, "install_monitor"))
        self.writer = self.contexts.enter_context(patch.object(coexist, "write_rendered"))
        self.calls = []
        self.contexts.enter_context(patch.object(system, "run", side_effect=self.process))
        self.unit_files = {}
        actual_write = system.atomic_write

        def private_write(path, content, mode=0o600, group=None):
            path = Path(path)
            if path.parent == Path("/etc/systemd/system"):
                self.assertTrue(path.name == "vpnkit.service" or path.name.startswith("vpnkit-"), str(path))
                self.unit_files[path.name] = content
                return
            self.assertTrue(path.is_relative_to(self.root), f"Unexpected host write: {path}")
            return actual_write(path, content, mode, group)

        self.contexts.enter_context(patch.object(system, "atomic_write", side_effect=private_write))
        self.forbidden = {}
        for name in ("install_dependencies", "configure_firewall", "issue_certificate"):
            self.forbidden[name] = self.contexts.enter_context(patch.object(
                system, name, side_effect=AssertionError(f"Shared-host operation called: {name}")))

    def process(self, argv, **kwargs):
        argv = list(map(str, argv))
        self.calls.append(argv)
        if Path(argv[0]).name == "sing-box" and argv[1:] == ["generate", "reality-keypair"]:
            output = "PrivateKey: " + "A" * 43 + "\nPublicKey: " + "A" * 43 + "\n"
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[0] == "systemctl":
            if argv[1] != "daemon-reload":
                self.assertIn(argv[-1], {"vpnkit.service", "vpnkit-web.service", "vpnkit-cert-sync.timer"})
            return subprocess.CompletedProcess(argv, 0, "active\n", "")
        if Path(argv[0]).name == "nginx" and "-t" in argv:
            self.assertIn(str(system.ETC / "nginx.conf"), argv)
            self.assertIn(str(system.DATA / "nginx") + "/", argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if Path(argv[0]).name == "sing-box" and argv[1] == "check":
            self.assertIn(str(system.ETC / "sing-box.json"), argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"Unexpected host process: {argv}")

    def assert_no_installation(self):
        for path in (system.ETC, system.APP, system.DATA, system.ACCESS):
            self.assertFalse(path.exists(), str(path))
        self.directories.assert_not_called()
        self.core.assert_not_called()
        self.assertEqual(self.unit_files, {})
        self.assertEqual(self.calls, [])
        for path, content in self.original_site.items():
            self.assertEqual(path.read_bytes(), content)

    def test_missing_existing_dependency_aborts_before_claiming_private_paths(self):
        self.preflight.side_effect = self.actual_preflight
        for missing in ("curl", "openssl", "ip", "systemctl", "useradd"):
            with self.subTest(missing=missing), patch.object(
                    coexist.shutil, "which", side_effect=lambda name: None if name == missing else f"/usr/bin/{name}"):
                with self.assertRaisesRegex(RuntimeError, "Missing"):
                    coexist.install(self.args)
                self.assert_no_installation()
        self.snapshot.assert_not_called()

    def test_missing_existing_nginx_does_not_install_a_package_or_claim_paths(self):
        self.preflight.side_effect = self.actual_preflight
        with patch.object(coexist.shutil, "which", side_effect=lambda name: None if name == "nginx" else f"/usr/bin/{name}"):
            with self.assertRaisesRegex(RuntimeError, "Existing nginx binary required"):
                coexist.install(self.args)
        self.assert_no_installation()
        for function in self.forbidden.values():
            function.assert_not_called()

    def test_conflicting_custom_port_aborts_before_claiming_private_paths(self):
        self.ports.side_effect = RuntimeError("Cannot bind VPN port")
        with self.assertRaisesRegex(RuntimeError, "Cannot bind"):
            coexist.install(self.args)
        self.assert_no_installation()
        self.snapshot.assert_not_called()

    def test_invalid_certificate_aborts_before_claiming_private_paths(self):
        self.snapshot.side_effect = RuntimeError("Invalid TLS certificate")
        with self.assertRaisesRegex(RuntimeError, "Invalid TLS"):
            coexist.install(self.args)
        self.assert_no_installation()
        self.handshake.assert_not_called()

    def test_install_uses_only_owned_services_and_preserves_website_material(self):
        coexist.install(self.args)
        state, metadata = system.load_state(), system.load_install()
        self.assertEqual(metadata["mode"], "coexist")
        self.assertTrue(metadata["complete"])
        self.assertEqual(state["public_host"], self.args.tls_host)
        for field in ("vpn_port", "subscription_port", "monitor_port", "api_port"):
            self.assertEqual(state[field], getattr(self.args, field))
        for path, content in self.original_site.items():
            self.assertEqual(path.read_bytes(), content)
        for function in self.forbidden.values():
            function.assert_not_called()
        self.assertEqual(set(self.unit_files), {
            "vpnkit.service", "vpnkit-web.service", "vpnkit-cert-sync.service", "vpnkit-cert-sync.timer",
        })
        actions = [argv for argv in self.calls if argv[0] == "systemctl" and argv[1] in {"restart", "reload"}]
        self.assertEqual({argv[-1] for argv in actions}, {"vpnkit.service", "vpnkit-web.service"})
        self.assertEqual((system.ETC / "state.json").stat().st_mode & 0o777, 0o600)

    def test_completed_replay_preserves_keys_and_does_not_restart_any_service(self):
        coexist.install(self.args)
        previous = (system.ETC / "state.json").read_bytes()
        self.calls.clear()
        self.preflight.reset_mock()
        self.snapshot.reset_mock()
        self.core.reset_mock()
        coexist.install(self.args)
        self.assertEqual((system.ETC / "state.json").read_bytes(), previous)
        self.assertEqual(self.calls, [])
        self.preflight.assert_not_called()
        self.snapshot.assert_not_called()
        self.core.assert_not_called()


if __name__ == "__main__":
    unittest.main()

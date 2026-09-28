"""Exercise credential preservation and failure paths without root or networking."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpnkit import system
from vpnkit.render import new_state


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        root = Path(self.temporary.name)
        for name, path in {
            "ETC": root / "etc", "DATA": root / "data",
            "APP": root / "app", "ACCESS": root / "access.txt",
        }.items():
            self.contexts.enter_context(patch.object(system, name, path))
        self.contexts.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.preflight = self.contexts.enter_context(patch.object(system, "preflight", return_value="amd64"))
        self.ports = self.contexts.enter_context(patch.object(system, "check_ports"))
        self.handshake = self.contexts.enter_context(patch.object(system, "verify_handshake"))
        self.addresses = self.contexts.enter_context(patch.object(system, "local_addresses", return_value=["127.0.0.1"]))
        # Every path that could invoke a privileged process is mocked here.
        self.dependencies = self.contexts.enter_context(patch.object(system, "install_dependencies"))
        self.process = self.contexts.enter_context(patch.object(system, "run"))
        self.writer = self.contexts.enter_context(patch.object(system, "write_rendered"))
        self.start = self.contexts.enter_context(patch.object(system, "start_services"))
        self.issuer = self.contexts.enter_context(patch.object(system, "issue_certificate"))
        self.args = argparse.Namespace(
            accept_acme_tos=True, server_ip="1.1.1.1", name="Test VPN",
            handshake_host="dl.google.com", with_monitor=True,
        )

    def existing(self, *, complete=True, with_monitor=True):
        state = new_state("1.1.1.1", private_key="A" * 43, public_key="A" * 43)
        system.ETC.mkdir()
        system.save_json(system.ETC / "state.json", state)
        system.save_json(system.ETC / "install.json", {
            "complete": complete, "keys_created": complete, "with_monitor": with_monitor,
        })
        return state

    def test_terms_consent_is_checked_before_preflight_or_mutation(self):
        self.args.accept_acme_tos = False
        with self.assertRaisesRegex(RuntimeError, "accept-acme-tos"):
            system.install(self.args)
        self.preflight.assert_not_called()
        self.dependencies.assert_not_called()
        self.assertFalse(system.ETC.exists())
        self.assertFalse(system.APP.exists())

    def test_completed_replay_preserves_credentials_without_installing(self):
        state = self.existing()
        original = (system.ETC / "state.json").read_bytes()
        system.install(self.args)
        self.assertEqual((system.ETC / "state.json").read_bytes(), original)
        self.assertEqual(system.load_state(), state)
        self.dependencies.assert_not_called()
        self.issuer.assert_not_called()
        self.writer.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(system.ACCESS.stat().st_mode & 0o777, 0o600)

    def test_replay_requires_explicit_update_ip_instead_of_rotating_state(self):
        state = self.existing()
        self.args.server_ip = "8.8.8.8"
        with self.assertRaisesRegex(RuntimeError, "update-ip"):
            system.install(self.args)
        self.assertEqual(system.load_state(), state)
        self.dependencies.assert_not_called()

    def test_replay_refuses_implicit_monitoring_expansion(self):
        state = self.existing(with_monitor=False)
        with self.assertRaisesRegex(RuntimeError, "without monitoring"):
            system.install(self.args)
        self.assertEqual(system.load_state(), state)
        self.dependencies.assert_not_called()

    def test_failed_dependency_install_can_resume_without_new_credentials(self):
        self.dependencies.side_effect = RuntimeError("simulated apt failure")
        with self.assertRaisesRegex(RuntimeError, "simulated apt failure"):
            system.install(self.args)
        first_state = system.load_state()
        self.assertFalse(system.load_install()["complete"])
        self.assertFalse(system.load_install()["keys_created"])
        with self.assertRaisesRegex(RuntimeError, "simulated apt failure"):
            system.install(self.args)
        self.assertEqual(system.load_state(), first_state)
        self.assertEqual((system.ETC / "state.json").stat().st_mode & 0o777, 0o600)
        self.writer.assert_not_called()
        self.start.assert_not_called()

    def test_invalid_input_is_rejected_before_persistent_changes(self):
        self.args.handshake_host = "example.com;touch /tmp/unwanted"
        with self.assertRaises(ValueError):
            system.install(self.args)
        self.assertFalse(system.ETC.exists())
        self.dependencies.assert_not_called()
        self.handshake.assert_not_called()

    def test_port_conflict_does_not_create_owned_state(self):
        self.ports.side_effect = RuntimeError("occupied")
        with self.assertRaisesRegex(RuntimeError, "occupied"):
            system.install(self.args)
        self.assertFalse(system.ETC.exists())
        self.dependencies.assert_not_called()

    def test_update_certificate_failure_leaves_existing_config_and_state(self):
        state = self.existing()
        self.args.server_ip = "8.8.8.8"
        self.issuer.side_effect = RuntimeError("simulated ACME failure")
        with self.assertRaisesRegex(RuntimeError, "ACME failure"):
            system.update_ip(self.args)
        self.assertEqual(system.load_state(), state)
        self.writer.assert_not_called()
        self.start.assert_not_called()

    def test_update_activation_failure_restores_prior_configuration(self):
        state = self.existing()
        self.args.server_ip = "8.8.8.8"
        self.start.side_effect = RuntimeError("simulated service failure")
        with self.assertRaisesRegex(RuntimeError, "previous configuration restored"):
            system.update_ip(self.args)
        self.assertEqual(system.load_state(), state)
        self.assertEqual(self.writer.call_count, 2)
        self.assertEqual(self.writer.call_args_list[0].args[0]["server_ip"], "8.8.8.8")
        self.assertEqual(self.writer.call_args_list[1].args[0], state)
        self.issuer.assert_called_once_with("8.8.8.8")
        # The ACME side effect is deliberately not asserted to roll back.
        self.process.assert_called_once_with(
            ["systemctl", "restart", "vpnkit-web.service", "vpnkit.service"], check=False,
        )

    def test_successful_update_preserves_all_access_credentials(self):
        state = self.existing()
        self.args.server_ip = "8.8.8.8"
        system.update_ip(self.args)
        updated = system.load_state()
        self.assertEqual(updated["server_ip"], "8.8.8.8")
        for key in state.keys() - {"server_ip", "local_addresses"}:
            self.assertEqual(updated[key], state[key], key)
        self.issuer.assert_called_once_with("8.8.8.8")
        self.start.assert_called_once()

    def test_incomplete_install_cannot_update_ip(self):
        state = self.existing(complete=False)
        self.args.server_ip = "8.8.8.8"
        with self.assertRaisesRegex(RuntimeError, "Finish installation"):
            system.update_ip(self.args)
        self.assertEqual(system.load_state(), state)
        self.issuer.assert_not_called()


class FileSafetyTests(unittest.TestCase):
    def test_failed_atomic_replace_keeps_previous_file_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            system.save_json(path, {"uuid": "previous"})
            with patch.object(system.os, "replace", side_effect=OSError("simulated full disk")):
                with self.assertRaises(OSError):
                    system.save_json(path, {"uuid": "new"})
            self.assertEqual(json.loads(path.read_text())["uuid"], "previous")
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_checksum_mismatch_removes_download_before_it_can_be_used(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "core.tgz"
            def downloaded(_argv):
                path.write_bytes(b"not the expected upstream release")
            with patch.object(system, "run", side_effect=downloaded):
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    system.download("https://example.com/archive", path, "0" * 64)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()

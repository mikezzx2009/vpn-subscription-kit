"""Exercise the real bootstrap's release URL without root or network access."""

import ast
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def packaged_version():
    """The archive builder defines the version the bootstrap must download."""
    tree = ast.parse((ROOT / "scripts/package.py").read_text())
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "VERSION"
                        for target in node.targets)):
            return ast.literal_eval(node.value)
    raise AssertionError("The release archive version was not found")


class BootstrapReleaseTests(unittest.TestCase):
    def test_os_release_version_does_not_change_downloaded_release(self):
        fixtures = (
            ("ubuntu", "22.04", "22.04.5 LTS (Jammy Jellyfish)"),
            ("ubuntu", "24.04", "24.04.3 LTS (Noble Numbat)"),
            ("debian", "12", "12 (bookworm)"),
            ("debian", "13", "13 (trixie)"),
        )
        version = packaged_version()
        expected_url = (
            "https://github.com/mikezzx2009/vpn-subscription-kit/releases/download/"
            f"v{version}/vpnkit-v{version}.tar.gz"
        )
        for distro, version_id, os_version in fixtures:
            with self.subTest(distro=distro, version_id=version_id):
                values = self.capture_first_download(distro, version_id, os_version)
                # Verify that the fixture was actually sourced by Bash before curl.
                self.assertEqual(values[:3], [distro, version_id, os_version])
                urls = [arg for arg in values[3:] if arg.startswith("https://")]
                self.assertEqual(urls, [expected_url])

    def capture_first_download(self, distro, version_id, os_version):
        result, values, _ = self.run_bootstrap(distro, version_id, os_version)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(values, f"curl was not reached: {result.stdout}\n{result.stderr}")
        return values

    def test_coexist_with_existing_python_does_not_require_acme_terms(self):
        result, values, operations = self.run_bootstrap(
            "ubuntu", "24.04", "24.04.3 LTS (Noble Numbat)",
            arguments=("--coexist", "--with-monitor"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(values, "Coexist bootstrap must reach its download without ACME consent")
        self.assertEqual(operations, ["mktemp", "curl"])
        version = packaged_version()
        self.assertIn(
            "https://github.com/mikezzx2009/vpn-subscription-kit/releases/download/"
            f"v{version}/vpnkit-v{version}.tar.gz", values,
        )

    def test_coexist_without_python_aborts_before_packages_or_download(self):
        result, values, operations = self.run_bootstrap(
            "ubuntu", "24.04", "24.04.3 LTS (Noble Numbat)",
            arguments=("--coexist", "--with-monitor"), python_available=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("requires an existing python3", result.stderr)
        self.assertIsNone(values)
        self.assertEqual(operations, [], "No package command, workspace or download may occur")

    def run_bootstrap(self, distro, version_id, os_version, *,
                      arguments=("--accept-acme-tos", "--with-monitor"), python_available=True):
        script = (ROOT / "install.sh").read_text()
        # Only host prerequisites and the os-release path change. Bash executes
        # the real assignments, source command, validation and curl expansion.
        replacements = {
            '[[ "$EUID" -eq 0 ]]': "[[ 0 -eq 0 ]]",
            "[[ -d /run/systemd/system ]]": "[[ 0 -eq 0 ]]",
        }
        for old, new in replacements.items():
            self.assertEqual(script.count(old), 1, f"Bootstrap guard changed: {old}")
            script = script.replace(old, new, 1)
        with tempfile.TemporaryDirectory(prefix="vpnkit-bootstrap-test-") as directory:
            directory = Path(directory)
            fixture = directory / "os-release"
            fixture.write_text(
                f"ID={shlex.quote(distro)}\nVERSION_ID={shlex.quote(version_id)}\n"
                f"VERSION={shlex.quote(os_version)}\n"
            )
            self.assertEqual(script.count("source /etc/os-release"), 1)
            script = script.replace("source /etc/os-release", f"source {shlex.quote(str(fixture))}", 1)
            capture = directory / "curl-arguments"
            operations = directory / "operations"
            workspace = directory / "workspace"
            workspace.mkdir()
            harness = r'''
function command() {
    if [[ "$#" -eq 2 && "$1" == '-v' && ( "$2" == 'curl' || "$2" == 'python3' ) ]]; then
        if [[ "$2" == 'python3' && "$VPNKIT_TEST_PYTHON" == 'missing' ]]; then
            return 1
        fi
        return 0
    fi
    builtin command "$@"
}
function uname() { printf '%s\n' x86_64; }
function mktemp() {
    printf '%s\n' mktemp >> "$VPNKIT_TEST_OPERATIONS"
    printf '%s\n' "$VPNKIT_TEST_WORKSPACE"
}
function apt-get() {
    printf 'apt-get %s\n' "$*" >> "$VPNKIT_TEST_OPERATIONS"
    printf '%s\n' 'Unexpected package installation' >&2
    exit 91
}
function curl() {
    printf '%s\n' curl >> "$VPNKIT_TEST_OPERATIONS"
    printf '%s\0' "${ID:-}" "${VERSION_ID:-}" "${VERSION:-}" "$@" > "$VPNKIT_TEST_CAPTURE"
    # Exit the shell at the first download; nothing after it may run.
    exit 0
}
'''
            result = subprocess.run(
                ["bash", "-s", "--", *arguments],
                input=harness + script, text=True, capture_output=True, timeout=10,
                env={**os.environ, "VPNKIT_TEST_CAPTURE": str(capture),
                     "VPNKIT_TEST_WORKSPACE": str(workspace),
                     "VPNKIT_TEST_OPERATIONS": str(operations),
                     "VPNKIT_TEST_PYTHON": "present" if python_available else "missing"},
            )
            values = capture.read_bytes().decode().rstrip("\0").split("\0") if capture.exists() else None
            return result, values, operations.read_text().splitlines() if operations.exists() else []


if __name__ == "__main__":
    unittest.main()

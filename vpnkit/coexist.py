"""Opt-in deployment alongside existing services, using externally renewed TLS.

This path never installs OS packages, operates the website's nginx service,
edits its configuration/certificates, or changes host firewall rules.
"""

import hashlib
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import tempfile

from . import system
from .render import new_state, render


PORT_DEFAULTS = {"vpn_port": 24443, "subscription_port": 28443,
                 "monitor_port": 28444, "api_port": 29090}
UNITS = ("vpnkit.service", "vpnkit-web.service", "vpnkit-cert-sync.timer")


def preflight(nginx_binary=None):
    system.preflight()
    missing = [name for name in ("curl", "openssl", "ip", "systemctl", "useradd")
               if shutil.which(name) is None]
    if missing:
        raise RuntimeError("Coexist mode does not install system packages. Missing: " + ", ".join(missing))
    candidate = nginx_binary or shutil.which("nginx")
    if not candidate:
        raise RuntimeError("Existing nginx binary required; pass --nginx-binary /absolute/path/nginx.")
    path = Path(candidate).resolve()
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", str(path)):
        raise ValueError("nginx binary path contains unsupported characters")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("nginx binary must be a root-owned file that other users cannot modify")
    if not os.access(path, os.X_OK):
        raise RuntimeError("nginx binary is not executable")
    system.run([path, "-V"], timeout=15)
    return str(path)


def source_path(value, label):
    if not value or not Path(value).is_absolute():
        raise ValueError(f"{label} must be an absolute file path")
    # Preserve the symlink path: certificate managers replace its target on renewal.
    path = Path(os.path.abspath(value))
    if path.is_relative_to(system.ETC) or not path.is_file():
        raise ValueError(f"{label} must be an existing external file outside {system.ETC}")
    return str(path)


def validate_certificate(host, cert_path, key_path):
    system.run(["openssl", "x509", "-in", cert_path, "-noout", "-checkend", "86400"], timeout=15)
    system.run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", host,
                "-untrusted", cert_path, cert_path], timeout=15)
    public_cert = system.run(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"], timeout=15).stdout
    public_key = system.run(["openssl", "pkey", "-in", key_path, "-passin", "pass:", "-pubout"],
                            input="", timeout=15).stdout
    if public_cert.strip() != public_key.strip():
        raise RuntimeError("TLS certificate and private key do not match")


def certificate_snapshot(host, cert_path, key_path):
    cert, key = Path(cert_path).read_bytes(), Path(key_path).read_bytes()
    if not cert or not key or len(cert) > 1024 * 1024 or len(key) > 1024 * 1024:
        raise RuntimeError("Invalid certificate or key file size")
    # Validate exactly the bytes that will be installed, even during external renewal.
    with tempfile.TemporaryDirectory(prefix="vpnkit-tls-check-") as directory:
        certificate, private_key = Path(directory) / "fullchain.pem", Path(directory) / "privkey.pem"
        certificate.write_bytes(cert)
        private_key.write_bytes(key)
        private_key.chmod(0o600)
        validate_certificate(host, certificate, private_key)
    return cert, key


def check_host(host, ip):
    addresses = {item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)}
    if addresses != {ip}:
        raise RuntimeError("Subscription hostname must resolve directly to this public IPv4 only. "
                           "Use an A-only DNS record without a CDN proxy; do not change the website's DNS blindly.")


def check_ports(state, with_monitor):
    ports = [state["vpn_port"], state["subscription_port"]]
    if with_monitor:
        ports += [state["monitor_port"], state["api_port"]]
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
            except OSError as exc:
                raise RuntimeError(f"Cannot bind VPN port {port}: {exc.strerror}. Choose another port.") from exc


def nginx_command(metadata, *args):
    return [metadata["nginx_binary"], "-p", str(system.DATA / "nginx") + "/",
            "-c", system.ETC / "nginx.conf", *args]


def _switch_certificate(target):
    link = system.ETC / ".tls-next"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)
    os.replace(link, system.ETC / "tls")


def install_certificate(cert, key, *, reload=False, metadata=None):
    digest = hashlib.sha256(cert + b"\0" + key).hexdigest()
    revisions = system.ETC / "tls-revisions"
    revisions.mkdir(mode=0o700, exist_ok=True)
    target = "tls-revisions/" + digest
    active = system.ETC / "tls"
    if active.exists() and not active.is_symlink():
        raise RuntimeError("Refusing to replace an unmanaged TLS directory")
    previous = os.readlink(active) if active.is_symlink() else None
    generation = system.ETC / target
    if generation.exists():
        if ((generation / "fullchain.pem").read_bytes() != cert
                or (generation / "privkey.pem").read_bytes() != key):
            raise RuntimeError("Stored VPN TLS generation is damaged; no files were replaced")
    else:
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=revisions) as directory:
            staged = Path(directory)
            system.atomic_write(staged / "fullchain.pem", cert.decode("ascii"))
            system.atomic_write(staged / "privkey.pem", key.decode("ascii"))
            # Both files become available before a single atomic symlink switch.
            os.replace(staged, generation)
    if previous == target:
        return False
    _switch_certificate(target)
    if reload:
        try:
            system.run(nginx_command(metadata, "-t"))
            system.run(["systemctl", "reload", "vpnkit-web.service"])
        except Exception:
            if previous is None:
                active.unlink()
            else:
                _switch_certificate(previous)
                system.run(["systemctl", "reload", "vpnkit-web.service"], check=False)
            raise RuntimeError("VPN certificate activation failed; previous certificate restored")
    return True


def make_directories():
    try:
        account = pwd.getpwnam("vpnkit")
    except KeyError:
        system.run(["useradd", "--system", "--user-group", "--no-create-home",
                    "--shell", "/usr/sbin/nologin", "vpnkit"])
        account = pwd.getpwnam("vpnkit")
    system.ETC.mkdir(mode=0o750, parents=True, exist_ok=True)
    system.ETC.chmod(0o750)
    os.chown(system.ETC, 0, account.pw_gid)
    for directory in (system.DATA, system.DATA / "subscriptions", system.DATA / "monitor",
                      system.DATA / "nginx"):
        directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        directory.chmod(0o750)
        os.chown(directory, 0, account.pw_gid)
    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        directory = system.DATA / "nginx" / name
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, account.pw_uid, account.pw_gid)


def write_rendered(state, with_monitor):
    files = render(state, with_monitor=with_monitor)
    group = pwd.getpwnam("vpnkit").pw_gid
    for name in ("sing-box.json", "nginx.conf"):
        system.atomic_write(system.ETC / name, files[name], 0o640, group)
    for name in ("clash.yaml", "shadowrocket.txt"):
        system.atomic_write(system.DATA / "subscriptions" / name, files[name], 0o640, group)
    for name in ("urls.json", "direct-vless.txt"):
        system.atomic_write(system.ETC / name, files[name])
    if with_monitor:
        hashed = system.run(["openssl", "passwd", "-6", "-stdin"],
                            input=state["monitor_password"] + "\n").stdout.strip()
        system.atomic_write(system.ETC / "monitor.htpasswd",
                            state["monitor_username"] + ":" + hashed + "\n", 0o640, group)


def system_units(metadata):
    common = "After=network-online.target\nWants=network-online.target\n"
    limits = "NoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nCPUWeight=10\nIOWeight=10\nTasksMax=64\n"
    nginx = metadata["nginx_binary"]
    prefix = f"{nginx} -p /var/lib/vpnkit/nginx/ -c /etc/vpnkit/nginx.conf"
    web = "[Unit]\nDescription=VPN Kit isolated HTTPS subscriptions\n" + common + f'''[Service]
Type=simple
ExecStartPre={prefix} -t
ExecStart={prefix} -g "daemon off;"
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
CPUQuota=10%
MemoryMax=128M
LimitNOFILE=4096
''' + limits + "[Install]\nWantedBy=multi-user.target\n"
    core = "[Unit]\nDescription=VPN Kit isolated VLESS REALITY\n" + common + '''[Service]
User=vpnkit
Group=vpnkit
ExecStartPre=/opt/vpnkit/bin/sing-box check -c /etc/vpnkit/sing-box.json
ExecStart=/opt/vpnkit/bin/sing-box run -c /etc/vpnkit/sing-box.json
Restart=on-failure
RestartSec=3
CPUQuota=25%
MemoryMax=256M
LimitNOFILE=8192
''' + limits + "[Install]\nWantedBy=multi-user.target\n"
    sync = '''[Unit]
Description=Copy externally renewed certificate to VPN Kit only
After=vpnkit-web.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnkit sync-cert
CPUQuota=10%
MemoryMax=128M
'''
    timer = '''[Unit]
Description=Watch externally renewed VPN Kit TLS certificate
[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
'''
    for name, content in (("vpnkit-web.service", web), ("vpnkit.service", core),
                          ("vpnkit-cert-sync.service", sync), ("vpnkit-cert-sync.timer", timer)):
        system.atomic_write(Path("/etc/systemd/system") / name, content, 0o644)
    system.run(["systemctl", "daemon-reload"])


def start_services(metadata):
    system.run([system.APP / "bin/sing-box", "check", "-c", system.ETC / "sing-box.json"])
    system.run(nginx_command(metadata, "-t"))
    for unit in UNITS[:2]:
        system.run(["systemctl", "enable", unit])
        system.run(["systemctl", "restart", unit])
    system.run(["systemctl", "enable", "--now", UNITS[2]])
    for unit in UNITS:
        system.run(["systemctl", "is-active", "--quiet", unit])


def _refuse_existing_resources():
    reserved = [system.ETC, system.APP, system.DATA, Path("/usr/local/bin/vpnkit")]
    unit_names = (*UNITS, "vpnkit-cert-sync.service", "vpnkit-renew.service", "vpnkit-renew.timer")
    reserved += [Path(directory) / unit for unit in unit_names
                 for directory in ("/etc/systemd/system", "/run/systemd/system",
                                   "/usr/lib/systemd/system", "/lib/systemd/system")]
    if any(path.exists() or path.is_symlink() for path in reserved):
        raise RuntimeError("Unmanaged vpnkit paths exist; inspect them before installing")
    for unit in unit_names:
        load_state = system.run(["systemctl", "show", unit, "--property=LoadState", "--value"],
                                check=False, timeout=15).stdout.strip()
        if load_state != "not-found":
            raise RuntimeError(f"Refusing to replace existing or unverified unit {unit}")
    try:
        pwd.getpwnam("vpnkit")
    except KeyError:
        return
    raise RuntimeError("The reserved system account vpnkit already exists")


def _check_replay(args, state, metadata):
    expected = {"server_ip": state["server_ip"], "tls_host": state["public_host"],
                "tls_cert": metadata["certificate_source"], "tls_key": metadata["key_source"],
                "nginx_binary": metadata["nginx_binary"], **{key: state[key] for key in PORT_DEFAULTS}}
    for field, value in expected.items():
        supplied = getattr(args, field, None)
        if supplied is not None and field == "nginx_binary":
            supplied = str(Path(supplied).resolve())
        elif supplied is not None and field in ("tls_cert", "tls_key"):
            supplied = os.path.abspath(supplied)
        if supplied is not None and supplied != value:
            raise RuntimeError(f"Existing coexist installation has different {field}; automatic migration is refused")
    if getattr(args, "with_monitor", False) and not metadata["with_monitor"]:
        raise RuntimeError("This installation was created without monitoring")


def install(args):
    owned = (system.ETC / "state.json").is_file() and (system.ETC / "install.json").is_file()
    if owned:
        metadata, state = system.load_install(), system.load_state()
        if metadata.get("mode") != "coexist" or state.get("mode") != "coexist":
            raise RuntimeError("Cannot convert a standalone installation to coexist mode implicitly")
        _check_replay(args, state, metadata)
        if metadata["complete"]:
            system.show_urls()
            return
        nginx = preflight(metadata["nginx_binary"])
        certificate = certificate_snapshot(state["public_host"], metadata["certificate_source"], metadata["key_source"])
    else:
        nginx = preflight(getattr(args, "nginx_binary", None))
        _refuse_existing_resources()
        cert_source = source_path(getattr(args, "tls_cert", None), "--tls-cert")
        key_source = source_path(getattr(args, "tls_key", None), "--tls-key")
        ip = system.public_ipv4(args.server_ip) if args.server_ip else system.detect_public_ip()
        dummy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        state = new_state(ip, args.name, args.handshake_host, private_key=dummy, public_key=dummy,
                          mode="coexist", public_host=getattr(args, "tls_host", None),
                          **{key: value if getattr(args, key, None) is None else getattr(args, key)
                             for key, value in PORT_DEFAULTS.items()})
        check_ports(state, args.with_monitor)
        check_host(state["public_host"], ip)
        certificate = certificate_snapshot(state["public_host"], cert_source, key_source)
        system.verify_handshake(state["handshake_host"], ip)
        metadata = {"mode": "coexist", "complete": False, "keys_created": False,
                    "with_monitor": args.with_monitor, "nginx_binary": nginx,
                    "certificate_source": cert_source, "key_source": key_source}
        # Only after all read-only checks succeed do we claim our private paths.
        system.ETC.mkdir(mode=0o700, parents=True)
        system.save_json(system.ETC / "state.json", state)
        system.save_json(system.ETC / "install.json", metadata)
    print("Installing isolated VPN services; OS packages, existing website and firewall are not modified.")
    system.APP.mkdir(mode=0o755, parents=True, exist_ok=True)
    system.APP.chmod(0o755)
    make_directories()
    system.install_app()
    arch = system.preflight()
    system.install_core(arch)
    if not metadata["keys_created"]:
        output = system.run([system.APP / "bin/sing-box", "generate", "reality-keypair"]).stdout
        values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
        state.update(reality_private_key=values["PrivateKey"].strip(), reality_public_key=values["PublicKey"].strip())
        metadata["keys_created"] = True
        system.save_json(system.ETC / "state.json", state)
        system.save_json(system.ETC / "install.json", metadata)
    state["local_addresses"] = system.local_addresses()
    if metadata["with_monitor"]:
        system.install_monitor()
    install_certificate(*certificate)
    write_rendered(state, metadata["with_monitor"])
    system_units(metadata)
    start_services(metadata)
    metadata["complete"] = True
    system.save_json(system.ETC / "state.json", state)
    system.save_json(system.ETC / "install.json", metadata)
    system.show_urls()
    ports = [state["vpn_port"], state["subscription_port"]]
    if metadata["with_monitor"]:
        ports.append(state["monitor_port"])
    print("Allow inbound TCP ports in the cloud and host firewalls: " + ", ".join(map(str, ports)))
    print("Existing certificate renewal remains your website's responsibility. VPN services share host bandwidth.")


def sync_certificate():
    metadata, state = system.load_install(), system.load_state()
    if metadata.get("mode") != "coexist" or not metadata.get("complete"):
        raise RuntimeError("sync-cert requires a completed coexist installation")
    snapshot = certificate_snapshot(state["public_host"], metadata["certificate_source"], metadata["key_source"])
    changed = install_certificate(*snapshot, reload=True, metadata=metadata)
    print("VPN TLS certificate updated" if changed else "VPN TLS certificate unchanged")


def status():
    for unit in UNITS:
        result = system.run(["systemctl", "is-active", unit], check=False)
        print(f"{unit}: {result.stdout.strip()}")


def doctor():
    metadata, state = system.load_install(), system.load_state()
    for unit in UNITS:
        system.run(["systemctl", "is-active", "--quiet", unit])
    system.run(nginx_command(metadata, "-t"))
    system.run([system.APP / "bin/sing-box", "check", "-c", system.ETC / "sing-box.json"])
    validate_certificate(state["public_host"], system.ETC / "tls/fullchain.pem", system.ETC / "tls/privkey.pem")
    check_host(state["public_host"], state["server_ip"])
    for port in [state["vpn_port"], state["subscription_port"]] + ([state["monitor_port"]] if metadata["with_monitor"] else []):
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
        print(f"PASS: TCP {port} listening locally")
    print("Local checks passed; verify reachability from the client and cloud/host firewall rules.")


def update_ip(args):
    metadata, state = system.load_install(), system.load_state()
    if not metadata.get("complete"):
        raise RuntimeError("Finish installation before updating its IP")
    ip = system.public_ipv4(args.server_ip) if args.server_ip else system.detect_public_ip()
    check_host(state["public_host"], ip)
    system.verify_handshake(state["handshake_host"], ip)
    candidate = dict(state, server_ip=ip, local_addresses=system.local_addresses())
    try:
        write_rendered(candidate, metadata["with_monitor"])
        start_services(metadata)
    except Exception:
        write_rendered(state, metadata["with_monitor"])
        start_services(metadata)
        raise RuntimeError("VPN IP update failed; previous VPN configuration restored")
    system.save_json(system.ETC / "state.json", candidate)
    system.show_urls()

"""Host operations. Deliberately uses argv arrays and private, persistent state."""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request

from .render import new_state, render

ETC = Path('/etc/vpnkit')
DATA = Path('/var/lib/vpnkit')
APP = Path('/opt/vpnkit')
CERT = Path('/etc/letsencrypt/live/vpnkit-ip')
ACCESS = Path('/root/vpnkit-access.txt')
SOURCE = Path(__file__).resolve().parent.parent
CORE_VERSION = '1.14.0'
CORE_HASHES = {
    'amd64': '2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63',
    'arm64': '04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088',
}
MONITOR_VERSION = '1.273.1'
MONITOR_HASH = 'a178e00b67acabcda2dcef00afa90be6a7bb261e466a67dad58c8478d9553603'


def run(argv, *, input=None, check=True, timeout=600):
    result = subprocess.run([str(x) for x in argv], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        # Do not echo argv/input: they may contain credentials or subscription paths.
        raise RuntimeError(f'{Path(str(argv[0])).name} failed (exit {result.returncode}): '
                           f'{result.stderr[-1800:].strip()}')
    return result


def require_root():
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo or as root.')


@contextlib.contextmanager
def operation_lock():
    with open('/run/vpnkit-install.lock', 'w') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another vpnkit command is running.') from exc
        yield


def atomic_write(path, content, mode=0o600, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.vpnkit-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if group is not None:
            os.chown(temporary, 0, group)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def load_state():
    try:
        state = json.loads((ETC / 'state.json').read_text())
    except FileNotFoundError as exc:
        raise RuntimeError('No installation found. Run install first.') from exc
    render(state)  # validate before using it in privileged operations
    return state


def load_install():
    return json.loads((ETC / 'install.json').read_text())


def public_ipv4(value):
    addr = ipaddress.ip_address(value)
    if addr.version != 4 or not addr.is_global or addr.is_multicast:
        raise ValueError('A canonical public IPv4 address is required.')
    return str(addr)


def detect_public_ip():
    failures = []
    for url in ('https://api.ipify.org', 'https://ipv4.icanhazip.com'):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'vpnkit/1.0'})
            with urllib.request.urlopen(request, timeout=15) as response:
                return public_ipv4(response.read(128).decode().strip())
        except (OSError, ValueError) as exc:
            failures.append(type(exc).__name__)
    raise RuntimeError('Cannot detect public IPv4; pass --server-ip explicitly. ' + ', '.join(failures))


def preflight():
    if platform.system() != 'Linux' or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('Requires a Linux VPS booted with systemd.')
    info = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            info[key] = value.strip('"')
    supported = {'ubuntu': {'22.04', '24.04'}, 'debian': {'12', '13'}}
    if info.get('VERSION_ID') not in supported.get(info.get('ID'), set()):
        raise RuntimeError('Supported OS: Ubuntu 22.04/24.04 and Debian 12/13.')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Supported architectures: amd64 and arm64.')
    return arch


def check_ports(with_monitor):
    for port in [80, 443, 8443] + ([8444, 19090] if with_monitor else []):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('0.0.0.0', port))
            except OSError as exc:
                raise RuntimeError(f'TCP port {port} is occupied. Use a fresh VPS or resolve the conflict.') from exc


def verify_handshake(host, own_ip):
    # The renderer validates the hostname syntax before this function is called.
    addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(ip).is_global or ip == own_ip for ip in addresses):
        raise RuntimeError('REALITY handshake host must resolve to public addresses other than this VPS.')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    for ip in sorted(addresses):
        try:
            with socket.create_connection((ip, 443), timeout=12) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    if tls.selected_alpn_protocol() != 'h2':
                        raise RuntimeError('Handshake host does not support HTTP/2.')
                    return
        except OSError:
            continue
    raise RuntimeError('Handshake host is unreachable or lacks verified TLS 1.3 / HTTP/2.')


def download(url, path, expected_hash):
    run(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '3',
         '--connect-timeout', '20', '--max-time', '300', '--proto', '=https',
         '--tlsv1.2', url, '-o', path])
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected_hash:
        Path(path).unlink(missing_ok=True)
        raise RuntimeError('Upstream download checksum mismatch; installation stopped.')


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination) or not (member.isfile() or member.isdir()):
                raise RuntimeError('Unsafe path or link in release archive.')
        tar.extractall(destination)


def install_dependencies():
    nginx_was_missing = load_install().get('nginx_installed_by_vpnkit', False)
    run(['apt-get', 'update'], timeout=900)
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a')
    result = subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends',
                             'ca-certificates', 'curl', 'openssl', 'python3-venv', 'nginx', 'iproute2'],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
    if result.returncode:
        raise RuntimeError('APT dependency installation failed: ' + result.stderr[-1800:])
    if nginx_was_missing:
        # Debian packages start their default site automatically. Only stop a service we just installed.
        run(['systemctl', 'disable', '--now', 'nginx.service'])
    if not (APP / 'certbot/bin/certbot').exists():
        run(['python3', '-m', 'venv', APP / 'certbot'])
    run([APP / 'certbot/bin/pip', 'install', '--disable-pip-version-check', 'certbot==5.8.0'], timeout=900)


def install_core(arch):
    APP.joinpath('bin').mkdir(parents=True, exist_ok=True)
    os.chmod(APP / 'bin', 0o755)
    with tempfile.TemporaryDirectory(prefix='vpnkit-core-') as temporary:
        archive = Path(temporary) / 'core.tgz'
        name = f'sing-box-{CORE_VERSION}-linux-{arch}'
        download(f'https://github.com/SagerNet/sing-box/releases/download/v{CORE_VERSION}/{name}.tar.gz',
                 archive, CORE_HASHES[arch])
        safe_extract(archive, Path(temporary) / 'unpacked')
        source = Path(temporary) / 'unpacked' / name / 'sing-box'
        shutil.copyfile(source, APP / 'bin/sing-box.new')
        os.chmod(APP / 'bin/sing-box.new', 0o755)
        os.replace(APP / 'bin/sing-box.new', APP / 'bin/sing-box')


def install_monitor():
    with tempfile.TemporaryDirectory(prefix='vpnkit-monitor-') as temporary:
        archive = Path(temporary) / 'monitor.tgz'
        download(f'https://github.com/MetaCubeX/metacubexd/releases/download/v{MONITOR_VERSION}/compressed-dist.tgz',
                 archive, MONITOR_HASH)
        unpacked = Path(temporary) / 'unpacked'
        safe_extract(archive, unpacked)
        if not (unpacked / 'index.html').is_file():
            raise RuntimeError('Unexpected MetaCubeXD archive structure.')
        shutil.copytree(unpacked, DATA / 'monitor', dirs_exist_ok=True)
    shutil.copyfile(SOURCE / 'assets/online.html', DATA / 'monitor/online.html')
    os.chmod(DATA / 'monitor', 0o755)
    atomic_write(DATA / 'monitor/config.js',
                 "window.__METACUBEXD_CONFIG__={defaultBackendURL:window.location.origin+'/api',githubToken:''};\n", 0o644)
    for path in (DATA / 'monitor').rglob('*'):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def install_app():
    target = APP / 'app'
    if SOURCE != target:
        target.mkdir(parents=True, exist_ok=True)
        for name in ('vpnkit', 'assets'):
            shutil.copytree(SOURCE / name, target / name, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in ('LICENSE', 'THIRD_PARTY.md'):
            shutil.copyfile(SOURCE / name, target / name)
    atomic_write('/usr/local/bin/vpnkit',
                 '#!/bin/sh\ncd /opt/vpnkit/app\nexec /usr/bin/python3 -m vpnkit "$@"\n', 0o755)


def make_directories():
    run(['id', '-u', 'vpnkit'], check=False)
    try:
        account = pwd.getpwnam('vpnkit')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'vpnkit'])
        account = pwd.getpwnam('vpnkit')
    ETC.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(ETC, 0o750)
    os.chown(ETC, 0, account.pw_gid)
    for name in ('subscriptions', 'acme', 'monitor'):
        DATA.joinpath(name).mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(DATA / name, 0o755)
    os.chmod(DATA, 0o755)
    # Token files are readable by nginx only, not by other unprivileged users.
    os.chown(DATA / 'subscriptions', 0, pwd.getpwnam('www-data').pw_gid)
    os.chmod(DATA / 'subscriptions', 0o750)


def system_units():
    common = 'After=network-online.target\nWants=network-online.target\n'
    web = '[Unit]\nDescription=VPN Kit subscription HTTPS server\n' + common + '''
[Service]
Type=simple
ExecStartPre=/usr/sbin/nginx -t -c /etc/vpnkit/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/vpnkit/nginx.conf -g "daemon off;"
ExecReload=/usr/sbin/nginx -c /etc/vpnkit/nginx.conf -s reload
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''
    core = '[Unit]\nDescription=VPN Kit VLESS REALITY\n' + common + '''
[Service]
User=vpnkit
Group=vpnkit
ExecStartPre=/opt/vpnkit/bin/sing-box check -c /etc/vpnkit/sing-box.json
ExecStart=/opt/vpnkit/bin/sing-box run -c /etc/vpnkit/sing-box.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
[Install]
WantedBy=multi-user.target
'''
    renewal = '''[Unit]
Description=Renew VPN Kit short-lived IP certificate
After=network-online.target vpnkit-web.service
[Service]
Type=oneshot
ExecStart=/opt/vpnkit/certbot/bin/certbot renew --cert-name vpnkit-ip --quiet --no-random-sleep-on-renew
'''
    timer = '''[Unit]
Description=Check VPN Kit IP certificate every six hours
[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
'''
    for name, content in [('vpnkit-web.service', web), ('vpnkit.service', core),
                          ('vpnkit-renew.service', renewal), ('vpnkit-renew.timer', timer)]:
        atomic_write(Path('/etc/systemd/system') / name, content, 0o644)
    hook = '''#!/bin/sh
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/vpnkit-ip ] || exit 0
/usr/sbin/nginx -t -c /etc/vpnkit/nginx.conf
systemctl reload vpnkit-web.service
'''
    atomic_write('/etc/letsencrypt/renewal-hooks/deploy/vpnkit-reload', hook, 0o700)
    run(['systemctl', 'daemon-reload'])


def configure_firewall(with_monitor):
    ports = [80, 443, 8443] + ([8444] if with_monitor else [])
    if shutil.which('ufw') and 'Status: active' in run(['ufw', 'status'], check=False).stdout:
        for port in ports:
            run(['ufw', 'allow', f'{port}/tcp', 'comment', 'vpnkit'])
    if shutil.which('firewall-cmd') and run(['firewall-cmd', '--state'], check=False).returncode == 0:
        for port in ports:
            run(['firewall-cmd', '--add-port', f'{port}/tcp'])
            run(['firewall-cmd', '--permanent', '--add-port', f'{port}/tcp'])
    print('Cloud security group must allow TCP 80, 443, 8443' + (', 8444.' if with_monitor else '.'))


def issue_certificate(ip):
    run([APP / 'certbot/bin/certbot', 'certonly', '--non-interactive', '--agree-tos',
         '--register-unsafely-without-email', '--webroot', '-w', DATA / 'acme',
         '--preferred-challenges', 'http', '--required-profile', 'shortlived',
         '--cert-name', 'vpnkit-ip', '--ip-address', ip,
         '--renew-with-new-domains', '--keep-until-expiring', '--key-type', 'ecdsa'], timeout=600)


def local_addresses():
    addresses = []
    for interface in json.loads(run(['ip', '-j', 'address']).stdout):
        for address in interface.get('addr_info', []):
            ip = address.get('local')
            if ip and '%' not in ip:
                addresses.append(str(ipaddress.ip_address(ip)))
    return sorted(set(addresses))


def write_rendered(state, with_monitor, *, bootstrap=False):
    files = render(state, with_monitor=with_monitor)
    core_group = pwd.getpwnam('vpnkit').pw_gid
    web_group = pwd.getpwnam('www-data').pw_gid
    atomic_write(ETC / 'sing-box.json', files['sing-box.json'], 0o640, core_group)
    for name in ('clash.yaml', 'shadowrocket.txt'):
        atomic_write(DATA / 'subscriptions' / name, files[name], 0o640, web_group)
    atomic_write(ETC / 'urls.json', files['urls.json'])
    atomic_write(ETC / 'direct-vless.txt', files['direct-vless.txt'])
    if with_monitor:
        password_hash = run(['openssl', 'passwd', '-6', '-stdin'], input=state['monitor_password'] + '\n').stdout.strip()
        atomic_write(ETC / 'monitor.htpasswd', state['monitor_username'] + ':' + password_hash + '\n', 0o640, web_group)
        # nginx workers need directory traversal, while state/key files remain private.
        run(['setfacl', '-m', 'u:www-data:x', ETC]) if shutil.which('setfacl') else os.chmod(ETC, 0o751)
    atomic_write(ETC / 'nginx.conf', files['acme-nginx.conf' if bootstrap else 'nginx.conf'])


def check_configs():
    run([APP / 'bin/sing-box', 'check', '-c', ETC / 'sing-box.json'])
    run(['nginx', '-t', '-c', ETC / 'nginx.conf'])


def start_services():
    check_configs()
    for unit in ('vpnkit-web.service', 'vpnkit.service'):
        run(['systemctl', 'enable', unit])
        run(['systemctl', 'restart', unit])
    run(['systemctl', 'enable', '--now', 'vpnkit-renew.timer'])
    time.sleep(1)
    for unit in ('vpnkit-web.service', 'vpnkit.service'):
        run(['systemctl', 'is-active', '--quiet', unit])


def show_urls():
    state = load_state()
    with_monitor = load_install()['with_monitor']
    urls = json.loads(render(state, with_monitor=with_monitor)['urls.json'])
    lines = ['VPN Kit — private access information',
             json.dumps(urls, ensure_ascii=False, indent=2)]
    if with_monitor:
        lines += [f"Monitor username: {state['monitor_username']}", f"Monitor password: {state['monitor_password']}"]
    text = '\n'.join(lines) + '\n'
    atomic_write(ACCESS, text)
    print(text, end='')
    print(f'Saved with mode 0600: {ACCESS}')


def install(args):
    metadata_path = ETC / 'install.json'
    if getattr(args, 'coexist', False) or (metadata_path.is_file() and load_install().get('mode') == 'coexist'):
        from . import coexist
        return coexist.install(args)
    if any(getattr(args, field, None) is not None for field in
           ('tls_host', 'tls_cert', 'tls_key', 'nginx_binary', 'vpn_port',
            'subscription_port', 'monitor_port', 'api_port')):
        raise RuntimeError('External TLS and custom port options require --coexist')
    if not args.accept_acme_tos:
        raise RuntimeError("Add --accept-acme-tos to accept Let's Encrypt terms: https://letsencrypt.org/repository/")
    arch = preflight()
    owned = (ETC / 'state.json').is_file() and (ETC / 'install.json').is_file()
    if owned:
        state = load_state()
        metadata = load_install()
        if args.server_ip and public_ipv4(args.server_ip) != state['server_ip']:
            raise RuntimeError('IP differs from saved state. Use vpnkit update-ip --accept-acme-tos --server-ip IP.')
        if metadata.get('complete'):
            if args.with_monitor and not metadata['with_monitor']:
                raise RuntimeError('This installation was created without monitoring; use a fresh VPS for --with-monitor.')
            print('Existing installation preserved. Use vpnkit doctor to check it.')
            show_urls()
            return
        with_monitor = metadata['with_monitor']
    else:
        reserved = [ETC, APP, DATA, Path('/usr/local/bin/vpnkit'), CERT,
                    Path('/etc/letsencrypt/renewal/vpnkit-ip.conf'),
                    Path('/etc/letsencrypt/renewal-hooks/deploy/vpnkit-reload')]
        reserved += [Path('/etc/systemd/system') / unit for unit in
                     ('vpnkit.service', 'vpnkit-web.service', 'vpnkit-renew.service', 'vpnkit-renew.timer')]
        if any(path.exists() for path in reserved):
            raise RuntimeError('Unmanaged vpnkit paths already exist. Inspect them before retrying; nothing was overwritten.')
        try:
            pwd.getpwnam('vpnkit')
        except KeyError:
            pass
        else:
            raise RuntimeError('The reserved system account vpnkit already exists.')
        with_monitor = args.with_monitor
        check_ports(with_monitor)
        ip = public_ipv4(args.server_ip) if args.server_ip else detect_public_ip()
        # Validate caller values before any persistent mutation or network handshake.
        dummy_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        preview = new_state(ip, args.name, args.handshake_host, private_key=dummy_key, public_key=dummy_key)
        verify_handshake(preview['handshake_host'], ip)
        # Durable ownership marker permits safe recovery even if dependency installation fails.
        ETC.mkdir(mode=0o700, parents=True)
        state = preview
        metadata = {'with_monitor': with_monitor, 'complete': False, 'keys_created': False,
                    'nginx_installed_by_vpnkit': shutil.which('nginx') is None}
        save_json(ETC / 'state.json', state)
        save_json(ETC / 'install.json', metadata)
    print('Installing verified dependencies and services; existing credentials are preserved on retries.')
    APP.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(APP, 0o755)
    install_dependencies()
    make_directories()
    install_app()
    install_core(arch)
    if not metadata.get('keys_created'):
        values = {}
        for line in run([APP / 'bin/sing-box', 'generate', 'reality-keypair']).stdout.splitlines():
            key, value = line.split(':', 1)
            values[key.strip()] = value.strip()
        state['reality_private_key'] = values['PrivateKey']
        state['reality_public_key'] = values['PublicKey']
        metadata['keys_created'] = True
        save_json(ETC / 'state.json', state)
        save_json(ETC / 'install.json', metadata)
    state['local_addresses'] = local_addresses()
    save_json(ETC / 'state.json', state)
    if with_monitor:
        install_monitor()
    system_units()
    configure_firewall(with_monitor)
    write_rendered(state, with_monitor, bootstrap=True)
    run(['nginx', '-t', '-c', ETC / 'nginx.conf'])
    run(['systemctl', 'enable', '--now', 'vpnkit-web.service'])
    run(['systemctl', 'restart', 'vpnkit-web.service'])
    issue_certificate(state['server_ip'])
    write_rendered(state, with_monitor)
    start_services()
    metadata['complete'] = True
    save_json(ETC / 'install.json', metadata)
    show_urls()


def update_ip(args):
    if (ETC / 'install.json').is_file() and load_install().get('mode') == 'coexist':
        from . import coexist
        return coexist.update_ip(args)
    if not args.accept_acme_tos:
        raise RuntimeError('Add --accept-acme-tos to consent to certificate issuance.')
    preflight()
    state = load_state()
    metadata = load_install()
    if not metadata.get('complete'):
        raise RuntimeError('Finish installation first by re-running the original install command.')
    ip = public_ipv4(args.server_ip) if args.server_ip else detect_public_ip()
    verify_handshake(state['handshake_host'], ip)
    candidate = dict(state, server_ip=ip, local_addresses=local_addresses())
    render(candidate, with_monitor=metadata['with_monitor'])
    # ACME HTTP serves any Host; existing service keeps running during issuance.
    issue_certificate(ip)
    try:
        write_rendered(candidate, metadata['with_monitor'])
        start_services()
    except Exception:
        write_rendered(state, metadata['with_monitor'])
        run(['systemctl', 'restart', 'vpnkit-web.service', 'vpnkit.service'], check=False)
        raise RuntimeError('Config activation failed; previous configuration restored. Certificate may already use the new IP. Retry update-ip.')
    save_json(ETC / 'state.json', candidate)
    show_urls()
    print('Replace the subscription URL in both clients; credentials and path tokens remain unchanged.')


def status():
    if (ETC / 'install.json').is_file() and load_install().get('mode') == 'coexist':
        from . import coexist
        return coexist.status()
    for unit in ('vpnkit.service', 'vpnkit-web.service', 'vpnkit-renew.timer'):
        result = run(['systemctl', 'is-active', unit], check=False)
        print(f'{unit}: {result.stdout.strip()}')


def doctor():
    if (ETC / 'install.json').is_file() and load_install().get('mode') == 'coexist':
        from . import coexist
        return coexist.doctor()
    state = load_state()
    status()
    checks = []
    for unit in ('vpnkit.service', 'vpnkit-web.service', 'vpnkit-renew.timer'):
        checks.append((unit, run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0))
    for argv, label in [(['nginx', '-t', '-c', ETC / 'nginx.conf'], 'nginx config'),
                        ([APP / 'bin/sing-box', 'check', '-c', ETC / 'sing-box.json'], 'sing-box config'),
                        (['openssl', 'x509', '-in', CERT / 'fullchain.pem', '-noout', '-checkend', '86400'], 'certificate >24h')]:
        checks.append((label, run(argv, check=False).returncode == 0))
    # Some OpenSSL versions return exit 0 even when -checkip reports a mismatch.
    cert_info = ssl._ssl._test_decode_cert(str(CERT / 'fullchain.pem'))
    checks.append(('certificate IP matches', ('IP Address', state['server_ip']) in cert_info.get('subjectAltName', ())))
    for port in [80, 443, 8443] + ([8444] if load_install()['with_monitor'] else []):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=3):
                pass
            checks.append((f'TCP {port} listening locally', True))
        except OSError:
            checks.append((f'TCP {port} listening locally', False))
    for label, passed in checks:
        print(f'{"PASS" if passed else "FAIL"}: {label}')
    print('Local checks cannot prove reachability from your client network. Check cloud firewall and IP reachability if clients time out.')
    if not all(passed for _, passed in checks):
        raise RuntimeError('One or more health checks failed.')

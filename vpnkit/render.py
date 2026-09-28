"""Render a VPN deployment without reading files, networking, or changing state.

Only the server-side state and sing-box/nginx configuration contain private
credentials. All returned files must initially be written with restrictive
permissions; the installer can then make selected subscription files readable
by the web server.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from urllib.parse import quote, urlencode


_URL_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_RESERVED_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
_BLOCKED_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "::/0",
]
_READ_ONLY_API = {
    "version": "", "connections": "?interval=1000", "traffic": "",
    "memory": "", "logs": "?level=warning", "configs": "", "proxies": "",
    "rules": "", "providers/proxies": "", "providers/rules": "",
}


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _public_ipv4(value: object) -> str:
    value = _text(value, "server_ip")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("server_ip must be a public IPv4 address") from exc
    if (address.version != 4 or not address.is_global or address.is_multicast
            or address.is_reserved or address.is_unspecified):
        raise ValueError("server_ip must be a public IPv4 address")
    return str(address)


def _hostname(value: object) -> str:
    value = _text(value, "handshake_host")
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not _HOST_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("handshake_host must be a lowercase ASCII DNS hostname")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("handshake_host must be a DNS hostname, not an IP address")


def _name(value: object) -> str:
    value = _text(value, "name")
    if (not 1 <= len(value) <= 100 or value != value.strip()
            or value in _RESERVED_NAMES
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise ValueError("name must be 1–100 visible characters and not a reserved proxy name")
    return value


def _token(value: object, field: str) -> str:
    value = _text(value, field)
    if not _URL_TOKEN.fullmatch(value):
        raise ValueError(f"{field} must encode 32 bytes as unpadded URL-safe base64")
    raw = base64.urlsafe_b64decode(value + "=")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError(f"{field} must be canonical unpadded URL-safe base64")
    return value


def _uuid(value: object) -> str:
    value = _text(value, "uuid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ValueError("uuid must be a UUID") from exc
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("uuid must be a canonical non-zero UUID")
    return value


def _local_addresses(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("local_addresses must be a list of IPv4 or IPv6 addresses")
    addresses = []
    for address in value:
        try:
            parsed = ipaddress.ip_address(_text(address, "local_addresses entry"))
        except ValueError as exc:
            raise ValueError("local_addresses contains an invalid IP address") from exc
        # Zone suffixes are not CIDR syntax and are unnecessary for rejection.
        if "%" in str(parsed):
            raise ValueError("local_addresses must not contain IPv6 zone suffixes")
        canonical = str(parsed)
        if canonical not in addresses:
            addresses.append(canonical)
    return addresses


def validate_state(state: Mapping) -> dict:
    """Return validated canonical fields; never mutate the supplied state."""
    if not isinstance(state, Mapping):
        raise ValueError("state must be a mapping")
    if type(state.get("schema_version")) is not int or state["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    required = (
        "server_ip", "name", "handshake_host", "uuid", "reality_private_key",
        "reality_public_key", "short_id", "clash_token", "sr_token",
        "monitor_username", "monitor_password", "api_secret",
    )
    if any(field not in state for field in required):
        raise ValueError("state is missing required fields")
    clean = {"schema_version": 1}
    clean["server_ip"] = _public_ipv4(state["server_ip"])
    clean["name"] = _name(state["name"])
    clean["handshake_host"] = _hostname(state["handshake_host"])
    clean["uuid"] = _uuid(state["uuid"])
    for field in ("reality_private_key", "reality_public_key", "clash_token", "sr_token", "api_secret"):
        clean[field] = _token(state[field], field)
    short_id = _text(state["short_id"], "short_id")
    if not re.fullmatch(r"[0-9a-f]{16}", short_id):
        raise ValueError("short_id must contain exactly 16 lowercase hexadecimal characters")
    clean["short_id"] = short_id
    username = _text(state["monitor_username"], "monitor_username")
    if not _USERNAME.fullmatch(username):
        raise ValueError("monitor_username contains unsupported characters")
    password = _text(state["monitor_password"], "monitor_password")
    if not 8 <= len(password) <= 128 or any(not 32 <= ord(c) < 127 for c in password):
        raise ValueError("monitor_password must be 8–128 printable ASCII characters")
    clean["monitor_username"] = username
    clean["monitor_password"] = password
    clean["local_addresses"] = _local_addresses(state.get("local_addresses", []))
    return clean


def new_state(
    server_ip: str, name: str = "My-VPN", handshake_host: str = "dl.google.com",
    *, private_key: str, public_key: str, uuid_value: str | None = None,
    local_addresses: Sequence[str] | None = None,
) -> dict:
    """Create deployment credentials once. Preserve this state on every rerun.

    X25519 keys are generated by sing-box outside this dependency-free module.
    To move a deployment, update ``server_ip`` (and ``local_addresses``) in the
    existing state instead of creating new credentials.
    """
    return validate_state({
        "schema_version": 1, "server_ip": server_ip, "name": name,
        "handshake_host": handshake_host, "uuid": str(uuid.uuid4()) if uuid_value is None else uuid_value,
        "reality_private_key": private_key, "reality_public_key": public_key,
        "short_id": secrets.token_hex(8), "clash_token": secrets.token_urlsafe(32),
        "sr_token": secrets.token_urlsafe(32), "api_secret": secrets.token_urlsafe(32),
        "monitor_username": "admin", "monitor_password": secrets.token_urlsafe(24),
        "local_addresses": [] if local_addresses is None else list(local_addresses),
    })


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _sing_box(state: dict, with_monitor: bool) -> dict:
    reject_addresses = list(_BLOCKED_NETWORKS)
    for address in [state["server_ip"], *state["local_addresses"]]:
        parsed = ipaddress.ip_address(address)
        cidr = f"{parsed}/{parsed.max_prefixlen}"
        if cidr not in reject_addresses:
            reject_addresses.append(cidr)
    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [{
            "type": "vless", "tag": "vless-reality", "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [{"name": "owner", "uuid": state["uuid"], "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True, "server_name": state["handshake_host"],
                "reality": {
                    "enabled": True,
                    "handshake": {"server": state["handshake_host"], "server_port": 443},
                    "private_key": state["reality_private_key"], "short_id": [state["short_id"]],
                },
            },
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"action": "resolve", "strategy": "ipv4_only"},
                {"ip_is_private": True, "action": "reject"},
                {"ip_cidr": reject_addresses, "action": "reject"},
            ],
            "default_domain_resolver": "local", "final": "direct",
        },
    }
    if with_monitor:
        config["experimental"] = {"clash_api": {
            "external_controller": "127.0.0.1:19090", "secret": state["api_secret"],
            "access_control_allow_origin": [f'https://{state["server_ip"]}:8444'],
        }}
    return config


def _clash(state: dict) -> dict:
    group_name = "VPN" if state["name"] != "VPN" else "VPN-GROUP"
    return {
        "mixed-port": 7890, "bind-address": "127.0.0.1", "allow-lan": False,
        "mode": "rule", "log-level": "info",
        "ipv6": False,
        "dns": {
            "enable": True, "ipv6": False, "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16", "respect-rules": True,
            "nameserver": ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"],
            "proxy-server-nameserver": ["https://1.1.1.1/dns-query"],
        },
        "proxies": [{
            "name": state["name"], "type": "vless", "server": state["server_ip"],
            "port": 443, "uuid": state["uuid"], "network": "tcp", "tls": True,
            "udp": True, "packet-encoding": "xudp", "flow": "xtls-rprx-vision",
            "servername": state["handshake_host"], "client-fingerprint": "chrome",
            "reality-opts": {
                "public-key": state["reality_public_key"], "short-id": state["short_id"],
            },
        }],
        "proxy-groups": [{"name": group_name, "type": "select", "proxies": [state["name"]]}],
        "rules": [
            f'IP-CIDR,{state["server_ip"]}/32,DIRECT,no-resolve',
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve", f"MATCH,{group_name}",
        ],
    }


def _vless(state: dict) -> str:
    parameters = urlencode({
        "type": "tcp", "encryption": "none", "flow": "xtls-rprx-vision",
        "security": "reality", "sni": state["handshake_host"], "fp": "chrome",
        "pbk": state["reality_public_key"], "sid": state["short_id"], "spx": "/",
    }, quote_via=quote)
    return f'vless://{state["uuid"]}@{state["server_ip"]}:443?{parameters}#{quote(state["name"], safe="")}'


def _nginx_prefix() -> str:
    return """# Managed by vpnkit. This is an independent nginx configuration.
user www-data;
worker_processes auto;
pid /run/vpnkit-nginx.pid;
error_log /dev/null crit;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    sendfile on;
    client_max_body_size 1k;
    map $http_upgrade $vpnkit_connection_upgrade {
        default upgrade;
        '' close;
    }
"""


def _nginx_acme() -> str:
    return """    server {
        listen 80 default_server;
        server_name _;
        if ($request_method !~ ^(GET|HEAD)$) { return 405; }
        location ^~ /.well-known/acme-challenge/ {
            root /var/lib/vpnkit/acme;
            default_type text/plain;
            try_files $uri =404;
        }
        location / { return 404; }
    }
"""


def _nginx_tls(state: dict, port: int) -> str:
    return f"""    server {{
        listen {port} ssl;
        server_name {state['server_ip']};
        ssl_certificate /etc/letsencrypt/live/vpnkit-ip/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/vpnkit-ip/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:VPNKIT:1m;
        ssl_session_timeout 10m;
        ssl_session_tickets off;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        if ($request_method != GET) {{ return 405; }}
"""


def _nginx(state: dict, with_monitor: bool) -> str:
    output = _nginx_prefix()
    if with_monitor:
        # Basic credentials can be cached by a browser. Explicitly reject
        # cross-origin websocket handshakes rather than relying on CORS alone.
        output += f"""    map $http_origin $vpnkit_monitor_origin_allowed {{
        default 0;
        '' 1;
        'https://{state['server_ip']}:8444' 1;
    }}
"""
    output += _nginx_acme() + _nginx_tls(state, 8443)
    for token, url_filename, disk_filename in (
        (state["clash_token"], "clash.yaml", "clash.yaml"),
        (state["sr_token"], "shadowrocket", "shadowrocket.txt"),
    ):
        output += f"""        location = /sub/{token}/{url_filename} {{
            alias /var/lib/vpnkit/subscriptions/{disk_filename};
            default_type text/plain;
        }}
"""
    output += "        location / { return 404; }\n    }\n"
    if with_monitor:
        output += _nginx_tls(state, 8444)
        output += """        auth_basic "VPN Monitor";
        auth_basic_user_file /etc/vpnkit/monitor.htpasswd;
        if ($vpnkit_monitor_origin_allowed = 0) { return 403; }
        root /var/lib/vpnkit/monitor;
        index index.html;
        location = /online { try_files /online.html =404; }
"""
        for endpoint, fixed_query in _READ_ONLY_API.items():
            # A literal ? removes every user-supplied query string on routes
            # without parameters. Connections/logs get safe constant parameters.
            query = fixed_query or "?"
            output += f"""        location = /api/{endpoint} {{
            proxy_pass http://127.0.0.1:19090/{endpoint}{query};
            proxy_http_version 1.1;
            proxy_set_header Host 127.0.0.1;
            proxy_set_header Authorization "Bearer {state['api_secret']}";
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $vpnkit_connection_upgrade;
            proxy_buffering off;
            proxy_read_timeout 1h;
            proxy_hide_header Access-Control-Allow-Origin;
            proxy_hide_header Access-Control-Allow-Credentials;
        }}
"""
        output += """        location = /api { return 404; }
        location /api/ { return 404; }
        location ~ /\\. { return 404; }
        location / { try_files $uri $uri/ /index.html; }
    }
"""
    return output + "}\n"


def render(state: Mapping, with_monitor: bool = False) -> dict[str, str]:
    """Render relative filename -> text. JSON ``clash.yaml`` is valid YAML 1.2."""
    if type(with_monitor) is not bool:
        raise ValueError("with_monitor must be a boolean")
    clean = validate_state(state)
    direct_vless = _vless(clean)
    urls = {
        "clash": f'https://{clean["server_ip"]}:8443/sub/{clean["clash_token"]}/clash.yaml',
        "shadowrocket": f'https://{clean["server_ip"]}:8443/sub/{clean["sr_token"]}/shadowrocket',
        "direct_vless": direct_vless,
    }
    if with_monitor:
        urls["monitor"] = f'https://{clean["server_ip"]}:8444/online'
    return {
        "sing-box.json": _json(_sing_box(clean, with_monitor)),
        "clash.yaml": _json(_clash(clean)),
        "shadowrocket.txt": base64.b64encode((direct_vless + "\n").encode()).decode() + "\n",
        "direct-vless.txt": direct_vless + "\n", "urls.json": _json(urls),
        "nginx.conf": _nginx(clean, with_monitor),
        "acme-nginx.conf": _nginx_prefix() + _nginx_acme() + "}\n",
    }

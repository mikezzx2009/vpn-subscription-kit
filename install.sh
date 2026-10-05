#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
# /etc/os-release defines VERSION too; keep the package version separate.
readonly VPNKIT_RELEASE_VERSION='1.1.0'
APP_SHA256='e489aaa78c4750607def4a7b834dff912ff6f7e07c5eb79a3eac611adba7cdc3'

for arg in "$@"; do
  if [[ "$arg" == '--help' || "$arg" == '-h' ]]; then
    cat <<'HELP'
VPN Subscription Kit — one-command VLESS REALITY deployment

Usage: sudo bash install.sh --accept-acme-tos [standalone options]
       sudo bash install.sh --coexist --tls-host HOST --tls-cert PATH --tls-key PATH [options]
  --accept-acme-tos         Accept Let's Encrypt certificate service terms
  --server-ip PUBLIC_IPV4   Override automatic public IPv4 detection
  --name NAME              Client node name (default: My-VPN)
  --handshake-host HOST     TLS 1.3 + HTTP/2 host (default: dl.google.com)
  --with-monitor           Install a password-protected read-only monitoring UI
  --coexist                Preserve existing services; require externally renewed TLS
  --tls-host HOST          Subscription DNS hostname for coexist mode
  --tls-cert PATH          Existing full certificate chain (read only)
  --tls-key PATH           Existing matching private key (read only)
  --nginx-binary PATH      Existing nginx executable (defaults to PATH lookup)
  --vpn-port PORT          Coexist VPN port (default 24443)
  --subscription-port PORT Coexist HTTPS subscription port (default 28443)
  --monitor-port PORT      Coexist monitoring port (default 28444)
  --api-port PORT          Coexist local API port (default 29090)

Supported: Ubuntu 22.04/24.04, Debian 12/13, amd64/arm64, systemd.
Standalone requires public IPv4 and TCP 80, 443, 8443 (8444 for monitoring).
Coexist defaults to TCP 24443, 28443 (28444 for monitoring), requires existing
dependencies and trusted externally renewed TLS. It does not manage firewall rules.
After install: sudo vpnkit urls | status | doctor
After replacing IP: sudo vpnkit update-ip --accept-acme-tos
Terms: https://letsencrypt.org/repository/
HELP
    exit 0
  fi
done

[[ "$EUID" -eq 0 ]] || { echo 'Run with sudo or as root.' >&2; exit 1; }
consent=false
coexist=false
for arg in "$@"; do
  [[ "$arg" != '--accept-acme-tos' ]] || consent=true
  [[ "$arg" != '--coexist' ]] || coexist=true
done
[[ "$consent" == true || "$coexist" == true ]] || { echo 'Explicit --accept-acme-tos is required for standalone mode. See --help.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A systemd Linux VPS is required.' >&2; exit 1; }
# /etc/os-release is an operating-system supplied shell fragment.
# shellcheck source=/dev/null
source /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
  *) echo 'Supported: Ubuntu 22.04/24.04 and Debian 12/13.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo 'Supported architectures: amd64 and arm64.' >&2; exit 1 ;;
esac
command -v curl >/dev/null || { echo 'Install curl first.' >&2; exit 1; }
if ! command -v python3 >/dev/null; then
  [[ "$coexist" == false ]] || { echo 'Coexist mode requires an existing python3; no packages were installed.' >&2; exit 1; }
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
umask 077
workspace=$(mktemp -d /tmp/vpnkit-install.XXXXXXXX)
trap 'rm -rf -- "$workspace"' EXIT
archive="$workspace/vpnkit.tar.gz"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 300 \
  --proto '=https' --tlsv1.2 \
  "https://github.com/mikezzx2009/vpn-subscription-kit/releases/download/v${VPNKIT_RELEASE_VERSION}/vpnkit-v${VPNKIT_RELEASE_VERSION}.tar.gz" \
  -o "$archive"
printf '%s  %s\n' "$APP_SHA256" "$archive" | sha256sum --check --status || {
  echo 'Installer archive checksum mismatch; stopped.' >&2; exit 1;
}
tar --extract --gzip --file "$archive" --directory "$workspace" --no-same-owner
cd "$workspace"
exec_args=(python3 -m vpnkit install "$@")
"${exec_args[@]}"

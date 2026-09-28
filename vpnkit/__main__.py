"""Command line entry point; no work happens at import time."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="VPN Subscription Kit: VLESS REALITY + HTTPS subscriptions")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("install", help="Install on a fresh supported VPS; reruns preserve credentials")
    setup.add_argument("--accept-acme-tos", action="store_true", help="Accept Let's Encrypt ACME terms")
    setup.add_argument("--server-ip", help="Public IPv4; otherwise automatically detected")
    setup.add_argument("--name", default="My-VPN")
    setup.add_argument("--handshake-host", default="dl.google.com")
    setup.add_argument("--with-monitor", action="store_true")
    update = commands.add_parser("update-ip", help="Refresh certificate and subscriptions after replacing the public IP")
    update.add_argument("--accept-acme-tos", action="store_true")
    update.add_argument("--server-ip")
    commands.add_parser("urls", help="Show private subscription URLs and optional monitoring credentials")
    commands.add_parser("status", help="Show service status without credentials")
    commands.add_parser("doctor", help="Check local services, certificate, ports and renewal timer")
    args = parser.parse_args()
    from . import system
    try:
        system.require_root()
        with system.operation_lock():
            {"install": system.install, "update-ip": system.update_ip,
             "urls": lambda _: system.show_urls(), "status": lambda _: system.status(),
             "doctor": lambda _: system.doctor()}[args.command](args)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"vpnkit: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

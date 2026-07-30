#!/usr/bin/env python3

"""Notify MyDNS.JP of the relay's public IPv4 address."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request


CONFIG_DIRECTORY = Path("/etc/mydns-notify")
CONFIG_PATH = CONFIG_DIRECTORY / "config.json"
NOTIFY_ENDPOINT = "https://ipv4.mydns.jp/login.html"
SUCCESS_MARKERS = (
    "Login and IP address notify OK.",
    "login_status = 1.",
)
CHILD_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class MyDNSNotifyError(RuntimeError):
    """Raised for expected configuration and notification failures."""


def require_root() -> None:
    if os.geteuid() != 0:
        raise MyDNSNotifyError("run this command through sudo")


def validate_hostname(value: str) -> str:
    hostname = value.strip().rstrip(".").lower()
    if not hostname or len(hostname) > 253:
        raise MyDNSNotifyError("hostname must contain between 1 and 253 characters")

    labels = hostname.split(".")
    if len(labels) < 2 or any(not DNS_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise MyDNSNotifyError("hostname must be a valid fully qualified DNS name")
    return hostname


def validate_child_id(value: str) -> str:
    child_id = value.strip()
    if not CHILD_ID_PATTERN.fullmatch(child_id):
        raise MyDNSNotifyError(
            "Child ID must contain only letters, numbers, dots, underscores, or hyphens"
        )
    return child_id


def validate_password(value: str) -> str:
    if not value:
        raise MyDNSNotifyError("Child ID password must not be empty")
    if "\r" in value or "\n" in value:
        raise MyDNSNotifyError("Child ID password must not contain a newline")
    if len(value) > 1024:
        raise MyDNSNotifyError("Child ID password is unexpectedly long")
    return value


def validate_config_permissions(path: Path) -> None:
    file_stat = path.stat()
    file_mode = stat.S_IMODE(file_stat.st_mode)
    if file_mode & 0o077:
        raise MyDNSNotifyError(f"{path} must not be readable or writable by group or others")
    if os.geteuid() == 0 and file_stat.st_uid != 0:
        raise MyDNSNotifyError(f"{path} must be owned by root")


def normalize_config(raw_config: object) -> dict[str, str]:
    if not isinstance(raw_config, dict):
        raise MyDNSNotifyError("configuration must be a JSON object")

    try:
        hostname = validate_hostname(str(raw_config["hostname"]))
        child_id = validate_child_id(str(raw_config["child_id"]))
        password = validate_password(str(raw_config["password"]))
    except KeyError as exc:
        raise MyDNSNotifyError(f"configuration is missing {exc.args[0]}") from exc

    return {
        "hostname": hostname,
        "child_id": child_id,
        "password": password,
    }


def load_config() -> dict[str, str]:
    if not CONFIG_PATH.is_file():
        raise MyDNSNotifyError(
            f"configuration not found: run mydns-notify configure --hostname HOSTNAME first"
        )

    validate_config_permissions(CONFIG_PATH)
    try:
        raw_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MyDNSNotifyError(f"could not read {CONFIG_PATH}: {exc}") from exc
    return normalize_config(raw_config)


def write_config(config: dict[str, str]) -> None:
    require_root()
    CONFIG_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG_DIRECTORY, 0o700)

    temporary_path: Path | None = None
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=".config.",
        suffix=".json",
        dir=CONFIG_DIRECTORY,
        text=True,
    )
    try:
        temporary_path = Path(temporary_name)
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
            json.dump(config, output_file, ensure_ascii=True, sort_keys=True)
            output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, CONFIG_PATH)
        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        try:
            os.close(file_descriptor)
        except OSError:
            pass
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def build_request(config: dict[str, str]) -> urllib.request.Request:
    credentials = f"{config['child_id']}:{config['password']}".encode("utf-8")
    authorization = base64.b64encode(credentials).decode("ascii")
    return urllib.request.Request(
        NOTIFY_ENDPOINT,
        headers={
            "Authorization": f"Basic {authorization}",
            "User-Agent": "on-premises-with-vps-mydns-notify/1.0",
        },
        method="GET",
    )


def notification_succeeded(response_body: str) -> bool:
    return all(marker in response_body for marker in SUCCESS_MARKERS)


def notify(config: dict[str, str]) -> None:
    request = build_request(config)
    try:
        with urllib.request.urlopen(
            request,
            context=ssl.create_default_context(),
            timeout=30,
        ) as response:
            response_body = response.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise MyDNSNotifyError(f"MyDNS.JP returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise MyDNSNotifyError(f"could not reach MyDNS.JP: {exc.reason}") from exc
    except TimeoutError as exc:
        raise MyDNSNotifyError("MyDNS.JP notification timed out") from exc

    if not notification_succeeded(response_body):
        raise MyDNSNotifyError(
            "MyDNS.JP did not return its success marker; check the Child ID and password"
        )

    print(f"MyDNS.JP IPv4 notification succeeded for {config['hostname']}")


def configure(hostname: str) -> None:
    require_root()
    normalized_hostname = validate_hostname(hostname)
    if not sys.stdin.isatty():
        raise MyDNSNotifyError("configure requires an interactive terminal")

    child_id = validate_child_id(input("MyDNS.JP Child ID: "))
    password = validate_password(getpass.getpass("MyDNS.JP Child ID password: "))
    write_config(
        {
            "hostname": normalized_hostname,
            "child_id": child_id,
            "password": password,
        }
    )
    print(f"Saved root-only configuration for {normalized_hostname}")


def show() -> None:
    config = load_config()
    print(f"Configured hostname: {config['hostname']}")
    print(f"Credential file: {CONFIG_PATH} (root-only)")
    try:
        addresses = sorted(
            {
                result[4][0]
                for result in socket.getaddrinfo(
                    config["hostname"],
                    None,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                )
            }
        )
    except socket.gaierror:
        addresses = []

    if addresses:
        print(f"Current public A record: {', '.join(addresses)}")
    else:
        print("Current public A record: not resolved")


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure and run MyDNS.JP IPv4 notifications.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    configure_parser = subparsers.add_parser(
        "configure",
        help="store a Child ID and password in a root-only file",
    )
    configure_parser.add_argument("--hostname", required=True)
    subparsers.add_parser("notify", help="send the current public IPv4 address to MyDNS.JP")
    subparsers.add_parser("show", help="show non-secret configuration and DNS resolution")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv if argv is not None else sys.argv[1:])
    try:
        if arguments.command == "configure":
            configure(arguments.hostname)
        elif arguments.command == "notify":
            require_root()
            notify(load_config())
        elif arguments.command == "show":
            require_root()
            show()
        else:
            raise MyDNSNotifyError(f"unsupported command: {arguments.command}")
    except MyDNSNotifyError as exc:
        print(f"mydns-notify: ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse


class CliError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        target: str | None = None,
        retryable: bool = False,
        exit_code: int = 1,
        details: object | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.target = target
        self.retryable = retryable
        self.exit_code = exit_code
        self.details = details


class RelayClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        ca_file: str | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise CliError(
                "configuration_error",
                "RELAY_DASHBOARD_URL must be an HTTP(S) origin without credentials or a path",
                target="RELAY_DASHBOARD_URL",
                exit_code=3,
            )
        if not username or not password:
            raise CliError(
                "configuration_error",
                "RELAY_DASHBOARD_USERNAME and RELAY_DASHBOARD_PASSWORD are required",
                target="authentication",
                exit_code=3,
            )
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.authorization = f"Basic {credentials}"
        self.context = (
            ssl.create_default_context(cafile=ca_file)
            if parsed.scheme == "https"
            else None
        )

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> object:
        headers = {
            "Accept": "application/json",
            "Authorization": self.authorization,
        }
        if method != "GET":
            state = self.request("/api/state")
            if not isinstance(state, dict) or not isinstance(state.get("csrf_token"), str):
                raise CliError(
                    "invalid_response",
                    "API state did not include a CSRF token",
                    target="/api/state",
                    retryable=True,
                    exit_code=5,
                )
            headers["X-Relay-CSRF"] = state["csrf_token"]
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, ensure_ascii=False).encode()
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=data,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.context) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                raw = error.read()
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {"message": str(error.reason)}
            finally:
                error.close()
            retryable = error.code in {408, 425, 429} or error.code >= 500
            raise CliError(
                "api_error",
                str(payload.get("message") or f"HTTP {error.code}"),
                target=path,
                retryable=retryable,
                exit_code=5 if retryable else 6,
                details={"status": error.code, "response": payload},
            ) from error
        except (OSError, urllib.error.URLError) as error:
            raise CliError(
                "network_error",
                str(getattr(error, "reason", error)),
                target=self.base_url,
                retryable=True,
                exit_code=5,
            ) from error


def input_object(path: str) -> dict[str, object]:
    try:
        raw = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CliError(
            "input_error",
            f"JSON input could not be read: {error}",
            target=path,
            exit_code=4,
        ) from error
    if not isinstance(value, dict):
        raise CliError(
            "input_error",
            "JSON input must be an object",
            target=path,
            exit_code=4,
        )
    return value


def require_change_confirmation(
    client: RelayClient,
    confirmation: str | None,
    idempotency_key: str | None,
) -> str:
    if confirmation != client.base_url:
        raise CliError(
            "confirmation_required",
            f"real changes require --confirm {client.base_url}",
            target=client.base_url,
            exit_code=4,
        )
    if not idempotency_key:
        raise CliError(
            "idempotency_key_required",
            "real changes require --idempotency-key or RELAY_IDEMPOTENCY_KEY",
            target=client.base_url,
            exit_code=4,
        )
    return idempotency_key


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="relay-dashboard-cli",
        description="OCI Relay Controlの認証済みAPIを非対話で安全に操作します。",
        epilog=(
            "例: python3 -m dashboard.cli --json route create --input route.json --dry-run\n"
            "    python3 -m dashboard.cli --json apply --confirm http://127.0.0.1:8080 "
            "--idempotency-key apply-20260803-01"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    result.add_argument("--json", action="store_true", help="1行JSONで出力")
    result.add_argument(
        "--url",
        default=os.environ.get("RELAY_DASHBOARD_URL", "http://127.0.0.1:8080"),
        help="API Origin（既定: RELAY_DASHBOARD_URLまたはコンテナ内localhost）",
    )
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("state", "preflight", "routes", "web-routes", "wireguard"):
        commands.add_parser(name)

    route = commands.add_parser("route")
    route_commands = route.add_subparsers(dest="route_command", required=True)
    create = route_commands.add_parser("create")
    create.add_argument("--input", required=True, help="JSONファイル、または標準入力は-")
    create.add_argument("--dry-run", action="store_true")
    create.add_argument("--confirm")
    create.add_argument("--idempotency-key")

    plan = commands.add_parser("plan")
    plan.add_argument("--idempotency-key")
    for name in ("apply", "sync"):
        mutation = commands.add_parser(name)
        mutation.add_argument("--confirm")
        mutation.add_argument("--idempotency-key")
    return result


def run(arguments: argparse.Namespace, client: RelayClient) -> object:
    read_paths = {
        "state": "/api/state",
        "preflight": "/api/preflight",
        "routes": "/api/state",
        "web-routes": "/api/web-routes",
        "wireguard": "/api/wireguard",
    }
    if arguments.command in read_paths:
        value = client.request(read_paths[arguments.command])
        if arguments.command == "routes" and isinstance(value, dict):
            return {"routes": value.get("routes", []), "groups": value.get("groups", [])}
        return value
    if arguments.command == "route" and arguments.route_command == "create":
        body = input_object(arguments.input)
        if arguments.dry_run:
            if arguments.confirm or arguments.idempotency_key:
                raise CliError(
                    "usage_error",
                    "--dry-run cannot be combined with change confirmation",
                    target="route create",
                    exit_code=2,
                )
            return client.request("/api/routes/validate", method="POST", body=body)
        key = require_change_confirmation(
            client,
            arguments.confirm,
            arguments.idempotency_key or os.environ.get("RELAY_IDEMPOTENCY_KEY"),
        )
        return client.request(
            "/api/routes",
            method="POST",
            body=body,
            idempotency_key=key,
        )
    if arguments.command == "plan":
        return client.request(
            "/api/plan",
            method="POST",
            body={},
            idempotency_key=arguments.idempotency_key,
        )
    if arguments.command in {"apply", "sync"}:
        key = require_change_confirmation(
            client,
            arguments.confirm,
            arguments.idempotency_key or os.environ.get("RELAY_IDEMPOTENCY_KEY"),
        )
        confirmation = "APPLY" if arguments.command == "apply" else "SYNC"
        return client.request(
            f"/api/{quote(arguments.command)}",
            method="POST",
            body={"confirmation": confirmation},
            idempotency_key=key,
        )
    raise CliError("usage_error", "unsupported command", exit_code=2)


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    client = RelayClient(
        arguments.url,
        os.environ.get("RELAY_DASHBOARD_USERNAME")
        or os.environ.get("DASHBOARD_USERNAME", ""),
        os.environ.get("RELAY_DASHBOARD_PASSWORD")
        or os.environ.get("DASHBOARD_PASSWORD", ""),
        os.environ.get("RELAY_DASHBOARD_CA_CERT"),
    )
    value = run(arguments, client)
    print(json.dumps(value, ensure_ascii=False, indent=None if arguments.json else 2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CliError as error:
        print(
            json.dumps(
                {
                    "error": {
                        "code": error.code,
                        "message": str(error),
                        "target": error.target,
                        "retryable": error.retryable,
                        "details": error.details,
                    }
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(error.exit_code) from error

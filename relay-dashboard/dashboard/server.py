from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import threading
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from dashboard.core import (
    AuditLog,
    CommandError,
    ConflictError,
    DashboardError,
    IdempotencyStore,
    PeerAccessRule,
    RelayManager,
    Route,
    RouteStore,
    TerraformManager,
    ValidationError,
    WebRoute,
    WebRouteStore,
    hash_basic_auth_password,
    preflight_checks,
)


MAX_REQUEST_BYTES = 64 * 1024
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
IDEMPOTENT_ENDPOINTS = {
    ("POST", "/api/routes"),
    ("POST", "/api/plan"),
    ("POST", "/api/apply"),
    ("POST", "/api/sync"),
}


class AppContext:
    def __init__(self) -> None:
        self.username = require_environment("DASHBOARD_USERNAME")
        self.password = require_environment("DASHBOARD_PASSWORD")
        if (
            self.password in {"change-me", "replace-me", "password"}
            or self.password.startswith("replace-")
            or len(self.password) < 16
        ):
            raise RuntimeError("DASHBOARD_PASSWORD must be at least 16 characters and not a placeholder")
        if ":" in self.username:
            raise RuntimeError("DASHBOARD_USERNAME must not contain a colon")

        self.bind = os.environ.get("DASHBOARD_BIND", "0.0.0.0")
        self.port = int(os.environ.get("DASHBOARD_PORT", "8080"))
        self.data_dir = Path(os.environ.get("DASHBOARD_DATA_DIR", "/data"))
        self.workspace = Path(os.environ.get("TERRAFORM_WORKSPACE", "/workspace"))
        self.static_dir = Path(os.environ.get("DASHBOARD_STATIC_DIR", "/app/static"))
        self.relay_network = os.environ.get("RELAY_NETWORK", "10.99.0.0/24")
        self.relay_address = os.environ.get("RELAY_ADDRESS", "10.99.0.1")
        self.dashboard_target_address = os.environ.get(
            "DASHBOARD_WIREGUARD_TARGET",
            "10.99.0.2",
        )
        self.dashboard_external_port = int(
            os.environ.get("DASHBOARD_EXTERNAL_PORT", "41800")
        )
        if not 1 <= self.dashboard_external_port <= 65535:
            raise RuntimeError("DASHBOARD_EXTERNAL_PORT must be between 1 and 65535")
        relay_script = Path(
            os.environ.get("RELAY_SCRIPT", "/workspace/scripts/wg-relay.sh")
        )
        relay_ssh_host = os.environ.get("RELAY_SSH_HOST", "oci-relay")

        self.store = RouteStore(
            self.data_dir,
            relay_network=self.relay_network,
            relay_address=self.relay_address,
        )
        self.web_store = WebRouteStore(
            self.data_dir,
            Path(
                os.environ.get(
                    "TRAEFIK_DYNAMIC_CONFIG",
                    "/run/traefik-dynamic/ui-web-routes.yml",
                )
            ),
        )
        self.audit = AuditLog(self.data_dir)
        self.idempotency = IdempotencyStore(self.data_dir)
        self.relay = RelayManager(relay_script, relay_ssh_host)
        self.terraform = TerraformManager(self.workspace, self.data_dir)
        # A saved plan must not survive a container restart because its runtime
        # configuration workspace is ephemeral.
        self.terraform.invalidate_plan()
        self.operation_lock = threading.Lock()
        self.csrf_token = secrets.token_urlsafe(32)

    def route_from_payload(self, payload: dict[str, object]) -> Route:
        return Route.from_mapping(
            payload,
            relay_network=self.relay_network,
            relay_address=self.relay_address,
        )

    @staticmethod
    def web_route_from_payload(
        payload: dict[str, object],
        existing: WebRoute | None = None,
    ) -> tuple[WebRoute, dict[str, str] | None]:
        mapping = dict(payload)
        enabled_value = payload.get(
            "basic_auth_enabled",
            existing.basic_auth_enabled if existing else False,
        )
        rotate_value = payload.get("rotate_basic_auth", False)
        if not isinstance(enabled_value, bool):
            raise ValidationError("Basic認証の有効状態はtrueまたはfalseで指定してください。")
        if not isinstance(rotate_value, bool):
            raise ValidationError("Basic認証の再生成状態はtrueまたはfalseで指定してください。")
        mapping.pop("basic_auth_enabled", None)
        mapping.pop("rotate_basic_auth", None)

        one_time_credentials: dict[str, str] | None = None
        if enabled_value:
            username = str(
                payload.get(
                    "basic_auth_username",
                    existing.basic_auth_username if existing else mapping.get("name", ""),
                )
            ).strip()
            password_hash = (
                existing.basic_auth_password_hash
                if existing and existing.basic_auth_enabled
                else ""
            )
            if (
                not password_hash
                or rotate_value
                or (
                    existing is not None
                    and username != existing.basic_auth_username
                )
            ):
                password = secrets.token_urlsafe(32)
                password_hash = hash_basic_auth_password(password)
                one_time_credentials = {
                    "username": username,
                    "password": password,
                }
            mapping["basic_auth_username"] = username
            mapping["basic_auth_password_hash"] = password_hash
        else:
            mapping["basic_auth_username"] = ""
            mapping["basic_auth_password_hash"] = ""
        return WebRoute.from_mapping(mapping), one_time_credentials

    def web_gateway_status(self) -> dict[str, object]:
        ports: dict[str, dict[str, object]] = {}
        views = self.store.views()
        for port in (80, 443):
            matching = next(
                (
                    route
                    for route in views
                    if (
                        route["deleted_at"] is None
                        and route["protocol"] == "tcp"
                        and route["public_port"] == port
                    )
                ),
                None,
            )
            if matching is None:
                ports[str(port)] = {"state": "missing", "label": "未登録"}
            elif (
                matching["target_address"] != self.dashboard_target_address
                or matching["target_port"] != port
            ):
                ports[str(port)] = {
                    "state": "conflict",
                    "label": "競合",
                    "target": (
                        f"{matching['target_address']}:{matching['target_port']}"
                    ),
                }
            elif (
                not matching["desired_enabled"]
                or matching["state"] == "pending_delete"
            ):
                ports[str(port)] = {
                    "state": "disabled",
                    "label": (
                        "削除待ち"
                        if matching["state"] == "pending_delete"
                        else "無効"
                    ),
                }
            elif matching["state"] == "enabled":
                ports[str(port)] = {"state": "ready", "label": "反映済み"}
            else:
                ports[str(port)] = {
                    "state": "pending",
                    "label": "Terraform未反映",
                }
        return {
            "target": self.dashboard_target_address,
            "ports": ports,
            "ready": all(item["state"] == "ready" for item in ports.values()),
            "staged": all(
                item["state"] in {"ready", "pending"} for item in ports.values()
            ),
        }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "RelayDashboard/1.0"

    @property
    def app(self) -> AppContext:
        return self.server.app  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_json({"status": "ok"})
            return
        if not self.authenticate():
            return

        if path == "/api/state":
            self.send_json(
                {
                    "routes": self.app.store.views(),
                    "groups": self.app.store.group_views(),
                    "web_routes": self.app.web_store.views(),
                    "web_routes_status": self.app.web_store.status(),
                    "web_gateway": self.app.web_gateway_status(),
                    "plan": self.app.terraform.load_plan_metadata(),
                    "audit": self.app.audit.recent(),
                    "busy": self.app.operation_lock.locked(),
                    "pending_relay": self.app.store.has_pending_relay(),
                    "csrf_token": self.app.csrf_token,
                }
            )
            return
        if path == "/api/preflight":
            checks = preflight_checks(
                self.app.workspace,
                self.app.data_dir,
                self.app.relay,
            )
            web_config_ok, web_config_detail = (
                self.app.web_store.config_target_status()
            )
            checks.append(
                {
                    "name": "Traefik動的設定",
                    "ok": web_config_ok,
                    "detail": web_config_detail,
                }
            )
            self.send_json({"checks": checks, "ok": all(check["ok"] for check in checks)})
            return
        if path == "/api/web-routes":
            self.send_web_store_state()
            return
        if path.startswith("/api/web-routes/"):
            record_id = unquote(path[len("/api/web-routes/") :])
            route = next(
                (
                    item
                    for item in self.app.web_store.views()
                    if item["id"] == record_id
                ),
                None,
            )
            if route is None:
                self.send_error_json(
                    HTTPStatus.NOT_FOUND,
                    f"Webルートが見つかりません: {record_id}",
                )
            else:
                self.send_json({"web_route": route})
            return
        if path == "/api/relay/status":
            try:
                actual = self.app.relay.list()
                applied = {route.remote_name: route for route in self.app.store.applied()}
                rows = []
                for name, route in sorted(actual.items()):
                    wanted = applied.get(name)
                    matches = bool(
                        wanted
                        and (
                            wanted.protocol,
                            wanted.public_port,
                            wanted.target_address,
                            wanted.target_port,
                        )
                        == route.signature
                    )
                    rows.append(
                        {
                            **asdict(route),
                            "managed_by_dashboard": name.startswith("ui-"),
                            "matches_desired": matches,
                        }
                    )
                self.send_json({"routes": rows})
            except DashboardError as exc:
                self.send_error_json(HTTPStatus.BAD_GATEWAY, str(exc), command_output(exc))
            return
        if path == "/api/wireguard":
            if not self.acquire_operation():
                return
            try:
                self.send_wireguard_state()
            except DashboardError as exc:
                self.send_error_json(
                    HTTPStatus.BAD_GATEWAY,
                    str(exc),
                    command_output(exc),
                )
            finally:
                self.app.operation_lock.release()
            return
        if path == "/" or path.startswith("/static/"):
            self.serve_static(path)
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "ページが見つかりません。")

    def do_POST(self) -> None:
        if not self.authenticate() or not self.validate_csrf():
            return
        path = urlparse(self.path).path
        try:
            payload = self.read_json()
            if not self.prepare_idempotency(path, payload):
                return
            if path == "/api/wireguard/peers":
                if not self.acquire_operation():
                    return
                try:
                    name, client_config = self.app.relay.create_peer(
                        payload.get("name"),
                        payload.get("address"),
                        self.app.relay_network,
                        self.app.relay_address,
                    )
                    self.app.audit.append("wireguard-peer-create", "success", name)
                    self.send_json(
                        {
                            "ok": True,
                            "message": f"WireGuard Peer「{name}」を追加しました。",
                            "filename": f"{name}.conf",
                            "client_config": client_config,
                        },
                        HTTPStatus.CREATED,
                    )
                finally:
                    self.app.operation_lock.release()
                return
            peer_prefix = "/api/wireguard/peers/"
            rotate_suffix = "/rotate"
            if path.startswith(peer_prefix) and path.endswith(rotate_suffix):
                if payload.get("confirmation") != "ROTATE":
                    raise ValidationError("鍵を更新するにはROTATEと入力してください。")
                if not self.acquire_operation():
                    return
                try:
                    name = unquote(path[len(peer_prefix) : -len(rotate_suffix)])
                    name, client_config = self.app.relay.rotate_peer(name)
                    self.app.audit.append("wireguard-peer-rotate", "success", name)
                    self.send_json(
                        {
                            "ok": True,
                            "message": f"WireGuard Peer「{name}」の鍵を更新しました。",
                            "filename": f"{name}.conf",
                            "client_config": client_config,
                        }
                    )
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/wireguard/access-rules":
                if not self.acquire_operation():
                    return
                try:
                    rule = PeerAccessRule.from_mapping(
                        payload,
                        self.app.relay_network,
                        self.app.relay_address,
                    )
                    self.app.relay.create_peer_access_rule(rule)
                    self.app.audit.append(
                        "wireguard-access-create",
                        "success",
                        rule.name,
                    )
                    self.send_json(
                        {
                            "ok": True,
                            "message": f"Peer間アクセス「{rule.name}」を追加しました。",
                        },
                        HTTPStatus.CREATED,
                    )
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/web-gateway/setup":
                if not self.acquire_operation():
                    return
                try:
                    staged = self.app.store.setup_web_gateway(
                        self.app.dashboard_target_address
                    )
                    self.app.terraform.invalidate_plan()
                    self.app.audit.append(
                        "web-gateway-setup",
                        "success",
                        ", ".join(
                            f"TCP/{record.route.public_port}" for record in staged
                        ),
                    )
                    self.send_store_state(HTTPStatus.CREATED)
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/web-routes":
                if not self.acquire_operation():
                    return
                try:
                    route, one_time_credentials = self.app.web_route_from_payload(
                        payload
                    )
                    self.app.web_store.create(
                        route,
                        desired_enabled=payload.get("desired_enabled", True),  # type: ignore[arg-type]
                    )
                    self.app.audit.append("web-route-create", "success", route.name)
                    self.send_web_store_state(
                        HTTPStatus.CREATED,
                        one_time_basic_auth=one_time_credentials,
                    )
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/web-routes/preview":
                if not self.acquire_operation():
                    return
                try:
                    preview = self.app.web_store.preview()
                    self.app.audit.append(
                        "web-route-preview",
                        "success",
                        json.dumps(preview["counts"], ensure_ascii=False),
                    )
                    self.send_json({"preview": preview})
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/web-routes/publish":
                if payload.get("confirmation") != "PUBLISH":
                    raise ValidationError(
                        "反映するには確認欄へPUBLISHと入力してください。"
                    )
                if not self.acquire_operation():
                    return
                try:
                    try:
                        result = self.app.web_store.publish()
                    except DashboardError as exc:
                        self.app.audit.append("web-route-publish", "error", str(exc))
                        raise
                    self.app.audit.append(
                        "web-route-publish",
                        "success",
                        (
                            "再反映" if result["recovered"] else "通常反映"
                        )
                        + f": {result['active_count']}件",
                    )
                    self.send_json(
                        {
                            "ok": True,
                            "message": (
                                "Webルートを再反映しました。"
                                if result["recovered"]
                                else "WebルートをTraefikへ反映しました。"
                            ),
                            **result,
                            "web_routes": self.app.web_store.views(),
                            "web_routes_status": self.app.web_store.status(),
                        }
                    )
                finally:
                    self.app.operation_lock.release()
                return
            web_route_prefix = "/api/web-routes/"
            web_cancel_suffix = "/cancel-delete"
            if (
                path.startswith(web_route_prefix)
                and path.endswith(web_cancel_suffix)
            ):
                if not self.acquire_operation():
                    return
                try:
                    record_id = unquote(
                        path[
                            len(web_route_prefix) : -len(web_cancel_suffix)
                        ]
                    )
                    restored = self.app.web_store.cancel_delete(record_id)
                    self.app.audit.append(
                        "web-route-delete-cancel",
                        "success",
                        restored.route.name,
                    )
                    self.send_web_store_state()
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/routes/validate":
                route = self.app.route_from_payload(payload)
                group_value = payload.get("group_id")
                group_id = str(group_value) if group_value else None
                summary = self.app.store.validate_create(
                    route,
                    group_id=group_id,
                    desired_enabled=payload.get("desired_enabled", True),  # type: ignore[arg-type]
                )
                self.send_json({"ok": True, "dry_run": True, "summary": summary})
                return
            if path == "/api/routes":
                if not self.acquire_operation():
                    return
                try:
                    route = self.app.route_from_payload(payload)
                    group_value = payload.get("group_id")
                    group_id = str(group_value) if group_value else None
                    self.app.store.create(
                        route,
                        group_id=group_id,
                        desired_enabled=payload.get("desired_enabled", True),  # type: ignore[arg-type]
                    )
                    self.app.terraform.invalidate_plan()
                    self.app.audit.append("route-create", "success", route.name)
                    self.send_store_state(HTTPStatus.CREATED)
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/groups":
                if not self.acquire_operation():
                    return
                try:
                    parent_value = payload.get("parent_id")
                    group = self.app.store.create_group(
                        payload.get("name"),
                        payload.get("description", ""),
                        payload.get("members", []),
                        parent_id=str(parent_value) if parent_value else None,
                    )
                    self.app.terraform.invalidate_plan()
                    self.app.audit.append("group-create", "success", group.name)
                    self.send_store_state(HTTPStatus.CREATED)
                finally:
                    self.app.operation_lock.release()
                return
            group_prefix = "/api/groups/"
            group_routes_suffix = "/routes"
            if path.startswith(group_prefix) and path.endswith(group_routes_suffix):
                if not self.acquire_operation():
                    return
                try:
                    group_id = unquote(
                        path[len(group_prefix) : -len(group_routes_suffix)]
                    )
                    created = self.app.store.add_group_routes(
                        group_id,
                        payload.get("members", []),
                    )
                    self.app.terraform.invalidate_plan()
                    self.app.audit.append(
                        "group-routes-create",
                        "success",
                        f"{group_id}: {len(created)}件",
                    )
                    self.send_store_state(HTTPStatus.CREATED)
                finally:
                    self.app.operation_lock.release()
                return
            route_prefix = "/api/routes/"
            cancel_suffix = "/cancel-delete"
            if path.startswith(route_prefix) and path.endswith(cancel_suffix):
                if not self.acquire_operation():
                    return
                try:
                    record_id = unquote(
                        path[len(route_prefix) : -len(cancel_suffix)]
                    )
                    restored = self.app.store.cancel_delete(record_id)
                    self.app.terraform.invalidate_plan()
                    self.app.audit.append(
                        "route-delete-cancel", "success", restored.route.name
                    )
                    self.send_store_state()
                finally:
                    self.app.operation_lock.release()
                return
            if path == "/api/plan":
                self.create_plan()
                return
            if path == "/api/apply":
                self.apply_plan(payload)
                return
            if path == "/api/sync":
                self.sync_relay(payload)
                return
            self.send_error_json(HTTPStatus.NOT_FOUND, "APIが見つかりません。")
        except (DashboardError, ValueError) as exc:
            self.send_error_json(error_status(exc), str(exc), command_output(exc))

    def do_PUT(self) -> None:
        if not self.authenticate() or not self.validate_csrf():
            return
        path = urlparse(self.path).path
        if not self.acquire_operation():
            return
        try:
            payload = self.read_json()
            access_prefix = "/api/wireguard/access-rules/"
            if path.startswith(access_prefix):
                name = unquote(path[len(access_prefix) :])
                rule = PeerAccessRule.from_mapping(
                    {**payload, "name": name},
                    self.app.relay_network,
                    self.app.relay_address,
                    existing_name=True,
                )
                self.app.relay.update_peer_access_rule(rule)
                self.app.audit.append(
                    "wireguard-access-update",
                    "success",
                    rule.name,
                )
                self.send_json(
                    {
                        "ok": True,
                        "message": f"Peer間アクセス「{rule.name}」を更新しました。",
                    }
                )
                return
            web_route_prefix = "/api/web-routes/"
            enabled_suffix = "/enabled"
            if (
                path.startswith(web_route_prefix)
                and path.endswith(enabled_suffix)
            ):
                record_id = unquote(
                    path[len(web_route_prefix) : -len(enabled_suffix)]
                )
                updated = self.app.web_store.set_enabled(
                    record_id,
                    payload.get("enabled"),  # type: ignore[arg-type]
                )
                self.app.audit.append(
                    (
                        "web-route-enabled"
                        if updated.desired_enabled
                        else "web-route-disabled"
                    ),
                    "success",
                    updated.route.name,
                )
                self.send_web_store_state()
                return
            if path.startswith(web_route_prefix):
                record_id = unquote(path[len(web_route_prefix) :])
                existing = self.app.web_store.record(record_id).route
                route, one_time_credentials = self.app.web_route_from_payload(
                    payload,
                    existing,
                )
                updated = self.app.web_store.update(record_id, route)
                self.app.audit.append(
                    "web-route-update",
                    "success",
                    updated.route.name,
                )
                self.send_web_store_state(
                    one_time_basic_auth=one_time_credentials,
                )
                return
            route_prefix = "/api/routes/"
            if path.startswith(route_prefix) and path.endswith(enabled_suffix):
                record_id = unquote(
                    path[len(route_prefix) : -len(enabled_suffix)]
                )
                updated = self.app.store.set_enabled(
                    record_id,
                    payload.get("enabled"),  # type: ignore[arg-type]
                )
                self.app.terraform.invalidate_plan()
                self.app.audit.append(
                    "route-enabled" if updated.desired_enabled else "route-disabled",
                    "success",
                    updated.route.name,
                )
                self.send_store_state()
                return
            if path.startswith(route_prefix):
                record_id = unquote(path[len(route_prefix) :])
                route = self.app.route_from_payload(payload)
                if "group_id" in payload:
                    group_value = payload.get("group_id")
                    updated = self.app.store.update(
                        record_id,
                        route,
                        str(group_value) if group_value else None,
                    )
                else:
                    updated = self.app.store.update(record_id, route)
                self.app.terraform.invalidate_plan()
                self.app.audit.append("route-update", "success", updated.route.name)
                self.send_store_state()
                return

            group_prefix = "/api/groups/"
            if path.startswith(group_prefix) and path.endswith(enabled_suffix):
                group_id = unquote(
                    path[len(group_prefix) : -len(enabled_suffix)]
                )
                enabled = payload.get("enabled")
                updated = self.app.store.set_group_enabled(
                    group_id,
                    enabled,  # type: ignore[arg-type]
                )
                self.app.terraform.invalidate_plan()
                self.app.audit.append(
                    "group-enabled" if enabled is True else "group-disabled",
                    "success",
                    f"{group_id}: {len(updated)}件",
                )
                self.send_store_state()
                return
            if path.startswith(group_prefix):
                group_id = unquote(path[len(group_prefix) :])
                if "parent_id" in payload:
                    parent_value = payload.get("parent_id")
                    group = self.app.store.update_group(
                        group_id,
                        payload.get("name"),
                        payload.get("description", ""),
                        str(parent_value) if parent_value else None,
                    )
                else:
                    group = self.app.store.update_group(
                        group_id,
                        payload.get("name"),
                        payload.get("description", ""),
                    )
                self.app.terraform.invalidate_plan()
                self.app.audit.append("group-update", "success", group.name)
                self.send_store_state()
                return
            self.send_error_json(HTTPStatus.NOT_FOUND, "APIが見つかりません。")
        except (DashboardError, ValueError) as exc:
            self.send_error_json(error_status(exc), str(exc), command_output(exc))
        finally:
            self.app.operation_lock.release()

    def do_DELETE(self) -> None:
        if not self.authenticate() or not self.validate_csrf():
            return
        path = urlparse(self.path).path
        if not self.acquire_operation():
            return
        try:
            payload = self.read_json()
            peer_prefix = "/api/wireguard/peers/"
            access_prefix = "/api/wireguard/access-rules/"
            if path.startswith(peer_prefix):
                name = unquote(path[len(peer_prefix) :])
                if payload.get("confirmation") != name:
                    raise ValidationError(
                        "Peerを削除するには確認欄へPeer名を入力してください。"
                    )
                deleted_name = self.app.relay.delete_peer(name)
                self.app.audit.append(
                    "wireguard-peer-delete",
                    "success",
                    deleted_name,
                )
                self.send_json(
                    {
                        "ok": True,
                        "message": f"WireGuard Peer「{deleted_name}」を削除しました。",
                    }
                )
                return
            if path.startswith(access_prefix):
                if payload.get("confirmation") != "DELETE":
                    raise ValidationError(
                        "アクセスルールを削除するにはDELETEと入力してください。"
                    )
                name = unquote(path[len(access_prefix) :])
                deleted_name = self.app.relay.delete_peer_access_rule(name)
                self.app.audit.append(
                    "wireguard-access-delete",
                    "success",
                    deleted_name,
                )
                self.send_json(
                    {
                        "ok": True,
                        "message": f"Peer間アクセス「{deleted_name}」を削除しました。",
                    }
                )
                return
            route_prefix = "/api/routes/"
            history_prefix = "/api/deleted-routes/"
            web_route_prefix = "/api/web-routes/"
            web_history_prefix = "/api/deleted-web-routes/"
            group_prefix = "/api/groups/"
            if path.startswith(web_route_prefix):
                record_id = unquote(path[len(web_route_prefix) :])
                record = next(
                    (
                        item
                        for item in self.app.web_store.views()
                        if item["id"] == record_id
                    ),
                    None,
                )
                if record is None:
                    raise DashboardError(
                        f"Webルートが見つかりません: {record_id}"
                    )
                cancelled = self.app.web_store.delete(record_id)
                self.app.audit.append(
                    (
                        "web-route-create-cancel"
                        if cancelled
                        else "web-route-delete-pending"
                    ),
                    "success",
                    str(record["name"]),
                )
                self.send_web_store_state()
                return
            if path.startswith(web_history_prefix):
                record_id = unquote(path[len(web_history_prefix) :])
                record = next(
                    (
                        item
                        for item in self.app.web_store.views()
                        if item["id"] == record_id
                    ),
                    None,
                )
                if record is None:
                    raise DashboardError(
                        f"Webルートが見つかりません: {record_id}"
                    )
                self.app.web_store.purge_deleted(record_id)
                self.app.audit.append(
                    "web-route-history-purge",
                    "success",
                    str(record["name"]),
                )
                self.send_web_store_state()
                return
            if path.startswith(route_prefix):
                record_id = unquote(path[len(route_prefix) :])
                record = next(
                    (
                        item
                        for item in self.app.store.views()
                        if item["id"] == record_id
                    ),
                    None,
                )
                if record is None:
                    raise DashboardError(f"経路が見つかりません: {record_id}")
                cancelled = self.app.store.delete(record_id)
                self.app.terraform.invalidate_plan()
                action = "route-create-cancel" if cancelled else "route-delete-pending"
                self.app.audit.append(action, "success", str(record["name"]))
                self.send_store_state()
                return
            if path.startswith(history_prefix):
                record_id = unquote(path[len(history_prefix) :])
                record = next(
                    (
                        item
                        for item in self.app.store.views()
                        if item["id"] == record_id
                    ),
                    None,
                )
                if record is None:
                    raise DashboardError(f"経路が見つかりません: {record_id}")
                self.app.store.purge_deleted(record_id)
                self.app.audit.append("route-history-purge", "success", str(record["name"]))
                self.send_store_state()
                return
            if path.startswith(group_prefix):
                group_id = unquote(path[len(group_prefix) :])
                group = next(
                    (
                        item
                        for item in self.app.store.group_views()
                        if item["id"] == group_id
                    ),
                    None,
                )
                if group is None:
                    raise DashboardError(f"グループが見つかりません: {group_id}")
                self.app.store.delete_group(group_id)
                self.app.terraform.invalidate_plan()
                self.app.audit.append("group-delete", "success", str(group["name"]))
                self.send_store_state()
                return
            self.send_error_json(HTTPStatus.NOT_FOUND, "APIが見つかりません。")
        except DashboardError as exc:
            self.send_error_json(error_status(exc), str(exc), command_output(exc))
        finally:
            self.app.operation_lock.release()

    def create_plan(self) -> None:
        if not self.app.operation_lock.acquire(blocking=False):
            self.send_error_json(HTTPStatus.CONFLICT, "別の操作を実行中です。")
            return
        try:
            if self.app.store.has_pending_relay():
                raise ConflictError(
                    "Terraform適用後のリレー同期待ちです。先に「リレーだけ再同期」を実行してください。"
                )
            routes = self.app.store.list()
            actual = self.app.relay.list()
            conflicts = self.app.relay.check_conflicts(routes, actual)
            if conflicts:
                raise ConflictError(" ".join(conflicts))
            relay_adoptions = self.app.relay.adoptions(routes, actual)
            metadata = self.app.terraform.plan(
                routes,
                relay_adoptions=relay_adoptions,
            )
            result = "success" if metadata.get("safe") else "blocked"
            self.app.audit.append(
                "terraform-plan",
                result,
                json.dumps(metadata.get("counts", {}), ensure_ascii=False),
            )
            self.send_json({"plan": metadata})
        except DashboardError as exc:
            self.app.audit.append("terraform-plan", "error", str(exc))
            self.send_error_json(HTTPStatus.BAD_GATEWAY, str(exc), command_output(exc))
        finally:
            self.app.operation_lock.release()

    def apply_plan(self, payload: dict[str, object]) -> None:
        if payload.get("confirmation") != "APPLY":
            self.send_error_json(
                HTTPStatus.BAD_REQUEST,
                "適用するには確認欄へAPPLYと入力してください。",
            )
            return
        if not self.app.operation_lock.acquire(blocking=False):
            self.send_error_json(HTTPStatus.CONFLICT, "別の操作を実行中です。")
            return
        try:
            routes = self.app.store.list()
            actual = self.app.relay.list()
            conflicts = self.app.relay.check_conflicts(routes, actual)
            if conflicts:
                raise ConflictError(" ".join(conflicts))
            current_adoptions = self.app.relay.adoptions(routes, actual)
            plan_metadata = self.app.terraform.load_plan_metadata() or {}
            if plan_metadata.get("relay_adoptions", []) != current_adoptions:
                raise ConflictError(
                    "手動リレールールの移管対象がplan作成後に変わりました。"
                    "変更内容を確認し直してください。"
                )
            terraform_output = self.app.terraform.apply(routes)
            self.app.store.mark_terraform_applied()
            try:
                relay_actions = self.app.relay.sync(self.app.store.relay_sync_routes())
            except DashboardError as exc:
                self.app.terraform.invalidate_plan()
                self.app.audit.append(
                    "apply",
                    "partial",
                    f"Terraform成功、リレー同期失敗: {exc}",
                )
                self.send_json(
                    {
                        "ok": False,
                        "partial": True,
                        "message": (
                            "Terraformは適用されましたが、OCIリレー同期に失敗しました。"
                            "接続を直した後に「リレーだけ再同期」を実行してください。"
                        ),
                        "terraform_output": terraform_output,
                        "relay_output": command_output(exc),
                    },
                    HTTPStatus.BAD_GATEWAY,
                )
                return

            self.app.store.commit_relay_sync()
            self.app.terraform.invalidate_plan()
            self.app.audit.append("apply", "success", " / ".join(relay_actions))
            self.send_json(
                {
                    "ok": True,
                    "message": "TerraformとOCIリレーの同期が完了しました。",
                    "terraform_output": terraform_output,
                    "relay_actions": relay_actions,
                }
            )
        except DashboardError as exc:
            self.app.audit.append("apply", "error", str(exc))
            self.send_error_json(HTTPStatus.BAD_GATEWAY, str(exc), command_output(exc))
        finally:
            self.app.operation_lock.release()

    def sync_relay(self, payload: dict[str, object]) -> None:
        if payload.get("confirmation") != "SYNC":
            self.send_error_json(
                HTTPStatus.BAD_REQUEST,
                "同期するには確認欄へSYNCと入力してください。",
            )
            return
        if not self.app.operation_lock.acquire(blocking=False):
            self.send_error_json(HTTPStatus.CONFLICT, "別の操作を実行中です。")
            return
        try:
            recovering = self.app.store.has_pending_relay()
            actions = self.app.relay.sync(self.app.store.relay_sync_routes())
            if recovering:
                self.app.store.commit_relay_sync()
            self.app.audit.append("relay-sync", "success", " / ".join(actions))
            self.send_json({"ok": True, "actions": actions})
        except DashboardError as exc:
            self.app.audit.append("relay-sync", "error", str(exc))
            self.send_error_json(HTTPStatus.BAD_GATEWAY, str(exc), command_output(exc))
        finally:
            self.app.operation_lock.release()

    def send_store_state(self, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_json(
            {
                "routes": self.app.store.views(),
                "groups": self.app.store.group_views(),
                "web_gateway": self.app.web_gateway_status(),
            },
            status,
        )

    def send_web_store_state(
        self,
        status: HTTPStatus = HTTPStatus.OK,
        one_time_basic_auth: dict[str, str] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "web_routes": self.app.web_store.views(),
            "web_routes_status": self.app.web_store.status(),
            "web_gateway": self.app.web_gateway_status(),
        }
        if one_time_basic_auth is not None:
            payload["one_time_basic_auth"] = one_time_basic_auth
        self.send_json(payload, status)

    def send_wireguard_state(self) -> None:
        self.send_json(
            self.app.relay.wireguard_state(
                self.app.relay_network,
                self.app.relay_address,
                self.app.dashboard_target_address,
                self.app.dashboard_external_port,
            )
        )

    def acquire_operation(self) -> bool:
        if self.app.operation_lock.acquire(blocking=False):
            return True
        self.send_error_json(HTTPStatus.CONFLICT, "別の操作を実行中です。")
        return False

    def prepare_idempotency(
        self,
        path: str,
        payload: dict[str, object],
    ) -> bool:
        key = self.headers.get("Idempotency-Key", "")
        if not key:
            return True
        endpoint = (self.command, path)
        if endpoint not in IDEMPOTENT_ENDPOINTS:
            raise ValidationError("このAPIは冪等性キーに対応していません。")
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(key):
            raise ValidationError(
                "冪等性キーは英数字と._:-を使った8〜128文字にしてください。"
            )
        scope = f"{self.command} {path}"
        request_hash = hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        replay = self.app.idempotency.replay(key, scope, request_hash)
        if replay is not None:
            status, response = replay
            self._idempotency_replayed = True
            self.send_json(response, HTTPStatus(status))
            return False
        self._idempotency_pending = (key, scope, request_hash)
        return True

    def authenticate(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            self.request_authentication()
            return False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode()
            username, password = decoded.split(":", 1)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            self.request_authentication()
            return False
        valid = hmac.compare_digest(username, self.app.username) and hmac.compare_digest(
            password,
            self.app.password,
        )
        if not valid:
            self.request_authentication()
            return False
        return True

    def validate_csrf(self) -> bool:
        token = self.headers.get("X-Relay-CSRF", "")
        if not hmac.compare_digest(token, self.app.csrf_token):
            self.send_error_json(HTTPStatus.FORBIDDEN, "CSRFトークンが不正です。")
            return False
        return True

    def request_authentication(self) -> None:
        body = b"Authentication required"
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="OCI Relay Dashboard", charset="UTF-8"')
        self.security_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, object]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            raise ValueError("リクエストが大きすぎます。")
        raw = self.rfile.read(content_length)
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("JSONを解析できません。") from exc
        if not isinstance(value, dict):
            raise ValueError("JSONオブジェクトを送信してください。")
        return value

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.removeprefix("/static/")
        if "/" in relative or "\\" in relative or relative.startswith("."):
            self.send_error_json(HTTPStatus.NOT_FOUND, "ファイルが見つかりません。")
            return
        target = self.app.static_dir / relative
        if not target.is_file():
            self.send_error_json(HTTPStatus.NOT_FOUND, "ファイルが見つかりません。")
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.security_headers()
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        pending = getattr(self, "_idempotency_pending", None)
        if pending is not None and 200 <= int(status) < 300:
            key, scope, request_hash = pending
            self.app.idempotency.save(
                key,
                scope,
                request_hash,
                int(status),
                payload,
            )
            self._idempotency_pending = None
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.security_headers()
        if getattr(self, "_idempotency_replayed", False):
            self.send_header("Idempotency-Replayed", "true")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(
        self,
        status: HTTPStatus,
        message: str,
        detail: str = "",
    ) -> None:
        self.send_json(
            {
                "ok": False,
                "message": message,
                "detail": detail[:20_000],
            },
            status,
        )

    def security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def log_message(self, format_string: str, *args: object) -> None:
        print(
            f"{self.address_string()} - [{self.log_date_time_string()}] "
            f"{format_string % args}",
            flush=True,
        )


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, app: AppContext) -> None:
        self.app = app
        super().__init__((app.bind, app.port), DashboardHandler)


def require_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def command_output(error: BaseException) -> str:
    return error.output if isinstance(error, CommandError) else ""


def error_status(error: BaseException) -> HTTPStatus:
    if isinstance(error, CommandError):
        return HTTPStatus.BAD_GATEWAY
    if isinstance(error, ConflictError):
        return HTTPStatus.CONFLICT
    return HTTPStatus.BAD_REQUEST


def main() -> None:
    app = AppContext()
    server = DashboardServer(app)
    print(f"OCI Relay Dashboard listening on {app.bind}:{app.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

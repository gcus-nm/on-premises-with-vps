from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

from dashboard.cli import RelayClient
from dashboard.core import (
    ConflictError,
    DashboardError,
    Route,
    RouteStore,
    parse_relay_routes,
)
from dashboard.server import AppContext, DashboardServer


class DashboardServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        project_root = Path(__file__).resolve().parents[2]
        environment = {
            "DASHBOARD_USERNAME": "admin",
            "DASHBOARD_PASSWORD": "test-password-1234567890",
            "DASHBOARD_BIND": "127.0.0.1",
            "DASHBOARD_PORT": "0",
            "DASHBOARD_DATA_DIR": self.temporary.name,
            "DASHBOARD_STATIC_DIR": str(project_root / "relay-dashboard/static"),
            "TERRAFORM_WORKSPACE": str(project_root),
            "RELAY_SCRIPT": str(project_root / "scripts/wg-relay.sh"),
            "TRAEFIK_DYNAMIC_CONFIG": str(
                Path(self.temporary.name)
                / "traefik-dynamic"
                / "ui-web-routes.yml"
            ),
        }
        self.environment = patch.dict(os.environ, environment, clear=False)
        self.environment.start()
        self.app = AppContext()
        self.app.wireguard_qr.generate = Mock(
            return_value='<svg xmlns="http://www.w3.org/2000/svg"></svg>\n'
        )
        self.server = DashboardServer(self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        credentials = base64.b64encode(b"admin:test-password-1234567890").decode()
        self.authorization = f"Basic {credentials}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.environment.stop()
        self.temporary.cleanup()

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, object] | None = None,
        csrf: str | None = None,
        authenticated: bool = True,
        idempotency_key: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = self.authorization
        if csrf is not None:
            headers["X-Relay-CSRF"] = csrf
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=data,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_health_does_not_require_authentication(self) -> None:
        status, payload = self.request("/healthz", authenticated=False)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_cli_uses_authenticated_api_and_backend_dry_run(self) -> None:
        client = RelayClient(
            self.base_url,
            "admin",
            "test-password-1234567890",
        )
        state = client.request("/api/state")
        self.assertIsInstance(state, dict)
        route = {
            "name": "cli-route",
            "protocol": "tcp",
            "public_port": 18082,
            "target_address": "10.99.0.2",
            "target_port": 18082,
        }
        preview = client.request(
            "/api/routes/validate",
            method="POST",
            body=route,
        )
        self.assertTrue(preview["dry_run"])  # type: ignore[index]
        self.assertEqual(self.app.store.views(), [])

        for _ in range(2):
            result = client.request(
                "/api/routes",
                method="POST",
                body=route,
                idempotency_key="cli-route-create-18082",
            )
            self.assertEqual(len(result["routes"]), 1)  # type: ignore[arg-type]
        self.assertEqual(len(self.app.store.views()), 1)

    def test_route_mutation_is_blocked_during_an_operation(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        self.app.operation_lock.acquire()
        try:
            status, _ = self.request(
                "/api/routes",
                method="POST",
                body={
                    "name": "minecraft",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_address": "10.99.0.2",
                    "target_port": 25565,
                },
                csrf=csrf,
            )
        finally:
            self.app.operation_lock.release()

        self.assertEqual(status, 409)
        self.assertEqual(self.app.store.views(), [])

    def test_route_api_requires_csrf_and_persists_route(self) -> None:
        status, state = self.request("/api/state")
        self.assertEqual(status, 200)
        csrf = str(state["csrf_token"])
        route = {
            "name": "minecraft",
            "protocol": "tcp",
            "public_port": 25565,
            "target_address": "10.99.0.2",
            "target_port": 25565,
            "description": "Minecraft",
        }

        preview_status, preview = self.request(
            "/api/routes/validate",
            method="POST",
            body=route,
            csrf=csrf,
        )
        self.assertEqual(preview_status, 200)
        self.assertTrue(preview["dry_run"])
        self.assertEqual(preview["summary"]["target_count"], 1)  # type: ignore[index]
        self.assertEqual(self.app.store.views(), [])

        rejected_status, _ = self.request(
            "/api/routes",
            method="POST",
            body=route,
        )
        self.assertEqual(rejected_status, 403)

        created_status, created = self.request(
            "/api/routes",
            method="POST",
            body=route,
            csrf=csrf,
        )
        self.assertEqual(created_status, 201)
        self.assertEqual(created["routes"][0]["name"], "minecraft")  # type: ignore[index]
        self.assertEqual(created["routes"][0]["state"], "pending_create")  # type: ignore[index]

        _, refreshed = self.request("/api/state")
        self.assertEqual(refreshed["routes"][0]["public_port"], 25565)  # type: ignore[index]

        record_id = str(refreshed["routes"][0]["id"])  # type: ignore[index]
        updated_status, updated = self.request(
            f"/api/routes/{record_id}",
            method="PUT",
            body={**route, "name": "minecraft-main"},
            csrf=csrf,
        )
        self.assertEqual(updated_status, 200)
        self.assertEqual(updated["routes"][0]["name"], "minecraft-main")  # type: ignore[index]

        deleted_status, deleted = self.request(
            f"/api/routes/{record_id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.assertEqual(deleted_status, 200)
        self.assertEqual(deleted["routes"], [])

    def test_route_create_replays_matching_idempotency_key(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        route = {
            "name": "idempotent-route",
            "protocol": "tcp",
            "public_port": 18080,
            "target_address": "10.99.0.2",
            "target_port": 18080,
        }
        for _ in range(2):
            status, response = self.request(
                "/api/routes",
                method="POST",
                body=route,
                csrf=csrf,
                idempotency_key="route-create-18080",
            )
            self.assertEqual(status, 201)
            self.assertEqual(len(response["routes"]), 1)  # type: ignore[arg-type]
        self.assertEqual(len(self.app.store.views()), 1)

        conflict_status, _ = self.request(
            "/api/routes",
            method="POST",
            body={**route, "public_port": 18081},
            csrf=csrf,
            idempotency_key="route-create-18080",
        )
        self.assertEqual(conflict_status, 409)

    def test_plan_reports_exact_manual_rule_adoption(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        self.app.store.create(
            Route.from_mapping(
                {
                    "name": "minecraft-26-2-vanilla",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_address": "10.99.0.2",
                    "target_port": 25565,
                }
            )
        )
        self.app.relay.list = Mock(  # type: ignore[method-assign]
            return_value=parse_relay_routes(
                "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
                "minecraft\ttcp\t25565\t10.99.0.2:25565\n"
            )
        )

        def plan_result(
            routes: list[Route],
            relay_adoptions: list[dict[str, object]],
        ) -> dict[str, object]:
            return {
                "safe": True,
                "counts": {"create": 1},
                "relay_adoptions": relay_adoptions,
                "output": "safe plan",
            }

        self.app.terraform.plan = Mock(side_effect=plan_result)  # type: ignore[method-assign]

        status, payload = self.request(
            "/api/plan",
            method="POST",
            body={},
            csrf=csrf,
        )

        self.assertEqual(status, 200)
        adoptions = payload["plan"]["relay_adoptions"]  # type: ignore[index]
        self.assertEqual(adoptions[0]["manual_name"], "minecraft")  # type: ignore[index]
        self.assertEqual(
            adoptions[0]["managed_name"],  # type: ignore[index]
            "ui-minecraft-26-2-vanilla",
        )

    def test_apply_rejects_manual_rule_change_after_plan(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        self.app.store.create(
            Route.from_mapping(
                {
                    "name": "minecraft",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_address": "10.99.0.2",
                    "target_port": 25565,
                }
            )
        )
        self.app.relay.list = Mock(  # type: ignore[method-assign]
            return_value=parse_relay_routes(
                "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
                "minecraft\ttcp\t25565\t10.99.0.2:25565\n"
            )
        )
        self.app.terraform.load_plan_metadata = Mock(  # type: ignore[method-assign]
            return_value={"relay_adoptions": []}
        )
        self.app.terraform.apply = Mock()  # type: ignore[method-assign]

        status, payload = self.request(
            "/api/apply",
            method="POST",
            body={"confirmation": "APPLY"},
            csrf=csrf,
        )

        self.assertEqual(status, 502)
        self.assertIn("移管対象がplan作成後に変わりました", payload["message"])
        self.app.terraform.apply.assert_not_called()

    def test_web_route_api_requires_csrf_preview_and_publish_confirmation(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        route = {
            "name": "app",
            "hostname": "app.oci.example.jp",
            "docker_alias": "app-service",
            "container_port": 8080,
            "description": "App",
        }

        status, _ = self.request(
            "/api/web-routes",
            method="POST",
            body=route,
        )
        self.assertEqual(status, 403)

        status, created = self.request(
            "/api/web-routes",
            method="POST",
            body=route,
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["web_routes"][0]["state"], "pending_create")  # type: ignore[index]
        record_id = str(created["web_routes"][0]["id"])  # type: ignore[index]
        status, listed = self.request("/api/web-routes")
        self.assertEqual(status, 200)
        self.assertEqual(len(listed["web_routes"]), 1)  # type: ignore[arg-type]
        status, fetched = self.request(f"/api/web-routes/{record_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["web_route"]["hostname"], "app.oci.example.jp")  # type: ignore[index]

        status, _ = self.request(
            "/api/web-routes/publish",
            method="POST",
            body={"confirmation": "wrong"},
            csrf=csrf,
        )
        self.assertEqual(status, 400)

        status, preview = self.request(
            "/api/web-routes/preview",
            method="POST",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertIn("Host(`app.oci.example.jp`)", preview["preview"]["config"])  # type: ignore[index]

        status, published = self.request(
            "/api/web-routes/publish",
            method="POST",
            body={"confirmation": "PUBLISH"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(published["web_routes"][0]["state"], "enabled")  # type: ignore[index]
        config = (
            Path(self.temporary.name)
            / "traefik-dynamic"
            / "ui-web-routes.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("certResolver: letsencrypt", config)

        status, disabled = self.request(
            f"/api/web-routes/{record_id}/enabled",
            method="PUT",
            body={"enabled": False},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(disabled["web_routes"][0]["state"], "pending_disable")  # type: ignore[index]
        audit = (Path(self.temporary.name) / "audit.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertIn('"action": "web-route-publish"', audit)

    def test_web_route_basic_auth_is_generated_once_and_redacted(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        route = {
            "name": "private-app",
            "hostname": "private.oci.example.jp",
            "docker_alias": "private-app",
            "container_port": 8080,
            "description": "Private App",
            "basic_auth_enabled": True,
            "basic_auth_username": "reader",
        }

        status, created = self.request(
            "/api/web-routes",
            method="POST",
            body=route,
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        credentials = created["one_time_basic_auth"]  # type: ignore[index]
        self.assertEqual(credentials["username"], "reader")  # type: ignore[index]
        password = str(credentials["password"])  # type: ignore[index]
        self.assertGreaterEqual(len(password), 40)
        created_route = created["web_routes"][0]  # type: ignore[index]
        self.assertTrue(created_route["basic_auth_enabled"])
        self.assertNotIn("basic_auth_password_hash", created_route)
        self.assertNotIn("{SHA}", json.dumps(created))
        record_id = str(created_route["id"])

        status, updated = self.request(
            f"/api/web-routes/{record_id}",
            method="PUT",
            body={
                "name": "private-app",
                "hostname": "private.oci.example.jp",
                "docker_alias": "private-app",
                "container_port": 8081,
                "description": "Private App",
            },
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertNotIn("one_time_basic_auth", updated)
        self.assertTrue(updated["web_routes"][0]["basic_auth_enabled"])  # type: ignore[index]

        _, preview = self.request(
            "/api/web-routes/preview",
            method="POST",
            body={},
            csrf=csrf,
        )
        config = str(preview["preview"]["config"])  # type: ignore[index]
        self.assertIn("basicAuth:", config)
        self.assertNotIn(password, config)
        self.assertNotIn("{SHA}", config)

        status, published = self.request(
            "/api/web-routes/publish",
            method="POST",
            body={"confirmation": "PUBLISH"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(published["web_routes"][0]["state"], "enabled")  # type: ignore[index]
        auth_files = list(
            (
                Path(self.temporary.name)
                / "traefik-dynamic"
            ).glob("ui-web-private-app-auth-*.htpasswd")
        )
        self.assertEqual(len(auth_files), 1)
        users_file = auth_files[0].read_text(encoding="utf-8")
        self.assertTrue(users_file.startswith("reader:{SHA}"))
        self.assertNotIn(password, users_file)

    def test_web_gateway_setup_is_atomic_and_rejects_conflict(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])

        status, staged = self.request(
            "/api/web-gateway/setup",
            method="POST",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            {route["public_port"] for route in staged["routes"]},  # type: ignore[index]
            {80, 443},
        )
        self.assertTrue(staged["web_gateway"]["staged"])  # type: ignore[index]

        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            store.create(
                Route.from_mapping(
                    {
                        "name": "other-http",
                        "protocol": "tcp",
                        "public_port": 80,
                        "target_address": "10.99.0.3",
                        "target_port": 8080,
                    }
                )
            )
            with self.assertRaises(ConflictError):
                store.setup_web_gateway("10.99.0.2")
            self.assertEqual(len(store.views()), 1)

    def test_wireguard_peer_and_access_rule_apis(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        inventory = {
            "peers": [
                {
                    "name": "windows-minibox",
                    "address": "10.99.0.2",
                    "cidr": "10.99.0.2/32",
                    "public_key": "windows-key",
                    "endpoint": "",
                    "latest_handshake": "1 minute ago",
                    "transfer": "1 MiB received, 2 MiB sent",
                    "access_rules": [],
                }
            ],
            "access_presets": [],
            "access_rules": [],
            "suggested_address": "10.99.0.3",
            "relay_network": "10.99.0.0/24",
            "relay_address": "10.99.0.1",
            "dashboard_target_address": "10.99.0.2",
            "dashboard_port": 8081,
        }
        self.app.relay.wireguard_state = Mock(return_value=inventory)  # type: ignore[method-assign]
        status, payload = self.request("/api/wireguard")
        self.assertEqual(status, 200)
        self.assertEqual(payload["suggested_address"], "10.99.0.3")

        self.app.relay.create_peer = Mock(  # type: ignore[method-assign]
            return_value=(
                "mac-admin",
                "[Interface]\nPrivateKey = generated\nAddress = 10.99.0.3/32\n",
            )
        )
        status, created = self.request(
            "/api/wireguard/peers",
            method="POST",
            body={"name": "mac-admin", "address": "10.99.0.3"},
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["filename"], "mac-admin.conf")
        self.assertIn("PrivateKey", created["client_config"])
        self.assertTrue(created["one_time"])
        self.assertEqual(created["qr_filename"], "mac-admin-wireguard-qr.svg")
        self.assertIn(
            b"<svg",
            base64.b64decode(str(created["qr_svg_base64"])),
        )
        self.assertEqual(created["qr_warning"], "")
        self.assertNotIn(
            "PrivateKey",
            (Path(self.temporary.name) / "audit.jsonl").read_text(encoding="utf-8"),
        )

        self.app.relay.rotate_peer = Mock(  # type: ignore[method-assign]
            return_value=(
                "mac-admin",
                "[Interface]\nPrivateKey = rotated\nAddress = 10.99.0.3/32\n",
            )
        )
        status, rotated = self.request(
            "/api/wireguard/peers/mac-admin/rotate",
            method="POST",
            body={"confirmation": "ROTATE"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertIn("rotated", rotated["client_config"])

        self.app.wireguard_qr.generate = Mock(side_effect=RuntimeError("QR失敗"))
        status, rotated_without_qr = self.request(
            "/api/wireguard/peers/mac-admin/rotate",
            method="POST",
            body={"confirmation": "ROTATE"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(rotated_without_qr["qr_svg_base64"], "")
        self.assertIn("構成ファイルは取得できます", rotated_without_qr["qr_warning"])

        self.app.relay.create_peer_access_preset = Mock()  # type: ignore[method-assign]
        preset_payload = {
            "name": "dashboard",
            "protocol": "tcp",
            "target_address": "10.99.0.2",
            "target_port": 8081,
        }
        status, _ = self.request(
            "/api/wireguard/access-presets",
            method="POST",
            body=preset_payload,
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        created_preset = self.app.relay.create_peer_access_preset.call_args.args[0]
        self.assertEqual(created_preset.source_addresses, ())

        self.app.relay.update_peer_access_preset_definition = Mock()  # type: ignore[method-assign]
        status, updated = self.request(
            "/api/wireguard/access-presets/dashboard",
            method="PUT",
            body={
                **preset_payload,
                "name": "relay-dashboard",
                "target_port": 8443,
            },
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        update_arguments = (
            self.app.relay.update_peer_access_preset_definition.call_args.args
        )
        self.assertEqual(update_arguments[0], "dashboard")
        updated_preset = update_arguments[1]
        self.assertEqual(updated_preset.name, "relay-dashboard")
        self.assertEqual(updated_preset.target_port, 8443)
        self.assertEqual(updated["previous_name"], "dashboard")
        self.assertEqual(updated["name"], "relay-dashboard")

        self.app.relay.set_peer_access_presets = Mock(  # type: ignore[method-assign]
            return_value=("mac-admin", ("dashboard", "ssh"))
        )
        status, assigned = self.request(
            "/api/wireguard/peers/mac-admin/access-presets",
            method="PUT",
            body={"preset_names": ["dashboard", "ssh"]},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(assigned["preset_names"], ["dashboard", "ssh"])

        self.app.relay.delete_peer_access_preset = Mock(  # type: ignore[method-assign]
            return_value="dashboard"
        )
        status, _ = self.request(
            "/api/wireguard/access-presets/dashboard",
            method="DELETE",
            body={"confirmation": "DELETE"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)

        self.app.relay.create_peer_access_rule = Mock()  # type: ignore[method-assign]
        access_payload = {
            "name": "mac-to-dashboard",
            "protocol": "tcp",
            "source_address": "10.99.0.3",
            "target_address": "10.99.0.2",
            "target_port": 8081,
        }
        status, _ = self.request(
            "/api/wireguard/access-rules",
            method="POST",
            body=access_payload,
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        created_rule = self.app.relay.create_peer_access_rule.call_args.args[0]
        self.assertEqual(created_rule.target_port, 8081)

        self.app.relay.update_peer_access_rule = Mock()  # type: ignore[method-assign]
        status, _ = self.request(
            "/api/wireguard/access-rules/mac-to-dashboard",
            method="PUT",
            body={**access_payload, "target_port": 8443},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        updated_rule = self.app.relay.update_peer_access_rule.call_args.args[0]
        self.assertEqual(updated_rule.target_port, 8443)

        self.app.relay.delete_peer_access_rule = Mock(  # type: ignore[method-assign]
            return_value="mac-to-dashboard"
        )
        status, _ = self.request(
            "/api/wireguard/access-rules/mac-to-dashboard",
            method="DELETE",
            body={"confirmation": "DELETE"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)

        self.app.relay.delete_peer = Mock(return_value="mac-admin")  # type: ignore[method-assign]
        status, _ = self.request(
            "/api/wireguard/peers/mac-admin",
            method="DELETE",
            body={"confirmation": "mac-admin"},
            csrf=csrf,
        )
        self.assertEqual(status, 200)

    def test_wireguard_mutations_require_csrf_and_confirmations(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        status, _ = self.request(
            "/api/wireguard/peers",
            method="POST",
            body={"name": "mac-admin", "address": "10.99.0.3"},
        )
        self.assertEqual(status, 403)

        self.app.relay.rotate_peer = Mock()  # type: ignore[method-assign]
        status, _ = self.request(
            "/api/wireguard/peers/mac-admin/rotate",
            method="POST",
            body={"confirmation": "wrong"},
            csrf=csrf,
        )
        self.assertEqual(status, 400)
        self.app.relay.rotate_peer.assert_not_called()

        self.app.relay.delete_peer = Mock()  # type: ignore[method-assign]
        status, _ = self.request(
            "/api/wireguard/peers/mac-admin",
            method="DELETE",
            body={"confirmation": "wrong"},
            csrf=csrf,
        )
        self.assertEqual(status, 400)
        self.app.relay.delete_peer.assert_not_called()

    def test_applied_delete_cancel_and_history_purge(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        record = self.app.store.create(
            self.app.route_from_payload(
                {
                    "name": "minecraft",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_address": "10.99.0.2",
                    "target_port": 25565,
                }
            )
        )
        self.app.store.mark_terraform_applied()
        self.app.store.commit_relay_sync()

        status, pending = self.request(
            f"/api/routes/{record.id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(pending["routes"][0]["state"], "pending_delete")  # type: ignore[index]

        status, restored = self.request(
            f"/api/routes/{record.id}/cancel-delete",
            method="POST",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(restored["routes"][0]["state"], "enabled")  # type: ignore[index]

        self.request(
            f"/api/routes/{record.id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.app.store.mark_terraform_applied()
        self.app.store.commit_relay_sync()
        status, purged = self.request(
            f"/api/deleted-routes/{record.id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(purged["routes"], [])

    def test_partial_apply_locks_mutation_until_relay_resync(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        route_payload = {
            "name": "minecraft",
            "protocol": "tcp",
            "public_port": 25565,
            "target_address": "10.99.0.2",
            "target_port": 25565,
        }
        self.app.store.create(self.app.route_from_payload(route_payload))
        self.app.terraform.apply = Mock(return_value="terraform applied")  # type: ignore[method-assign]
        self.app.terraform.invalidate_plan = Mock()  # type: ignore[method-assign]
        self.app.terraform.load_plan_metadata = Mock(  # type: ignore[method-assign]
            return_value={"relay_adoptions": []}
        )
        self.app.relay.list = Mock(return_value={})  # type: ignore[method-assign]
        self.app.relay.sync = Mock(  # type: ignore[method-assign]
            side_effect=DashboardError("relay unavailable")
        )

        status, partial = self.request(
            "/api/apply",
            method="POST",
            body={"confirmation": "APPLY"},
            csrf=csrf,
        )
        self.assertEqual(status, 502)
        self.assertTrue(partial["partial"])
        _, pending_state = self.request("/api/state")
        self.assertTrue(pending_state["pending_relay"])
        self.assertEqual(pending_state["routes"][0]["state"], "pending_relay")  # type: ignore[index]

        blocked_status, _ = self.request(
            "/api/routes",
            method="POST",
            body={**route_payload, "name": "blocked", "public_port": 25566},
            csrf=csrf,
        )
        self.assertEqual(blocked_status, 409)

        self.app.relay.sync = Mock(return_value=["追加: ui-minecraft"])  # type: ignore[method-assign]
        sync_status, _ = self.request(
            "/api/sync",
            method="POST",
            body={"confirmation": "SYNC"},
            csrf=csrf,
        )
        self.assertEqual(sync_status, 200)
        _, applied_state = self.request("/api/state")
        self.assertFalse(applied_state["pending_relay"])
        self.assertEqual(applied_state["routes"][0]["state"], "enabled")  # type: ignore[index]

    def test_group_bulk_routes_and_enable_apis(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])

        status, created = self.request(
            "/api/groups",
            method="POST",
            body={
                "name": "game",
                "description": "ゲーム用",
                "members": [
                    {
                        "protocol": "tcp",
                        "ports": "8000-8001",
                        "target_address": "10.99.0.2",
                    },
                    {
                        "protocol": "udp",
                        "ports": "9000",
                        "target_address": "10.99.0.2",
                    },
                ],
            },
            csrf=csrf,
        )

        self.assertEqual(status, 201)
        self.assertEqual(len(created["routes"]), 3)  # type: ignore[arg-type]
        group = created["groups"][0]  # type: ignore[index]
        group_id = str(group["id"])  # type: ignore[index]
        self.assertEqual(group["enabled_state"], "enabled")  # type: ignore[index]
        self.assertTrue(
            all(route["target_port"] == route["public_port"] for route in created["routes"])  # type: ignore[index]
        )

        status, added = self.request(
            f"/api/groups/{group_id}/routes",
            method="POST",
            body={
                "members": [
                    {
                        "protocol": "udp",
                        "ports": "9001",
                        "target_address": "10.99.0.2",
                    }
                ]
            },
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        self.assertEqual(len(added["routes"]), 4)  # type: ignore[arg-type]
        self.assertTrue(
            any(route["name"] == "game-udp-9001" for route in added["routes"])  # type: ignore[index]
        )

        status, disabled = self.request(
            f"/api/groups/{group_id}/enabled",
            method="PUT",
            body={"enabled": False},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertTrue(
            all(route["state"] == "disabled" for route in disabled["routes"])  # type: ignore[index]
        )

        record_id = str(disabled["routes"][0]["id"])  # type: ignore[index]
        status, mixed = self.request(
            f"/api/routes/{record_id}/enabled",
            method="PUT",
            body={"enabled": True},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mixed["groups"][0]["enabled_state"], "mixed")  # type: ignore[index]

        status, ungrouped = self.request(
            f"/api/groups/{group_id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(ungrouped["groups"], [])
        self.assertTrue(
            all(route["group_id"] is None for route in ungrouped["routes"])  # type: ignore[index]
        )

    def test_group_bulk_creation_rolls_back_on_conflict(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        route_payload = {
            "name": "existing",
            "protocol": "tcp",
            "public_port": 8000,
            "target_address": "10.99.0.2",
            "target_port": 8000,
        }
        self.request(
            "/api/routes",
            method="POST",
            body=route_payload,
            csrf=csrf,
        )

        status, _ = self.request(
            "/api/groups",
            method="POST",
            body={
                "name": "game",
                "members": [
                    {
                        "protocol": "tcp",
                        "ports": "8000-8001",
                        "target_address": "10.99.0.2",
                    }
                ],
            },
            csrf=csrf,
        )

        self.assertEqual(status, 409)
        _, refreshed = self.request("/api/state")
        self.assertEqual(refreshed["groups"], [])
        self.assertEqual(len(refreshed["routes"]), 1)  # type: ignore[arg-type]

    def test_subgroup_api_aggregates_and_rejects_cycles(self) -> None:
        _, state = self.request("/api/state")
        csrf = str(state["csrf_token"])
        status, parent_state = self.request(
            "/api/groups",
            method="POST",
            body={"name": "games", "members": []},
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        parent_id = str(parent_state["groups"][0]["id"])  # type: ignore[index]

        status, nested_state = self.request(
            "/api/groups",
            method="POST",
            body={
                "name": "survival",
                "parent_id": parent_id,
                "members": [
                    {
                        "protocol": "tcp",
                        "ports": "25565",
                        "target_address": "10.99.0.2",
                    }
                ],
            },
            csrf=csrf,
        )
        self.assertEqual(status, 201)
        groups = {
            str(group["name"]): group for group in nested_state["groups"]  # type: ignore[union-attr]
        }
        child_id = str(groups["survival"]["id"])
        self.assertEqual(groups["survival"]["parent_id"], parent_id)
        self.assertEqual(groups["games"]["total_ports"], 1)

        status, _ = self.request(
            f"/api/groups/{parent_id}",
            method="PUT",
            body={"name": "games", "parent_id": child_id},
            csrf=csrf,
        )
        self.assertEqual(status, 400)

        status, disabled = self.request(
            f"/api/groups/{parent_id}/enabled",
            method="PUT",
            body={"enabled": False},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(disabled["routes"][0]["state"], "disabled")  # type: ignore[index]

        status, promoted = self.request(
            f"/api/groups/{parent_id}",
            method="DELETE",
            body={},
            csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertIsNone(promoted["groups"][0]["parent_id"])  # type: ignore[index]
        self.assertEqual(promoted["routes"][0]["group_id"], child_id)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()

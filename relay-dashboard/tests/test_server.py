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

from dashboard.core import DashboardError
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
        }
        self.environment = patch.dict(os.environ, environment, clear=False)
        self.environment.start()
        self.app = AppContext()
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
    ) -> tuple[int, dict[str, object]]:
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = self.authorization
        if csrf is not None:
            headers["X-Relay-CSRF"] = csrf
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
        self.assertEqual(restored["routes"][0]["state"], "applied")  # type: ignore[index]

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
        self.assertEqual(applied_state["routes"][0]["state"], "applied")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()

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
from unittest.mock import patch

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

        _, refreshed = self.request("/api/state")
        self.assertEqual(refreshed["routes"][0]["public_port"], 25565)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()

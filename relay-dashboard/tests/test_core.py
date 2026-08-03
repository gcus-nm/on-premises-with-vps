from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from dashboard.core import (
    CommandResult,
    ConflictError,
    DashboardError,
    PeerAccessRule,
    RelayManager,
    Route,
    RouteStore,
    TerraformManager,
    ValidationError,
    WebRoute,
    WebRouteStore,
    WireGuardPeer,
    analyze_terraform_plan,
    compact_port_ranges,
    hash_basic_auth_password,
    normalize_peer_address,
    oci_config_status,
    parse_peer_access_rules,
    parse_port_expression,
    parse_relay_routes,
    parse_wireguard_peers,
    parse_wireguard_status,
    routes_fingerprint,
    suggest_peer_address,
    validate_route_set,
)


def route(**overrides: object) -> Route:
    value: dict[str, object] = {
        "name": "minecraft",
        "protocol": "tcp",
        "public_port": 25565,
        "target_address": "10.99.0.2",
        "target_port": 25565,
        "description": "Minecraft入口",
    }
    value.update(overrides)
    return Route.from_mapping(value)


def web_route(**overrides: object) -> WebRoute:
    value: dict[str, object] = {
        "name": "app",
        "hostname": "app.oci.example.jp",
        "docker_alias": "app-service",
        "container_port": 8080,
        "description": "Webアプリ",
    }
    value.update(overrides)
    return WebRoute.from_mapping(value)


class RouteValidationTests(unittest.TestCase):
    def test_normalizes_route(self) -> None:
        result = Route.from_mapping(
            {
                "name": "  Minecraft-Hardcore ",
                "protocol": "TCP",
                "public_port": "25565",
                "target_address": "10.99.0.2",
                "target_port": "41411",
                "description": " hard mode ",
            }
        )
        self.assertEqual(result.name, "minecraft-hardcore")
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.target_port, 41411)
        self.assertEqual(result.remote_name, "ui-minecraft-hardcore")

    def test_rejects_protected_ports(self) -> None:
        for protected in (22, 51820):
            with self.subTest(port=protected), self.assertRaises(ValidationError):
                route(public_port=protected)

    def test_rejects_target_outside_wireguard_network(self) -> None:
        with self.assertRaises(ValidationError):
            route(target_address="192.168.1.39")

    def test_rejects_duplicate_listener(self) -> None:
        with self.assertRaises(ConflictError):
            validate_route_set(
                [
                    route(name="one"),
                    route(name="two", target_port=41409),
                ]
            )

    def test_fingerprint_is_order_independent(self) -> None:
        first = route(name="first", public_port=25565)
        second = route(name="second", protocol="udp", public_port=8211)
        self.assertEqual(
            routes_fingerprint([first, second]),
            routes_fingerprint([second, first]),
            )


class WebRouteTests(unittest.TestCase):
    def test_normalizes_and_validates_fields(self) -> None:
        result = WebRoute.from_mapping(
            {
                "name": " App ",
                "hostname": "APP.OCI.Example.JP.",
                "docker_alias": "App-Service",
                "container_port": "8080",
                "description": " app ",
            }
        )
        self.assertEqual(result.name, "app")
        self.assertEqual(result.hostname, "app.oci.example.jp")
        self.assertEqual(result.docker_alias, "app-service")
        self.assertEqual(result.container_port, 8080)
        self.assertFalse(result.basic_auth_enabled)

    def test_validates_basic_auth_fields(self) -> None:
        password_hash = hash_basic_auth_password("x" * 32)
        result = web_route(
            basic_auth_username="reader",
            basic_auth_password_hash=password_hash,
        )
        self.assertTrue(result.basic_auth_enabled)
        self.assertEqual(result.basic_auth_username, "reader")

        invalid = (
            {"basic_auth_username": "reader"},
            {"basic_auth_password_hash": password_hash},
            {
                "basic_auth_username": "bad:user",
                "basic_auth_password_hash": password_hash,
            },
            {
                "basic_auth_username": "reader",
                "basic_auth_password_hash": "$2y$not-supported-here",
            },
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                web_route(**values)

    def test_rejects_invalid_hostname_alias_and_port(self) -> None:
        invalid = (
            {"hostname": "*.example.jp"},
            {"hostname": "example"},
            {"hostname": "https://app.example.jp"},
            {"hostname": "app.example.jp.."},
            {"hostname": "127.0.0.1"},
            {"docker_alias": "bad_alias"},
            {"docker_alias": "localhost"},
            {"container_port": 0},
            {"container_port": 65536},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                web_route(**values)

    def test_store_publish_state_machine_and_deterministic_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "dynamic" / "ui-web-routes.yml"
            config.parent.mkdir()
            sibling = config.parent / "minecraft.yml"
            sibling.write_text("tcp: {}\n", encoding="utf-8")
            store = WebRouteStore(root / "data", config)
            second = store.create(
                web_route(
                    name="z-app",
                    hostname="z.example.jp",
                    docker_alias="z-app",
                    container_port=9000,
                )
            )
            first = store.create(web_route())
            store.set_enabled(second.id, False)

            preview = store.preview()
            self.assertEqual(preview["counts"]["create"], 2)
            self.assertIn("Host(`app.oci.example.jp`)", preview["config"])
            self.assertNotIn("z.example.jp", preview["config"])
            published = store.publish()

            self.assertEqual(published["active_count"], 1)
            content = config.read_text(encoding="utf-8")
            self.assertEqual(content, preview["config"])
            self.assertEqual(sibling.read_text(encoding="utf-8"), "tcp: {}\n")
            self.assertEqual(
                [item["state"] for item in store.views()],
                ["enabled", "disabled"],
            )

            store.update(first.id, web_route(container_port=8081))
            store.preview()
            store.set_enabled(first.id, False)
            with self.assertRaises(ConflictError):
                store.publish()

    def test_publish_writes_redacted_basic_auth_middleware_and_users_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "dynamic" / "ui-web-routes.yml"
            config.parent.mkdir()
            password_hash = hash_basic_auth_password("secret-" + "x" * 32)
            store = WebRouteStore(root / "data", config)
            store.create(
                web_route(
                    basic_auth_username="comic-reader",
                    basic_auth_password_hash=password_hash,
                )
            )

            preview = store.preview()
            self.assertIn("basicAuth:", preview["config"])
            self.assertIn("usersFile:", preview["config"])
            self.assertIn("removeHeader: true", preview["config"])
            self.assertNotIn(password_hash, preview["config"])
            self.assertTrue(preview["routes"][0]["basic_auth_enabled"])

            store.publish()
            auth_files = list(config.parent.glob("ui-web-*-auth-*.htpasswd"))
            self.assertEqual(len(auth_files), 1)
            self.assertEqual(
                auth_files[0].read_text(encoding="utf-8"),
                f"comic-reader:{password_hash}\n",
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(auth_files[0].stat().st_mode), 0o600)
            view = store.views()[0]
            self.assertTrue(view["basic_auth_enabled"])
            self.assertEqual(view["basic_auth_username"], "comic-reader")
            self.assertNotIn("basic_auth_password_hash", view)

    def test_rejects_duplicate_name_and_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WebRouteStore(root / "data", root / "dynamic" / "ui-web-routes.yml")
            store.create(web_route())
            with self.assertRaises(ConflictError):
                store.create(web_route(hostname="other.example.jp"))
            with self.assertRaises(ConflictError):
                store.create(web_route(name="other"))

    def test_soft_delete_cancel_and_history_purge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WebRouteStore(root / "data", root / "dynamic" / "ui-web-routes.yml")
            created = store.create(web_route())
            store.preview()
            store.publish()
            self.assertFalse(store.delete(created.id))
            self.assertEqual(store.views()[0]["state"], "pending_delete")
            store.cancel_delete(created.id)
            self.assertEqual(store.views()[0]["state"], "enabled")
            store.delete(created.id)
            store.preview()
            store.publish()
            self.assertEqual(store.views()[0]["state"], "deleted")
            store.purge_deleted(created.id)
            self.assertEqual(store.views(), [])

    def test_failed_write_locks_changes_and_retry_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocked = root / "not-a-directory"
            blocked.write_text("blocked", encoding="utf-8")
            store = WebRouteStore(root / "data", blocked / "ui-web-routes.yml")
            store.create(web_route())
            store.preview()
            with self.assertRaises(DashboardError):
                store.publish()
            with self.assertRaises(ConflictError):
                store.create(web_route(name="other", hostname="other.example.jp"))

            dynamic = root / "dynamic"
            store.dynamic_config_path = dynamic / "ui-web-routes.yml"
            result = store.publish()
            self.assertTrue(result["recovered"])
            self.assertEqual(store.views()[0]["state"], "enabled")

    def test_refuses_to_overwrite_unmanaged_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "dynamic" / "ui-web-routes.yml"
            config.parent.mkdir()
            config.write_text("http: {}\n", encoding="utf-8")
            store = WebRouteStore(root / "data", config)
            store.create(web_route())
            store.preview()
            with self.assertRaises(ConflictError):
                store.publish()
            self.assertEqual(config.read_text(encoding="utf-8"), "http: {}\n")
            self.assertFalse(store.status()["publish_recovery_required"])


class PortExpressionTests(unittest.TestCase):
    def test_parses_numbers_ranges_and_whitespace(self) -> None:
        self.assertEqual(
            parse_port_expression(" 8000-8003, 8080,9000-9001 "),
            [8000, 8001, 8002, 8003, 8080, 9000, 9001],
        )

    def test_rejects_invalid_duplicate_and_protected_ports(self) -> None:
        for expression in (
            "",
            "8000,,8001",
            "8010-8000",
            "8000-8002,8001",
            "0",
            "65536",
            "22",
            "51820",
        ):
            with self.subTest(expression=expression), self.assertRaises(ValidationError):
                parse_port_expression(expression)

    def test_enforces_64_port_limit(self) -> None:
        self.assertEqual(len(parse_port_expression("1000-1063")), 64)
        with self.assertRaises(ValidationError):
            parse_port_expression("1000-1064")

    def test_compacts_contiguous_ports(self) -> None:
        self.assertEqual(
            compact_port_ranges([8000, 8001, 8002, 8004, 9000, 9000]),
            [
                {"min": 8000, "max": 8002},
                {"min": 8004, "max": 8004},
                {"min": 9000, "max": 9000},
            ],
        )


class RouteStoreTests(unittest.TestCase):
    def test_web_gateway_setup_is_atomic_when_second_port_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            store.create(
                route(
                    name="other-https",
                    public_port=443,
                    target_address="10.99.0.3",
                    target_port=8443,
                )
            )
            with self.assertRaises(ConflictError):
                store.setup_web_gateway("10.99.0.2")
            self.assertEqual(
                [(item["public_port"], item["target_address"]) for item in store.views()],
                [(443, "10.99.0.3")],
            )

    def test_unapplied_create_update_and_delete_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            created = store.create(route())
            self.assertEqual([item.name for item in store.list()], ["minecraft"])
            self.assertEqual(store.views()[0]["state"], "pending_create")

            store.update(created.id, route(name="minecraft-main", target_port=41409))
            self.assertEqual(store.list()[0].name, "minecraft-main")
            self.assertEqual(store.list()[0].target_port, 41409)

            cancelled = store.delete(created.id)
            self.assertTrue(cancelled)
            self.assertEqual(store.list(), [])
            payload = json.loads((Path(directory) / "routes.json").read_text())
            self.assertEqual(payload["version"], 4)
            self.assertEqual(payload["records"], [])

    def test_migrates_v1_routes_as_applied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text(
                json.dumps({"version": 1, "routes": [route().__dict__]}),
                encoding="utf-8",
            )

            store = RouteStore(Path(directory))
            views = store.views()

            self.assertEqual(views[0]["state"], "enabled")
            self.assertEqual(json.loads(path.read_text())["version"], 4)
            backup = Path(directory) / "routes.json.v1.bak"
            self.assertTrue(backup.is_file())
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_applied_update_delete_restore_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            created = store.create(route())
            store.mark_terraform_applied()
            self.assertEqual(store.views()[0]["state"], "pending_relay")
            store.commit_relay_sync()
            self.assertEqual(store.views()[0]["state"], "enabled")

            store.update(created.id, route(target_port=41409))
            self.assertEqual(store.views()[0]["state"], "pending_update")
            store.update(created.id, route())
            self.assertEqual(store.views()[0]["state"], "enabled")

            self.assertFalse(store.delete(created.id))
            self.assertEqual(store.views()[0]["state"], "pending_delete")
            store.cancel_delete(created.id)
            self.assertEqual(store.views()[0]["state"], "enabled")

            store.delete(created.id)
            store.mark_terraform_applied()
            reloaded = RouteStore(Path(directory))
            self.assertTrue(reloaded.has_pending_relay())
            self.assertEqual(reloaded.relay_sync_routes(), [])
            with self.assertRaises(ConflictError):
                reloaded.create(route(name="blocked", public_port=25566))
            reloaded.commit_relay_sync()

            deleted = reloaded.views()[0]
            self.assertEqual(deleted["state"], "deleted")
            self.assertEqual(reloaded.list(), [])
            self.assertEqual(reloaded.applied(), [])
            reloaded.purge_deleted(created.id)
            self.assertEqual(reloaded.views(), [])

    def test_normal_relay_sync_uses_last_applied_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            applied = store.create(route())
            store.mark_terraform_applied()
            store.commit_relay_sync()
            store.update(applied.id, route(target_port=41409))
            store.create(route(name="new", public_port=25566))

            sync_routes = store.relay_sync_routes()

            self.assertEqual(len(sync_routes), 1)
            self.assertEqual(sync_routes[0].target_port, 25565)

    def test_pending_relay_marks_only_changed_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            changed = store.create(route())
            store.create(route(name="unchanged", public_port=25566))
            store.mark_terraform_applied()
            store.commit_relay_sync()
            store.update(changed.id, route(target_port=41409))

            store.mark_terraform_applied()
            states = {item["name"]: item["state"] for item in store.views()}

            self.assertEqual(states["minecraft"], "pending_relay")
            self.assertEqual(states["unchanged"], "enabled")

    def test_uses_configured_wireguard_network_when_reloading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(
                Path(directory),
                relay_network="10.42.0.0/24",
                relay_address="10.42.0.1",
            )
            custom_route = Route.from_mapping(
                {
                    "name": "custom",
                    "protocol": "udp",
                    "public_port": 8211,
                    "target_address": "10.42.0.2",
                    "target_port": 8211,
                },
                relay_network="10.42.0.0/24",
                relay_address="10.42.0.1",
            )
            store.create(custom_route)

            self.assertEqual(store.list()[0].target_address, "10.42.0.2")

    def test_enable_disable_state_machine_and_listener_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            created = store.create(route())
            store.set_enabled(created.id, False)
            self.assertEqual(store.views()[0]["state"], "disabled")
            self.assertEqual(store.list(), [])
            with self.assertRaises(ConflictError):
                store.create(route(name="duplicate"))

            store.set_enabled(created.id, True)
            self.assertEqual(store.views()[0]["state"], "pending_create")
            store.mark_terraform_applied()
            store.commit_relay_sync()
            self.assertEqual(store.views()[0]["state"], "enabled")

            store.set_enabled(created.id, False)
            self.assertEqual(store.views()[0]["state"], "pending_disable")
            store.set_enabled(created.id, True)
            self.assertEqual(store.views()[0]["state"], "enabled")
            store.set_enabled(created.id, False)
            store.mark_terraform_applied()
            store.commit_relay_sync()
            self.assertEqual(store.views()[0]["state"], "disabled")
            self.assertEqual(store.applied(), [])
            store.set_enabled(created.id, True)
            self.assertEqual(store.views()[0]["state"], "pending_enable")

    def test_creates_mixed_protocol_group_and_bulk_toggles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            group = store.create_group(
                "game",
                "ゲーム用",
                [
                    {
                        "protocol": "tcp",
                        "ports": "8000-8015",
                        "target_address": "10.99.0.2",
                    },
                    {
                        "protocol": "udp",
                        "ports": "9000",
                        "target_address": "10.99.0.2",
                    },
                ],
            )

            self.assertEqual(len(store.views()), 17)
            self.assertEqual(store.views()[0]["group_id"], group.id)
            self.assertEqual(store.group_views()[0]["enabled_state"], "enabled")
            self.assertEqual(
                {item["protocol"] for item in store.views()},
                {"tcp", "udp"},
            )

            store.set_group_enabled(group.id, False)
            self.assertTrue(
                all(item["state"] == "disabled" for item in store.views())
            )
            self.assertEqual(store.group_views()[0]["enabled_state"], "disabled")
            store.set_enabled(store.records()[0].id, True)
            self.assertEqual(store.group_views()[0]["enabled_state"], "mixed")

    def test_nested_groups_aggregate_toggle_and_promote_on_delete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            parent = store.create_group("games")
            child = store.create_group(
                "survival",
                members=[
                    {
                        "protocol": "tcp",
                        "ports": "25565",
                        "target_address": "10.99.0.2",
                    }
                ],
                parent_id=parent.id,
            )
            grandchild = store.create_group(
                "voice",
                members=[
                    {
                        "protocol": "udp",
                        "ports": "24454",
                        "target_address": "10.99.0.2",
                    }
                ],
                parent_id=child.id,
            )

            groups = {group["name"]: group for group in store.group_views()}
            self.assertEqual(groups["games"]["total_ports"], 2)
            self.assertEqual(groups["survival"]["total_ports"], 2)
            self.assertEqual(groups["voice"]["total_ports"], 1)
            self.assertEqual(groups["survival"]["parent_id"], parent.id)

            updated_child = store.update_group(child.id, "survival", "更新済み")
            self.assertEqual(updated_child.parent_id, parent.id)
            store.set_group_enabled(parent.id, False)
            self.assertTrue(
                all(item["state"] == "disabled" for item in store.views())
            )
            with self.assertRaises(ValidationError):
                store.update_group(parent.id, "games", parent_id=grandchild.id)

            store.delete_group(child.id)
            promoted_groups = {
                group["name"]: group for group in store.group_views()
            }
            self.assertEqual(promoted_groups["voice"]["parent_id"], parent.id)
            route_groups = {
                item["name"]: item["group_id"] for item in store.views()
            }
            self.assertEqual(route_groups["survival-tcp-25565"], parent.id)
            self.assertEqual(route_groups["voice-udp-24454"], grandchild.id)

    def test_bulk_group_creation_is_atomic_on_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            store.create(route(public_port=8000))

            with self.assertRaises(ConflictError):
                store.create_group(
                    "game",
                    members=[
                        {
                            "protocol": "tcp",
                            "ports": "8000-8001",
                            "target_address": "10.99.0.2",
                        }
                    ],
                )

            self.assertEqual(store.group_views(), [])
            self.assertEqual(len(store.views()), 1)

    def test_existing_route_can_move_groups_without_renaming(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            created = store.create(route())
            store.mark_terraform_applied()
            store.commit_relay_sync()
            group = store.create_group("game")

            updated = store.update(created.id, route(), group.id)

            self.assertEqual(updated.route.name, "minecraft")
            self.assertEqual(store.views()[0]["group_id"], group.id)
            self.assertEqual(store.views()[0]["state"], "enabled")

    def test_migrates_v2_pending_relay_and_creates_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            route_value = route().__dict__
            stable_value = route(name="stable", public_port=25566).__dict__
            deleting_value = route(name="deleting", public_port=25567).__dict__
            deleted_value = route(name="deleted", public_port=25568).__dict__
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "records": [
                            {
                                "id": "route-id",
                                "route": route_value,
                                "applied_route": route_value,
                                "desired_active": True,
                                "created_at": "2026-01-01T00:00:00+00:00",
                                "updated_at": "2026-01-01T00:00:00+00:00",
                                "applied_at": "2026-01-01T00:00:00+00:00",
                                "deleted_at": None,
                            },
                            {
                                "id": "stable-id",
                                "route": stable_value,
                                "applied_route": stable_value,
                                "desired_active": True,
                                "created_at": "2026-01-01T00:00:00+00:00",
                                "updated_at": "2026-01-01T00:00:00+00:00",
                                "applied_at": "2026-01-01T00:00:00+00:00",
                                "deleted_at": None,
                            },
                            {
                                "id": "deleting-id",
                                "route": deleting_value,
                                "applied_route": deleting_value,
                                "desired_active": False,
                                "created_at": "2026-01-01T00:00:00+00:00",
                                "updated_at": "2026-01-01T00:00:00+00:00",
                                "applied_at": "2026-01-01T00:00:00+00:00",
                                "deleted_at": None,
                            },
                            {
                                "id": "deleted-id",
                                "route": deleted_value,
                                "applied_route": None,
                                "desired_active": False,
                                "created_at": "2026-01-01T00:00:00+00:00",
                                "updated_at": "2026-01-01T00:00:00+00:00",
                                "applied_at": "2026-01-01T00:00:00+00:00",
                                "deleted_at": "2026-01-02T00:00:00+00:00",
                            }
                        ],
                        "pending_relay": {
                            "active": [
                                {"id": "route-id", "route": route_value},
                                {"id": "stable-id", "route": stable_value},
                            ],
                            "deleted_ids": ["deleting-id"],
                            "changed_ids": ["route-id"],
                        },
                    }
                ),
                encoding="utf-8",
            )

            store = RouteStore(Path(directory))

            states = {item["name"]: item["state"] for item in store.views()}
            self.assertEqual(
                states,
                {
                    "minecraft": "pending_relay",
                    "stable": "enabled",
                    "deleting": "pending_delete",
                    "deleted": "deleted",
                },
            )
            self.assertTrue(store.has_pending_relay())
            backup = Path(directory) / "routes.json.v2.bak"
            self.assertTrue(backup.is_file())
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text())["version"], 4)

    def test_migrates_v3_groups_to_parent_aware_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "groups": [
                            {
                                "id": "group-id",
                                "name": "game",
                                "description": "ゲーム用",
                                "created_at": "2026-01-01T00:00:00+00:00",
                                "updated_at": "2026-01-01T00:00:00+00:00",
                            }
                        ],
                        "records": [],
                        "pending_relay": None,
                    }
                ),
                encoding="utf-8",
            )

            store = RouteStore(Path(directory))

            self.assertIsNone(store.groups()[0].parent_id)
            self.assertEqual(json.loads(path.read_text())["version"], 4)
            backup = Path(directory) / "routes.json.v3.bak"
            self.assertTrue(backup.is_file())
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)


class RelayParsingTests(unittest.TestCase):
    def test_parses_tsv(self) -> None:
        parsed = parse_relay_routes(
            "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
            "minecraft\ttcp\t25565\t10.99.0.2:25565\n"
            "ui-palworld\tudp\t8211\t10.99.0.2:8211\n"
        )
        self.assertEqual(parsed["minecraft"].public_port, 25565)
        self.assertEqual(parsed["ui-palworld"].target_port, 8211)

    def test_dashboard_sync_preserves_manual_rules(self) -> None:
        commands: list[list[str]] = []

        def runner(
            command: list[str],
            environment: dict[str, str],
            cwd: Path | None,
            timeout: int,
        ) -> CommandResult:
            commands.append(command)
            if command[-2:] == ["forward", "list"]:
                return CommandResult(
                    0,
                    "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
                    "manual-rule\ttcp\t41408\t10.99.0.2:41408\n"
                    "ui-minecraft\ttcp\t25565\t10.99.0.2:41409\n",
                    "",
                )
            return CommandResult(0, "", "")

        manager = RelayManager(Path("/workspace/scripts/wg-relay.sh"), "oci-relay", runner)
        actions = manager.sync([route(target_port=25565)])
        self.assertTrue(commands)
        expected_script = str(Path("/workspace/scripts/wg-relay.sh"))
        self.assertTrue(
            all(
                command[:2] == ["bash", expected_script]
                for command in commands
            )
        )
        command_arguments = [item[2:] for item in commands]

        self.assertIn(
            ["forward", "delete", "ui-minecraft", "--yes"],
            command_arguments,
        )
        self.assertIn(
            [
                "forward",
                "add",
                "ui-minecraft",
                "--protocol",
                "tcp",
                "--listen-port",
                "25565",
                "--target-address",
                "10.99.0.2",
                "--target-port",
                "25565",
            ],
            command_arguments,
        )
        self.assertFalse(any("manual-rule" in command for command in command_arguments))
        self.assertEqual(len(actions), 2)

    def test_detects_manual_listener_conflict(self) -> None:
        manager = RelayManager(Path("/workspace/scripts/wg-relay.sh"), "oci-relay")
        actual = parse_relay_routes(
            "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
            "manual-minecraft\ttcp\t25565\t10.99.0.2:41409\n"
        )
        conflicts = manager.check_conflicts([route()], actual)
        self.assertEqual(len(conflicts), 1)
        self.assertIn("manual-minecraft", conflicts[0])

    def test_adopts_exact_manual_listener_match(self) -> None:
        commands: list[list[str]] = []

        def runner(
            command: list[str],
            environment: dict[str, str],
            cwd: Path | None,
            timeout: int,
        ) -> CommandResult:
            commands.append(command)
            if command[-2:] == ["forward", "list"]:
                return CommandResult(
                    0,
                    "NAME\tPROTOCOL\tPUBLIC_PORT\tTARGET\n"
                    "minecraft\ttcp\t25565\t10.99.0.2:25565\n",
                    "",
                )
            return CommandResult(0, "", "")

        manager = RelayManager(
            Path("/workspace/scripts/wg-relay.sh"),
            "oci-relay",
            runner,
        )
        actual = manager.list()

        self.assertEqual(manager.check_conflicts([route()], actual), [])
        self.assertEqual(
            manager.adoptions([route()], actual),
            [
                {
                    "manual_name": "minecraft",
                    "managed_name": "ui-minecraft",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_address": "10.99.0.2",
                    "target_port": 25565,
                }
            ],
        )

        actions = manager.sync([route()])
        command_arguments = [item[2:] for item in commands]
        self.assertIn(
            ["forward", "delete", "minecraft", "--yes"],
            command_arguments,
        )
        self.assertIn(
            [
                "forward",
                "add",
                "ui-minecraft",
                "--protocol",
                "tcp",
                "--listen-port",
                "25565",
                "--target-address",
                "10.99.0.2",
                "--target-port",
                "25565",
            ],
            command_arguments,
        )
        self.assertIn("移管: minecraft → ui-minecraft", actions)


class WireGuardManagementTests(unittest.TestCase):
    def test_parses_peers_status_and_access_rules(self) -> None:
        peers = parse_wireguard_peers(
            "NAME\tADDRESS\tPUBLIC_KEY\n"
            "windows-minibox\t10.99.0.2/32\twindows-key\n"
            "mac-admin\t10.99.0.3/32\tmac-key\n"
        )
        statuses = parse_wireguard_status(
            "interface: wg0\n"
            "peer: mac-key\n"
            "  endpoint: 203.0.113.10:12345\n"
            "  latest handshake: 42 seconds ago\n"
            "  transfer: 1.2 MiB received, 3.4 MiB sent\n"
        )
        rules = parse_peer_access_rules(
            "NAME\tPROTOCOL\tSOURCE\tTARGET\n"
            "mac-to-dashboard\ttcp\t10.99.0.3\t10.99.0.2:8081\n"
        )

        self.assertEqual(peers["windows-minibox"].address, "10.99.0.2")
        self.assertEqual(statuses["mac-key"]["latest_handshake"], "42 seconds ago")
        self.assertEqual(rules["mac-to-dashboard"].target_port, 8081)

    def test_validates_and_suggests_peer_addresses(self) -> None:
        peers = [
            WireGuardPeer("windows", "10.99.0.2", "10.99.0.2/32", "key1"),
            WireGuardPeer("mac", "10.99.0.3", "10.99.0.3/32", "key2"),
        ]

        self.assertEqual(
            normalize_peer_address("10.99.0.4"),
            "10.99.0.4/32",
        )
        self.assertEqual(
            suggest_peer_address(peers, "10.99.0.0/24", "10.99.0.1"),
            "10.99.0.4",
        )
        for invalid in ("10.99.0.1", "10.99.0.4/24", "192.168.1.2"):
            with self.subTest(address=invalid), self.assertRaises(ValidationError):
                normalize_peer_address(invalid)

    def test_validates_peer_access_rule(self) -> None:
        rule = PeerAccessRule.from_mapping(
            {
                "name": "mac-to-dashboard",
                "protocol": "TCP",
                "source_address": "10.99.0.3",
                "target_address": "10.99.0.2",
                "target_port": "8081",
            }
        )
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.target_port, 8081)

        with self.assertRaises(ValidationError):
            PeerAccessRule.from_mapping(
                {
                    "name": "same-peer",
                    "protocol": "tcp",
                    "source_address": "10.99.0.3",
                    "target_address": "10.99.0.3",
                    "target_port": 8081,
                }
            )

    def test_manager_generates_peer_config_on_stdout_and_access_commands(self) -> None:
        commands: list[list[str]] = []

        def runner(
            command: list[str],
            environment: dict[str, str],
            cwd: Path | None,
            timeout: int,
        ) -> CommandResult:
            commands.append(command[2:])
            if command[2:] == ["list"]:
                return CommandResult(
                    0,
                    "NAME\tADDRESS\tPUBLIC_KEY\n"
                    "laptop\t10.99.0.4/32\tlaptop-key\n",
                    "",
                )
            if "--output" in command:
                return CommandResult(
                    0,
                    "[Interface]\nPrivateKey = generated\nAddress = 10.99.0.4/32",
                    "",
                )
            return CommandResult(0, "", "")

        manager = RelayManager(Path("/workspace/scripts/wg-relay.sh"), "oci-relay", runner)
        name, config = manager.create_peer(
            "laptop",
            "10.99.0.4",
            "10.99.0.0/24",
            "10.99.0.1",
        )
        rotated_name, rotated_config = manager.rotate_peer("laptop")
        rule = PeerAccessRule(
            "laptop-to-dashboard",
            "tcp",
            "10.99.0.4",
            "10.99.0.2",
            8081,
        )
        manager.create_peer_access_rule(rule)
        manager.update_peer_access_rule(rule)
        manager.delete_peer_access_rule(rule.name)

        self.assertEqual(name, "laptop")
        self.assertEqual(rotated_name, "laptop")
        self.assertTrue(config.endswith("\n"))
        self.assertTrue(rotated_config.startswith("[Interface]"))
        self.assertIn(
            [
                "add",
                "laptop",
                "--address",
                "10.99.0.4/32",
                "--output",
                "-",
            ],
            commands,
        )
        self.assertIn(
            [
                "peer-forward",
                "add",
                "laptop-to-dashboard",
                "--protocol",
                "tcp",
                "--source-address",
                "10.99.0.4",
                "--target-address",
                "10.99.0.2",
                "--target-port",
                "8081",
            ],
            commands,
        )


class RelayScriptTests(unittest.TestCase):
    def test_uses_runtime_home_ssh_config(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            binary_directory = temporary / "bin"
            ssh_directory = temporary / ".ssh"
            binary_directory.mkdir()
            ssh_directory.mkdir()
            ssh_config = ssh_directory / "config"
            ssh_config.write_text("Host oci-relay\n", encoding="utf-8")
            capture = temporary / "ssh-arguments"
            fake_ssh = binary_directory / "ssh"
            fake_ssh.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$@" >"$WG_RELAY_TEST_CAPTURE"\n'
                "printf 'NAME\\tPROTOCOL\\tPUBLIC_PORT\\tTARGET\\n'\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(temporary),
                    "PATH": f"{binary_directory}:{environment['PATH']}",
                    "WG_RELAY_TEST_CAPTURE": str(capture),
                }
            )
            environment.pop("WG_RELAY_SSH_CONFIG", None)

            result = subprocess.run(
                [
                    "bash",
                    str(project_root / "scripts/wg-relay.sh"),
                    "forward",
                    "list",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                capture.read_text(encoding="utf-8").splitlines()[:3],
                ["-F", str(ssh_config), "oci-relay"],
            )

    def test_can_stream_generated_peer_config_without_writing_a_file(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            binary_directory = temporary / "bin"
            ssh_directory = temporary / ".ssh"
            binary_directory.mkdir()
            ssh_directory.mkdir()
            (ssh_directory / "config").write_text("Host oci-relay\n", encoding="utf-8")
            fake_ssh = binary_directory / "ssh"
            fake_ssh.write_text(
                "#!/bin/sh\n"
                "printf '[Interface]\\nPrivateKey = generated\\nAddress = 10.99.0.4/32\\n'\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(temporary),
                    "PATH": f"{binary_directory}:{environment['PATH']}",
                }
            )

            result = subprocess.run(
                [
                    "bash",
                    str(project_root / "scripts/wg-relay.sh"),
                    "add",
                    "laptop",
                    "--address",
                    "10.99.0.4/32",
                    "--output",
                    "-",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith("[Interface]"))
            self.assertFalse((project_root / "generated/wireguard/laptop.conf").exists())


class OciConfigTests(unittest.TestCase):
    def test_accepts_complete_default_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_text(
                "[DEFAULT]\n"
                "tenancy=ocid1.tenancy.example\n"
                "user=ocid1.user.example\n"
                "fingerprint=00:11\n"
                "region=ap-tokyo-1\n"
                "key_file=/run/relay-home/.oci/oci_api_key.pem\n",
                encoding="utf-8",
            )

            self.assertEqual(oci_config_status(config), (True, "DEFAULTを読込可能"))

    def test_rejects_empty_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_text("", encoding="utf-8")

            ok, detail = oci_config_status(config)

            self.assertFalse(ok)
            self.assertIn("DEFAULTに必須項目がありません", detail)


class TerraformPlanAnalysisTests(unittest.TestCase):
    def test_allows_only_public_nsg_rules(self) -> None:
        plan = {
            "resource_changes": [
                {
                    "address": (
                        'oci_core_network_security_group_security_rule.'
                        'public_tcp["25565:0.0.0.0/0"]'
                    ),
                    "change": {"actions": ["create"]},
                },
                {
                    "address": "oci_core_instance.relay_image[0]",
                    "change": {"actions": ["no-op"]},
                },
            ]
        }
        analysis = analyze_terraform_plan(plan)
        self.assertTrue(analysis["safe"])
        self.assertEqual(analysis["counts"]["create"], 1)

    def test_blocks_instance_change(self) -> None:
        plan = {
            "resource_changes": [
                {
                    "address": "oci_core_instance.relay_image[0]",
                    "change": {"actions": ["delete", "create"]},
                }
            ]
        }
        analysis = analyze_terraform_plan(plan)
        self.assertFalse(analysis["safe"])
        self.assertEqual(analysis["unexpected"][0]["address"], "oci_core_instance.relay_image[0]")
        self.assertEqual(analysis["counts"]["replace"], 1)

    def test_prepares_ephemeral_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as data_directory:
            source = Path(source_directory)
            for name in ("versions.tf", "variables.tf", "terraform.tfvars", "cloud-init.yaml"):
                (source / name).write_text(f"# {name}\n", encoding="utf-8")

            manager = TerraformManager(source, Path(data_directory))
            manager.workspace = Path(data_directory) / "runtime"
            manager.prepare_workspace()

            self.assertTrue((manager.workspace / "versions.tf").is_file())
            self.assertTrue((manager.workspace / "terraform.tfvars").is_file())
            self.assertFalse((manager.workspace / "unrelated.txt").exists())
            self.assertEqual(
                manager._environment()["TMPDIR"],
                str(Path(data_directory) / "tmp"),
            )
            self.assertEqual(
                manager._environment()["TF_HOME_OVERRIDE"],
                str(manager.runtime_home),
            )
            self.assertEqual(
                manager._environment()["OCI_HOME_OVERRIDE"],
                str(manager.runtime_home),
            )
            self.assertTrue((Path(data_directory) / "tmp").is_dir())

    def test_writes_compacted_protocol_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as data_directory:
            manager = TerraformManager(Path(source_directory), Path(data_directory))
            manager.write_var_file(
                [
                    route(name="tcp-one", public_port=8000),
                    route(name="tcp-two", public_port=8001),
                    route(name="tcp-four", public_port=8003),
                    route(name="udp-one", protocol="udp", public_port=9000),
                ]
            )

            payload = json.loads(manager.var_file.read_text(encoding="utf-8"))

            self.assertEqual(
                payload["dashboard_public_tcp_port_ranges"],
                [{"min": 8000, "max": 8001}, {"min": 8003, "max": 8003}],
            )
            self.assertEqual(
                payload["dashboard_public_udp_port_ranges"],
                [{"min": 9000, "max": 9000}],
            )


if __name__ == "__main__":
    unittest.main()

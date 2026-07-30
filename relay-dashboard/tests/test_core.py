from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dashboard.core import (
    CommandResult,
    ConflictError,
    RelayManager,
    Route,
    RouteStore,
    TerraformManager,
    ValidationError,
    analyze_terraform_plan,
    parse_relay_routes,
    routes_fingerprint,
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


class RouteStoreTests(unittest.TestCase):
    def test_crud_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RouteStore(Path(directory))
            store.create(route())
            self.assertEqual([item.name for item in store.list()], ["minecraft"])

            store.update("minecraft", route(name="minecraft-main", target_port=41409))
            self.assertEqual(store.list()[0].name, "minecraft-main")
            self.assertEqual(store.list()[0].target_port, 41409)

            store.delete("minecraft-main")
            self.assertEqual(store.list(), [])
            payload = json.loads((Path(directory) / "routes.json").read_text())
            self.assertEqual(payload["version"], 1)

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
        self.assertTrue(
            all(
                command[:2] == ["bash", "/workspace/scripts/wg-relay.sh"]
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
            "manual-minecraft\ttcp\t25565\t10.99.0.2:25565\n"
        )
        conflicts = manager.check_conflicts([route()], actual)
        self.assertEqual(len(conflicts), 1)
        self.assertIn("manual-minecraft", conflicts[0])


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


if __name__ == "__main__":
    unittest.main()

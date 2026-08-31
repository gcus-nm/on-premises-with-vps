from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class WireGuardRelayRemoteScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remote_script = (
            PROJECT_ROOT / "scripts" / "wg-relay-remote.sh"
        ).read_text(encoding="utf-8")
        cls.local_script = (PROJECT_ROOT / "scripts" / "wg-relay.sh").read_text(
            encoding="utf-8"
        )

    def test_renders_fixed_mtu_for_server_and_clients(self) -> None:
        self.assertIn('readonly DEFAULT_MTU="1380"', self.remote_script)
        self.assertIn("printf 'MTU = %s\\n'", self.remote_script)
        self.assertIn("MTU = ${mtu}", self.remote_script)
        self.assertIn("printf 'MTU=%s\\n'", self.remote_script)

    def test_clamps_forwarded_tcp_and_removes_managed_chain(self) -> None:
        self.assertIn('readonly FORWARD_MANGLE_CHAIN="WG_RELAY_MANGLE"', self.remote_script)
        self.assertIn("--clamp-mss-to-pmtu", self.remote_script)
        self.assertIn(
            'remove_jump mangle FORWARD "${FORWARD_MANGLE_CHAIN}"',
            self.remote_script,
        )
        self.assertIn(
            'remove_chain mangle "${FORWARD_MANGLE_CHAIN}"',
            self.remote_script,
        )
        self.assertIn("printf '\\nTCP MSS rules:\\n'", self.remote_script)

    def test_local_init_passes_mtu_to_remote_manager(self) -> None:
        self.assertIn('local mtu="1380"', self.local_script)
        self.assertIn('--mtu "${mtu}"', self.local_script)

    def test_local_init_prefers_ipv6_endpoint_with_ipv4_fallback(self) -> None:
        ipv6_lookup = "terraform output -raw wireguard_endpoint_ipv6"
        ipv4_lookup = "terraform output -raw wireguard_endpoint_ipv4"
        self.assertIn(ipv6_lookup, self.local_script)
        self.assertIn(ipv4_lookup, self.local_script)
        self.assertLess(
            self.local_script.index(ipv6_lookup),
            self.local_script.index(ipv4_lookup),
        )
        self.assertIn("falling back to IPv4", self.local_script)

    def test_endpoint_update_does_not_restart_active_peers(self) -> None:
        self.assertIn("endpoint_remote", self.local_script)
        self.assertIn("endpoint_command", self.remote_script)
        endpoint_function = self.remote_script.split("endpoint_command() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn('set_setting PUBLIC_ENDPOINT "${endpoint}"', endpoint_function)
        self.assertNotIn("systemctl", endpoint_function)
        self.assertNotIn("sync_interface", endpoint_function)

    def test_tunnel_ipv6_is_added_without_replacing_ipv4(self) -> None:
        self.assertIn(
            'readonly DEFAULT_SERVER_IPV6_ADDRESS="fdae:3e62:c345:99::1/64"',
            self.local_script,
        )
        self.assertIn('printf \'Address = %s, %s\\n\'', self.remote_script)
        self.assertIn('printf \'AllowedIPs = %s, %s\\n\'', self.remote_script)
        self.assertIn('ip -6 address replace "$(server_ipv6_address)" dev wg0', self.remote_script)
        self.assertIn("firewall_sync_ipv6", self.remote_script)
        self.assertIn("ip6tables -w -t filter", self.remote_script)


if __name__ == "__main__":
    unittest.main()

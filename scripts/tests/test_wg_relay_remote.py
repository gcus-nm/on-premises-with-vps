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


if __name__ == "__main__":
    unittest.main()

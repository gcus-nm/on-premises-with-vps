from __future__ import annotations

import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "mydns-notify-remote.py"
SPEC = importlib.util.spec_from_file_location("mydns_notify_remote", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
mydns_notify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mydns_notify)


class MyDNSNotifyTests(unittest.TestCase):
    def test_validate_hostname_normalizes_case_and_trailing_dot(self) -> None:
        self.assertEqual(
            mydns_notify.validate_hostname("OCI.Example.MyDNS.JP."),
            "oci.example.mydns.jp",
        )

    def test_validate_hostname_rejects_invalid_label(self) -> None:
        with self.assertRaises(mydns_notify.MyDNSNotifyError):
            mydns_notify.validate_hostname("-oci.example.mydns.jp")

    def test_notification_requires_both_success_markers(self) -> None:
        self.assertTrue(
            mydns_notify.notification_succeeded(
                "Login and IP address notify OK.<BR>login_status = 1.<BR>"
            )
        )
        self.assertFalse(
            mydns_notify.notification_succeeded("Login and IP address notify OK.")
        )

    def test_request_uses_basic_auth_without_credentials_in_url(self) -> None:
        request = mydns_notify.build_request(
            {
                "hostname": "oci.example.mydns.jp",
                "child_id": "mydns123456",
                "password": "test-password",
            }
        )
        expected = base64.b64encode(b"mydns123456:test-password").decode("ascii")
        self.assertEqual(request.full_url, mydns_notify.NOTIFY_ENDPOINT)
        self.assertEqual(request.get_header("Authorization"), f"Basic {expected}")

    def test_load_config_rejects_group_readable_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "config.json"
            config_path.write_text(
                (
                    '{"hostname":"oci.example.mydns.jp",'
                    '"child_id":"mydns123456","password":"test-password"}'
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o640)
            with mock.patch.object(mydns_notify, "CONFIG_PATH", config_path):
                with self.assertRaises(mydns_notify.MyDNSNotifyError):
                    mydns_notify.load_config()

    def test_load_config_accepts_root_only_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "config.json"
            config_path.write_text(
                (
                    '{"hostname":"oci.example.mydns.jp",'
                    '"child_id":"mydns123456","password":"test-password"}'
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            with mock.patch.object(mydns_notify, "CONFIG_PATH", config_path):
                config = mydns_notify.load_config()
            self.assertEqual(config["hostname"], "oci.example.mydns.jp")


if __name__ == "__main__":
    unittest.main()

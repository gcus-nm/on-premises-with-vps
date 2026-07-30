from __future__ import annotations

import re
import unittest
from pathlib import Path


VARIABLE_WITH_NON_ASCII_SUFFIX = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7f]"
)


class PowerShellCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        project_root = Path(__file__).resolve().parents[2]
        cls.scripts = sorted(
            [
                *project_root.glob("relay-dashboard/*.ps1"),
                *project_root.glob("scripts/*.ps1"),
            ]
        )

    def test_scripts_use_utf8_bom_for_windows_powershell_51(self) -> None:
        for script in self.scripts:
            with self.subTest(script=script.name):
                self.assertTrue(script.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_ascii_variable_names_are_delimited_before_japanese_text(self) -> None:
        for script in self.scripts:
            with self.subTest(script=script.name):
                content = script.read_text(encoding="utf-8-sig")
                self.assertIsNone(
                    VARIABLE_WITH_NON_ASCII_SUFFIX.search(content),
                    "Use ${name} when Japanese text immediately follows a variable.",
                )


if __name__ == "__main__":
    unittest.main()

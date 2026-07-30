from __future__ import annotations

import unittest
from html.parser import HTMLParser
from pathlib import Path


class RouteDialogButtonParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_route_form = False
        self.cancel_buttons: list[dict[str, str | None]] = []

    def handle_starttag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attributes)
        if tag == "form" and values.get("id") == "route-form":
            self.in_route_form = True
        if (
            self.in_route_form
            and tag == "button"
            and values.get("value") == "cancel"
        ):
            self.cancel_buttons.append(values)

    def handle_endtag(self, tag: str) -> None:
        if self.in_route_form and tag == "form":
            self.in_route_form = False


class RouteDialogMarkupTests(unittest.TestCase):
    def test_cancel_buttons_bypass_required_field_validation(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        parser = RouteDialogButtonParser()
        parser.feed(
            (project_root / "relay-dashboard/static/index.html").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(len(parser.cancel_buttons), 2)
        for button in parser.cancel_buttons:
            self.assertEqual(button.get("type"), "submit")
            self.assertIn("formnovalidate", button)


if __name__ == "__main__":
    unittest.main()

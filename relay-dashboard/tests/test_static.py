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

    def test_hidden_elements_are_never_overridden_by_component_display(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        styles = (project_root / "relay-dashboard/static/styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("[hidden] {\n  display: none !important;\n}", styles)

    def test_route_state_tabs_and_actions_are_present(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        html = (project_root / "relay-dashboard/static/index.html").read_text(
            encoding="utf-8"
        )
        javascript = (project_root / "relay-dashboard/static/app.js").read_text(
            encoding="utf-8"
        )

        for route_filter in ("all", "enabled", "disabled", "pending", "deleted"):
            self.assertIn(f'data-route-filter="{route_filter}"', html)
        self.assertNotIn("data-cancel-delete", javascript)
        self.assertNotIn("data-purge-route", javascript)
        self.assertIn("/cancel-delete", javascript)
        self.assertIn("/api/deleted-routes/", javascript)
        self.assertIn("高度な操作", javascript)
        self.assertIn("data-route-toggle", javascript)
        self.assertIn("data-group-toggle", javascript)
        self.assertIn("data-group-collapse", javascript)
        self.assertIn("window.localStorage", javascript)
        self.assertIn("renderGroupTree", javascript)
        self.assertIn('pending_relay: "リレー同期待ち"', javascript)
        self.assertIn('id="group-dialog"', html)
        self.assertIn('id="group-parent"', html)
        self.assertIn('id="route-advanced"', html)

    def test_wireguard_peer_and_access_management_are_present(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        html = (project_root / "relay-dashboard/static/index.html").read_text(
            encoding="utf-8"
        )
        javascript = (project_root / "relay-dashboard/static/app.js").read_text(
            encoding="utf-8"
        )

        for element_id in (
            "wireguard-peer-list",
            "wireguard-access-list",
            "peer-dialog",
            "access-rule-dialog",
        ):
            self.assertIn(f'id="{element_id}"', html)
        for endpoint in (
            "/api/wireguard",
            "/api/wireguard/peers",
            "/api/wireguard/access-rules",
        ):
            self.assertIn(endpoint, javascript)
        self.assertIn("downloadClientConfig", javascript)


if __name__ == "__main__":
    unittest.main()

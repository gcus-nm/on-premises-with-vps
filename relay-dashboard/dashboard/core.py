from __future__ import annotations

import base64
import configparser
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable


ROUTE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,27}$")
DOCKER_ALIAS_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
BASIC_AUTH_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BASIC_AUTH_SHA1_PATTERN = re.compile(r"^\{SHA\}[A-Za-z0-9+/]{27}=$")
GROUP_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,17}$")
WIREGUARD_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
EXISTING_WIREGUARD_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
MANAGED_ROUTE_PREFIX = "ui-"
PROTECTED_PUBLIC_PORTS = {22, 51820}
MAX_BULK_PORTS = 64
ALLOWED_TERRAFORM_PREFIXES = (
    "oci_core_network_security_group_security_rule.public_tcp[",
    "oci_core_network_security_group_security_rule.public_udp[",
)


class DashboardError(Exception):
    """Expected error that can be shown to an operator."""


class ValidationError(DashboardError):
    """Input validation error."""


class ConflictError(DashboardError):
    """Route conflict error."""


class CommandError(DashboardError):
    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


class WireGuardQrEncoder:
    """Generate a scan-ready SVG without persisting the WireGuard profile."""

    def __init__(self, qr_factory: Callable[[str], Any] | None = None) -> None:
        self.qr_factory = qr_factory or make_wireguard_qr

    def generate(self, client_config: str) -> str:
        if not client_config.startswith("[Interface]"):
            raise CommandError("QRコードへ変換できるWireGuard接続設定ではありません。")
        try:
            output = io.BytesIO()
            self.qr_factory(client_config).save(
                output,
                kind="svg",
                scale=8,
                border=2,
                xmldecl=False,
            )
            svg = output.getvalue().decode("utf-8").strip()
        except (ImportError, OSError, UnicodeError, ValueError) as exc:
            raise CommandError("QRコードを生成できませんでした。") from exc
        if "<svg" not in svg or not svg.endswith("</svg>"):
            raise CommandError("QRコード生成結果がSVGではありません。")
        return svg + "\n"


def make_wireguard_qr(client_config: str) -> Any:
    try:
        import segno
    except ImportError as exc:
        raise CommandError("QRコード生成ライブラリを読み込めません。") from exc
    return segno.make_qr(client_config, error="m", boost_error=False)


@dataclass(frozen=True)
class Route:
    name: str
    protocol: str
    public_port: int
    target_address: str
    target_port: int
    description: str = ""

    @property
    def remote_name(self) -> str:
        return f"{MANAGED_ROUTE_PREFIX}{self.name}"

    @classmethod
    def from_mapping(
        cls,
        value: dict[str, Any],
        relay_network: str = "10.99.0.0/24",
        relay_address: str = "10.99.0.1",
    ) -> "Route":
        name = str(value.get("name", "")).strip().lower()
        protocol = str(value.get("protocol", "")).strip().lower()
        target_address = str(value.get("target_address", "")).strip()
        description = str(value.get("description", "")).strip()

        if not ROUTE_NAME_PATTERN.fullmatch(name):
            raise ValidationError(
                "名前は小文字英数字で始まる1〜28文字とし、ハイフンだけを追加で使用できます。"
            )
        if protocol not in {"tcp", "udp"}:
            raise ValidationError("プロトコルはTCPまたはUDPを選択してください。")

        public_port = parse_port(value.get("public_port"), "公開ポート")
        target_port = parse_port(value.get("target_port"), "転送先ポート")
        if public_port in PROTECTED_PUBLIC_PORTS:
            raise ValidationError(
                f"公開ポート{public_port}はSSHまたはWireGuard用のため管理画面では使用できません。"
            )

        try:
            target = ipaddress.ip_address(target_address)
            network = ipaddress.ip_network(relay_network, strict=True)
            relay = ipaddress.ip_address(relay_address)
        except ValueError as exc:
            raise ValidationError(f"WireGuardアドレス設定が不正です: {exc}") from exc
        if target.version != 4 or target not in network:
            raise ValidationError(f"転送先は{network}内のIPv4アドレスにしてください。")
        if target == relay or target in {network.network_address, network.broadcast_address}:
            raise ValidationError("転送先には利用可能なWireGuard Peerアドレスを指定してください。")
        if len(description) > 120:
            raise ValidationError("説明は120文字以内にしてください。")

        return cls(
            name=name,
            protocol=protocol,
            public_port=public_port,
            target_address=str(target),
            target_port=target_port,
            description=description,
        )


@dataclass(frozen=True)
class RouteRecord:
    id: str
    route: Route
    applied_route: Route | None
    desired_active: bool
    group_id: str | None
    desired_enabled: bool
    applied_enabled: bool
    created_at: str
    updated_at: str
    applied_at: str | None = None
    deleted_at: str | None = None


@dataclass(frozen=True)
class WebRoute:
    name: str
    hostname: str
    docker_alias: str
    container_port: int
    description: str = ""
    basic_auth_username: str = ""
    basic_auth_password_hash: str = ""

    @property
    def basic_auth_enabled(self) -> bool:
        return bool(self.basic_auth_username and self.basic_auth_password_hash)

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "WebRoute":
        name = str(value.get("name", "")).strip().lower()
        raw_hostname = str(value.get("hostname", "")).strip().lower()
        if raw_hostname.endswith("."):
            raw_hostname = raw_hostname[:-1]
        docker_alias = str(value.get("docker_alias", "")).strip().lower()
        description = str(value.get("description", "")).strip()
        basic_auth_username = str(value.get("basic_auth_username", "")).strip()
        basic_auth_password_hash = str(
            value.get("basic_auth_password_hash", "")
        ).strip()

        if not ROUTE_NAME_PATTERN.fullmatch(name):
            raise ValidationError(
                "名前は小文字英数字で始まる1〜28文字とし、ハイフンだけを追加で使用できます。"
            )
        if not raw_hostname or any(
            token in raw_hostname for token in ("*", "/", ":", " ", "\t", "\n")
        ):
            raise ValidationError("ドメインにはポートやパスを含まないFQDNを入力してください。")
        try:
            hostname = raw_hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValidationError("ドメインをFQDNとして解釈できません。") from exc
        labels = hostname.split(".")
        if (
            len(labels) < 2
            or len(hostname) > 253
            or any(not DNS_LABEL_PATTERN.fullmatch(label) for label in labels)
        ):
            raise ValidationError("ドメインには有効なFQDNを入力してください。")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValidationError("ドメインにはIPアドレスではなくFQDNを入力してください。")

        if not DOCKER_ALIAS_PATTERN.fullmatch(docker_alias):
            raise ValidationError(
                "Dockerエイリアスは小文字英数字とハイフンを使用した1〜63文字にしてください。"
            )
        if docker_alias in {"localhost", "host", "traefik"}:
            raise ValidationError("予約済みのDockerエイリアスは使用できません。")
        if len(description) > 120:
            raise ValidationError("説明は120文字以内にしてください。")
        if bool(basic_auth_username) != bool(basic_auth_password_hash):
            raise ValidationError(
                "Basic認証のユーザー名とパスワードハッシュは両方指定してください。"
            )
        if basic_auth_username and not BASIC_AUTH_USERNAME_PATTERN.fullmatch(
            basic_auth_username
        ):
            raise ValidationError(
                "Basic認証のユーザー名は英数字で始まる1〜64文字とし、"
                "英数字、ピリオド、アンダースコア、ハイフンだけを使用してください。"
            )
        if basic_auth_password_hash and not BASIC_AUTH_SHA1_PATTERN.fullmatch(
            basic_auth_password_hash
        ):
            raise ValidationError("Basic認証のパスワードハッシュ形式が不正です。")

        return cls(
            name=name,
            hostname=hostname,
            docker_alias=docker_alias,
            container_port=parse_port(value.get("container_port"), "コンテナポート"),
            description=description,
            basic_auth_username=basic_auth_username,
            basic_auth_password_hash=basic_auth_password_hash,
        )


@dataclass(frozen=True)
class WebRouteRecord:
    id: str
    route: WebRoute
    applied_route: WebRoute | None
    desired_active: bool
    desired_enabled: bool
    applied_enabled: bool
    created_at: str
    updated_at: str
    applied_at: str | None = None
    deleted_at: str | None = None


@dataclass(frozen=True)
class GroupRecord:
    id: str
    name: str
    description: str
    parent_id: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RelayRoute:
    name: str
    protocol: str
    public_port: int
    target_address: str
    target_port: int

    @property
    def signature(self) -> tuple[str, int, str, int]:
        return (
            self.protocol,
            self.public_port,
            self.target_address,
            self.target_port,
        )


@dataclass(frozen=True)
class WireGuardPeer:
    name: str
    address: str
    cidr: str
    public_key: str


@dataclass(frozen=True)
class PeerAccessRule:
    name: str
    protocol: str
    source_address: str
    target_address: str
    target_port: int

    @classmethod
    def from_mapping(
        cls,
        value: dict[str, Any],
        relay_network: str = "10.99.0.0/24",
        relay_address: str = "10.99.0.1",
        *,
        existing_name: bool = False,
    ) -> "PeerAccessRule":
        name = normalize_wireguard_name(
            value.get("name"),
            "アクセスルール名",
            existing=existing_name,
        )
        protocol = str(value.get("protocol", "")).strip().lower()
        if protocol not in {"tcp", "udp"}:
            raise ValidationError("プロトコルはTCPまたはUDPにしてください。")
        source_address = normalize_peer_ip(
            value.get("source_address"),
            "接続元アドレス",
            relay_network,
            relay_address,
        )
        target_address = normalize_peer_ip(
            value.get("target_address"),
            "接続先アドレス",
            relay_network,
            relay_address,
        )
        if source_address == target_address:
            raise ValidationError("接続元と接続先には異なるPeerを指定してください。")
        return cls(
            name=name,
            protocol=protocol,
            source_address=source_address,
            target_address=target_address,
            target_port=parse_port(value.get("target_port"), "接続先ポート"),
        )


@dataclass(frozen=True)
class PeerAccessPreset:
    name: str
    protocol: str
    target_address: str
    target_port: int
    source_addresses: tuple[str, ...] = ()

    @classmethod
    def from_mapping(
        cls,
        value: dict[str, Any],
        relay_network: str = "10.99.0.0/24",
        relay_address: str = "10.99.0.1",
        *,
        existing_name: bool = False,
    ) -> "PeerAccessPreset":
        name = normalize_wireguard_name(
            value.get("name"),
            "アクセスプリセット名",
            existing=existing_name,
        )
        protocol = str(value.get("protocol", "")).strip().lower()
        if protocol not in {"tcp", "udp"}:
            raise ValidationError("プロトコルはTCPまたはUDPにしてください。")
        target_address = normalize_peer_ip(
            value.get("target_address"),
            "接続先アドレス",
            relay_network,
            relay_address,
        )

        raw_sources = value.get("source_addresses")
        legacy_source = value.get("source_address")
        if raw_sources is None and legacy_source is not None and legacy_source != "":
            raw_sources = [legacy_source]
        if raw_sources is None:
            raw_sources = []
        if not isinstance(raw_sources, (list, tuple)):
            raise ValidationError("接続元アドレス一覧は配列にしてください。")

        sources: list[str] = []
        for raw_source in raw_sources:
            source = normalize_peer_ip(
                raw_source,
                "接続元アドレス",
                relay_network,
                relay_address,
            )
            if source == target_address:
                raise ValidationError("接続元と接続先には異なるPeerを指定してください。")
            if source not in sources:
                sources.append(source)
        sources.sort(key=lambda item: int(ipaddress.ip_address(item)))

        return cls(
            name=name,
            protocol=protocol,
            target_address=target_address,
            target_port=parse_port(value.get("target_port"), "接続先ポート"),
            source_addresses=tuple(sources),
        )


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr) if part).strip()


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def parse_port(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{label}は1〜65535の整数にしてください。")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label}は1〜65535の整数にしてください。") from exc
    if str(value).strip() != str(port) or not 1 <= port <= 65535:
        raise ValidationError(f"{label}は1〜65535の整数にしてください。")
    return port


def parse_port_expression(value: Any, limit: int = MAX_BULK_PORTS) -> list[int]:
    expression = str(value or "").strip()
    if not expression:
        raise ValidationError("ポート番号または範囲を入力してください。")

    ports: list[int] = []
    seen: set[int] = set()
    for raw_token in expression.split(","):
        token = raw_token.strip()
        if not token:
            raise ValidationError("ポート指定に空の要素があります。")
        if "-" in token:
            parts = [part.strip() for part in token.split("-")]
            if len(parts) != 2 or not all(parts):
                raise ValidationError(f"ポート範囲の形式が不正です: {token}")
            start = parse_port(parts[0], "範囲の開始ポート")
            end = parse_port(parts[1], "範囲の終了ポート")
            if start > end:
                raise ValidationError(f"ポート範囲は昇順にしてください: {token}")
            expanded = range(start, end + 1)
        else:
            expanded = (parse_port(token, "ポート"),)

        for port in expanded:
            if port in PROTECTED_PUBLIC_PORTS:
                raise ValidationError(
                    f"公開ポート{port}はSSHまたはWireGuard用のため管理画面では使用できません。"
                )
            if port in seen:
                raise ValidationError(f"ポート{port}が重複しています。")
            seen.add(port)
            ports.append(port)
            if len(ports) > limit:
                raise ValidationError(f"一度に追加できるポートは最大{limit}件です。")
    return sorted(ports)


def compact_port_ranges(ports: Iterable[int]) -> list[dict[str, int]]:
    ordered = sorted(set(ports))
    if not ordered:
        return []
    ranges: list[dict[str, int]] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append({"min": start, "max": previous})
        start = previous = port
    ranges.append({"min": start, "max": previous})
    return ranges


def normalize_group(name: Any, description: Any = "") -> tuple[str, str]:
    normalized_name = str(name or "").strip().lower()
    normalized_description = str(description or "").strip()
    if not GROUP_NAME_PATTERN.fullmatch(normalized_name):
        raise ValidationError(
            "グループ名は小文字英数字で始まる1〜18文字とし、ハイフンだけを追加で使用できます。"
        )
    if len(normalized_description) > 120:
        raise ValidationError("グループの説明は120文字以内にしてください。")
    return normalized_name, normalized_description


def validate_route_set(routes: Iterable[Route]) -> list[Route]:
    result = sorted(routes, key=lambda route: (route.protocol, route.public_port, route.name))
    names: set[str] = set()
    listeners: set[tuple[str, int]] = set()
    for route in result:
        if route.name in names:
            raise ConflictError(f"経路名が重複しています: {route.name}")
        listener = (route.protocol, route.public_port)
        if listener in listeners:
            raise ConflictError(
                f"{route.protocol.upper()}/{route.public_port}は別のGUI経路で使用されています。"
            )
        names.add(route.name)
        listeners.add(listener)
    return result


def routes_fingerprint(routes: Iterable[Route]) -> str:
    payload = json.dumps(
        [asdict(route) for route in validate_route_set(routes)],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def parse_relay_routes(output: str) -> dict[str, RelayRoute]:
    routes: dict[str, RelayRoute] = {}
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("NAME\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise DashboardError(f"リレー経路一覧の{line_number}行目を解析できません。")
        name, protocol, public_port_text, target = fields
        if ":" not in target:
            raise DashboardError(f"リレー経路一覧の転送先を解析できません: {target}")
        target_address, target_port_text = target.rsplit(":", 1)
        try:
            route = RelayRoute(
                name=name,
                protocol=protocol,
                public_port=int(public_port_text),
                target_address=target_address,
                target_port=int(target_port_text),
            )
        except ValueError as exc:
            raise DashboardError(f"リレー経路一覧のポートを解析できません: {line}") from exc
        routes[name] = route
    return routes


def normalize_wireguard_name(
    value: Any,
    label: str,
    *,
    existing: bool = False,
) -> str:
    normalized = str(value or "").strip()
    pattern = EXISTING_WIREGUARD_NAME_PATTERN if existing else WIREGUARD_NAME_PATTERN
    if not existing:
        normalized = normalized.lower()
    if not pattern.fullmatch(normalized):
        if existing:
            raise ValidationError(
                f"{label}は英数字で始まる1〜32文字とし、ハイフンとアンダースコアだけを追加で使用できます。"
            )
        raise ValidationError(
            f"{label}は小文字英数字で始まる1〜32文字とし、ハイフンだけを追加で使用できます。"
        )
    return normalized


def normalize_peer_address(
    value: Any,
    relay_network: str = "10.99.0.0/24",
    relay_address: str = "10.99.0.1",
) -> str:
    text = str(value or "").strip()
    if "/" not in text:
        text = f"{text}/32"
    try:
        interface = ipaddress.ip_interface(text)
        network = ipaddress.ip_network(relay_network, strict=False)
        server = ipaddress.ip_address(relay_address)
    except ValueError as exc:
        raise ValidationError(f"WireGuard Peerアドレスが不正です: {exc}") from exc
    if interface.version != 4 or interface.network.prefixlen != 32:
        raise ValidationError("WireGuard PeerアドレスはIPv4の/32で指定してください。")
    if interface.ip not in network or interface.ip in {
        network.network_address,
        network.broadcast_address,
        server,
    }:
        raise ValidationError(
            f"WireGuard Peerアドレスには{network}内の利用可能なアドレスを指定してください。"
        )
    return f"{interface.ip}/32"


def normalize_peer_ip(
    value: Any,
    label: str,
    relay_network: str,
    relay_address: str,
) -> str:
    try:
        return str(
            ipaddress.ip_interface(
                normalize_peer_address(value, relay_network, relay_address)
            ).ip
        )
    except ValidationError as exc:
        raise ValidationError(f"{label}が不正です。{exc}") from exc


def parse_wireguard_peers(output: str) -> dict[str, WireGuardPeer]:
    peers: dict[str, WireGuardPeer] = {}
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("NAME\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise DashboardError(f"WireGuard Peer一覧の{line_number}行目を解析できません。")
        name, cidr, public_key = fields
        try:
            interface = ipaddress.ip_interface(cidr)
        except ValueError as exc:
            raise DashboardError(f"WireGuard Peerアドレスを解析できません: {cidr}") from exc
        if interface.version != 4 or interface.network.prefixlen != 32:
            raise DashboardError(f"WireGuard Peerアドレスが/32ではありません: {cidr}")
        peers[name] = WireGuardPeer(
            name=name,
            address=str(interface.ip),
            cidr=f"{interface.ip}/32",
            public_key=public_key,
        )
    return peers


def parse_peer_access_rules(output: str) -> dict[str, PeerAccessPreset]:
    presets: dict[str, PeerAccessPreset] = {}
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("NAME\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise DashboardError(f"Peer間アクセス一覧の{line_number}行目を解析できません。")
        name, protocol, source_addresses_text, target = fields
        if ":" not in target:
            raise DashboardError(f"Peer間アクセスの接続先を解析できません: {target}")
        target_address, target_port_text = target.rsplit(":", 1)
        try:
            target_port = int(target_port_text)
        except ValueError as exc:
            raise DashboardError(f"Peer間アクセスのポートを解析できません: {line}") from exc
        try:
            source_addresses = tuple(
                sorted(
                    {
                        str(ipaddress.ip_address(source.strip()))
                        for source in source_addresses_text.split(",")
                        if source.strip()
                    },
                    key=lambda item: int(ipaddress.ip_address(item)),
                )
            )
            target_address = str(ipaddress.ip_address(target_address))
        except ValueError as exc:
            raise DashboardError(
                f"Peer間アクセスのアドレスを解析できません: {line}"
            ) from exc
        presets[name] = PeerAccessPreset(
            name=name,
            protocol=protocol,
            target_address=target_address,
            target_port=target_port,
            source_addresses=source_addresses,
        )
    return presets


def parse_wireguard_status(output: str) -> dict[str, dict[str, str]]:
    statuses: dict[str, dict[str, str]] = {}
    current_key = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("peer: "):
            current_key = line.removeprefix("peer: ").strip()
            statuses[current_key] = {}
            continue
        if not current_key or ":" not in line:
            continue
        label, value = line.split(":", 1)
        if label in {"endpoint", "latest handshake", "transfer"}:
            statuses[current_key][label.replace(" ", "_")] = value.strip()
    return statuses


def suggest_peer_address(
    peers: Iterable[WireGuardPeer],
    relay_network: str,
    relay_address: str,
) -> str:
    try:
        network = ipaddress.ip_network(relay_network, strict=False)
        server = ipaddress.ip_address(relay_address)
    except ValueError as exc:
        raise ValidationError(f"WireGuardネットワーク設定が不正です: {exc}") from exc
    used = {ipaddress.ip_address(peer.address) for peer in peers}
    candidate_value = int(network.network_address) + 1
    last_value = int(network.broadcast_address)
    while candidate_value < last_value:
        candidate = ipaddress.ip_address(candidate_value)
        if candidate != server and candidate not in used:
            return str(candidate)
        candidate_value += 1
    raise ConflictError(f"{network}に空きPeerアドレスがありません。")


def analyze_terraform_plan(plan: dict[str, Any]) -> dict[str, Any]:
    unexpected: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0}

    for resource in plan.get("resource_changes", []):
        address = str(resource.get("address", ""))
        actions = list(resource.get("change", {}).get("actions", []))
        if actions in (["no-op"], ["read"]) or not actions:
            continue

        if actions == ["create"]:
            counts["create"] += 1
        elif actions == ["update"]:
            counts["update"] += 1
        elif actions == ["delete"]:
            counts["delete"] += 1
        elif set(actions) == {"create", "delete"}:
            counts["replace"] += 1

        item = {"address": address, "actions": actions}
        changes.append(item)
        if not address.startswith(ALLOWED_TERRAFORM_PREFIXES):
            unexpected.append(item)

    return {
        "safe": not unexpected,
        "changes": changes,
        "unexpected": unexpected,
        "counts": counts,
    }


_UNCHANGED = object()


class RouteStore:
    def __init__(
        self,
        data_dir: Path,
        relay_network: str = "10.99.0.0/24",
        relay_address: str = "10.99.0.1",
    ) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "routes.json"
        self.relay_network = relay_network
        self.relay_address = relay_address
        self.lock = threading.RLock()
        data_dir.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[Route]:
        return [
            record.route
            for record in self.records()
            if (
                record.desired_active
                and record.desired_enabled
                and record.deleted_at is None
            )
        ]

    def applied(self) -> list[Route]:
        return [
            record.applied_route
            for record in self.records()
            if record.applied_enabled and record.applied_route is not None
        ]

    def records(self) -> list[RouteRecord]:
        with self.lock:
            records, _, _ = self._load()
            return records

    def groups(self) -> list[GroupRecord]:
        with self.lock:
            _, groups, _ = self._load()
            return groups

    def views(self) -> list[dict[str, Any]]:
        with self.lock:
            records, _, pending_relay = self._load()
            pending_ids = self._pending_record_ids(pending_relay)
            return [
                self._record_view(record, record.id in pending_ids)
                for record in sorted(
                    records,
                    key=lambda item: (
                        item.deleted_at is not None,
                        item.group_id or "",
                        item.route.protocol,
                        item.route.public_port,
                        item.route.name,
                    ),
                )
            ]

    def group_views(self) -> list[dict[str, Any]]:
        with self.lock:
            records, groups, _ = self._load()
            views: list[dict[str, Any]] = []
            for group in sorted(groups, key=lambda item: item.name):
                descendant_ids = self._group_descendant_ids(groups, group.id)
                members = [
                    record
                    for record in records
                    if (
                        record.group_id in descendant_ids
                        and record.desired_active
                        and record.deleted_at is None
                    )
                ]
                enabled_count = sum(record.desired_enabled for record in members)
                if not members:
                    enabled_state = "empty"
                elif enabled_count == len(members):
                    enabled_state = "enabled"
                elif enabled_count == 0:
                    enabled_state = "disabled"
                else:
                    enabled_state = "mixed"
                views.append(
                    {
                        **asdict(group),
                        "total_ports": len(members),
                        "enabled_ports": enabled_count,
                        "enabled_state": enabled_state,
                    }
                )
            return views

    def create(
        self,
        route: Route,
        group_id: str | None = None,
        desired_enabled: bool = True,
    ) -> RouteRecord:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._validate_group_reference(groups, group_id)
            if not isinstance(desired_enabled, bool):
                raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
            now = utc_now()
            record = RouteRecord(
                id=str(uuid.uuid4()),
                route=route,
                applied_route=None,
                desired_active=True,
                group_id=group_id,
                desired_enabled=desired_enabled,
                applied_enabled=False,
                created_at=now,
                updated_at=now,
            )
            records.append(record)
            self._save(records, groups, pending_relay)
            return record

    def validate_create(
        self,
        route: Route,
        group_id: str | None = None,
        desired_enabled: bool = True,
    ) -> dict[str, Any]:
        """Validate a prospective route without changing desired state."""
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._validate_group_reference(groups, group_id)
            if not isinstance(desired_enabled, bool):
                raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
            now = utc_now()
            candidate = RouteRecord(
                id="dry-run",
                route=route,
                applied_route=None,
                desired_active=True,
                group_id=group_id,
                desired_enabled=desired_enabled,
                applied_enabled=False,
                created_at=now,
                updated_at=now,
            )
            self._validate_records([*records, candidate], groups)
            return {
                "action": "create",
                "target_count": 1,
                "route": asdict(route),
                "group_id": group_id,
                "desired_enabled": desired_enabled,
            }

    def update(
        self,
        record_id: str,
        route: Route,
        group_id: str | None | object = _UNCHANGED,
    ) -> RouteRecord:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find(records, record_id)
            if target.deleted_at is not None or not target.desired_active:
                raise DashboardError("削除待ちまたは削除済みの経路は編集できません。")
            resolved_group = target.group_id if group_id is _UNCHANGED else group_id
            if resolved_group is not None and not isinstance(resolved_group, str):
                raise ValidationError("所属グループの指定が不正です。")
            self._validate_group_reference(groups, resolved_group)
            updated = replace(
                target,
                route=route,
                group_id=resolved_group,
                updated_at=utc_now(),
            )
            records = [updated if item.id == record_id else item for item in records]
            self._save(records, groups, pending_relay)
            return updated

    def set_enabled(self, record_id: str, enabled: bool) -> RouteRecord:
        if not isinstance(enabled, bool):
            raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find(records, record_id)
            if target.deleted_at is not None or not target.desired_active:
                raise DashboardError("削除待ちまたは削除済みの経路は切り替えできません。")
            updated = replace(target, desired_enabled=enabled, updated_at=utc_now())
            records = [updated if item.id == record_id else item for item in records]
            self._save(records, groups, pending_relay)
            return updated

    def setup_web_gateway(self, target_address: str) -> list[RouteRecord]:
        """Atomically stage TCP/80 and TCP/443 for the on-premises gateway."""
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            planned = list(records)
            selected: list[RouteRecord] = []
            now = utc_now()
            for port, name, description in (
                (80, "web-http", "Web HTTP入口（HTTPSへリダイレクト）"),
                (443, "web-https", "Web HTTPS入口"),
            ):
                matches = [
                    record
                    for record in planned
                    if (
                        record.deleted_at is None
                        and (
                            (
                                record.desired_active
                                and record.route.protocol == "tcp"
                                and record.route.public_port == port
                            )
                            or (
                                not record.desired_active
                                and record.applied_route is not None
                                and record.applied_route.protocol == "tcp"
                                and record.applied_route.public_port == port
                            )
                        )
                    )
                ]
                if matches:
                    existing = matches[0]
                    candidate = (
                        existing.route
                        if existing.desired_active
                        else existing.applied_route
                    )
                    assert candidate is not None
                    if (
                        candidate.target_address != target_address
                        or candidate.target_port != port
                    ):
                        raise ConflictError(
                            f"TCP/{port}は別の転送先"
                            f"（{candidate.target_address}:{candidate.target_port}）"
                            "で使用されています。"
                        )
                    updated = replace(
                        existing,
                        route=candidate,
                        desired_active=True,
                        desired_enabled=True,
                        updated_at=now,
                        deleted_at=None,
                    )
                    planned = [
                        updated if item.id == existing.id else item
                        for item in planned
                    ]
                    selected.append(updated)
                    continue

                candidate = Route.from_mapping(
                    {
                        "name": name,
                        "protocol": "tcp",
                        "public_port": port,
                        "target_address": target_address,
                        "target_port": port,
                        "description": description,
                    },
                    relay_network=self.relay_network,
                    relay_address=self.relay_address,
                )
                created = RouteRecord(
                    id=str(uuid.uuid4()),
                    route=candidate,
                    applied_route=None,
                    desired_active=True,
                    group_id=None,
                    desired_enabled=True,
                    applied_enabled=False,
                    created_at=now,
                    updated_at=now,
                )
                planned.append(created)
                selected.append(created)

            self._save(planned, groups, pending_relay)
            return selected

    def create_group(
        self,
        name: Any,
        description: Any = "",
        members: Any = None,
        parent_id: str | None = None,
    ) -> GroupRecord:
        normalized_name, normalized_description = normalize_group(name, description)
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._ensure_group_name_available(groups, normalized_name)
            if parent_id is not None and not isinstance(parent_id, str):
                raise ValidationError("親グループの指定が不正です。")
            self._validate_group_parent(groups, None, parent_id)
            now = utc_now()
            group = GroupRecord(
                id=str(uuid.uuid4()),
                name=normalized_name,
                description=normalized_description,
                parent_id=parent_id,
                created_at=now,
                updated_at=now,
            )
            groups.append(group)
            if members is not None:
                records.extend(self._expand_group_members(group, members))
            self._save(records, groups, pending_relay)
            return group

    def add_group_routes(self, group_id: str, members: Any) -> list[RouteRecord]:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            group = self._find_group(groups, group_id)
            created = self._expand_group_members(group, members)
            records.extend(created)
            self._save(records, groups, pending_relay)
            return created

    def update_group(
        self,
        group_id: str,
        name: Any,
        description: Any = "",
        parent_id: str | None | object = _UNCHANGED,
    ) -> GroupRecord:
        normalized_name, normalized_description = normalize_group(name, description)
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find_group(groups, group_id)
            self._ensure_group_name_available(groups, normalized_name, excluded_id=group_id)
            resolved_parent = target.parent_id if parent_id is _UNCHANGED else parent_id
            if resolved_parent is not None and not isinstance(resolved_parent, str):
                raise ValidationError("親グループの指定が不正です。")
            self._validate_group_parent(groups, group_id, resolved_parent)
            updated = replace(
                target,
                name=normalized_name,
                description=normalized_description,
                parent_id=resolved_parent,
                updated_at=utc_now(),
            )
            groups = [updated if item.id == group_id else item for item in groups]
            self._save(records, groups, pending_relay)
            return updated

    def set_group_enabled(self, group_id: str, enabled: bool) -> list[RouteRecord]:
        if not isinstance(enabled, bool):
            raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._find_group(groups, group_id)
            descendant_ids = self._group_descendant_ids(groups, group_id)
            now = utc_now()
            updated_records = [
                replace(record, desired_enabled=enabled, updated_at=now)
                if (
                    record.group_id in descendant_ids
                    and record.desired_active
                    and record.deleted_at is None
                )
                else record
                for record in records
            ]
            self._save(updated_records, groups, pending_relay)
            return [
                record
                for record in updated_records
                if (
                    record.group_id in descendant_ids
                    and record.desired_active
                    and record.deleted_at is None
                )
            ]

    def delete_group(self, group_id: str) -> None:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find_group(groups, group_id)
            records = [
                replace(record, group_id=target.parent_id, updated_at=utc_now())
                if record.group_id == group_id
                else record
                for record in records
            ]
            groups = [
                replace(group, parent_id=target.parent_id, updated_at=utc_now())
                if group.parent_id == group_id
                else group
                for group in groups
                if group.id != group_id
            ]
            self._save(records, groups, pending_relay)

    def delete(self, record_id: str) -> bool:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find(records, record_id)
            if target.deleted_at is not None:
                raise DashboardError("削除済み履歴は履歴消去を使用してください。")
            if target.applied_route is None and not target.applied_enabled:
                self._save(
                    [item for item in records if item.id != record_id],
                    groups,
                    pending_relay,
                )
                return True
            pending_delete = replace(
                target,
                route=target.applied_route or target.route,
                desired_active=False,
                desired_enabled=False,
                updated_at=utc_now(),
                deleted_at=None,
            )
            records = [pending_delete if item.id == record_id else item for item in records]
            self._save(records, groups, pending_relay)
            return False

    def cancel_delete(self, record_id: str) -> RouteRecord:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find(records, record_id)
            if target.deleted_at is not None or target.desired_active or target.applied_route is None:
                raise DashboardError("削除待ちの経路ではありません。")
            restored = replace(
                target,
                route=target.applied_route,
                desired_active=True,
                desired_enabled=target.applied_enabled,
                updated_at=utc_now(),
            )
            records = [restored if item.id == record_id else item for item in records]
            self._save(records, groups, pending_relay)
            return restored

    def purge_deleted(self, record_id: str) -> None:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find(records, record_id)
            if target.deleted_at is None:
                raise DashboardError("削除済みの経路だけ履歴から消去できます。")
            self._save(
                [item for item in records if item.id != record_id],
                groups,
                pending_relay,
            )

    def has_pending_relay(self) -> bool:
        with self.lock:
            _, _, pending_relay = self._load()
            return pending_relay is not None

    def mark_terraform_applied(self) -> None:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            pending_relay = {
                "created_at": utc_now(),
                "active": [
                    {"id": record.id, "route": asdict(record.route)}
                    for record in records
                    if (
                        record.desired_active
                        and record.desired_enabled
                        and record.deleted_at is None
                    )
                ],
                "disabled_ids": [
                    record.id
                    for record in records
                    if (
                        record.desired_active
                        and not record.desired_enabled
                        and record.deleted_at is None
                        and record.applied_enabled
                    )
                ],
                "deleted_ids": [
                    record.id
                    for record in records
                    if (
                        not record.desired_active
                        and record.deleted_at is None
                        and record.applied_route is not None
                    )
                ],
                "changed_ids": [
                    record.id for record in records if self._record_has_pending_change(record)
                ],
            }
            self._save(records, groups, pending_relay)

    def relay_sync_routes(self) -> list[Route]:
        with self.lock:
            _, _, pending_relay = self._load()
            if pending_relay is None:
                return self.applied()
            return [
                self._route_from_mapping(item["route"])
                for item in pending_relay.get("active", [])
            ]

    def commit_relay_sync(self) -> None:
        with self.lock:
            records, groups, pending_relay = self._load()
            if pending_relay is None:
                return
            now = utc_now()
            active = {
                str(item["id"]): self._route_from_mapping(item["route"])
                for item in pending_relay.get("active", [])
            }
            disabled_ids = {str(item) for item in pending_relay.get("disabled_ids", [])}
            deleted_ids = {str(item) for item in pending_relay.get("deleted_ids", [])}
            committed: list[RouteRecord] = []
            for record in records:
                if record.id in active:
                    committed.append(
                        replace(
                            record,
                            route=active[record.id],
                            applied_route=active[record.id],
                            desired_active=True,
                            desired_enabled=True,
                            applied_enabled=True,
                            updated_at=now,
                            applied_at=now,
                        )
                    )
                elif record.id in disabled_ids:
                    committed.append(
                        replace(
                            record,
                            desired_enabled=False,
                            applied_enabled=False,
                            updated_at=now,
                            applied_at=now,
                        )
                    )
                elif record.id in deleted_ids:
                    committed.append(
                        replace(
                            record,
                            applied_route=None,
                            desired_active=False,
                            desired_enabled=False,
                            applied_enabled=False,
                            updated_at=now,
                            deleted_at=now,
                        )
                    )
                else:
                    committed.append(record)
            self._save(committed, groups, None)

    def _load(
        self,
    ) -> tuple[list[RouteRecord], list[GroupRecord], dict[str, Any] | None]:
        if not self.path.exists():
            return [], [], None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            version = value.get("version")
            if version == 1:
                return self._migrate_v1(value)
            if version == 2:
                return self._migrate_v2(value)
            if version == 3:
                return self._migrate_v3(value)
            if version != 4:
                raise DashboardError("未対応の経路データ形式です。")
            records = [self._record_from_mapping(item) for item in value.get("records", [])]
            groups = [self._group_from_mapping(item) for item in value.get("groups", [])]
            pending_relay = value.get("pending_relay")
            if pending_relay is not None and not isinstance(pending_relay, dict):
                raise DashboardError("リレー同期待ちデータが不正です。")
            self._validate_records(records, groups)
            return records, groups, pending_relay
        except (OSError, json.JSONDecodeError, TypeError, KeyError) as exc:
            raise DashboardError(f"経路データを読み込めません: {exc}") from exc

    def _migrate_v1(
        self,
        value: dict[str, Any],
    ) -> tuple[list[RouteRecord], list[GroupRecord], None]:
        self._backup_legacy(1)
        now = utc_now()
        routes = [self._route_from_mapping(item) for item in value.get("routes", [])]
        validate_route_set(routes)
        records = [
            RouteRecord(
                id=str(uuid.uuid4()),
                route=route,
                applied_route=route,
                desired_active=True,
                group_id=None,
                desired_enabled=True,
                applied_enabled=True,
                created_at=now,
                updated_at=now,
                applied_at=now,
            )
            for route in routes
        ]
        self._save(records, [], None)
        return records, [], None

    def _migrate_v2(
        self,
        value: dict[str, Any],
    ) -> tuple[list[RouteRecord], list[GroupRecord], dict[str, Any] | None]:
        self._backup_legacy(2)
        records = [self._record_from_v2_mapping(item) for item in value.get("records", [])]
        pending_relay = value.get("pending_relay")
        if pending_relay is not None and not isinstance(pending_relay, dict):
            raise DashboardError("リレー同期待ちデータが不正です。")
        self._save(records, [], pending_relay)
        return records, [], pending_relay

    def _migrate_v3(
        self,
        value: dict[str, Any],
    ) -> tuple[list[RouteRecord], list[GroupRecord], dict[str, Any] | None]:
        self._backup_legacy(3)
        records = [self._record_from_mapping(item) for item in value.get("records", [])]
        groups = [self._group_from_mapping(item) for item in value.get("groups", [])]
        pending_relay = value.get("pending_relay")
        if pending_relay is not None and not isinstance(pending_relay, dict):
            raise DashboardError("リレー同期待ちデータが不正です。")
        self._validate_records(records, groups)
        self._save(records, groups, pending_relay)
        return records, groups, pending_relay

    def _backup_legacy(self, version: int) -> None:
        backup = self.data_dir / f"routes.json.v{version}.bak"
        if backup.exists():
            return
        shutil.copy2(self.path, backup)
        os.chmod(backup, 0o600)

    def _route_from_mapping(self, value: dict[str, Any]) -> Route:
        return Route.from_mapping(
            value,
            relay_network=self.relay_network,
            relay_address=self.relay_address,
        )

    def _record_from_mapping(self, value: dict[str, Any]) -> RouteRecord:
        applied_value = value.get("applied_route")
        return RouteRecord(
            id=str(value["id"]),
            route=self._route_from_mapping(value["route"]),
            applied_route=(
                self._route_from_mapping(applied_value)
                if isinstance(applied_value, dict)
                else None
            ),
            desired_active=bool(value["desired_active"]),
            group_id=str(value["group_id"]) if value.get("group_id") else None,
            desired_enabled=bool(value["desired_enabled"]),
            applied_enabled=bool(value["applied_enabled"]),
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
            applied_at=str(value["applied_at"]) if value.get("applied_at") else None,
            deleted_at=str(value["deleted_at"]) if value.get("deleted_at") else None,
        )

    def _record_from_v2_mapping(self, value: dict[str, Any]) -> RouteRecord:
        applied_value = value.get("applied_route")
        applied_route = (
            self._route_from_mapping(applied_value)
            if isinstance(applied_value, dict)
            else None
        )
        desired_active = bool(value["desired_active"])
        deleted_at = str(value["deleted_at"]) if value.get("deleted_at") else None
        return RouteRecord(
            id=str(value["id"]),
            route=self._route_from_mapping(value["route"]),
            applied_route=applied_route,
            desired_active=desired_active,
            group_id=None,
            desired_enabled=desired_active and deleted_at is None,
            applied_enabled=applied_route is not None and deleted_at is None,
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
            applied_at=str(value["applied_at"]) if value.get("applied_at") else None,
            deleted_at=deleted_at,
        )

    @staticmethod
    def _group_from_mapping(value: dict[str, Any]) -> GroupRecord:
        name, description = normalize_group(value["name"], value.get("description", ""))
        return GroupRecord(
            id=str(value["id"]),
            name=name,
            description=description,
            parent_id=str(value["parent_id"]) if value.get("parent_id") else None,
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
        )

    def _expand_group_members(
        self,
        group: GroupRecord,
        members: Any,
    ) -> list[RouteRecord]:
        if not isinstance(members, list):
            raise ValidationError("ポート定義は配列で指定してください。")
        now = utc_now()
        created: list[RouteRecord] = []
        total = 0
        for index, member in enumerate(members, start=1):
            if not isinstance(member, dict):
                raise ValidationError(f"{index}行目のポート定義が不正です。")
            protocol = str(member.get("protocol", "")).strip().lower()
            if protocol not in {"tcp", "udp"}:
                raise ValidationError(f"{index}行目のプロトコルを選択してください。")
            ports = parse_port_expression(member.get("ports"))
            total += len(ports)
            if total > MAX_BULK_PORTS:
                raise ValidationError(
                    f"一度に追加できるポートは合計{MAX_BULK_PORTS}件です。"
                )
            for port in ports:
                route = self._route_from_mapping(
                    {
                        "name": f"{group.name}-{protocol}-{port}",
                        "protocol": protocol,
                        "public_port": port,
                        "target_address": member.get("target_address"),
                        "target_port": port,
                        "description": member.get("description", ""),
                    }
                )
                created.append(
                    RouteRecord(
                        id=str(uuid.uuid4()),
                        route=route,
                        applied_route=None,
                        desired_active=True,
                        group_id=group.id,
                        desired_enabled=True,
                        applied_enabled=False,
                        created_at=now,
                        updated_at=now,
                    )
                )
        return created

    def _validate_records(
        self,
        records: list[RouteRecord],
        groups: list[GroupRecord],
    ) -> None:
        ids = [record.id for record in records]
        if len(ids) != len(set(ids)):
            raise DashboardError("経路IDが重複しています。")
        group_ids = [group.id for group in groups]
        if len(group_ids) != len(set(group_ids)):
            raise DashboardError("グループIDが重複しています。")
        group_names = [group.name for group in groups]
        if len(group_names) != len(set(group_names)):
            raise ConflictError("グループ名が重複しています。")
        available_groups = set(group_ids)
        if any(
            group.parent_id is not None and group.parent_id not in available_groups
            for group in groups
        ):
            raise DashboardError("存在しない親グループを参照するグループがあります。")
        for group in groups:
            visited = {group.id}
            parent_id = group.parent_id
            while parent_id is not None:
                if parent_id in visited:
                    raise DashboardError("グループ階層が循環しています。")
                visited.add(parent_id)
                parent_id = self._find_group(groups, parent_id).parent_id
        if any(
            record.group_id is not None and record.group_id not in available_groups
            for record in records
        ):
            raise DashboardError("存在しないグループを参照する経路があります。")
        validate_route_set(
            record.route
            for record in records
            if record.desired_active and record.deleted_at is None
        )

    def _save(
        self,
        records: Iterable[RouteRecord],
        groups: Iterable[GroupRecord],
        pending_relay: dict[str, Any] | None,
    ) -> None:
        materialized_records = list(records)
        materialized_groups = list(groups)
        self._validate_records(materialized_records, materialized_groups)
        payload = {
            "version": 4,
            "groups": [asdict(group) for group in materialized_groups],
            "records": [asdict(record) for record in materialized_records],
            "pending_relay": pending_relay,
        }
        atomic_write_json(self.path, payload, mode=0o600)

    @staticmethod
    def _find(records: list[RouteRecord], record_id: str) -> RouteRecord:
        for record in records:
            if record.id == record_id:
                return record
        raise DashboardError(f"経路が見つかりません: {record_id}")

    @staticmethod
    def _find_group(groups: list[GroupRecord], group_id: str) -> GroupRecord:
        for group in groups:
            if group.id == group_id:
                return group
        raise DashboardError(f"グループが見つかりません: {group_id}")

    @staticmethod
    def _ensure_group_name_available(
        groups: list[GroupRecord],
        name: str,
        excluded_id: str | None = None,
    ) -> None:
        if any(group.name == name and group.id != excluded_id for group in groups):
            raise ConflictError(f"グループ名は既に使用されています: {name}")

    @classmethod
    def _validate_group_parent(
        cls,
        groups: list[GroupRecord],
        group_id: str | None,
        parent_id: str | None,
    ) -> None:
        if parent_id is None:
            return
        cls._find_group(groups, parent_id)
        if group_id is None:
            return
        if parent_id == group_id:
            raise ValidationError("グループ自身を親グループにはできません。")
        if parent_id in cls._group_descendant_ids(groups, group_id):
            raise ValidationError("サブグループを親にすると階層が循環します。")

    @staticmethod
    def _group_descendant_ids(
        groups: list[GroupRecord],
        group_id: str,
    ) -> set[str]:
        descendants = {group_id}
        pending = [group_id]
        while pending:
            parent_id = pending.pop()
            children = [
                group.id
                for group in groups
                if group.parent_id == parent_id and group.id not in descendants
            ]
            descendants.update(children)
            pending.extend(children)
        return descendants

    @staticmethod
    def _validate_group_reference(
        groups: list[GroupRecord],
        group_id: str | None,
    ) -> None:
        if group_id is not None and not any(group.id == group_id for group in groups):
            raise ValidationError("所属グループが見つかりません。")

    @staticmethod
    def _require_mutable(pending_relay: dict[str, Any] | None) -> None:
        if pending_relay is not None:
            raise ConflictError(
                "Terraform適用後のリレー同期待ちです。先に「リレーだけ再同期」を実行してください。"
            )

    @staticmethod
    def _pending_record_ids(pending_relay: dict[str, Any] | None) -> set[str]:
        if pending_relay is None:
            return set()
        if "changed_ids" in pending_relay:
            return {str(item) for item in pending_relay.get("changed_ids", [])}
        return {
            *(str(item["id"]) for item in pending_relay.get("active", [])),
            *(str(item) for item in pending_relay.get("disabled_ids", [])),
            *(str(item) for item in pending_relay.get("deleted_ids", [])),
        }

    @staticmethod
    def _record_has_pending_change(record: RouteRecord) -> bool:
        if record.deleted_at is not None:
            return False
        if not record.desired_active:
            return record.applied_route is not None
        if record.desired_enabled:
            return not record.applied_enabled or record.route != record.applied_route
        return record.applied_enabled

    def _record_view(self, record: RouteRecord, relay_pending: bool) -> dict[str, Any]:
        if record.deleted_at is not None:
            state = "deleted"
            group = "deleted"
        elif relay_pending:
            state = "pending_relay"
            group = "pending"
        elif not record.desired_active:
            state = "pending_delete"
            group = "pending"
        elif record.desired_enabled:
            if not record.applied_enabled:
                state = "pending_create" if record.applied_route is None else "pending_enable"
                group = "pending"
            elif record.route != record.applied_route:
                state = "pending_update"
                group = "pending"
            else:
                state = "enabled"
                group = "enabled"
        elif record.applied_enabled:
            state = "pending_disable"
            group = "pending"
        else:
            state = "disabled"
            group = "disabled"
        return {
            "id": record.id,
            **asdict(record.route),
            "group_id": record.group_id,
            "desired_enabled": record.desired_enabled,
            "applied_enabled": record.applied_enabled,
            "state": state,
            "state_group": group,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "applied_at": record.applied_at,
            "deleted_at": record.deleted_at,
        }


WEB_ROUTE_MARKER = "# Managed by OCI Relay Control. Do not edit directly."
WEB_ROUTE_AUTH_FILE_PATTERN = "ui-web-*-auth-*.htpasswd"


def hash_basic_auth_password(password: str) -> str:
    if len(password) < 32:
        raise ValidationError("自動生成Basic認証パスワードが短すぎます。")
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).digest()
    return "{SHA}" + base64.b64encode(digest).decode("ascii")


def web_route_public_mapping(route: WebRoute) -> dict[str, Any]:
    return {
        "name": route.name,
        "hostname": route.hostname,
        "docker_alias": route.docker_alias,
        "container_port": route.container_port,
        "description": route.description,
        "basic_auth_enabled": route.basic_auth_enabled,
        "basic_auth_username": (
            route.basic_auth_username if route.basic_auth_enabled else ""
        ),
    }


def web_route_auth_filename(route: WebRoute) -> str:
    if not route.basic_auth_enabled:
        raise ValidationError("Basic認証が無効なWebルートです。")
    fingerprint = hashlib.sha256(
        route.basic_auth_password_hash.encode("ascii")
    ).hexdigest()[:12]
    return f"ui-web-{route.name}-auth-{fingerprint}.htpasswd"


def render_web_route_auth_files(
    records: Iterable[WebRouteRecord],
) -> dict[str, str]:
    return {
        web_route_auth_filename(record.route): (
            f"{record.route.basic_auth_username}:"
            f"{record.route.basic_auth_password_hash}\n"
        )
        for record in records
        if (
            record.desired_active
            and record.desired_enabled
            and record.deleted_at is None
            and record.route.basic_auth_enabled
        )
    }


def web_routes_fingerprint(records: Iterable[WebRouteRecord]) -> str:
    payload = [
        {
            "id": record.id,
            "route": asdict(record.route),
            "desired_active": record.desired_active,
            "desired_enabled": record.desired_enabled,
            "deleted_at": record.deleted_at,
        }
        for record in sorted(records, key=lambda item: item.id)
    ]
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def render_web_routes_config(records: Iterable[WebRouteRecord]) -> str:
    active = sorted(
        (
            record
            for record in records
            if (
                record.desired_active
                and record.desired_enabled
                and record.deleted_at is None
            )
        ),
        key=lambda item: (item.route.hostname, item.route.name, item.id),
    )
    lines = [
        WEB_ROUTE_MARKER,
        "# Generated from /data/web-routes.json. Changes will be overwritten.",
        "http:",
    ]
    if not active:
        lines.append("  routers: {}")
    else:
        lines.append("  routers:")
        for record in active:
            route = record.route
            key = f"ui-web-{route.name}"
            router = [
                f"    {key}:",
                "      entryPoints:",
                "        - websecure",
                f"      rule: {json.dumps(f'Host(`{route.hostname}`)')}",
            ]
            if route.basic_auth_enabled:
                router.extend(
                    [
                        "      middlewares:",
                        f"        - {key}-auth",
                    ]
                )
            router.extend(
                [
                    f"      service: {key}",
                    "      tls:",
                    "        certResolver: letsencrypt",
                ]
            )
            lines.extend(router)
    authenticated = [record for record in active if record.route.basic_auth_enabled]
    if authenticated:
        lines.append("  middlewares:")
        for record in authenticated:
            route = record.route
            key = f"ui-web-{route.name}-auth"
            auth_file = web_route_auth_filename(route)
            lines.extend(
                [
                    f"    {key}:",
                    "      basicAuth:",
                    (
                        "        usersFile: "
                        + json.dumps(f"/etc/traefik/dynamic/{auth_file}")
                    ),
                    f"        realm: {json.dumps(f'OCI Relay {route.name}')}",
                    "        removeHeader: true",
                ]
            )
    if not active:
        lines.append("  services: {}")
    else:
        lines.append("  services:")
        for record in active:
            route = record.route
            key = f"ui-web-{route.name}"
            lines.extend(
                [
                    f"    {key}:",
                    "      loadBalancer:",
                    "        servers:",
                    f"          - url: {json.dumps(f'http://{route.docker_alias}:{route.container_port}')}",
                ]
            )
    return "\n".join(lines) + "\n"


class WebRouteStore:
    def __init__(self, data_dir: Path, dynamic_config_path: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "web-routes.json"
        self.preview_path = data_dir / "web-plan.json"
        self.dynamic_config_path = dynamic_config_path
        self.lock = threading.RLock()
        data_dir.mkdir(parents=True, exist_ok=True)

    def records(self) -> list[WebRouteRecord]:
        with self.lock:
            records, _ = self._load()
            return records

    def record(self, record_id: str) -> WebRouteRecord:
        with self.lock:
            records, _ = self._load()
            return self._find(records, record_id)

    def views(self) -> list[dict[str, Any]]:
        with self.lock:
            records, pending_publish = self._load()
            pending_ids = {
                str(item)
                for item in (pending_publish or {}).get("changed_ids", [])
            }
            return [
                self._record_view(record, record.id in pending_ids)
                for record in sorted(
                    records,
                    key=lambda item: (
                        item.deleted_at is not None,
                        item.route.hostname,
                        item.route.name,
                    ),
                )
            ]

    def create(
        self,
        route: WebRoute,
        desired_enabled: bool = True,
    ) -> WebRouteRecord:
        if not isinstance(desired_enabled, bool):
            raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            now = utc_now()
            record = WebRouteRecord(
                id=str(uuid.uuid4()),
                route=route,
                applied_route=None,
                desired_active=True,
                desired_enabled=desired_enabled,
                applied_enabled=False,
                created_at=now,
                updated_at=now,
            )
            records.append(record)
            self._save(records, pending_publish)
            return record

    def update(self, record_id: str, route: WebRoute) -> WebRouteRecord:
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            target = self._find(records, record_id)
            if target.deleted_at is not None or not target.desired_active:
                raise DashboardError("削除待ちまたは削除済みのWebルートは編集できません。")
            updated = replace(target, route=route, updated_at=utc_now())
            records = [updated if item.id == record_id else item for item in records]
            self._save(records, pending_publish)
            return updated

    def set_enabled(self, record_id: str, enabled: bool) -> WebRouteRecord:
        if not isinstance(enabled, bool):
            raise ValidationError("有効状態はtrueまたはfalseで指定してください。")
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            target = self._find(records, record_id)
            if target.deleted_at is not None or not target.desired_active:
                raise DashboardError("削除待ちまたは削除済みのWebルートは切り替えできません。")
            updated = replace(target, desired_enabled=enabled, updated_at=utc_now())
            records = [updated if item.id == record_id else item for item in records]
            self._save(records, pending_publish)
            return updated

    def delete(self, record_id: str) -> bool:
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            target = self._find(records, record_id)
            if target.deleted_at is not None:
                raise DashboardError("削除済み履歴は履歴消去を使用してください。")
            if target.applied_route is None:
                self._save(
                    [item for item in records if item.id != record_id],
                    pending_publish,
                )
                return True
            pending_delete = replace(
                target,
                route=target.applied_route,
                desired_active=False,
                desired_enabled=False,
                updated_at=utc_now(),
                deleted_at=None,
            )
            records = [
                pending_delete if item.id == record_id else item for item in records
            ]
            self._save(records, pending_publish)
            return False

    def cancel_delete(self, record_id: str) -> WebRouteRecord:
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            target = self._find(records, record_id)
            if target.deleted_at is not None or target.desired_active or target.applied_route is None:
                raise DashboardError("削除待ちのWebルートではありません。")
            restored = replace(
                target,
                route=target.applied_route,
                desired_active=True,
                desired_enabled=target.applied_enabled,
                updated_at=utc_now(),
            )
            records = [restored if item.id == record_id else item for item in records]
            self._save(records, pending_publish)
            return restored

    def purge_deleted(self, record_id: str) -> None:
        with self.lock:
            records, pending_publish = self._load()
            self._require_mutable(pending_publish)
            target = self._find(records, record_id)
            if target.deleted_at is None:
                raise DashboardError("削除済みのWebルートだけ履歴から消去できます。")
            self._save(
                [item for item in records if item.id != record_id],
                pending_publish,
            )

    def preview(self) -> dict[str, Any]:
        with self.lock:
            records, pending_publish = self._load()
            if pending_publish is not None:
                raise ConflictError(
                    "Webルートの反映途中です。先に「Webルートを再反映」を実行してください。"
                )
            config = render_web_routes_config(records)
            metadata = {
                "created_at": utc_now(),
                "fingerprint": web_routes_fingerprint(records),
                "config_sha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
                "counts": self._change_counts(records),
                "routes": [
                    {
                        "hostname": record.route.hostname,
                        "target": (
                            f"http://{record.route.docker_alias}:"
                            f"{record.route.container_port}"
                        ),
                        "basic_auth_enabled": record.route.basic_auth_enabled,
                    }
                    for record in sorted(
                        records,
                        key=lambda item: (item.route.hostname, item.route.name),
                    )
                    if (
                        record.desired_active
                        and record.desired_enabled
                        and record.deleted_at is None
                    )
                ],
                "config": config,
            }
            atomic_write_json(self.preview_path, metadata, mode=0o600)
            return metadata

    def publish(self) -> dict[str, Any]:
        with self.lock:
            records, pending_publish = self._load()
            recovering = pending_publish is not None
            if pending_publish is None:
                self._require_managed_target()
                preview = self.load_preview()
                if preview is None:
                    raise DashboardError("先にWebルートの反映内容を確認してください。")
                current_fingerprint = web_routes_fingerprint(records)
                if not hmac.compare_digest(
                    str(preview.get("fingerprint", "")),
                    current_fingerprint,
                ):
                    raise ConflictError(
                        "プレビュー作成後にWebルートが変更されています。反映内容を確認し直してください。"
                    )
                config = render_web_routes_config(records)
                if not hmac.compare_digest(
                    str(preview.get("config_sha256", "")),
                    hashlib.sha256(config.encode("utf-8")).hexdigest(),
                ):
                    raise ConflictError(
                        "生成内容がプレビューと一致しません。反映内容を確認し直してください。"
                    )
                pending_publish = self._pending_snapshot(records, config)
                self._save(records, pending_publish)
            else:
                config = str(pending_publish.get("config", ""))
                if not config.startswith(WEB_ROUTE_MARKER + "\n"):
                    raise DashboardError("反映途中のWebルート設定データが破損しています。")

                self._require_managed_target()
            auth_files = render_web_route_auth_files(records)
            try:
                for filename, content in auth_files.items():
                    atomic_write_text(
                        self.dynamic_config_path.parent / filename,
                        content,
                        mode=0o600,
                    )
                atomic_write_text(self.dynamic_config_path, config, mode=0o644)
            except OSError as exc:
                raise DashboardError(
                    "Traefik設定の書き込みに失敗しました。"
                    "原因を解消して「Webルートを再反映」を実行してください。"
                    f" ({exc})"
                ) from exc

            committed = self._commit_pending(records, pending_publish)
            self._save(committed, None)
            for path in self.dynamic_config_path.parent.glob(
                WEB_ROUTE_AUTH_FILE_PATTERN
            ):
                if path.name not in auth_files:
                    try:
                        path.unlink()
                    except OSError:
                        pass
            try:
                self.preview_path.unlink()
            except FileNotFoundError:
                pass
            return {
                "recovered": recovering,
                "published_at": utc_now(),
                "active_count": sum(
                    record.desired_active
                    and record.desired_enabled
                    and record.deleted_at is None
                    for record in committed
                ),
            }

    def load_preview(self) -> dict[str, Any] | None:
        if not self.preview_path.exists():
            return None
        try:
            value = json.loads(self.preview_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def status(self) -> dict[str, Any]:
        with self.lock:
            records, pending_publish = self._load()
            views = [
                self._record_view(record, False)
                for record in records
            ]
            config_ok, config_message = self.config_target_status()
            return {
                "total": sum(view["state_group"] != "deleted" for view in views),
                "pending": sum(view["state_group"] == "pending" for view in views),
                "enabled": sum(view["state_group"] == "enabled" for view in views),
                "disabled": sum(view["state_group"] == "disabled" for view in views),
                "deleted": sum(view["state_group"] == "deleted" for view in views),
                "publish_recovery_required": pending_publish is not None,
                "config_ready": config_ok,
                "config_message": config_message,
            }

    def config_target_status(self) -> tuple[bool, str]:
        parent = self.dynamic_config_path.parent
        if not parent.exists():
            return False, f"動的設定ディレクトリがありません: {parent}"
        if not os.access(parent, os.W_OK):
            return False, f"動的設定ディレクトリへ書き込めません: {parent}"
        try:
            self._require_managed_target()
        except DashboardError as exc:
            return False, str(exc)
        return True, f"管理対象ファイルへ書き込み可能: {self.dynamic_config_path}"

    def _load(self) -> tuple[list[WebRouteRecord], dict[str, Any] | None]:
        if not self.path.exists():
            return [], None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if value.get("version") != 1:
                raise DashboardError("未対応のWebルートデータ形式です。")
            records = [
                self._record_from_mapping(item)
                for item in value.get("records", [])
            ]
            pending_publish = value.get("pending_publish")
            if pending_publish is not None and not isinstance(pending_publish, dict):
                raise DashboardError("Webルート反映途中データが不正です。")
            self._validate_records(records)
            return records, pending_publish
        except (OSError, json.JSONDecodeError, TypeError, KeyError) as exc:
            raise DashboardError(f"Webルートデータを読み込めません: {exc}") from exc

    @staticmethod
    def _record_from_mapping(value: dict[str, Any]) -> WebRouteRecord:
        applied_value = value.get("applied_route")
        return WebRouteRecord(
            id=str(value["id"]),
            route=WebRoute.from_mapping(value["route"]),
            applied_route=(
                WebRoute.from_mapping(applied_value)
                if isinstance(applied_value, dict)
                else None
            ),
            desired_active=bool(value["desired_active"]),
            desired_enabled=bool(value["desired_enabled"]),
            applied_enabled=bool(value["applied_enabled"]),
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
            applied_at=str(value["applied_at"]) if value.get("applied_at") else None,
            deleted_at=str(value["deleted_at"]) if value.get("deleted_at") else None,
        )

    def _save(
        self,
        records: Iterable[WebRouteRecord],
        pending_publish: dict[str, Any] | None,
    ) -> None:
        materialized = list(records)
        self._validate_records(materialized)
        atomic_write_json(
            self.path,
            {
                "version": 1,
                "records": [asdict(record) for record in materialized],
                "pending_publish": pending_publish,
            },
            mode=0o600,
        )

    @staticmethod
    def _validate_records(records: list[WebRouteRecord]) -> None:
        ids = [record.id for record in records]
        if len(ids) != len(set(ids)):
            raise DashboardError("WebルートIDが重複しています。")
        active = [
            record
            for record in records
            if record.desired_active and record.deleted_at is None
        ]
        names = [record.route.name for record in active]
        if len(names) != len(set(names)):
            raise ConflictError("Webルート名が重複しています。")
        hostnames = [record.route.hostname for record in active]
        if len(hostnames) != len(set(hostnames)):
            raise ConflictError("同じドメインを複数のWebルートへ登録できません。")

    @staticmethod
    def _find(
        records: list[WebRouteRecord],
        record_id: str,
    ) -> WebRouteRecord:
        for record in records:
            if record.id == record_id:
                return record
        raise DashboardError(f"Webルートが見つかりません: {record_id}")

    @staticmethod
    def _require_mutable(pending_publish: dict[str, Any] | None) -> None:
        if pending_publish is not None:
            raise ConflictError(
                "Webルートの反映途中です。先に「Webルートを再反映」を実行してください。"
            )

    def _require_managed_target(self) -> None:
        if not self.dynamic_config_path.exists():
            return
        try:
            content = self.dynamic_config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise DashboardError(f"Traefik設定を読み込めません: {exc}") from exc
        if content and not content.startswith(WEB_ROUTE_MARKER + "\n"):
            raise ConflictError(
                "ui-web-routes.ymlは管理画面が作成したファイルではないため上書きできません。"
            )

    @classmethod
    def _record_has_pending_change(cls, record: WebRouteRecord) -> bool:
        if record.deleted_at is not None:
            return False
        if not record.desired_active:
            return record.applied_route is not None
        return (
            record.route != record.applied_route
            or record.desired_enabled != record.applied_enabled
        )

    @classmethod
    def _change_counts(cls, records: list[WebRouteRecord]) -> dict[str, int]:
        counts = {
            "create": 0,
            "update": 0,
            "enable": 0,
            "disable": 0,
            "delete": 0,
        }
        for record in records:
            if record.deleted_at is not None:
                continue
            if not record.desired_active and record.applied_route is not None:
                counts["delete"] += 1
            elif record.applied_route is None:
                counts["create"] += 1
            elif record.route != record.applied_route:
                counts["update"] += 1
            elif record.desired_enabled and not record.applied_enabled:
                counts["enable"] += 1
            elif not record.desired_enabled and record.applied_enabled:
                counts["disable"] += 1
        return counts

    @classmethod
    def _pending_snapshot(
        cls,
        records: list[WebRouteRecord],
        config: str,
    ) -> dict[str, Any]:
        return {
            "created_at": utc_now(),
            "fingerprint": web_routes_fingerprint(records),
            "config": config,
            "active": [
                {
                    "id": record.id,
                    "route": asdict(record.route),
                    "enabled": record.desired_enabled,
                }
                for record in records
                if record.desired_active and record.deleted_at is None
            ],
            "deleted_ids": [
                record.id
                for record in records
                if (
                    not record.desired_active
                    and record.deleted_at is None
                    and record.applied_route is not None
                )
            ],
            "changed_ids": [
                record.id
                for record in records
                if cls._record_has_pending_change(record)
            ],
        }

    @staticmethod
    def _commit_pending(
        records: list[WebRouteRecord],
        pending_publish: dict[str, Any],
    ) -> list[WebRouteRecord]:
        now = utc_now()
        active = {
            str(item["id"]): (
                WebRoute.from_mapping(item["route"]),
                bool(item["enabled"]),
            )
            for item in pending_publish.get("active", [])
        }
        deleted_ids = {
            str(item) for item in pending_publish.get("deleted_ids", [])
        }
        committed: list[WebRouteRecord] = []
        for record in records:
            if record.id in active:
                route, enabled = active[record.id]
                committed.append(
                    replace(
                        record,
                        route=route,
                        applied_route=route,
                        desired_active=True,
                        desired_enabled=enabled,
                        applied_enabled=enabled,
                        updated_at=now,
                        applied_at=now,
                    )
                )
            elif record.id in deleted_ids:
                committed.append(
                    replace(
                        record,
                        applied_route=None,
                        desired_active=False,
                        desired_enabled=False,
                        applied_enabled=False,
                        updated_at=now,
                        applied_at=now,
                        deleted_at=now,
                    )
                )
            else:
                committed.append(record)
        return committed

    @classmethod
    def _record_view(
        cls,
        record: WebRouteRecord,
        publish_pending: bool,
    ) -> dict[str, Any]:
        if record.deleted_at is not None:
            state = "deleted"
            group = "deleted"
        elif publish_pending:
            state = "publishing"
            group = "pending"
        elif not record.desired_active:
            state = "pending_delete"
            group = "pending"
        elif record.desired_enabled:
            if not record.applied_enabled:
                state = (
                    "pending_create"
                    if record.applied_route is None
                    else "pending_enable"
                )
                group = "pending"
            elif record.route != record.applied_route:
                state = "pending_update"
                group = "pending"
            else:
                state = "enabled"
                group = "enabled"
        elif record.applied_enabled:
            state = "pending_disable"
            group = "pending"
        elif record.route != record.applied_route:
            state = (
                "pending_create"
                if record.applied_route is None
                else "pending_update"
            )
            group = "pending"
        else:
            state = "disabled"
            group = "disabled"
        return {
            "id": record.id,
            **web_route_public_mapping(record.route),
            "desired_enabled": record.desired_enabled,
            "applied_enabled": record.applied_enabled,
            "state": state,
            "state_group": group,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "applied_at": record.applied_at,
            "deleted_at": record.deleted_at,
        }


class AuditLog:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "audit.jsonl"
        self.lock = threading.Lock()

    def append(self, action: str, result: str, detail: str) -> None:
        entry = {
            "time": datetime.now(UTC).isoformat(),
            "action": action,
            "result": result,
            "detail": detail[:1000],
        }
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
            os.chmod(self.path, 0o600)

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
            return [json.loads(line) for line in reversed(lines)]
        except (OSError, json.JSONDecodeError):
            return []


class IdempotencyStore:
    """Persist replayable, non-secret API results for 24 hours."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "idempotency.json"
        self.lock = threading.RLock()

    def replay(
        self,
        key: str,
        scope: str,
        request_hash: str,
    ) -> tuple[int, object] | None:
        with self.lock:
            records = self._load()
            existing = records.get(hashlib.sha256(key.encode()).hexdigest())
            if existing is None:
                return None
            if (
                existing.get("scope") != scope
                or existing.get("request_hash") != request_hash
            ):
                raise ConflictError(
                    "同じ冪等性キーが異なる操作に使用されています。"
                )
            return int(existing["status"]), existing["response"]

    def save(
        self,
        key: str,
        scope: str,
        request_hash: str,
        status: int,
        response: object,
    ) -> None:
        with self.lock:
            records = self._load()
            records[hashlib.sha256(key.encode()).hexdigest()] = {
                "scope": scope,
                "request_hash": request_hash,
                "status": status,
                "response": response,
                "created_at": utc_now(),
            }
            atomic_write_json(self.path, {"version": 1, "records": records}, mode=0o600)

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if value.get("version") != 1 or not isinstance(value.get("records"), dict):
                raise ValueError("unsupported idempotency data")
            cutoff = datetime.now(UTC).timestamp() - 86_400
            return {
                str(key): record
                for key, record in value["records"].items()
                if isinstance(record, dict)
                and datetime.fromisoformat(str(record.get("created_at"))).timestamp() >= cutoff
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise DashboardError(f"冪等性データを読み込めません: {exc}") from exc


Runner = Callable[[list[str], dict[str, str], Path | None, int], CommandResult]


def run_command(
    command: list[str],
    environment: dict[str, str],
    cwd: Path | None,
    timeout: int,
) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"コマンドが{timeout}秒以内に完了しませんでした。") from exc
    except OSError as exc:
        raise CommandError(f"コマンドを実行できません: {exc}") from exc
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def child_process_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("DASHBOARD_PASSWORD", "DASHBOARD_USERNAME"):
        environment.pop(name, None)
    return environment


class RelayManager:
    def __init__(
        self,
        script: Path,
        ssh_host: str,
        runner: Runner = run_command,
        timeout: int = 60,
    ) -> None:
        self.script = script
        self.ssh_host = ssh_host
        self.runner = runner
        self.timeout = timeout

    def _run(self, arguments: list[str]) -> CommandResult:
        environment = child_process_environment()
        environment["WG_RELAY_SSH_HOST"] = self.ssh_host
        result = self.runner(
            ["bash", str(self.script), *arguments],
            environment,
            self.script.parent.parent,
            self.timeout,
        )
        if result.returncode != 0:
            raise CommandError("OCIリレー管理コマンドに失敗しました。", result.output)
        return result

    def list(self) -> dict[str, RelayRoute]:
        return parse_relay_routes(self._run(["forward", "list"]).stdout)

    def list_peers(self) -> dict[str, WireGuardPeer]:
        return parse_wireguard_peers(self._run(["list"]).stdout)

    def list_peer_access_presets(self) -> dict[str, PeerAccessPreset]:
        return parse_peer_access_rules(self._run(["peer-forward", "list"]).stdout)

    def list_peer_access_rules(self) -> dict[str, PeerAccessPreset]:
        """Backward-compatible name for callers using the former rule API."""
        return self.list_peer_access_presets()

    def wireguard_state(
        self,
        relay_network: str,
        relay_address: str,
        dashboard_target_address: str,
        dashboard_port: int,
    ) -> dict[str, Any]:
        peers = self.list_peers()
        statuses = parse_wireguard_status(self._run(["status"]).stdout)
        presets = self.list_peer_access_presets()
        references: dict[str, list[str]] = {peer.address: [] for peer in peers.values()}
        assigned: dict[str, list[str]] = {peer.address: [] for peer in peers.values()}
        targets: dict[str, list[str]] = {peer.address: [] for peer in peers.values()}
        for preset in presets.values():
            for source_address in preset.source_addresses:
                references.setdefault(source_address, []).append(preset.name)
                assigned.setdefault(source_address, []).append(preset.name)
            references.setdefault(preset.target_address, []).append(preset.name)
            targets.setdefault(preset.target_address, []).append(preset.name)
        peer_rows = []
        for peer in sorted(
            peers.values(),
            key=lambda item: int(ipaddress.ip_address(item.address)),
        ):
            status = statuses.get(peer.public_key, {})
            peer_rows.append(
                {
                    **asdict(peer),
                    "endpoint": status.get("endpoint", ""),
                    "latest_handshake": status.get("latest_handshake", "未接続"),
                    "transfer": status.get("transfer", ""),
                    "access_rules": sorted(references.get(peer.address, [])),
                    "access_presets": sorted(assigned.get(peer.address, [])),
                    "target_presets": sorted(targets.get(peer.address, [])),
                }
            )
        preset_rows = [
            asdict(preset)
            for preset in sorted(presets.values(), key=lambda item: item.name)
        ]
        return {
            "peers": peer_rows,
            "access_presets": preset_rows,
            # Retained during the access-rule to access-preset API transition.
            "access_rules": [
                {
                    **row,
                    "source_address": (
                        row["source_addresses"][0]
                        if len(row["source_addresses"]) == 1
                        else ""
                    ),
                }
                for row in preset_rows
            ],
            "suggested_address": suggest_peer_address(
                peers.values(),
                relay_network,
                relay_address,
            ),
            "relay_network": relay_network,
            "relay_address": relay_address,
            "dashboard_target_address": dashboard_target_address,
            "dashboard_port": dashboard_port,
        }

    def create_peer(
        self,
        name: Any,
        address: Any,
        relay_network: str,
        relay_address: str,
    ) -> tuple[str, str]:
        normalized_name = normalize_wireguard_name(name, "Peer名")
        normalized_address = normalize_peer_address(
            address,
            relay_network,
            relay_address,
        )
        result = self._run(
            [
                "add",
                normalized_name,
                "--address",
                normalized_address,
                "--output",
                "-",
            ]
        )
        if not result.stdout.startswith("[Interface]"):
            raise CommandError(
                "Peerは追加されましたが、接続設定を取得できませんでした。鍵を更新して再発行してください。",
                result.stderr,
            )
        return normalized_name, result.stdout + "\n"

    def rotate_peer(self, name: Any) -> tuple[str, str]:
        normalized_name = normalize_wireguard_name(name, "Peer名", existing=True)
        peers = self.list_peers()
        peer = peers.get(normalized_name)
        if peer is None:
            raise ValidationError(f"WireGuard Peerが見つかりません: {normalized_name}")
        result = self._run(
            [
                "update",
                normalized_name,
                "--address",
                peer.cidr,
                "--output",
                "-",
            ]
        )
        if not result.stdout.startswith("[Interface]"):
            raise CommandError(
                "Peerの鍵は更新されましたが、接続設定を取得できませんでした。もう一度更新してください。",
                result.stderr,
            )
        return normalized_name, result.stdout + "\n"

    def rename_peer(
        self,
        current_name: Any,
        new_name: Any,
    ) -> tuple[str, str]:
        normalized_current_name = normalize_wireguard_name(
            current_name,
            "現在のPeer名",
            existing=True,
        )
        normalized_new_name = normalize_wireguard_name(new_name, "新しいPeer名")
        peers = self.list_peers()
        if normalized_current_name not in peers:
            raise ValidationError(
                f"WireGuard Peerが見つかりません: {normalized_current_name}"
            )
        if normalized_new_name == normalized_current_name:
            return normalized_current_name, normalized_new_name
        if normalized_new_name in peers:
            raise ConflictError(
                f"Peer名はすでに使用されています: {normalized_new_name}"
            )
        self._run(
            [
                "rename",
                normalized_current_name,
                normalized_new_name,
            ]
        )
        return normalized_current_name, normalized_new_name

    def delete_peer(self, name: Any) -> str:
        normalized_name = normalize_wireguard_name(name, "Peer名", existing=True)
        self._run(["delete", normalized_name, "--yes"])
        return normalized_name

    def create_peer_access_rule(self, rule: PeerAccessRule) -> None:
        self.create_peer_access_preset(
            PeerAccessPreset(
                name=rule.name,
                protocol=rule.protocol,
                target_address=rule.target_address,
                target_port=rule.target_port,
                source_addresses=(rule.source_address,),
            )
        )

    def update_peer_access_rule(self, rule: PeerAccessRule) -> None:
        self.update_peer_access_preset(
            PeerAccessPreset(
                name=rule.name,
                protocol=rule.protocol,
                target_address=rule.target_address,
                target_port=rule.target_port,
                source_addresses=(rule.source_address,),
            )
        )

    def create_peer_access_preset(self, preset: PeerAccessPreset) -> None:
        self._run(self._peer_access_preset_arguments("add", preset))

    def update_peer_access_preset(
        self,
        preset: PeerAccessPreset,
        current_name: str | None = None,
    ) -> None:
        self._run(
            self._peer_access_preset_arguments(
                "update",
                preset,
                current_name=current_name,
            )
        )

    @staticmethod
    def _peer_access_preset_arguments(
        operation: str,
        preset: PeerAccessPreset,
        current_name: str | None = None,
    ) -> list[str]:
        command_name = current_name or preset.name
        arguments = [
            "peer-forward",
            operation,
            command_name,
            "--protocol",
            preset.protocol,
        ]
        if operation == "update" and command_name != preset.name:
            arguments.extend(["--new-name", preset.name])
        for source_address in preset.source_addresses:
            arguments.extend(["--source-address", source_address])
        arguments.extend(
            [
                "--target-address",
                preset.target_address,
                "--target-port",
                str(preset.target_port),
            ]
        )
        return arguments

    def set_peer_access_presets(
        self,
        peer_name: Any,
        preset_names: Any,
    ) -> tuple[str, tuple[str, ...]]:
        normalized_peer_name = normalize_wireguard_name(
            peer_name,
            "Peer名",
            existing=True,
        )
        if not isinstance(preset_names, list):
            raise ValidationError("アクセスプリセット一覧は配列にしてください。")
        normalized_preset_names: list[str] = []
        for value in preset_names:
            name = normalize_wireguard_name(
                value,
                "アクセスプリセット名",
                existing=True,
            )
            if name not in normalized_preset_names:
                normalized_preset_names.append(name)

        peers = self.list_peers()
        peer = peers.get(normalized_peer_name)
        if peer is None:
            raise ValidationError(
                f"WireGuard Peerが見つかりません: {normalized_peer_name}"
            )
        self._run(
            [
                "peer-forward",
                "assign-source",
                peer.address,
                *normalized_preset_names,
            ]
        )
        return normalized_peer_name, tuple(normalized_preset_names)

    def delete_peer_access_preset(self, name: Any) -> str:
        normalized_name = normalize_wireguard_name(
            name,
            "アクセスプリセット名",
            existing=True,
        )
        self._run(["peer-forward", "delete", normalized_name, "--yes"])
        return normalized_name

    def update_peer_access_preset_definition(
        self,
        current_name: Any,
        preset: PeerAccessPreset,
    ) -> None:
        normalized_current_name = normalize_wireguard_name(
            current_name,
            "アクセスプリセット名",
            existing=True,
        )
        presets = self.list_peer_access_presets()
        current = presets.get(normalized_current_name)
        if current is None:
            raise ValidationError(
                f"アクセスプリセットが見つかりません: {normalized_current_name}"
            )
        if preset.name != normalized_current_name and preset.name in presets:
            raise ConflictError(
                f"アクセスプリセット名はすでに使用されています: {preset.name}"
            )
        self.update_peer_access_preset(
            replace(preset, source_addresses=current.source_addresses),
            current_name=normalized_current_name,
        )

    def delete_peer_access_rule(self, name: Any) -> str:
        return self.delete_peer_access_preset(name)

    def check_conflicts(
        self,
        desired_routes: Iterable[Route],
        actual_routes: dict[str, RelayRoute] | None = None,
    ) -> list[str]:
        actual = actual_routes if actual_routes is not None else self.list()
        desired = validate_route_set(desired_routes)
        conflicts: list[str] = []
        for route in desired:
            desired_signature = (
                route.protocol,
                route.public_port,
                route.target_address,
                route.target_port,
            )
            for existing in actual.values():
                if existing.name.startswith(MANAGED_ROUTE_PREFIX):
                    continue
                if (
                    existing.protocol == route.protocol
                    and existing.public_port == route.public_port
                ):
                    if existing.signature == desired_signature:
                        continue
                    conflicts.append(
                        f"{route.protocol.upper()}/{route.public_port}は"
                        f"手動ルール「{existing.name}」で使用されています。"
                    )
        return conflicts

    def adoptions(
        self,
        desired_routes: Iterable[Route],
        actual_routes: dict[str, RelayRoute] | None = None,
    ) -> list[dict[str, Any]]:
        """Return manual relay rules that can be safely adopted as GUI rules."""
        actual = actual_routes if actual_routes is not None else self.list()
        desired = validate_route_set(desired_routes)
        desired_by_signature = {
            (
                route.protocol,
                route.public_port,
                route.target_address,
                route.target_port,
            ): route
            for route in desired
        }
        adoptions: list[dict[str, Any]] = []
        for existing in sorted(actual.values(), key=lambda item: item.name):
            if existing.name.startswith(MANAGED_ROUTE_PREFIX):
                continue
            route = desired_by_signature.get(existing.signature)
            if route is None:
                continue
            adoptions.append(
                {
                    "manual_name": existing.name,
                    "managed_name": route.remote_name,
                    "protocol": route.protocol,
                    "public_port": route.public_port,
                    "target_address": route.target_address,
                    "target_port": route.target_port,
                }
            )
        return adoptions

    def sync(self, desired_routes: Iterable[Route]) -> list[str]:
        desired = validate_route_set(desired_routes)
        actual = self.list()
        conflicts = self.check_conflicts(desired, actual)
        if conflicts:
            raise ConflictError(" ".join(conflicts))
        adoptions = self.adoptions(desired, actual)

        desired_by_name = {route.remote_name: route for route in desired}
        managed_actual = {
            name: route
            for name, route in actual.items()
            if name.startswith(MANAGED_ROUTE_PREFIX)
        }
        actions: list[str] = []

        # Delete stale and changed rules first so port swaps and renames cannot
        # conflict with wg-relay's uniqueness check.
        for name, existing in sorted(managed_actual.items()):
            desired_route = desired_by_name.get(name)
            desired_signature = (
                desired_route.protocol,
                desired_route.public_port,
                desired_route.target_address,
                desired_route.target_port,
            ) if desired_route else None
            if desired_signature != existing.signature:
                self._run(["forward", "delete", name, "--yes"])
                actions.append(f"削除: {name}")

        # An exact signature match is an explicit handover request: replace the
        # manual rule with an equivalent ui-* rule so subsequent toggles and
        # edits are controlled by the dashboard. Non-matching manual listeners
        # remain protected by check_conflicts().
        for adoption in adoptions:
            manual_name = str(adoption["manual_name"])
            self._run(["forward", "delete", manual_name, "--yes"])
            actions.append(
                f"移管: {manual_name} → {adoption['managed_name']}"
            )

        for name, route in sorted(desired_by_name.items()):
            existing = managed_actual.get(name)
            signature = (
                route.protocol,
                route.public_port,
                route.target_address,
                route.target_port,
            )
            if existing and existing.signature == signature:
                continue
            self._run(
                [
                    "forward",
                    "add",
                    name,
                    "--protocol",
                    route.protocol,
                    "--listen-port",
                    str(route.public_port),
                    "--target-address",
                    route.target_address,
                    "--target-port",
                    str(route.target_port),
                ]
            )
            actions.append(
                f"追加: {name} {route.protocol.upper()}/{route.public_port}"
                f" → {route.target_address}:{route.target_port}"
            )

        return actions or ["リレー経路に変更はありません。"]


class TerraformManager:
    def __init__(
        self,
        workspace: Path,
        data_dir: Path,
        runner: Runner = run_command,
        timeout: int = 600,
    ) -> None:
        self.source_workspace = workspace
        self.runtime_home = Path.home()
        self.workspace = self.runtime_home / "terraform-workspace"
        self.data_dir = data_dir
        self.runner = runner
        self.timeout = timeout
        self.var_file = data_dir / "dashboard.tfvars.json"
        self.plan_file = data_dir / "dashboard.tfplan"
        self.plan_meta_file = data_dir / "plan-meta.json"
        self.tf_data_dir = data_dir / "terraform"
        self.temp_dir = data_dir / "tmp"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def configuration_files(self) -> list[Path]:
        candidates = sorted(self.source_workspace.glob("*.tf"))
        for name in (".terraform.lock.hcl", "terraform.tfvars", "cloud-init.yaml"):
            path = self.source_workspace / name
            if path.is_file():
                candidates.append(path)
        return candidates

    def configuration_fingerprint(self) -> str:
        digest = hashlib.sha256()
        for path in self.configuration_files():
            digest.update(path.name.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    def prepare_workspace(self) -> None:
        files = self.configuration_files()
        required_names = {"versions.tf", "terraform.tfvars", "cloud-init.yaml"}
        available_names = {path.name for path in files}
        missing = sorted(required_names - available_names)
        if missing:
            raise DashboardError(
                "Terraform実行に必要なファイルがありません: " + ", ".join(missing)
            )

        self.workspace.mkdir(parents=True, exist_ok=True)
        for existing in self.workspace.iterdir():
            if existing.is_file():
                existing.unlink()
        for source in files:
            shutil.copy2(source, self.workspace / source.name)

    def _environment(self) -> dict[str, str]:
        environment = child_process_environment()
        environment.update(
            {
                "OCI_HOME_OVERRIDE": str(self.runtime_home),
                "TMPDIR": str(self.temp_dir),
                "TF_DATA_DIR": str(self.tf_data_dir),
                "TF_HOME_OVERRIDE": str(self.runtime_home),
                "TF_IN_AUTOMATION": "true",
                "TF_INPUT": "false",
            }
        )
        return environment

    def _run(self, arguments: list[str], timeout: int | None = None) -> CommandResult:
        result = self.runner(
            ["terraform", f"-chdir={self.workspace}", *arguments],
            self._environment(),
            self.workspace,
            timeout or self.timeout,
        )
        if result.returncode != 0:
            raise CommandError("Terraformコマンドに失敗しました。", result.output)
        return result

    def write_var_file(self, routes: Iterable[Route]) -> None:
        validated = validate_route_set(routes)
        payload = {
            "dashboard_public_tcp_port_ranges": compact_port_ranges(
                route.public_port for route in validated if route.protocol == "tcp"
            ),
            "dashboard_public_udp_port_ranges": compact_port_ranges(
                route.public_port for route in validated if route.protocol == "udp"
            ),
        }
        atomic_write_json(self.var_file, payload, mode=0o600)

    def plan(
        self,
        routes: Iterable[Route],
        relay_adoptions: Iterable[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        validated = validate_route_set(routes)
        adoption_metadata = list(relay_adoptions)
        self.prepare_workspace()
        self.write_var_file(validated)
        self._run(["init", "-input=false", "-no-color"])
        self._run(["validate", "-no-color"])
        plan_result = self._run(
            [
                "plan",
                "-input=false",
                "-no-color",
                "-lock-timeout=30s",
                f"-var-file={self.var_file}",
                f"-out={self.plan_file}",
            ]
        )
        show_result = self._run(["show", "-json", str(self.plan_file)])
        try:
            plan_json = json.loads(show_result.stdout)
        except json.JSONDecodeError as exc:
            raise DashboardError("Terraform planのJSONを解析できません。") from exc

        analysis = analyze_terraform_plan(plan_json)
        metadata = {
            "created_at": datetime.now(UTC).isoformat(),
            "fingerprint": routes_fingerprint(validated),
            "configuration_fingerprint": self.configuration_fingerprint(),
            "safe": analysis["safe"],
            "unexpected": analysis["unexpected"],
            "counts": analysis["counts"],
            "relay_adoptions": adoption_metadata,
            "output": truncate_text(plan_result.output, 160_000),
        }
        atomic_write_json(self.plan_meta_file, metadata, mode=0o600)
        return metadata

    def load_plan_metadata(self) -> dict[str, Any] | None:
        if not self.plan_meta_file.exists():
            return None
        try:
            return json.loads(self.plan_meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def apply(self, routes: Iterable[Route]) -> str:
        validated = validate_route_set(routes)
        metadata = self.load_plan_metadata()
        if not metadata or not self.plan_file.exists():
            raise DashboardError("適用前にTerraform planを作成してください。")
        if not metadata.get("safe"):
            raise DashboardError("予期しない変更を含むplanは適用できません。")
        if not hmac.compare_digest(
            str(metadata.get("fingerprint", "")),
            routes_fingerprint(validated),
        ):
            raise DashboardError("経路がplan作成後に変更されています。planを作り直してください。")
        if not hmac.compare_digest(
            str(metadata.get("configuration_fingerprint", "")),
            self.configuration_fingerprint(),
        ):
            raise DashboardError(
                "Terraform構成がplan作成後に変更されています。planを作り直してください。"
            )
        result = self._run(
            ["apply", "-input=false", "-no-color", "-auto-approve", str(self.plan_file)]
        )
        return truncate_text(result.output, 160_000)

    def invalidate_plan(self) -> None:
        for path in (self.plan_file, self.plan_meta_file):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n\n…出力が長いため省略しました。"


def oci_config_status(path: Path) -> tuple[bool, str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8-sig") as stream:
            parser.read_file(stream)
    except (OSError, configparser.Error) as exc:
        return False, f"読込エラー: {exc}"

    required = {"tenancy", "user", "fingerprint", "region", "key_file"}
    missing = sorted(required - set(parser.defaults()))
    if missing:
        return False, "DEFAULTに必須項目がありません: " + ", ".join(missing)
    return True, "DEFAULTを読込可能"


def preflight_checks(
    workspace: Path,
    data_dir: Path,
    relay: RelayManager,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add(
        "Terraform CLI",
        shutil.which("terraform") is not None,
        "利用可能" if shutil.which("terraform") else "コンテナ内に見つかりません",
    )
    add(
        "Terraform構成",
        (workspace / "versions.tf").is_file(),
        str(workspace / "versions.tf"),
    )
    add(
        "terraform.tfvars",
        (workspace / "terraform.tfvars").is_file(),
        "読込可能" if (workspace / "terraform.tfvars").is_file() else "MiniPC側に配置してください",
    )
    home = Path.home()
    oci_config = home / ".oci/config"
    if oci_config.is_file():
        oci_config_ok, oci_config_detail = oci_config_status(oci_config)
        add("OCI設定", oci_config_ok, oci_config_detail)
    else:
        add("OCI設定", False, "secrets/oci/configを配置してください")
    add(
        "SSH設定",
        (home / ".ssh/config").is_file(),
        "読込可能" if (home / ".ssh/config").is_file() else "secrets/ssh/configを配置してください",
    )
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add("永続データ", True, "書込可能")
    except OSError as exc:
        add("永続データ", False, str(exc))

    try:
        routes = relay.list()
        add("OCIリレー", True, f"{len(routes)}件の転送ルールを確認")
    except DashboardError as exc:
        add("OCIリレー", False, str(exc))

    return checks

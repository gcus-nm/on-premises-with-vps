from __future__ import annotations

import configparser
import hashlib
import hmac
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
GROUP_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,17}$")
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
class GroupRecord:
    id: str
    name: str
    description: str
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
                members = [
                    record
                    for record in records
                    if (
                        record.group_id == group.id
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

    def create_group(
        self,
        name: Any,
        description: Any = "",
        members: Any = None,
    ) -> GroupRecord:
        normalized_name, normalized_description = normalize_group(name, description)
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._ensure_group_name_available(groups, normalized_name)
            now = utc_now()
            group = GroupRecord(
                id=str(uuid.uuid4()),
                name=normalized_name,
                description=normalized_description,
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

    def update_group(self, group_id: str, name: Any, description: Any = "") -> GroupRecord:
        normalized_name, normalized_description = normalize_group(name, description)
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            target = self._find_group(groups, group_id)
            self._ensure_group_name_available(groups, normalized_name, excluded_id=group_id)
            updated = replace(
                target,
                name=normalized_name,
                description=normalized_description,
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
            now = utc_now()
            updated_records = [
                replace(record, desired_enabled=enabled, updated_at=now)
                if (
                    record.group_id == group_id
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
                    record.group_id == group_id
                    and record.desired_active
                    and record.deleted_at is None
                )
            ]

    def delete_group(self, group_id: str) -> None:
        with self.lock:
            records, groups, pending_relay = self._load()
            self._require_mutable(pending_relay)
            self._find_group(groups, group_id)
            records = [
                replace(record, group_id=None, updated_at=utc_now())
                if record.group_id == group_id
                else record
                for record in records
            ]
            groups = [group for group in groups if group.id != group_id]
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
            if version != 3:
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
            "version": 3,
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

    def check_conflicts(
        self,
        desired_routes: Iterable[Route],
        actual_routes: dict[str, RelayRoute] | None = None,
    ) -> list[str]:
        actual = actual_routes if actual_routes is not None else self.list()
        desired = validate_route_set(desired_routes)
        conflicts: list[str] = []
        for route in desired:
            for existing in actual.values():
                if existing.name.startswith(MANAGED_ROUTE_PREFIX):
                    continue
                if (
                    existing.protocol == route.protocol
                    and existing.public_port == route.public_port
                ):
                    conflicts.append(
                        f"{route.protocol.upper()}/{route.public_port}は"
                        f"手動ルール「{existing.name}」で使用されています。"
                    )
        return conflicts

    def sync(self, desired_routes: Iterable[Route]) -> list[str]:
        desired = validate_route_set(desired_routes)
        actual = self.list()
        conflicts = self.check_conflicts(desired, actual)
        if conflicts:
            raise ConflictError(" ".join(conflicts))

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

    def plan(self, routes: Iterable[Route]) -> dict[str, Any]:
        validated = validate_route_set(routes)
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

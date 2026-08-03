"use strict";

const collapsedGroupsStorageKey = "relay-dashboard:collapsed-groups:v1";

const appState = {
  routes: [],
  groups: [],
  plan: null,
  audit: [],
  csrfToken: "",
  routeFilter: "all",
  webRoutes: [],
  webRoutesStatus: {},
  webGateway: { ports: { "80": {}, "443": {} } },
  webRouteFilter: "all",
  pendingRelay: false,
  busy: false,
  collapsedGroups: loadCollapsedGroups(),
  peers: [],
  accessRules: [],
  suggestedPeerAddress: "",
  relayNetwork: "10.99.0.0/24",
  dashboardTargetAddress: "10.99.0.2",
  dashboardPort: 8081,
  wireguardLoading: true,
  wireguardError: "",
};

const routeStateLabels = {
  enabled: "有効",
  disabled: "無効",
  pending_create: "作成待ち",
  pending_update: "更新待ち",
  pending_enable: "有効化待ち",
  pending_disable: "無効化待ち",
  pending_delete: "削除待ち",
  pending_relay: "リレー同期待ち",
  publishing: "反映途中",
  deleted: "削除済み",
};

const elements = {
  total: document.querySelector("#metric-total"),
  tcp: document.querySelector("#metric-tcp"),
  udp: document.querySelector("#metric-udp"),
  status: document.querySelector("#metric-status"),
  statusDetail: document.querySelector("#metric-status-detail"),
  empty: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyDescription: document.querySelector("#empty-description"),
  emptyNewRoute: document.querySelector("#empty-new-route-button"),
  routeTabs: document.querySelector("#route-tabs"),
  tableWrap: document.querySelector("#routes-table-wrap"),
  routesBody: document.querySelector("#routes-body"),
  auditList: document.querySelector("#audit-list"),
  webGateway80: document.querySelector("#web-gateway-80"),
  webGateway443: document.querySelector("#web-gateway-443"),
  webRouteSummary: document.querySelector("#web-route-summary"),
  webRouteTabs: document.querySelector("#web-route-tabs"),
  webRoutesBody: document.querySelector("#web-routes-body"),
  webRouteDialog: document.querySelector("#web-route-dialog"),
  webRouteForm: document.querySelector("#web-route-form"),
  webRouteDialogTitle: document.querySelector("#web-route-dialog-title"),
  webRecordId: document.querySelector("#web-record-id"),
  webRouteName: document.querySelector("#web-route-name"),
  webRouteHostname: document.querySelector("#web-route-hostname"),
  webRouteAlias: document.querySelector("#web-route-alias"),
  webRoutePort: document.querySelector("#web-route-port"),
  webRouteDescription: document.querySelector("#web-route-description"),
  webRouteBasicAuthEnabled: document.querySelector("#web-route-basic-auth-enabled"),
  webRouteBasicAuthFields: document.querySelector("#web-route-basic-auth-fields"),
  webRouteBasicAuthUsername: document.querySelector("#web-route-basic-auth-username"),
  webRouteBasicAuthRotate: document.querySelector("#web-route-basic-auth-rotate"),
  webRouteBasicAuthRotateLabel: document.querySelector("#web-route-basic-auth-rotate-label"),
  webRouteAdvanced: document.querySelector("#web-route-advanced"),
  webRouteAdvancedDescription: document.querySelector("#web-route-advanced-description"),
  deleteWebRouteButton: document.querySelector("#delete-web-route-button"),
  saveWebRouteButton: document.querySelector("#save-web-route-button"),
  webRouteFormError: document.querySelector("#web-route-form-error"),
  webPublishDialog: document.querySelector("#web-publish-dialog"),
  webPublishSummary: document.querySelector("#web-publish-summary"),
  webPublishRoutes: document.querySelector("#web-publish-routes"),
  webPublishConfig: document.querySelector("#web-publish-config"),
  webPublishConfirmation: document.querySelector("#web-publish-confirmation"),
  webPublishConfirmButton: document.querySelector("#web-publish-confirm-button"),
  webPublishError: document.querySelector("#web-publish-error"),
  routeDialog: document.querySelector("#route-dialog"),
  routeForm: document.querySelector("#route-form"),
  routeDialogTitle: document.querySelector("#route-dialog-title"),
  recordId: document.querySelector("#record-id"),
  routeName: document.querySelector("#route-name"),
  routeProtocol: document.querySelector("#route-protocol"),
  routePublicPort: document.querySelector("#route-public-port"),
  routeTargetAddress: document.querySelector("#route-target-address"),
  routeTargetPort: document.querySelector("#route-target-port"),
  routeDescription: document.querySelector("#route-description"),
  routeGroup: document.querySelector("#route-group"),
  routeAdvanced: document.querySelector("#route-advanced"),
  routeAdvancedDescription: document.querySelector("#route-advanced-description"),
  deleteRouteButton: document.querySelector("#delete-route-button"),
  saveRouteButton: document.querySelector("#save-route-button"),
  routeFormError: document.querySelector("#route-form-error"),
  groupDialog: document.querySelector("#group-dialog"),
  groupForm: document.querySelector("#group-form"),
  groupDialogTitle: document.querySelector("#group-dialog-title"),
  groupId: document.querySelector("#group-id"),
  groupName: document.querySelector("#group-name"),
  groupDescription: document.querySelector("#group-description"),
  groupParent: document.querySelector("#group-parent"),
  groupMemberRows: document.querySelector("#group-member-rows"),
  groupPortPreview: document.querySelector("#group-port-preview"),
  groupAdvanced: document.querySelector("#group-advanced"),
  groupFormError: document.querySelector("#group-form-error"),
  planDialog: document.querySelector("#plan-dialog"),
  planSummary: document.querySelector("#plan-summary"),
  relayAdoptions: document.querySelector("#relay-adoptions"),
  unexpected: document.querySelector("#unexpected-changes"),
  planOutput: document.querySelector("#plan-output"),
  planError: document.querySelector("#plan-error"),
  applyConfirmation: document.querySelector("#apply-confirmation"),
  applyButton: document.querySelector("#apply-button"),
  infoDialog: document.querySelector("#info-dialog"),
  infoEyebrow: document.querySelector("#info-eyebrow"),
  infoTitle: document.querySelector("#info-title"),
  infoContent: document.querySelector("#info-content"),
  wireguardPeerSummary: document.querySelector("#wireguard-peer-summary"),
  wireguardPeerList: document.querySelector("#wireguard-peer-list"),
  wireguardAccessList: document.querySelector("#wireguard-access-list"),
  wireguardError: document.querySelector("#wireguard-error"),
  peerDialog: document.querySelector("#peer-dialog"),
  peerForm: document.querySelector("#peer-form"),
  peerName: document.querySelector("#peer-name"),
  peerAddress: document.querySelector("#peer-address"),
  peerFormError: document.querySelector("#peer-form-error"),
  savePeerButton: document.querySelector("#save-peer-button"),
  accessRuleDialog: document.querySelector("#access-rule-dialog"),
  accessRuleForm: document.querySelector("#access-rule-form"),
  accessRuleDialogTitle: document.querySelector("#access-rule-dialog-title"),
  accessRuleOriginalName: document.querySelector("#access-rule-original-name"),
  accessRuleName: document.querySelector("#access-rule-name"),
  accessSource: document.querySelector("#access-source"),
  accessTarget: document.querySelector("#access-target"),
  accessProtocol: document.querySelector("#access-protocol"),
  accessTargetPort: document.querySelector("#access-target-port"),
  accessRuleFormError: document.querySelector("#access-rule-form-error"),
  saveAccessRuleButton: document.querySelector("#save-access-rule-button"),
  toast: document.querySelector("#toast"),
};

function loadCollapsedGroups() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(collapsedGroupsStorageKey) || "[]");
    return new Set(
      Array.isArray(stored)
        ? stored.filter((groupId) => typeof groupId === "string")
        : [],
    );
  } catch {
    return new Set();
  }
}

function saveCollapsedGroups() {
  try {
    window.localStorage.setItem(
      collapsedGroupsStorageKey,
      JSON.stringify([...appState.collapsedGroups]),
    );
  } catch {
    // ブラウザストレージが使えない環境でも、現在の画面内では折りたたみを維持する。
  }
}

function pruneCollapsedGroups() {
  const knownGroupIds = new Set(appState.groups.map((group) => group.id));
  const pruned = new Set(
    [...appState.collapsedGroups].filter((groupId) => knownGroupIds.has(groupId)),
  );
  if (pruned.size === appState.collapsedGroups.size) return;
  appState.collapsedGroups = pruned;
  saveCollapsedGroups();
}

async function api(path, options = {}) {
  const request = {
    method: options.method || "GET",
    headers: { Accept: "application/json", ...(options.headers || {}) },
  };
  if (request.method !== "GET") {
    request.headers["Content-Type"] = "application/json";
    request.headers["X-Relay-CSRF"] = appState.csrfToken;
    request.body = JSON.stringify(options.body || {});
  }
  const response = await fetch(path, request);
  const payload = await response.json().catch(() => ({
    message: `HTTP ${response.status}`,
  }));
  if (!response.ok) {
    const detail = payload.detail ? `\n${payload.detail}` : "";
    throw new Error(`${payload.message || "操作に失敗しました。"}${detail}`);
  }
  return payload;
}

async function loadState() {
  const payload = await api("/api/state");
  appState.routes = payload.routes || [];
  appState.groups = payload.groups || [];
  appState.webRoutes = payload.web_routes || [];
  appState.webRoutesStatus = payload.web_routes_status || {};
  appState.webGateway = payload.web_gateway || appState.webGateway;
  pruneCollapsedGroups();
  appState.plan = payload.plan;
  appState.audit = payload.audit || [];
  appState.csrfToken = payload.csrf_token;
  appState.pendingRelay = Boolean(payload.pending_relay);
  appState.busy = Boolean(payload.busy);
  render();
}

async function loadWireGuard() {
  appState.wireguardLoading = true;
  appState.wireguardError = "";
  renderWireGuard();
  try {
    const payload = await api("/api/wireguard");
    appState.peers = payload.peers || [];
    appState.accessRules = payload.access_rules || [];
    appState.suggestedPeerAddress = payload.suggested_address || "";
    appState.relayNetwork = payload.relay_network || appState.relayNetwork;
    appState.dashboardTargetAddress =
      payload.dashboard_target_address || appState.dashboardTargetAddress;
    appState.dashboardPort = Number(payload.dashboard_port || appState.dashboardPort);
  } catch (error) {
    appState.wireguardError = firstLine(error.message);
    throw error;
  } finally {
    appState.wireguardLoading = false;
    renderWireGuard();
  }
}

function render() {
  const managed = appState.routes.filter((route) => route.state !== "deleted");
  const enabled = managed.filter((route) => route.desired_enabled);
  elements.total.textContent = String(managed.length);
  elements.tcp.textContent = String(
    enabled.filter((route) => route.protocol === "tcp").length,
  );
  elements.udp.textContent = String(
    enabled.filter((route) => route.protocol === "udp").length,
  );
  renderRoutes();
  renderWebRoutes();
  renderAudit();
  renderPlanStatus();
  renderOperationAvailability();
  renderWireGuard();
}

function renderWireGuard() {
  const locked = appState.busy || appState.wireguardLoading;
  document.querySelector("#new-peer-button").disabled = locked;
  document.querySelector("#new-access-rule-button").disabled =
    locked || appState.peers.length < 2;
  document.querySelector("#wireguard-refresh-button").disabled =
    appState.wireguardLoading;
  elements.wireguardError.textContent = appState.wireguardError;
  elements.wireguardPeerSummary.textContent = appState.wireguardLoading
    ? "OCIからPeer状態を読み込んでいます。"
    : `${appState.peers.length} Peer · ${appState.relayNetwork} · ACL ${appState.accessRules.length}件`;

  if (appState.wireguardLoading && !appState.peers.length) {
    elements.wireguardPeerList.innerHTML = '<p class="muted">読み込み中です。</p>';
    elements.wireguardAccessList.innerHTML = '<p class="muted">読み込み中です。</p>';
    return;
  }

  elements.wireguardPeerList.innerHTML = appState.peers.length
    ? appState.peers.map((peer) => renderPeerItem(peer, locked)).join("")
    : '<p class="muted">登録済みPeerはありません。</p>';
  elements.wireguardAccessList.innerHTML = appState.accessRules.length
    ? appState.accessRules.map((rule) => renderAccessRuleItem(rule, locked)).join("")
    : '<p class="muted">Peer間アクセスルールはありません。</p>';
}

function renderPeerItem(peer, locked) {
  const connected = peer.latest_handshake && peer.latest_handshake !== "未接続";
  const references = peer.access_rules || [];
  const canAddAccess =
    appState.peers.length > 1 && peer.address !== appState.dashboardTargetAddress;
  return `
    <article class="wireguard-item">
      <div class="wireguard-item-heading">
        <div>
          <strong>${escapeHtml(peer.name)}</strong>
          <small class="mono">${escapeHtml(peer.cidr)}</small>
        </div>
        <small>
          <span class="status-dot ${connected ? "connected" : ""}"></span>
          ${escapeHtml(peer.latest_handshake || "未接続")}
        </small>
      </div>
      <div class="wireguard-peer-meta">
        <div>
          <span>Endpoint</span>
          <strong title="${escapeAttribute(peer.endpoint || "未接続")}">${escapeHtml(peer.endpoint || "未接続")}</strong>
        </div>
        <div>
          <span>Transfer</span>
          <strong title="${escapeAttribute(peer.transfer || "データなし")}">${escapeHtml(peer.transfer || "データなし")}</strong>
        </div>
      </div>
      <p class="wireguard-reference">
        ${references.length ? `参照ルール: ${escapeHtml(references.join(", "))}` : "参照中のアクセスルールなし"}
      </p>
      <div class="wireguard-item-actions">
        ${
          canAddAccess
            ? `<button class="small-button" type="button" data-peer-access="${escapeAttribute(peer.name)}" ${locked ? "disabled" : ""}>アクセス追加</button>`
            : ""
        }
        <button class="small-button edit" type="button" data-peer-rotate="${escapeAttribute(peer.name)}" ${locked ? "disabled" : ""}>鍵を更新</button>
        <button class="small-button danger" type="button" data-peer-delete="${escapeAttribute(peer.name)}" ${locked ? "disabled" : ""}>削除</button>
      </div>
    </article>
  `;
}

function renderAccessRuleItem(rule, locked) {
  const source = peerLabel(rule.source_address);
  const target = peerLabel(rule.target_address);
  return `
    <article class="wireguard-item">
      <div class="wireguard-item-heading">
        <strong>${escapeHtml(rule.name)}</strong>
        <span class="protocol-badge ${escapeAttribute(rule.protocol)}">${rule.protocol.toUpperCase()}</span>
      </div>
      <div class="wireguard-flow">
        <span>${escapeHtml(source)}</span>
        <span class="wireguard-flow-arrow">→</span>
        <span>${escapeHtml(target)}:${rule.target_port}</span>
      </div>
      <div class="wireguard-item-actions">
        <button class="small-button edit" type="button" data-access-edit="${escapeAttribute(rule.name)}" ${locked ? "disabled" : ""}>編集</button>
        <button class="small-button danger" type="button" data-access-delete="${escapeAttribute(rule.name)}" ${locked ? "disabled" : ""}>削除</button>
      </div>
    </article>
  `;
}

function peerLabel(address) {
  const peer = appState.peers.find((item) => item.address === address);
  return peer ? `${peer.name} (${address})` : address;
}

function renderRoutes() {
  const counts = {
    all: appState.routes.length,
    enabled: appState.routes.filter((route) => route.state_group === "enabled").length,
    disabled: appState.routes.filter((route) => route.state_group === "disabled").length,
    pending: appState.routes.filter((route) => route.state_group === "pending").length,
    deleted: appState.routes.filter((route) => route.state_group === "deleted").length,
  };
  for (const tab of elements.routeTabs.querySelectorAll("[data-route-filter]")) {
    const selected = tab.dataset.routeFilter === appState.routeFilter;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  }
  for (const counter of elements.routeTabs.querySelectorAll("[data-filter-count]")) {
    counter.textContent = String(counts[counter.dataset.filterCount] || 0);
  }

  const visibleRoutes = appState.routes.filter(
    (route) =>
      appState.routeFilter === "all" || route.state_group === appState.routeFilter,
  );
  const hasEmptyGroups =
    appState.routeFilter === "all" && appState.groups.length > 0;
  elements.empty.hidden = visibleRoutes.length > 0 || hasEmptyGroups;
  elements.tableWrap.hidden = !elements.empty.hidden;
  elements.routesBody.replaceChildren();

  const emptyCopy = {
    all: ["経路はまだ登録されていません", "最初の公開ポートとMiniPCの転送先を追加してください。"],
    enabled: ["有効な経路はありません", "有効化済みの公開ポートはありません。"],
    disabled: ["無効な経路はありません", "無効化済みの公開ポートはありません。"],
    pending: ["未反映の経路はありません", "有効化・無効化・編集待ちの変更はありません。"],
    deleted: ["削除済みの経路はありません", "正常に削除された経路の履歴がここに残ります。"],
  };
  [elements.emptyTitle.textContent, elements.emptyDescription.textContent] =
    emptyCopy[appState.routeFilter];
  elements.emptyNewRoute.hidden = appState.routeFilter !== "all";

  const knownGroupIds = new Set(appState.groups.map((group) => group.id));
  const rootGroups = appState.groups.filter(
    (group) => !group.parent_id || !knownGroupIds.has(group.parent_id),
  );
  const groupMarkup = rootGroups
    .map((group) => renderGroupTree(group, visibleRoutes))
    .join("");
  if (groupMarkup) {
    elements.routesBody.insertAdjacentHTML("beforeend", groupMarkup);
  }

  const ungrouped = visibleRoutes.filter(
    (route) => !route.group_id || !knownGroupIds.has(route.group_id),
  );
  if (ungrouped.length) {
    elements.routesBody.insertAdjacentHTML(
      "beforeend",
      `
        <section class="single-routes">
          <div class="single-routes-heading">
            <strong>単一経路</strong>
            <small>グループに所属していない公開ポート</small>
          </div>
          <div class="route-members">
            ${ungrouped.map(renderRouteItem).join("")}
          </div>
        </section>
      `,
    );
  }
}

function renderWebRoutes() {
  const counts = {
    all: appState.webRoutes.length,
    enabled: appState.webRoutes.filter((route) => route.state_group === "enabled").length,
    disabled: appState.webRoutes.filter((route) => route.state_group === "disabled").length,
    pending: appState.webRoutes.filter((route) => route.state_group === "pending").length,
    deleted: appState.webRoutes.filter((route) => route.state_group === "deleted").length,
  };
  for (const tab of elements.webRouteTabs.querySelectorAll("[data-web-route-filter]")) {
    const selected = tab.dataset.webRouteFilter === appState.webRouteFilter;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  }
  for (const counter of elements.webRouteTabs.querySelectorAll("[data-web-filter-count]")) {
    counter.textContent = String(counts[counter.dataset.webFilterCount] || 0);
  }

  const ports = appState.webGateway.ports || {};
  setGatewayPortStatus(elements.webGateway80, ports["80"]);
  setGatewayPortStatus(elements.webGateway443, ports["443"]);
  elements.webRouteSummary.textContent =
    `${appState.webRoutesStatus.total || 0}件・未反映${appState.webRoutesStatus.pending || 0}件`;

  const recovery = Boolean(appState.webRoutesStatus.publish_recovery_required);
  const locked = appState.busy || recovery;
  document.querySelector("#new-web-route-button").disabled = locked;
  document.querySelector("#web-gateway-setup-button").disabled =
    appState.busy || Boolean(appState.webGateway.staged);
  const previewButton = document.querySelector("#web-preview-button");
  previewButton.disabled =
    appState.busy || (!recovery && counts.pending === 0);
  previewButton.textContent = recovery
    ? "Webルートを再反映"
    : "反映内容を確認";

  const visible = appState.webRoutes.filter(
    (route) =>
      appState.webRouteFilter === "all" ||
      route.state_group === appState.webRouteFilter,
  );
  elements.webRoutesBody.innerHTML = visible.length
    ? visible.map((route) => renderWebRouteItem(route, locked)).join("")
    : `<p class="muted">${
        appState.webRouteFilter === "all"
          ? "Webルートはまだ登録されていません。"
          : "この状態のWebルートはありません。"
      }</p>`;
}

function setGatewayPortStatus(element, status = {}) {
  element.textContent = status.label || "未登録";
  element.className = `gateway-${status.state || "missing"}`;
  element.title = status.target ? `現在の転送先: ${status.target}` : "";
}

function renderWebRouteItem(route, locked) {
  let controls = "";
  if (route.state === "pending_delete" || route.state === "deleted") {
    controls = `<button class="small-button edit" type="button" data-web-route-edit="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>高度な操作</button>`;
  } else {
    controls = `
      <button
        class="toggle-button"
        type="button"
        role="switch"
        aria-checked="${String(route.desired_enabled)}"
        aria-label="${escapeAttribute(`${route.name}を${route.desired_enabled ? "無効" : "有効"}にする`)}"
        data-web-route-toggle="${escapeAttribute(route.id)}"
        data-state="${route.desired_enabled ? "enabled" : "disabled"}"
        ${locked ? "disabled" : ""}
      ></button>
      <button class="small-button edit" type="button" data-web-route-edit="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>編集</button>
    `;
  }
  return `
    <div class="web-route-item state-${escapeAttribute(route.state)}">
      <div class="route-main">
        <span class="route-name">${escapeHtml(route.name)}</span>
        <small>${escapeHtml(route.description || "説明なし")}${route.basic_auth_enabled ? "・Basic認証" : ""}</small>
      </div>
      <span class="web-hostname">${escapeHtml(route.hostname)}</span>
      <span class="web-route-arrow">→</span>
      <span class="mono">${escapeHtml(route.docker_alias)}:${route.container_port}</span>
      <span class="state-badge ${escapeAttribute(route.state)}">${escapeHtml(routeStateLabels[route.state] || route.state)}</span>
      <div class="route-controls">${controls}</div>
    </div>
  `;
}

function renderGroupTree(group, visibleRoutes, depth = 0) {
  const descendantIds = getGroupDescendantIds(group.id);
  const allMembers = appState.routes.filter((route) =>
    descendantIds.has(route.group_id),
  );
  const aggregateVisibleMembers = visibleRoutes.filter((route) =>
    descendantIds.has(route.group_id),
  );
  if (!aggregateVisibleMembers.length && appState.routeFilter !== "all") return "";

  const directVisibleMembers = visibleRoutes.filter(
    (route) => route.group_id === group.id,
  );
  const childMarkup = appState.groups
    .filter((candidate) => candidate.parent_id === group.id)
    .map((child) => renderGroupTree(child, visibleRoutes, depth + 1))
    .join("");
  return renderGroup(group, allMembers, directVisibleMembers, childMarkup, depth);
}

function renderGroup(group, allMembers, visibleMembers, childMarkup, depth) {
  const collapsed = appState.collapsedGroups.has(group.id);
  const state = group.enabled_state === "empty" ? "disabled" : group.enabled_state;
  const toggleLabel =
    state === "mixed"
      ? "一部有効。操作するとすべて無効になります"
      : state === "enabled"
        ? "すべて有効。操作するとすべて無効になります"
        : "すべて無効。操作するとすべて有効になります";
  const locked = appState.pendingRelay || appState.busy || group.total_ports === 0;
  const contentsId = `group-contents-${group.id}`;
  return `
    <section
      class="route-group"
      data-group-card="${escapeAttribute(group.id)}"
      data-group-depth="${depth}"
    >
      <div class="group-header">
        <button
          class="group-summary-button"
          type="button"
          aria-expanded="${String(!collapsed)}"
          aria-controls="${escapeAttribute(contentsId)}"
          data-group-collapse="${escapeAttribute(group.id)}"
        >
          <span class="group-identity">
            <strong>${escapeHtml(group.name)}</strong>
            <small>${escapeHtml(group.description || "説明なし")}</small>
          </span>
          <span class="group-summary-meta">
            <span class="group-port-summary">${escapeHtml(formatGroupPorts(allMembers))}</span>
            <small>${group.enabled_ports}/${group.total_ports} ポート有効</small>
          </span>
        </button>
        <div class="group-actions">
          <button
            class="toggle-button"
            type="button"
            role="checkbox"
            aria-checked="${state === "mixed" ? "mixed" : String(state === "enabled")}"
            aria-label="${escapeAttribute(`${group.name}: ${toggleLabel}`)}"
            title="${escapeAttribute(toggleLabel)}"
            data-group-toggle="${escapeAttribute(group.id)}"
            data-state="${escapeAttribute(state)}"
            ${locked ? "disabled" : ""}
          ></button>
          <button class="small-button edit" type="button" data-group-edit="${escapeAttribute(group.id)}" ${appState.pendingRelay || appState.busy ? "disabled" : ""}>編集</button>
          <button
            class="small-button collapse-button"
            type="button"
            aria-expanded="${String(!collapsed)}"
            aria-controls="${escapeAttribute(contentsId)}"
            aria-label="${collapsed ? "グループを展開" : "グループを折りたたむ"}"
            data-group-collapse="${escapeAttribute(group.id)}"
          >${collapsed ? "＋" : "−"}</button>
        </div>
      </div>
      <div
        class="group-contents"
        id="${escapeAttribute(contentsId)}"
        ${collapsed ? "hidden" : ""}
      >
        ${
          visibleMembers.length
            ? `<div class="route-members">${visibleMembers.map(renderRouteItem).join("")}</div>`
            : childMarkup
              ? ""
              : '<p class="muted">このグループにポートはありません。</p>'
        }
        ${childMarkup ? `<div class="route-subgroups">${childMarkup}</div>` : ""}
      </div>
    </section>
  `;
}

function getGroupDescendantIds(groupId) {
  const descendants = new Set([groupId]);
  const pending = [groupId];
  while (pending.length) {
    const parentId = pending.pop();
    for (const group of appState.groups) {
      if (group.parent_id !== parentId || descendants.has(group.id)) continue;
      descendants.add(group.id);
      pending.push(group.id);
    }
  }
  return descendants;
}

function renderRouteItem(route) {
  const locked = appState.pendingRelay || appState.busy;
  let controls = "";
  if (route.state === "pending_delete" || route.state === "deleted") {
    controls = `<button class="small-button edit" type="button" data-route-edit="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>高度な操作</button>`;
  } else {
    const toggleDisabled = locked || route.state === "pending_relay";
    controls = `
      <button
        class="toggle-button"
        type="button"
        role="switch"
        aria-checked="${String(route.desired_enabled)}"
        aria-label="${escapeAttribute(`${route.name}を${route.desired_enabled ? "無効" : "有効"}にする`)}"
        title="${route.desired_enabled ? "無効にする" : "有効にする"}"
        data-route-toggle="${escapeAttribute(route.id)}"
        data-state="${route.desired_enabled ? "enabled" : "disabled"}"
        ${toggleDisabled ? "disabled" : ""}
      ></button>
      <button class="small-button edit" type="button" data-route-edit="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>編集</button>
    `;
  }
  return `
    <div class="route-item state-${escapeAttribute(route.state)}">
      <div class="route-main">
        <span class="route-name">${escapeHtml(route.name)}</span>
        <small>${escapeHtml(route.description || "説明なし")}</small>
      </div>
      <span class="protocol-badge ${escapeAttribute(route.protocol)}">${route.protocol.toUpperCase()}</span>
      <span class="mono">${route.public_port}</span>
      <span class="mono">${escapeHtml(route.target_address)}:${route.target_port}</span>
      <span class="state-badge ${escapeAttribute(route.state)}">${escapeHtml(routeStateLabels[route.state] || route.state)}</span>
      <div class="route-controls">${controls}</div>
    </div>
  `;
}

function formatGroupPorts(routes) {
  const active = routes.filter((route) => route.state !== "deleted");
  if (!active.length) return "ポート未登録";
  return ["tcp", "udp"]
    .map((protocol) => {
      const ports = active
        .filter((route) => route.protocol === protocol)
        .map((route) => route.public_port);
      return ports.length ? `${protocol.toUpperCase()} ${compactNumbers(ports)}` : "";
    })
    .filter(Boolean)
    .join(" · ");
}

function compactNumbers(values) {
  const ordered = [...new Set(values)].sort((left, right) => left - right);
  if (!ordered.length) return "";
  const ranges = [];
  let start = ordered[0];
  let previous = ordered[0];
  for (const value of ordered.slice(1)) {
    if (value === previous + 1) {
      previous = value;
      continue;
    }
    ranges.push(start === previous ? String(start) : `${start}-${previous}`);
    start = previous = value;
  }
  ranges.push(start === previous ? String(start) : `${start}-${previous}`);
  return ranges.join(",");
}

function renderAudit() {
  elements.auditList.replaceChildren();
  if (!appState.audit.length) {
    elements.auditList.innerHTML = '<p class="muted">履歴はまだありません。</p>';
    return;
  }
  for (const item of appState.audit) {
    const node = document.createElement("div");
    node.className = "audit-item";
    const when = new Date(item.time).toLocaleString("ja-JP");
    node.innerHTML = `
      <strong>
        <span class="audit-result-${escapeAttribute(item.result)}">${escapeHtml(item.result)}</span>
        · ${escapeHtml(item.action)}
      </strong>
      <small>${escapeHtml(when)}<br>${escapeHtml(item.detail || "")}</small>
    `;
    elements.auditList.append(node);
  }
}

function renderPlanStatus() {
  const pendingCount = appState.routes.filter(
    (route) => route.state_group === "pending",
  ).length;
  if (appState.pendingRelay) {
    setMetricStatus("同期要確認", "Terraform反映済み・リレー同期待ち", "danger");
    return;
  }
  if (!appState.plan) {
    if (pendingCount > 0) {
      setMetricStatus(`未反映 ${pendingCount}件`, "変更を確認してApplyしてください", "warning");
    } else {
      setMetricStatus("反映済み", "保存状態と最後の適用状態が一致しています", "ready");
    }
    return;
  }
  if (!appState.plan.safe) {
    setMetricStatus("適用停止", "NSG以外の変更を検出しました", "danger");
    return;
  }
  setMetricStatus("確認待ち", "安全なplanが作成されています", "info");
}

function renderOperationAvailability() {
  const locked = appState.pendingRelay || appState.busy;
  document.querySelector("#new-route-button").disabled = locked;
  document.querySelector("#new-group-button").disabled = locked;
  elements.emptyNewRoute.disabled = locked;
  document.querySelector("#plan-button").disabled = appState.pendingRelay || appState.busy;
}

function setMetricStatus(label, detail, tone) {
  elements.status.textContent = label;
  elements.statusDetail.textContent = detail;
  elements.status.className = `tone-${tone}`;
}

function refreshGroupOptions(selected = "") {
  elements.routeGroup.innerHTML = `
    <option value="">単一経路（グループなし）</option>
    ${appState.groups
      .map(
        (group) =>
          `<option value="${escapeAttribute(group.id)}">${escapeHtml(groupOptionLabel(group))}</option>`,
      )
      .join("")}
  `;
  elements.routeGroup.value = selected || "";
}

function groupOptionLabel(group) {
  const names = [group.name];
  const visited = new Set([group.id]);
  let parentId = group.parent_id;
  while (parentId && !visited.has(parentId)) {
    const parent = appState.groups.find((candidate) => candidate.id === parentId);
    if (!parent) break;
    names.unshift(parent.name);
    visited.add(parent.id);
    parentId = parent.parent_id;
  }
  return names.join(" › ");
}

function refreshParentGroupOptions(selected = "", excludedGroupId = "") {
  const excludedIds = excludedGroupId
    ? getGroupDescendantIds(excludedGroupId)
    : new Set();
  elements.groupParent.innerHTML = `
    <option value="">最上位グループ</option>
    ${appState.groups
      .filter((group) => !excludedIds.has(group.id))
      .map(
        (group) =>
          `<option value="${escapeAttribute(group.id)}">${escapeHtml(groupOptionLabel(group))}</option>`,
      )
      .join("")}
  `;
  elements.groupParent.value = selected || "";
}

function openNewRoute() {
  if (appState.pendingRelay || appState.busy) return;
  elements.routeForm.reset();
  setRouteEditorReadonly(false);
  elements.recordId.value = "";
  elements.routeTargetAddress.value = "10.99.0.2";
  elements.routeDialogTitle.textContent = "単一経路を追加";
  elements.routeAdvanced.hidden = true;
  elements.routeAdvanced.removeAttribute("open");
  elements.routeFormError.textContent = "";
  refreshGroupOptions();
  elements.routeDialog.showModal();
  elements.routeName.focus();
}

function openEditRoute(id) {
  if (appState.pendingRelay || appState.busy) return;
  const route = appState.routes.find((item) => item.id === id);
  if (!route) return;
  const readonly = route.state === "deleted" || route.state === "pending_delete";
  setRouteEditorReadonly(false);
  elements.recordId.value = route.id;
  elements.routeName.value = route.name;
  elements.routeProtocol.value = route.protocol;
  elements.routePublicPort.value = route.public_port;
  elements.routeTargetAddress.value = route.target_address;
  elements.routeTargetPort.value = route.target_port;
  elements.routeDescription.value = route.description || "";
  refreshGroupOptions(route.group_id);
  setRouteEditorReadonly(readonly);
  elements.routeDialogTitle.textContent = readonly ? "経路の高度な操作" : "経路を編集";
  elements.routeAdvanced.hidden = false;
  elements.routeAdvanced.toggleAttribute("open", readonly);
  if (route.state === "pending_create") {
    elements.routeAdvancedDescription.textContent =
      "まだ反映していない経路を管理ダッシュボードから取り消します。";
    elements.deleteRouteButton.textContent = "未反映の作成を取り消す";
  } else if (route.state === "pending_delete") {
    elements.routeAdvancedDescription.textContent =
      "OCIへまだ反映していない削除待ち状態を取り消します。";
    elements.deleteRouteButton.textContent = "削除待ちを取り消す";
  } else if (route.state === "deleted") {
    elements.routeAdvancedDescription.textContent =
      "OCIから削除済みの経路履歴を管理ダッシュボードから完全に消去します。";
    elements.deleteRouteButton.textContent = "削除履歴を消去";
  } else {
    elements.routeAdvancedDescription.textContent =
      "経路をOCIから削除する場合だけ使用してください。通常は一覧のトグルで無効化します。";
    elements.deleteRouteButton.textContent = "この経路を削除待ちにする";
  }
  elements.routeFormError.textContent = "";
  elements.routeDialog.showModal();
  if (readonly) elements.deleteRouteButton.focus();
  else elements.routeName.focus();
}

function setRouteEditorReadonly(readonly) {
  for (const field of [
    elements.routeName,
    elements.routeProtocol,
    elements.routePublicPort,
    elements.routeTargetAddress,
    elements.routeTargetPort,
    elements.routeDescription,
    elements.routeGroup,
  ]) {
    field.disabled = readonly;
  }
  elements.saveRouteButton.hidden = readonly;
}

async function saveRoute() {
  elements.routeFormError.textContent = "";
  if (!elements.routeForm.reportValidity()) return;
  const recordId = elements.recordId.value;
  const body = {
    name: elements.routeName.value,
    protocol: elements.routeProtocol.value,
    public_port: Number(elements.routePublicPort.value),
    target_address: elements.routeTargetAddress.value,
    target_port: Number(elements.routeTargetPort.value),
    description: elements.routeDescription.value,
    group_id: elements.routeGroup.value || null,
  };
  const button = elements.saveRouteButton;
  setButtonBusy(button, true, "保存中…");
  try {
    if (recordId) {
      await api(`/api/routes/${encodeURIComponent(recordId)}`, {
        method: "PUT",
        body,
      });
    } else {
      await api("/api/routes", { method: "POST", body });
    }
    elements.routeDialog.close();
    await loadState();
    toast("経路を保存しました。");
  } catch (error) {
    elements.routeFormError.textContent = firstLine(error.message);
  } finally {
    setButtonBusy(button, false, "保存");
  }
}

async function toggleRoute(id) {
  const route = appState.routes.find((item) => item.id === id);
  if (!route) return;
  try {
    await api(`/api/routes/${encodeURIComponent(id)}/enabled`, {
      method: "PUT",
      body: { enabled: !route.desired_enabled },
    });
    await loadState();
    toast(`${route.name}を${route.desired_enabled ? "無効" : "有効"}にしました。`);
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function deleteRoute(id = elements.recordId.value) {
  const route = appState.routes.find((item) => item.id === id);
  if (!route) return;
  if (route.state === "pending_delete") {
    try {
      await api(`/api/routes/${encodeURIComponent(id)}/cancel-delete`, {
        method: "POST",
      });
      elements.routeDialog.close();
      await loadState();
      toast("経路の削除を取り消しました。");
    } catch (error) {
      elements.routeFormError.textContent = firstLine(error.message);
    }
    return;
  }
  if (route.state === "deleted") {
    if (!window.confirm(`削除済み経路「${route.name}」を履歴から完全に消去しますか？`)) {
      return;
    }
    try {
      await api(`/api/deleted-routes/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      elements.routeDialog.close();
      await loadState();
      toast("削除履歴を消去しました。");
    } catch (error) {
      elements.routeFormError.textContent = firstLine(error.message);
    }
    return;
  }
  const prompt =
    route.state === "pending_create"
      ? `未反映の経路「${route.name}」の作成を取り消しますか？`
      : `経路「${route.name}」を削除待ちにしますか？\n通常は無効トグルを使用してください。`;
  if (!window.confirm(prompt)) return;
  try {
    await api(`/api/routes/${encodeURIComponent(id)}`, { method: "DELETE" });
    elements.routeDialog.close();
    await loadState();
    toast(route.state === "pending_create" ? "経路の作成を取り消しました。" : "経路を削除待ちにしました。");
  } catch (error) {
    elements.routeFormError.textContent = firstLine(error.message);
  }
}

function openNewWebRoute() {
  if (appState.busy || appState.webRoutesStatus.publish_recovery_required) return;
  elements.webRouteForm.reset();
  elements.webRecordId.value = "";
  elements.webRouteDialogTitle.textContent = "Webルートを追加";
  elements.webRouteAdvanced.hidden = true;
  elements.webRouteAdvanced.removeAttribute("open");
  elements.webRouteBasicAuthUsername.value = "";
  elements.webRouteBasicAuthRotate.checked = false;
  syncWebRouteBasicAuthFields();
  elements.webRouteFormError.textContent = "";
  setWebRouteEditorReadonly(false);
  elements.webRouteDialog.showModal();
  elements.webRouteName.focus();
}

function openEditWebRoute(id) {
  if (appState.busy || appState.webRoutesStatus.publish_recovery_required) return;
  const route = appState.webRoutes.find((item) => item.id === id);
  if (!route) return;
  const readonly = route.state === "deleted" || route.state === "pending_delete";
  elements.webRecordId.value = route.id;
  elements.webRouteName.value = route.name;
  elements.webRouteHostname.value = route.hostname;
  elements.webRouteAlias.value = route.docker_alias;
  elements.webRoutePort.value = route.container_port;
  elements.webRouteDescription.value = route.description || "";
  elements.webRouteBasicAuthEnabled.checked = Boolean(route.basic_auth_enabled);
  elements.webRouteBasicAuthUsername.value = route.basic_auth_username || route.name;
  elements.webRouteBasicAuthRotate.checked = false;
  syncWebRouteBasicAuthFields();
  setWebRouteEditorReadonly(readonly);
  elements.webRouteDialogTitle.textContent = readonly
    ? "Webルートの高度な操作"
    : "Webルートを編集";
  elements.webRouteAdvanced.hidden = false;
  elements.webRouteAdvanced.toggleAttribute("open", readonly);
  if (route.state === "pending_create") {
    elements.webRouteAdvancedDescription.textContent =
      "まだ反映していないWebルートの作成を取り消します。";
    elements.deleteWebRouteButton.textContent = "未反映の作成を取り消す";
  } else if (route.state === "pending_delete") {
    elements.webRouteAdvancedDescription.textContent =
      "Traefikへまだ反映していない削除待ち状態を取り消します。";
    elements.deleteWebRouteButton.textContent = "削除待ちを取り消す";
  } else if (route.state === "deleted") {
    elements.webRouteAdvancedDescription.textContent =
      "Traefikから削除済みのWebルート履歴を完全に消去します。";
    elements.deleteWebRouteButton.textContent = "削除履歴を消去";
  } else {
    elements.webRouteAdvancedDescription.textContent =
      "Webルートを削除する場合だけ使用してください。通常は一覧のトグルで無効化します。";
    elements.deleteWebRouteButton.textContent = "このWebルートを削除待ちにする";
  }
  elements.webRouteFormError.textContent = "";
  elements.webRouteDialog.showModal();
  if (readonly) elements.deleteWebRouteButton.focus();
  else elements.webRouteName.focus();
}

function setWebRouteEditorReadonly(readonly) {
  for (const field of [
    elements.webRouteName,
    elements.webRouteHostname,
    elements.webRouteAlias,
    elements.webRoutePort,
    elements.webRouteDescription,
    elements.webRouteBasicAuthEnabled,
    elements.webRouteBasicAuthUsername,
    elements.webRouteBasicAuthRotate,
  ]) {
    field.disabled = readonly;
  }
  elements.saveWebRouteButton.hidden = readonly;
}

function syncWebRouteBasicAuthFields() {
  const enabled = elements.webRouteBasicAuthEnabled.checked;
  const editing = Boolean(elements.webRecordId.value);
  elements.webRouteBasicAuthFields.hidden = !enabled;
  elements.webRouteBasicAuthUsername.required = enabled;
  elements.webRouteBasicAuthRotateLabel.hidden = !enabled || !editing;
  if (!enabled) elements.webRouteBasicAuthRotate.checked = false;
  if (enabled && !elements.webRouteBasicAuthUsername.value) {
    elements.webRouteBasicAuthUsername.value = elements.webRouteName.value || "reader";
  }
}

async function saveWebRoute() {
  elements.webRouteFormError.textContent = "";
  if (!elements.webRouteForm.reportValidity()) return;
  const recordId = elements.webRecordId.value;
  const body = {
    name: elements.webRouteName.value,
    hostname: elements.webRouteHostname.value,
    docker_alias: elements.webRouteAlias.value,
    container_port: Number(elements.webRoutePort.value),
    description: elements.webRouteDescription.value,
    basic_auth_enabled: elements.webRouteBasicAuthEnabled.checked,
    basic_auth_username: elements.webRouteBasicAuthUsername.value,
    rotate_basic_auth: elements.webRouteBasicAuthRotate.checked,
  };
  setButtonBusy(elements.saveWebRouteButton, true, "保存中…");
  try {
    const response = await api(
      recordId
        ? `/api/web-routes/${encodeURIComponent(recordId)}`
        : "/api/web-routes",
      { method: recordId ? "PUT" : "POST", body },
    );
    elements.webRouteDialog.close();
    await loadState();
    if (response.one_time_basic_auth) {
      const credentials = response.one_time_basic_auth;
      window.prompt(
        "Basic認証情報は今回だけ表示されます。安全な場所へ保存してください。",
        `${credentials.username}:${credentials.password}`,
      );
    }
    toast("Webルートを下書き保存しました。");
  } catch (error) {
    elements.webRouteFormError.textContent = firstLine(error.message);
  } finally {
    setButtonBusy(elements.saveWebRouteButton, false, "保存");
  }
}

async function toggleWebRoute(id) {
  const route = appState.webRoutes.find((item) => item.id === id);
  if (!route) return;
  try {
    await api(`/api/web-routes/${encodeURIComponent(id)}/enabled`, {
      method: "PUT",
      body: { enabled: !route.desired_enabled },
    });
    await loadState();
    toast(`${route.name}を${route.desired_enabled ? "無効" : "有効"}の下書きにしました。`);
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function deleteWebRoute(id = elements.webRecordId.value) {
  const route = appState.webRoutes.find((item) => item.id === id);
  if (!route) return;
  try {
    if (route.state === "pending_delete") {
      await api(`/api/web-routes/${encodeURIComponent(id)}/cancel-delete`, {
        method: "POST",
      });
      toast("Webルートの削除を取り消しました。");
    } else if (route.state === "deleted") {
      if (!window.confirm(`削除済みWebルート「${route.name}」の履歴を消去しますか？`)) {
        return;
      }
      await api(`/api/deleted-web-routes/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      toast("Webルートの削除履歴を消去しました。");
    } else {
      const prompt = route.state === "pending_create"
        ? `未反映のWebルート「${route.name}」の作成を取り消しますか？`
        : `Webルート「${route.name}」を削除待ちにしますか？`;
      if (!window.confirm(prompt)) return;
      await api(`/api/web-routes/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      toast(route.state === "pending_create"
        ? "Webルートの作成を取り消しました。"
        : "Webルートを削除待ちにしました。");
    }
    elements.webRouteDialog.close();
    await loadState();
  } catch (error) {
    elements.webRouteFormError.textContent = firstLine(error.message);
  }
}

async function setupWebGateway() {
  const button = document.querySelector("#web-gateway-setup-button");
  setButtonBusy(button, true, "準備中…");
  try {
    await api("/api/web-gateway/setup", { method: "POST" });
    await loadState();
    toast("TCP/80・443を下書きしました。「変更を確認」からOCIへ適用してください。");
  } catch (error) {
    toast(firstLine(error.message), true);
  } finally {
    setButtonBusy(button, false, "Web入口を準備");
  }
}

async function reviewWebRoutes() {
  if (appState.webRoutesStatus.publish_recovery_required) {
    const confirmation = window.prompt(
      "前回の反映が途中で停止しています。保存済みスナップショットを再反映する場合は PUBLISH と入力してください。",
    );
    if (confirmation !== "PUBLISH") return;
    await publishWebRoutes(confirmation);
    return;
  }
  const button = document.querySelector("#web-preview-button");
  setButtonBusy(button, true, "確認中…");
  try {
    const payload = await api("/api/web-routes/preview", {
      method: "POST",
    });
    const preview = payload.preview;
    const labels = [
      ["追加", preview.counts.create || 0],
      ["更新", preview.counts.update || 0],
      ["有効化", preview.counts.enable || 0],
      ["無効化", preview.counts.disable || 0],
      ["削除", preview.counts.delete || 0],
    ];
    elements.webPublishSummary.innerHTML = labels
      .map(([label, count]) => `<div class="plan-count"><span>${label}</span><strong>${count}</strong></div>`)
      .join("");
    elements.webPublishRoutes.innerHTML = preview.routes.length
      ? preview.routes
          .map(
            (route) => `
              <div class="check-row">
                <span class="check-icon ok">●</span>
                <strong>${escapeHtml(route.hostname)}</strong>
                <small>→ ${escapeHtml(route.target)}</small>
              </div>
            `,
          )
          .join("")
      : '<p class="muted">有効なWebルートはありません。空の設定を反映します。</p>';
    elements.webPublishConfig.textContent = preview.config;
    elements.webPublishConfirmation.value = "";
    elements.webPublishConfirmButton.disabled = true;
    elements.webPublishError.textContent = "";
    elements.webPublishDialog.showModal();
  } catch (error) {
    toast(firstLine(error.message), true);
  } finally {
    setButtonBusy(button, false, "反映内容を確認");
  }
}

async function publishWebRoutes(confirmation = elements.webPublishConfirmation.value) {
  const button = elements.webPublishConfirmButton;
  setButtonBusy(button, true, "反映中…");
  try {
    const payload = await api("/api/web-routes/publish", {
      method: "POST",
      body: { confirmation },
    });
    if (elements.webPublishDialog.open) elements.webPublishDialog.close();
    await loadState();
    toast(payload.message || "Webルートを反映しました。");
  } catch (error) {
    if (elements.webPublishDialog.open) {
      elements.webPublishError.textContent = firstLine(error.message);
    } else {
      toast(firstLine(error.message), true);
      await loadState().catch(() => {});
    }
  } finally {
    setButtonBusy(button, false, "Traefikへ反映");
  }
}

function openNewGroup() {
  if (appState.pendingRelay || appState.busy) return;
  elements.groupForm.reset();
  elements.groupId.value = "";
  elements.groupDialogTitle.textContent = "ポートグループを追加";
  refreshParentGroupOptions();
  elements.groupAdvanced.hidden = true;
  elements.groupFormError.textContent = "";
  elements.groupMemberRows.replaceChildren();
  addMemberRow();
  updateGroupPreview();
  elements.groupDialog.showModal();
  elements.groupName.focus();
}

function openEditGroup(id) {
  if (appState.pendingRelay || appState.busy) return;
  const group = appState.groups.find((item) => item.id === id);
  if (!group) return;
  elements.groupForm.reset();
  elements.groupId.value = group.id;
  elements.groupName.value = group.name;
  elements.groupDescription.value = group.description || "";
  refreshParentGroupOptions(group.parent_id, group.id);
  elements.groupDialogTitle.textContent = "ポートグループを編集";
  elements.groupAdvanced.hidden = false;
  elements.groupFormError.textContent = "";
  elements.groupMemberRows.replaceChildren();
  addMemberRow();
  updateGroupPreview();
  elements.groupDialog.showModal();
  elements.groupName.focus();
}

function addMemberRow(values = {}) {
  const row = document.createElement("div");
  row.className = "group-member-row";
  row.innerHTML = `
    <label>
      <span>プロトコル</span>
      <select data-member-protocol>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
      </select>
    </label>
    <label>
      <span>ポート番号・範囲</span>
      <input data-member-ports placeholder="8000-8015,8080" autocomplete="off">
    </label>
    <label>
      <span>転送先アドレス</span>
      <input data-member-target value="10.99.0.2">
    </label>
    <label>
      <span>説明</span>
      <input data-member-description maxlength="120" placeholder="ゲーム通信">
    </label>
    <button class="small-button remove-member-row" type="button" aria-label="この入力行を削除">×</button>
  `;
  row.querySelector("[data-member-protocol]").value = values.protocol || "tcp";
  row.querySelector("[data-member-ports]").value = values.ports || "";
  row.querySelector("[data-member-target]").value = values.target_address || "10.99.0.2";
  row.querySelector("[data-member-description]").value = values.description || "";
  elements.groupMemberRows.append(row);
}

function collectGroupMembers() {
  const members = [];
  let total = 0;
  const listeners = new Set();
  for (const row of elements.groupMemberRows.querySelectorAll(".group-member-row")) {
    const portsExpression = row.querySelector("[data-member-ports]").value.trim();
    if (!portsExpression) continue;
    const protocol = row.querySelector("[data-member-protocol]").value;
    const ports = parsePortExpression(portsExpression);
    total += ports.length;
    if (total > 64) throw new Error("一度に追加できるポートは合計64件です。");
    for (const port of ports) {
      const listener = `${protocol}/${port}`;
      if (listeners.has(listener)) throw new Error(`${listener}が入力内で重複しています。`);
      listeners.add(listener);
    }
    const targetAddress = row.querySelector("[data-member-target]").value.trim();
    if (!targetAddress) throw new Error("転送先アドレスを入力してください。");
    members.push({
      protocol,
      ports: portsExpression,
      target_address: targetAddress,
      description: row.querySelector("[data-member-description]").value,
    });
  }
  return { members, total, listeners };
}

function parsePortExpression(expression) {
  const text = String(expression || "").trim();
  if (!text) throw new Error("ポート番号または範囲を入力してください。");
  const ports = [];
  const seen = new Set();
  for (const rawToken of text.split(",")) {
    const token = rawToken.trim();
    if (!token) throw new Error("ポート指定に空の要素があります。");
    let start;
    let end;
    if (token.includes("-")) {
      const parts = token.split("-").map((part) => part.trim());
      if (parts.length !== 2 || parts.some((part) => !/^\d+$/.test(part))) {
        throw new Error(`ポート範囲の形式が不正です: ${token}`);
      }
      [start, end] = parts.map(Number);
      if (start > end) throw new Error(`ポート範囲は昇順にしてください: ${token}`);
    } else {
      if (!/^\d+$/.test(token)) throw new Error(`ポート番号が不正です: ${token}`);
      start = end = Number(token);
    }
    if (start < 1 || end > 65535) throw new Error("ポートは1〜65535で指定してください。");
    for (let port = start; port <= end; port += 1) {
      if (port === 22 || port === 51820) {
        throw new Error(`公開ポート${port}は管理画面では使用できません。`);
      }
      if (seen.has(port)) throw new Error(`ポート${port}が重複しています。`);
      seen.add(port);
      ports.push(port);
      if (ports.length > 64) throw new Error("一度に追加できるポートは最大64件です。");
    }
  }
  return ports.sort((left, right) => left - right);
}

function updateGroupPreview() {
  try {
    const { total, listeners } = collectGroupMembers();
    elements.groupPortPreview.classList.remove("error");
    elements.groupPortPreview.textContent = total
      ? `${total}ポート: ${[...listeners].join(", ")}`
      : "ポートを追加しない場合は、空のグループとして保存します。";
  } catch (error) {
    elements.groupPortPreview.classList.add("error");
    elements.groupPortPreview.textContent = firstLine(error.message);
  }
}

async function saveGroup() {
  elements.groupFormError.textContent = "";
  if (!elements.groupForm.reportValidity()) return;
  let members;
  try {
    ({ members } = collectGroupMembers());
  } catch (error) {
    elements.groupFormError.textContent = firstLine(error.message);
    return;
  }
  const groupId = elements.groupId.value;
  const metadata = {
    name: elements.groupName.value,
    description: elements.groupDescription.value,
    parent_id: elements.groupParent.value || null,
  };
  const button = document.querySelector("#save-group-button");
  setButtonBusy(button, true, "保存中…");
  try {
    if (groupId) {
      await api(`/api/groups/${encodeURIComponent(groupId)}`, {
        method: "PUT",
        body: metadata,
      });
      if (members.length) {
        await api(`/api/groups/${encodeURIComponent(groupId)}/routes`, {
          method: "POST",
          body: { members },
        });
      }
    } else {
      await api("/api/groups", {
        method: "POST",
        body: { ...metadata, members },
      });
    }
    elements.groupDialog.close();
    await loadState();
    toast("ポートグループを保存しました。");
  } catch (error) {
    elements.groupFormError.textContent = firstLine(error.message);
  } finally {
    setButtonBusy(button, false, "保存");
  }
}

async function toggleGroup(id) {
  const group = appState.groups.find((item) => item.id === id);
  if (!group) return;
  const enabled = group.enabled_state === "disabled" || group.enabled_state === "empty";
  try {
    await api(`/api/groups/${encodeURIComponent(id)}/enabled`, {
      method: "PUT",
      body: { enabled },
    });
    await loadState();
    toast(`${group.name}を${enabled ? "すべて有効" : "すべて無効"}にしました。`);
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

function toggleGroupCollapse(id) {
  if (!id) return;
  if (appState.collapsedGroups.has(id)) appState.collapsedGroups.delete(id);
  else appState.collapsedGroups.add(id);
  saveCollapsedGroups();
  renderRoutes();
}

async function deleteGroup() {
  const groupId = elements.groupId.value;
  const group = appState.groups.find((item) => item.id === groupId);
  if (!group) return;
  if (!window.confirm(`グループ「${group.name}」を解除しますか？\n直下の経路とサブグループは1階層上へ移動し、OCI設定は削除されません。`)) {
    return;
  }
  try {
    await api(`/api/groups/${encodeURIComponent(groupId)}`, { method: "DELETE" });
    elements.groupDialog.close();
    await loadState();
    toast("グループを解除しました。");
  } catch (error) {
    elements.groupFormError.textContent = firstLine(error.message);
  }
}

async function createPlan() {
  const button = document.querySelector("#plan-button");
  setButtonBusy(button, true, "確認中…");
  try {
    const payload = await api("/api/plan", { method: "POST" });
    appState.plan = payload.plan;
    showPlan(payload.plan);
    await loadState();
  } catch (error) {
    showInfo(
      "TERRAFORM ERROR",
      "planに失敗しました",
      `<pre>${escapeHtml(error.message)}</pre>`,
    );
  } finally {
    setButtonBusy(button, false, "変更を確認");
  }
}

function showPlan(plan) {
  const counts = plan.counts || {};
  const relayAdoptions = plan.relay_adoptions || [];
  const labels = [
    ["追加", counts.create || 0],
    ["更新", counts.update || 0],
    ["削除", counts.delete || 0],
    ["置換", counts.replace || 0],
  ];
  elements.planSummary.innerHTML = labels
    .map(
      ([label, count]) => `
        <div class="plan-count"><span>${label}</span><strong>${count}</strong></div>
      `,
    )
    .join("");
  elements.relayAdoptions.hidden = relayAdoptions.length === 0;
  elements.relayAdoptions.innerHTML = relayAdoptions.length
    ? `
      <strong>一致する手動リレールールをOCI Controlへ移管します。</strong>
      <ul>
        ${relayAdoptions
          .map(
            (adoption) => `
              <li>
                ${escapeHtml(adoption.manual_name)} → ${escapeHtml(adoption.managed_name)}
                （${escapeHtml(String(adoption.protocol || "").toUpperCase())}/${adoption.public_port}
                → ${escapeHtml(adoption.target_address)}:${adoption.target_port}）
              </li>
            `,
          )
          .join("")}
      </ul>
    `
    : "";
  elements.planOutput.textContent = plan.output || "plan出力はありません。";
  elements.planError.textContent = "";
  elements.applyConfirmation.value = "";
  elements.applyButton.disabled = true;
  if (plan.safe) {
    elements.unexpected.hidden = true;
    elements.unexpected.textContent = "";
  } else {
    elements.unexpected.hidden = false;
    elements.unexpected.innerHTML = `
      <strong>安全装置が適用を停止しました。</strong><br>
      NSG公開ルール以外の変更が含まれています。通常のターミナルでplanを確認してください。
      <pre>${escapeHtml(JSON.stringify(plan.unexpected || [], null, 2))}</pre>
    `;
  }
  elements.applyButton.dataset.safe = plan.safe ? "true" : "false";
  elements.planDialog.showModal();
}

async function applyPlan() {
  elements.planError.textContent = "";
  const button = elements.applyButton;
  setButtonBusy(button, true, "適用中…");
  try {
    const payload = await api("/api/apply", {
      method: "POST",
      body: { confirmation: elements.applyConfirmation.value },
    });
    elements.planDialog.close();
    await loadState();
    toast(payload.message || "適用が完了しました。");
  } catch (error) {
    elements.planError.textContent = firstLine(error.message);
    await loadState().catch(() => {});
  } finally {
    setButtonBusy(button, false, "OCIへ適用");
  }
}

async function showPreflight() {
  const button = document.querySelector("#preflight-button");
  setButtonBusy(button, true, "確認中…");
  try {
    const payload = await api("/api/preflight");
    const rows = payload.checks
      .map(
        (check) => `
          <div class="check-row">
            <span class="check-icon ${check.ok ? "ok" : ""}">${check.ok ? "●" : "×"}</span>
            <strong>${escapeHtml(check.name)}</strong>
            <small>${escapeHtml(check.detail)}</small>
          </div>
        `,
      )
      .join("");
    showInfo(
      "PREFLIGHT",
      payload.ok ? "環境チェック完了" : "対応が必要です",
      `<div class="check-list">${rows}</div>`,
    );
    setMetricStatus(
      payload.ok ? "準備完了" : "要確認",
      payload.ok
        ? "Terraform・OCI・SSHへ接続できます"
        : "失敗した項目を確認してください",
      payload.ok ? "ready" : "danger",
    );
  } catch (error) {
    toast(firstLine(error.message), true);
  } finally {
    setButtonBusy(button, false, "環境チェック");
  }
}

async function showRelayStatus() {
  const button = document.querySelector("#relay-status-button");
  setButtonBusy(button, true, "確認中…");
  try {
    const payload = await api("/api/relay/status");
    const rows = payload.routes.length
      ? payload.routes
          .map(
            (route) => `
              <div class="check-row">
                <span class="check-icon ${route.matches_desired ? "ok" : ""}">
                  ${route.matches_desired ? "●" : "○"}
                </span>
                <strong>${escapeHtml(route.name)}</strong>
                <small>
                  ${route.protocol.toUpperCase()}/${route.public_port}
                  → ${escapeHtml(route.target_address)}:${route.target_port}
                  ${route.managed_by_dashboard ? " · GUI管理" : " · 手動管理"}
                </small>
              </div>
            `,
          )
          .join("")
      : '<p class="muted">OCIリレーに転送ルールはありません。</p>';
    showInfo("LIVE RELAY", "OCIリレー状態", `<div class="check-list">${rows}</div>`);
  } catch (error) {
    toast(firstLine(error.message), true);
  } finally {
    setButtonBusy(button, false, "リレー状態");
  }
}

async function syncRelay() {
  const confirmation = window.prompt(
    appState.pendingRelay
      ? "Terraformへ反映済みの経路をOCIリレーへ再同期します。\n続行する場合は SYNC と入力してください。"
      : "Terraformは変更せず、最後に反映済みの経路をOCIリレーへ再同期します。\n未反映の変更は同期されません。\n続行する場合は SYNC と入力してください。",
  );
  if (confirmation !== "SYNC") return;
  const button = document.querySelector("#sync-button");
  setButtonBusy(button, true, "同期中…");
  try {
    const payload = await api("/api/sync", {
      method: "POST",
      body: { confirmation },
    });
    await loadState();
    toast((payload.actions || []).join(" / "));
  } catch (error) {
    toast(firstLine(error.message), true);
  } finally {
    setButtonBusy(button, false, "リレーだけ再同期");
  }
}

function openNewPeer() {
  if (appState.busy || appState.wireguardLoading) return;
  elements.peerForm.reset();
  elements.peerAddress.value = appState.suggestedPeerAddress;
  elements.peerFormError.textContent = "";
  elements.peerDialog.showModal();
  elements.peerName.focus();
}

async function savePeer() {
  elements.peerFormError.textContent = "";
  if (!elements.peerForm.reportValidity()) return;
  setButtonBusy(elements.savePeerButton, true, "追加中…");
  try {
    const payload = await api("/api/wireguard/peers", {
      method: "POST",
      body: {
        name: elements.peerName.value,
        address: elements.peerAddress.value,
      },
    });
    downloadClientConfig(payload);
    elements.peerDialog.close();
    await refreshAfterWireGuardMutation();
    toast(payload.message || "Peerを追加しました。");
  } catch (error) {
    elements.peerFormError.textContent = firstLine(error.message);
  } finally {
    setButtonBusy(elements.savePeerButton, false, "追加して設定を保存");
  }
}

function downloadClientConfig(payload) {
  const content = String(payload.client_config || "");
  if (!content) throw new Error("クライアント接続設定を取得できませんでした。");
  const blob = new Blob([content], { type: "application/x-wireguard-profile" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = String(payload.filename || "wireguard.conf");
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  payload.client_config = "";
}

async function rotatePeer(name) {
  const confirmation = window.prompt(
    `${name}の秘密鍵を失効させ、新しい接続設定を発行します。\n既存設定は直ちに接続できなくなります。\n続行する場合は ROTATE と入力してください。`,
  );
  if (confirmation !== "ROTATE") return;
  try {
    const payload = await api(
      `/api/wireguard/peers/${encodeURIComponent(name)}/rotate`,
      {
        method: "POST",
        body: { confirmation },
      },
    );
    downloadClientConfig(payload);
    await refreshAfterWireGuardMutation();
    toast(payload.message || "鍵を更新しました。");
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function deletePeer(name) {
  const peer = appState.peers.find((item) => item.name === name);
  if (!peer) return;
  if ((peer.access_rules || []).length) {
    showInfo(
      "PEER DELETE BLOCKED",
      "先にアクセスルールを削除してください",
      `<p class="muted">参照中: ${escapeHtml(peer.access_rules.join(", "))}</p>`,
    );
    return;
  }
  const confirmation = window.prompt(
    `${name}を削除すると、このPeerの接続設定は使用できなくなります。\n続行する場合はPeer名を入力してください。`,
  );
  if (confirmation !== name) return;
  try {
    const payload = await api(`/api/wireguard/peers/${encodeURIComponent(name)}`, {
      method: "DELETE",
      body: { confirmation },
    });
    await refreshAfterWireGuardMutation();
    toast(payload.message || "Peerを削除しました。");
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

function refreshAccessPeerOptions(sourceAddress = "", targetAddress = "") {
  const options = appState.peers
    .map(
      (peer) =>
        `<option value="${escapeAttribute(peer.address)}">${escapeHtml(peer.name)} (${escapeHtml(peer.address)})</option>`,
    )
    .join("");
  elements.accessSource.innerHTML = options;
  elements.accessTarget.innerHTML = options;
  if (sourceAddress) elements.accessSource.value = sourceAddress;
  if (targetAddress) elements.accessTarget.value = targetAddress;
}

function suggestedAccessRuleName(sourcePeer, targetAddress) {
  const targetPeer = appState.peers.find((peer) => peer.address === targetAddress);
  const suffix =
    targetAddress === appState.dashboardTargetAddress
      ? "dashboard"
      : targetPeer?.name || "peer";
  return `${sourcePeer.name}-to-${suffix}`.slice(0, 32).replace(/-+$/, "");
}

function openNewAccessRule(sourceAddress = "") {
  if (appState.busy || appState.wireguardLoading || appState.peers.length < 2) return;
  elements.accessRuleForm.reset();
  elements.accessRuleOriginalName.value = "";
  elements.accessRuleName.readOnly = false;
  elements.accessRuleDialogTitle.textContent = "Peer間アクセスを追加";
  const sourcePeer =
    appState.peers.find((peer) => peer.address === sourceAddress) ||
    appState.peers.find((peer) => peer.address !== appState.dashboardTargetAddress) ||
    appState.peers[0];
  const preferredTarget =
    appState.peers.find(
      (peer) =>
        peer.address === appState.dashboardTargetAddress &&
        peer.address !== sourcePeer.address,
    ) ||
    appState.peers.find((peer) => peer.address !== sourcePeer.address);
  refreshAccessPeerOptions(sourcePeer.address, preferredTarget.address);
  elements.accessRuleName.value = suggestedAccessRuleName(
    sourcePeer,
    preferredTarget.address,
  );
  elements.accessProtocol.value = "tcp";
  elements.accessTargetPort.value =
    preferredTarget.address === appState.dashboardTargetAddress
      ? String(appState.dashboardPort)
      : "";
  elements.accessRuleFormError.textContent = "";
  elements.accessRuleDialog.showModal();
  elements.accessRuleName.focus();
}

function openEditAccessRule(name) {
  const rule = appState.accessRules.find((item) => item.name === name);
  if (!rule || appState.busy || appState.wireguardLoading) return;
  elements.accessRuleForm.reset();
  elements.accessRuleOriginalName.value = rule.name;
  elements.accessRuleName.value = rule.name;
  elements.accessRuleName.readOnly = true;
  elements.accessRuleDialogTitle.textContent = "Peer間アクセスを編集";
  refreshAccessPeerOptions(rule.source_address, rule.target_address);
  elements.accessProtocol.value = rule.protocol;
  elements.accessTargetPort.value = String(rule.target_port);
  elements.accessRuleFormError.textContent = "";
  elements.accessRuleDialog.showModal();
}

async function saveAccessRule() {
  elements.accessRuleFormError.textContent = "";
  if (!elements.accessRuleForm.reportValidity()) return;
  const originalName = elements.accessRuleOriginalName.value;
  const body = {
    name: elements.accessRuleName.value,
    protocol: elements.accessProtocol.value,
    source_address: elements.accessSource.value,
    target_address: elements.accessTarget.value,
    target_port: elements.accessTargetPort.value,
  };
  setButtonBusy(elements.saveAccessRuleButton, true, "反映中…");
  try {
    const payload = await api(
      originalName
        ? `/api/wireguard/access-rules/${encodeURIComponent(originalName)}`
        : "/api/wireguard/access-rules",
      {
        method: originalName ? "PUT" : "POST",
        body,
      },
    );
    elements.accessRuleDialog.close();
    await refreshAfterWireGuardMutation();
    toast(payload.message || "Peer間アクセスを反映しました。");
  } catch (error) {
    elements.accessRuleFormError.textContent = firstLine(error.message);
  } finally {
    setButtonBusy(elements.saveAccessRuleButton, false, "OCIへ反映");
  }
}

async function deleteAccessRule(name) {
  const confirmation = window.prompt(
    `${name}をOCIから削除します。\n続行する場合は DELETE と入力してください。`,
  );
  if (confirmation !== "DELETE") return;
  try {
    const payload = await api(
      `/api/wireguard/access-rules/${encodeURIComponent(name)}`,
      {
        method: "DELETE",
        body: { confirmation },
      },
    );
    await refreshAfterWireGuardMutation();
    toast(payload.message || "Peer間アクセスを削除しました。");
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function refreshAfterWireGuardMutation() {
  await loadWireGuard();
  await loadState();
}

function showInfo(eyebrow, title, html) {
  elements.infoEyebrow.textContent = eyebrow;
  elements.infoTitle.textContent = title;
  elements.infoContent.innerHTML = html;
  elements.infoDialog.showModal();
}

function toast(message, error = false) {
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.classList.add("visible");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => elements.toast.classList.remove("visible"), 4200);
}

function setButtonBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

function firstLine(message) {
  return String(message || "操作に失敗しました。").split("\n")[0];
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}

document.querySelector("#new-route-button").addEventListener("click", openNewRoute);
document.querySelector("#empty-new-route-button").addEventListener("click", openNewRoute);
document.querySelector("#new-group-button").addEventListener("click", openNewGroup);
elements.saveRouteButton.addEventListener("click", saveRoute);
elements.deleteRouteButton.addEventListener("click", () => deleteRoute());
document.querySelector("#save-group-button").addEventListener("click", saveGroup);
document.querySelector("#delete-group-button").addEventListener("click", deleteGroup);
document.querySelector("#add-member-row-button").addEventListener("click", () => {
  addMemberRow();
  updateGroupPreview();
});
document.querySelector("#plan-button").addEventListener("click", createPlan);
document.querySelector("#apply-button").addEventListener("click", applyPlan);
document.querySelector("#preflight-button").addEventListener("click", showPreflight);
document.querySelector("#relay-status-button").addEventListener("click", showRelayStatus);
document.querySelector("#sync-button").addEventListener("click", syncRelay);
document.querySelector("#new-web-route-button").addEventListener("click", openNewWebRoute);
document.querySelector("#web-gateway-setup-button").addEventListener("click", setupWebGateway);
document.querySelector("#web-preview-button").addEventListener("click", reviewWebRoutes);
elements.saveWebRouteButton.addEventListener("click", saveWebRoute);
elements.deleteWebRouteButton.addEventListener("click", () => deleteWebRoute());
elements.webRouteBasicAuthEnabled.addEventListener("change", syncWebRouteBasicAuthFields);
elements.webPublishConfirmButton.addEventListener("click", () => publishWebRoutes());
document.querySelector("#close-web-publish-button").addEventListener("click", () => {
  elements.webPublishDialog.close();
});
document.querySelector("#new-peer-button").addEventListener("click", openNewPeer);
document.querySelector("#new-access-rule-button").addEventListener("click", () => {
  openNewAccessRule();
});
document.querySelector("#wireguard-refresh-button").addEventListener("click", () => {
  loadWireGuard().catch((error) => toast(firstLine(error.message), true));
});
elements.savePeerButton.addEventListener("click", savePeer);
elements.saveAccessRuleButton.addEventListener("click", saveAccessRule);
document.querySelector("#close-plan-button").addEventListener("click", () => elements.planDialog.close());
document.querySelector("#close-info-button").addEventListener("click", () => elements.infoDialog.close());

elements.routesBody.addEventListener("click", (event) => {
  const routeEdit = event.target.closest("[data-route-edit]");
  const routeToggle = event.target.closest("[data-route-toggle]");
  const groupEdit = event.target.closest("[data-group-edit]");
  const groupToggle = event.target.closest("[data-group-toggle]");
  const collapse = event.target.closest("[data-group-collapse]");
  if (routeEdit) return openEditRoute(routeEdit.dataset.routeEdit);
  if (routeToggle) return toggleRoute(routeToggle.dataset.routeToggle);
  if (groupEdit) return openEditGroup(groupEdit.dataset.groupEdit);
  if (groupToggle) return toggleGroup(groupToggle.dataset.groupToggle);
  if (collapse) toggleGroupCollapse(collapse.dataset.groupCollapse);
});

elements.routeTabs.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-route-filter]");
  if (!tab) return;
  appState.routeFilter = tab.dataset.routeFilter;
  renderRoutes();
});

elements.webRoutesBody.addEventListener("click", (event) => {
  const edit = event.target.closest("[data-web-route-edit]");
  const toggle = event.target.closest("[data-web-route-toggle]");
  if (edit) return openEditWebRoute(edit.dataset.webRouteEdit);
  if (toggle) toggleWebRoute(toggle.dataset.webRouteToggle);
});

elements.webRouteTabs.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-web-route-filter]");
  if (!tab) return;
  appState.webRouteFilter = tab.dataset.webRouteFilter;
  renderWebRoutes();
});

elements.groupMemberRows.addEventListener("click", (event) => {
  const remove = event.target.closest(".remove-member-row");
  if (!remove) return;
  remove.closest(".group-member-row").remove();
  if (!elements.groupMemberRows.children.length) addMemberRow();
  updateGroupPreview();
});

elements.groupMemberRows.addEventListener("input", updateGroupPreview);
elements.groupMemberRows.addEventListener("change", updateGroupPreview);

elements.wireguardPeerList.addEventListener("click", (event) => {
  const access = event.target.closest("[data-peer-access]");
  const rotate = event.target.closest("[data-peer-rotate]");
  const remove = event.target.closest("[data-peer-delete]");
  if (access) {
    const peer = appState.peers.find((item) => item.name === access.dataset.peerAccess);
    if (peer) openNewAccessRule(peer.address);
  }
  if (rotate) rotatePeer(rotate.dataset.peerRotate);
  if (remove) deletePeer(remove.dataset.peerDelete);
});

elements.wireguardAccessList.addEventListener("click", (event) => {
  const edit = event.target.closest("[data-access-edit]");
  const remove = event.target.closest("[data-access-delete]");
  if (edit) openEditAccessRule(edit.dataset.accessEdit);
  if (remove) deleteAccessRule(remove.dataset.accessDelete);
});

elements.applyConfirmation.addEventListener("input", () => {
  elements.applyButton.disabled =
    elements.applyButton.dataset.safe !== "true" ||
    elements.applyConfirmation.value !== "APPLY";
});

elements.webPublishConfirmation.addEventListener("input", () => {
  elements.webPublishConfirmButton.disabled =
    elements.webPublishConfirmation.value !== "PUBLISH";
});

loadState()
  .then(() => loadWireGuard())
  .catch((error) => {
    toast(firstLine(error.message), true);
  });

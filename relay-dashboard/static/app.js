"use strict";

const appState = {
  routes: [],
  groups: [],
  plan: null,
  audit: [],
  csrfToken: "",
  routeFilter: "all",
  pendingRelay: false,
  busy: false,
  collapsedGroups: new Set(),
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
  groupMemberRows: document.querySelector("#group-member-rows"),
  groupPortPreview: document.querySelector("#group-port-preview"),
  groupAdvanced: document.querySelector("#group-advanced"),
  groupFormError: document.querySelector("#group-form-error"),
  planDialog: document.querySelector("#plan-dialog"),
  planSummary: document.querySelector("#plan-summary"),
  unexpected: document.querySelector("#unexpected-changes"),
  planOutput: document.querySelector("#plan-output"),
  planError: document.querySelector("#plan-error"),
  applyConfirmation: document.querySelector("#apply-confirmation"),
  applyButton: document.querySelector("#apply-button"),
  infoDialog: document.querySelector("#info-dialog"),
  infoEyebrow: document.querySelector("#info-eyebrow"),
  infoTitle: document.querySelector("#info-title"),
  infoContent: document.querySelector("#info-content"),
  toast: document.querySelector("#toast"),
};

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
  appState.plan = payload.plan;
  appState.audit = payload.audit || [];
  appState.csrfToken = payload.csrf_token;
  appState.pendingRelay = Boolean(payload.pending_relay);
  appState.busy = Boolean(payload.busy);
  render();
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
  renderAudit();
  renderPlanStatus();
  renderOperationAvailability();
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
  for (const group of appState.groups) {
    const allMembers = appState.routes.filter((route) => route.group_id === group.id);
    const members = visibleRoutes.filter((route) => route.group_id === group.id);
    if (!members.length && appState.routeFilter !== "all") continue;
    elements.routesBody.insertAdjacentHTML(
      "beforeend",
      renderGroup(group, allMembers, members),
    );
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

function renderGroup(group, allMembers, visibleMembers) {
  const collapsed = appState.collapsedGroups.has(group.id);
  const state = group.enabled_state === "empty" ? "disabled" : group.enabled_state;
  const toggleLabel =
    state === "mixed"
      ? "一部有効。操作するとすべて無効になります"
      : state === "enabled"
        ? "すべて有効。操作するとすべて無効になります"
        : "すべて無効。操作するとすべて有効になります";
  const locked = appState.pendingRelay || appState.busy || group.total_ports === 0;
  return `
    <section class="route-group" data-group-card="${escapeAttribute(group.id)}">
      <div class="group-header">
        <div class="group-identity">
          <strong>${escapeHtml(group.name)}</strong>
          <small>${escapeHtml(group.description || "説明なし")}</small>
        </div>
        <div>
          <span class="group-port-summary">${escapeHtml(formatGroupPorts(allMembers))}</span>
          <small>${group.enabled_ports}/${group.total_ports} ポート有効</small>
        </div>
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
            aria-label="${collapsed ? "グループを展開" : "グループを折りたたむ"}"
            data-group-collapse="${escapeAttribute(group.id)}"
          >${collapsed ? "＋" : "−"}</button>
        </div>
      </div>
      <div class="route-members" ${collapsed ? "hidden" : ""}>
        ${
          visibleMembers.length
            ? visibleMembers.map(renderRouteItem).join("")
            : '<p class="muted">この条件に一致するポートはありません。</p>'
        }
      </div>
    </section>
  `;
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
          `<option value="${escapeAttribute(group.id)}">${escapeHtml(group.name)}</option>`,
      )
      .join("")}
  `;
  elements.routeGroup.value = selected || "";
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

function openNewGroup() {
  if (appState.pendingRelay || appState.busy) return;
  elements.groupForm.reset();
  elements.groupId.value = "";
  elements.groupDialogTitle.textContent = "ポートグループを追加";
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

async function deleteGroup() {
  const groupId = elements.groupId.value;
  const group = appState.groups.find((item) => item.id === groupId);
  if (!group) return;
  if (!window.confirm(`グループ「${group.name}」を解除しますか？\n所属経路とOCI設定は削除されません。`)) {
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
document.querySelector("#close-plan-button").addEventListener("click", () => elements.planDialog.close());
document.querySelector("#close-info-button").addEventListener("click", () => elements.infoDialog.close());

elements.routesBody.addEventListener("click", (event) => {
  const routeEdit = event.target.closest("[data-route-edit]");
  const routeToggle = event.target.closest("[data-route-toggle]");
  const groupEdit = event.target.closest("[data-group-edit]");
  const groupToggle = event.target.closest("[data-group-toggle]");
  const collapse = event.target.closest("[data-group-collapse]");
  if (routeEdit) openEditRoute(routeEdit.dataset.routeEdit);
  if (routeToggle) toggleRoute(routeToggle.dataset.routeToggle);
  if (groupEdit) openEditGroup(groupEdit.dataset.groupEdit);
  if (groupToggle) toggleGroup(groupToggle.dataset.groupToggle);
  if (collapse) {
    const id = collapse.dataset.groupCollapse;
    if (appState.collapsedGroups.has(id)) appState.collapsedGroups.delete(id);
    else appState.collapsedGroups.add(id);
    renderRoutes();
  }
});

elements.routeTabs.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-route-filter]");
  if (!tab) return;
  appState.routeFilter = tab.dataset.routeFilter;
  renderRoutes();
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

elements.applyConfirmation.addEventListener("input", () => {
  elements.applyButton.disabled =
    elements.applyButton.dataset.safe !== "true" ||
    elements.applyConfirmation.value !== "APPLY";
});

loadState().catch((error) => {
  toast(firstLine(error.message), true);
});

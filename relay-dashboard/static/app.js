"use strict";

const appState = {
  routes: [],
  plan: null,
  audit: [],
  csrfToken: "",
  routeFilter: "all",
  pendingRelay: false,
  busy: false,
};

const routeStateLabels = {
  applied: "反映済み",
  pending_create: "作成待ち",
  pending_update: "更新待ち",
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
  routeFormError: document.querySelector("#route-form-error"),
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
  appState.plan = payload.plan;
  appState.audit = payload.audit || [];
  appState.csrfToken = payload.csrf_token;
  appState.pendingRelay = Boolean(payload.pending_relay);
  appState.busy = Boolean(payload.busy);
  render();
}

function render() {
  const managed = appState.routes.filter((route) => route.state !== "deleted");
  elements.total.textContent = String(managed.length);
  elements.tcp.textContent = String(
    managed.filter((route) => route.protocol === "tcp").length,
  );
  elements.udp.textContent = String(
    managed.filter((route) => route.protocol === "udp").length,
  );
  renderRoutes();
  renderAudit();
  renderPlanStatus();
  renderOperationAvailability();
}

function renderRoutes() {
  const counts = {
    all: appState.routes.length,
    applied: appState.routes.filter((route) => route.state_group === "applied").length,
    pending: appState.routes.filter((route) => route.state_group === "pending").length,
    deleted: appState.routes.filter((route) => route.state_group === "deleted").length,
  };
  for (const tab of elements.routeTabs.querySelectorAll("[data-route-filter]")) {
    const selected = tab.dataset.routeFilter === appState.routeFilter;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", selected ? "true" : "false");
  }
  for (const counter of elements.routeTabs.querySelectorAll("[data-filter-count]")) {
    counter.textContent = String(counts[counter.dataset.filterCount] || 0);
  }

  const visibleRoutes = appState.routes.filter(
    (route) =>
      appState.routeFilter === "all" || route.state_group === appState.routeFilter,
  );
  const hasRoutes = visibleRoutes.length > 0;
  elements.empty.hidden = hasRoutes;
  elements.tableWrap.hidden = !hasRoutes;
  elements.routesBody.replaceChildren();

  const emptyCopy = {
    all: ["経路はまだ登録されていません", "最初の公開ポートとMiniPCの転送先を追加してください。"],
    applied: ["反映済みの経路はありません", "Applyが完了した経路がここに表示されます。"],
    pending: ["未反映の経路はありません", "作成・更新・削除待ちの経路はありません。"],
    deleted: ["削除済みの経路はありません", "正常に削除された経路の履歴がここに残ります。"],
  };
  [elements.emptyTitle.textContent, elements.emptyDescription.textContent] =
    emptyCopy[appState.routeFilter];
  elements.emptyNewRoute.hidden = appState.routeFilter !== "all";

  for (const route of visibleRoutes) {
    const row = document.createElement("tr");
    row.className = `route-row state-${route.state}`;
    const locked = appState.pendingRelay || appState.busy;
    let actions = `
      <button class="small-button edit" type="button" data-route="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>編集</button>
      <button class="small-button delete" type="button" data-delete-route="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>削除</button>
    `;
    if (route.state === "pending_delete") {
      actions = `<button class="small-button restore" type="button" data-cancel-delete="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>削除を取り消す</button>`;
    } else if (route.state === "deleted") {
      actions = `<button class="small-button delete" type="button" data-purge-route="${escapeAttribute(route.id)}" ${locked ? "disabled" : ""}>履歴から消去</button>`;
    } else if (route.state === "pending_relay") {
      actions = '<span class="muted row-lock-note">再同期してください</span>';
    }
    row.innerHTML = `
      <td><span class="route-name">${escapeHtml(route.name)}</span></td>
      <td><span class="protocol-badge ${route.protocol}">${route.protocol.toUpperCase()}</span></td>
      <td><span class="mono">${route.public_port}</span></td>
      <td><span class="mono">${escapeHtml(route.target_address)}:${route.target_port}</span></td>
      <td class="description-cell">${escapeHtml(route.description || "—")}</td>
      <td><span class="state-badge ${escapeAttribute(route.state)}">${escapeHtml(routeStateLabels[route.state] || route.state)}</span></td>
      <td>
        <div class="row-actions">${actions}</div>
      </td>
    `;
    elements.routesBody.append(row);
  }
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
    setMetricStatus("再同期待ち", "Terraform反映済み・OCIリレー未同期", "danger");
    return;
  }
  if (!appState.plan) {
    if (pendingCount > 0) {
      setMetricStatus(`未反映 ${pendingCount}件`, "変更を確認してApplyしてください", "warning");
    } else {
      setMetricStatus("反映済み", "未反映の変更はありません", "ready");
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
  elements.emptyNewRoute.disabled = locked;
  document.querySelector("#plan-button").disabled = locked;
  document.querySelector("#sync-button").disabled = appState.busy;
}

function setMetricStatus(label, detail, tone) {
  elements.status.textContent = label;
  elements.statusDetail.textContent = detail;
  elements.status.className = `tone-${tone}`;
}

function openNewRoute() {
  if (appState.pendingRelay || appState.busy) return;
  elements.routeForm.reset();
  elements.recordId.value = "";
  elements.routeTargetAddress.value = "10.99.0.2";
  elements.routeDialogTitle.textContent = "経路を追加";
  elements.routeFormError.textContent = "";
  elements.routeDialog.showModal();
  elements.routeName.focus();
}

function openEditRoute(id) {
  if (appState.pendingRelay || appState.busy) return;
  const route = appState.routes.find((item) => item.id === id);
  if (!route) return;
  elements.recordId.value = route.id;
  elements.routeName.value = route.name;
  elements.routeProtocol.value = route.protocol;
  elements.routePublicPort.value = route.public_port;
  elements.routeTargetAddress.value = route.target_address;
  elements.routeTargetPort.value = route.target_port;
  elements.routeDescription.value = route.description || "";
  elements.routeDialogTitle.textContent = "経路を編集";
  elements.routeFormError.textContent = "";
  elements.routeDialog.showModal();
  elements.routeName.focus();
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
  };
  setButtonBusy(document.querySelector("#save-route-button"), true, "保存中…");
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
    setButtonBusy(document.querySelector("#save-route-button"), false, "保存");
  }
}

async function deleteRoute(id) {
  const route = appState.routes.find((item) => item.id === id);
  if (!route) return;
  const message =
    route.state === "pending_create"
      ? `未反映の経路「${route.name}」の作成を取り消しますか？`
      : `経路「${route.name}」を削除待ちにしますか？\n次回ApplyまではOCIから削除されません。`;
  if (!window.confirm(message)) {
    return;
  }
  try {
    await api(`/api/routes/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadState();
    toast(route.state === "pending_create" ? "経路の作成を取り消しました。" : "経路を削除待ちにしました。");
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function cancelDelete(id) {
  try {
    await api(`/api/routes/${encodeURIComponent(id)}/cancel-delete`, {
      method: "POST",
    });
    await loadState();
    toast("経路の削除を取り消しました。");
  } catch (error) {
    toast(firstLine(error.message), true);
  }
}

async function purgeDeleted(id) {
  const route = appState.routes.find((item) => item.id === id);
  if (!route || !window.confirm(`削除済み経路「${route.name}」を履歴から完全に消去しますか？`)) {
    return;
  }
  try {
    await api(`/api/deleted-routes/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    await loadState();
    toast("削除済み履歴を消去しました。");
  } catch (error) {
    toast(firstLine(error.message), true);
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
document.querySelector("#save-route-button").addEventListener("click", saveRoute);
document.querySelector("#plan-button").addEventListener("click", createPlan);
document.querySelector("#apply-button").addEventListener("click", applyPlan);
document.querySelector("#preflight-button").addEventListener("click", showPreflight);
document.querySelector("#relay-status-button").addEventListener("click", showRelayStatus);
document.querySelector("#sync-button").addEventListener("click", syncRelay);
document.querySelector("#close-plan-button").addEventListener("click", () => elements.planDialog.close());
document.querySelector("#close-info-button").addEventListener("click", () => elements.infoDialog.close());

elements.routesBody.addEventListener("click", (event) => {
  const edit = event.target.closest("[data-route]");
  const remove = event.target.closest("[data-delete-route]");
  const cancelDeleteButton = event.target.closest("[data-cancel-delete]");
  const purge = event.target.closest("[data-purge-route]");
  if (edit) openEditRoute(edit.dataset.route);
  if (remove) deleteRoute(remove.dataset.deleteRoute);
  if (cancelDeleteButton) cancelDelete(cancelDeleteButton.dataset.cancelDelete);
  if (purge) purgeDeleted(purge.dataset.purgeRoute);
});

elements.routeTabs.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-route-filter]");
  if (!tab) return;
  appState.routeFilter = tab.dataset.routeFilter;
  renderRoutes();
});

elements.applyConfirmation.addEventListener("input", () => {
  elements.applyButton.disabled =
    elements.applyButton.dataset.safe !== "true" ||
    elements.applyConfirmation.value !== "APPLY";
});

loadState().catch((error) => {
  toast(firstLine(error.message), true);
});

"use strict";

const appState = {
  routes: [],
  plan: null,
  audit: [],
  csrfToken: "",
};

const elements = {
  total: document.querySelector("#metric-total"),
  tcp: document.querySelector("#metric-tcp"),
  udp: document.querySelector("#metric-udp"),
  status: document.querySelector("#metric-status"),
  statusDetail: document.querySelector("#metric-status-detail"),
  empty: document.querySelector("#empty-state"),
  tableWrap: document.querySelector("#routes-table-wrap"),
  routesBody: document.querySelector("#routes-body"),
  auditList: document.querySelector("#audit-list"),
  routeDialog: document.querySelector("#route-dialog"),
  routeForm: document.querySelector("#route-form"),
  routeDialogTitle: document.querySelector("#route-dialog-title"),
  originalName: document.querySelector("#original-name"),
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
  render();
}

function render() {
  elements.total.textContent = String(appState.routes.length);
  elements.tcp.textContent = String(
    appState.routes.filter((route) => route.protocol === "tcp").length,
  );
  elements.udp.textContent = String(
    appState.routes.filter((route) => route.protocol === "udp").length,
  );
  renderRoutes();
  renderAudit();
  renderPlanStatus();
}

function renderRoutes() {
  const hasRoutes = appState.routes.length > 0;
  elements.empty.hidden = hasRoutes;
  elements.tableWrap.hidden = !hasRoutes;
  elements.routesBody.replaceChildren();

  for (const route of appState.routes) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="route-name">${escapeHtml(route.name)}</span></td>
      <td><span class="protocol-badge ${route.protocol}">${route.protocol.toUpperCase()}</span></td>
      <td><span class="mono">${route.public_port}</span></td>
      <td><span class="mono">${escapeHtml(route.target_address)}:${route.target_port}</span></td>
      <td class="description-cell">${escapeHtml(route.description || "—")}</td>
      <td>
        <div class="row-actions">
          <button class="small-button edit" type="button" data-route="${escapeAttribute(route.name)}">編集</button>
          <button class="small-button delete" type="button" data-delete-route="${escapeAttribute(route.name)}">削除</button>
        </div>
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
  if (!appState.plan) {
    setMetricStatus("未計画", "変更を確認するとplanを作成します", "warning");
    return;
  }
  if (!appState.plan.safe) {
    setMetricStatus("適用停止", "NSG以外の変更を検出しました", "danger");
    return;
  }
  setMetricStatus("確認待ち", "安全なplanが作成されています", "info");
}

function setMetricStatus(label, detail, tone) {
  elements.status.textContent = label;
  elements.statusDetail.textContent = detail;
  elements.status.className = `tone-${tone}`;
}

function openNewRoute() {
  elements.routeForm.reset();
  elements.originalName.value = "";
  elements.routeTargetAddress.value = "10.99.0.2";
  elements.routeDialogTitle.textContent = "経路を追加";
  elements.routeFormError.textContent = "";
  elements.routeDialog.showModal();
  elements.routeName.focus();
}

function openEditRoute(name) {
  const route = appState.routes.find((item) => item.name === name);
  if (!route) return;
  elements.originalName.value = route.name;
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
  const originalName = elements.originalName.value;
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
    if (originalName) {
      await api(`/api/routes/${encodeURIComponent(originalName)}`, {
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

async function deleteRoute(name) {
  if (!window.confirm(`経路「${name}」を削除しますか？\n次回applyまではOCIへ反映されません。`)) {
    return;
  }
  try {
    await api(`/api/routes/${encodeURIComponent(name)}`, { method: "DELETE" });
    await loadState();
    toast("経路を削除しました。");
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
    "Terraformは変更せず、現在のGUI経路をOCIリレーへ同期します。\n続行する場合は SYNC と入力してください。",
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
  if (edit) openEditRoute(edit.dataset.route);
  if (remove) deleteRoute(remove.dataset.deleteRoute);
});

elements.applyConfirmation.addEventListener("input", () => {
  elements.applyButton.disabled =
    elements.applyButton.dataset.safe !== "true" ||
    elements.applyConfirmation.value !== "APPLY";
});

loadState().catch((error) => {
  toast(firstLine(error.message), true);
});

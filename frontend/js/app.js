/* LUNATIC MOBILE SECURITY - application shell.
 *
 * - API client: JSON, per-launch anti-CSRF token on state-changing requests,
 *   errors normalised to { message, cause, action, detail }.
 * - Hash router between views.
 * - Every piece of server data is inserted with textContent (never innerHTML)
 *   to rule out HTML injection from device-provided strings.
 */
"use strict";

const LMS = (() => {
  // ---------------------------------------------------------------- DOM utils
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }
  const $ = (selector) => document.querySelector(selector);

  // --------------------------------------------------------------- API client
  class ApiError extends Error {
    constructor(payload, status) {
      super(payload.message || "Erreur");
      this.status = status;
      this.payload = payload;
    }
  }

  let csrfToken = null;

  async function request(method, path, body) {
    const headers = { Accept: "application/json" };
    if (method !== "GET") {
      if (!csrfToken) csrfToken = (await request("GET", "/api/session")).csrf_token;
      headers["X-LMS-Token"] = csrfToken;
      headers["Content-Type"] = "application/json";
    }
    let response;
    try {
      response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch (networkError) {
      setBackendState(false);
      throw new ApiError({
        code: "backend_unreachable",
        message: "Le moteur LUNATIC MOBILE SECURITY ne répond pas.",
        cause: "L'application a été fermée ou a rencontré une erreur.",
        action: "Relancez l'application puis rechargez cette page.",
      }, 0);
    }
    setBackendState(true);
    let data = null;
    try { data = await response.json(); } catch { data = null; }
    if (!response.ok) {
      const payload = (data && data.error) || {
        code: "http_" + response.status,
        message: "Requête refusée (HTTP " + response.status + ").",
        cause: "Réponse inattendue du serveur.",
        action: "Consultez l'onglet Logs.",
      };
      throw new ApiError(payload, response.status);
    }
    return data;
  }
  const api = {
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body ?? {}),
  };

  function setBackendState(ok) {
    $("#backend-dot").className = "status-dot " + (ok ? "ok" : "fail");
    $("#backend-status").textContent = ok ? "Moteur connecté" : "Moteur injoignable";
  }

  // ----------------------------------------------------------- notifications
  function toast(title, body = "", kind = "info", timeout = 6000) {
    const node = el("div", { class: "toast " + kind, role: "status" },
      el("div", { class: "toast-title", text: title }),
      body ? el("div", { class: "toast-body", text: body }) : null);
    $("#toasts").append(node);
    setTimeout(() => node.remove(), timeout);
  }

  function errorBox(error) {
    const payload = error instanceof ApiError ? error.payload : { message: String(error.message || error) };
    return el("div", { class: "error-box", role: "alert" },
      el("div", { class: "row" }, el("span", { class: "lbl", text: "ERREUR" }), payload.message),
      payload.cause ? el("div", { class: "row" }, el("span", { class: "lbl", text: "CAUSE POSSIBLE" }), payload.cause) : null,
      payload.action ? el("div", { class: "row" }, el("span", { class: "lbl", text: "ACTION" }), payload.action) : null,
      payload.detail ? el("details", {}, el("summary", { text: "Détail technique" }), el("pre", { text: payload.detail })) : null);
  }

  function notifyError(error) {
    const payload = error instanceof ApiError ? error.payload : { message: String(error) };
    toast(payload.message, payload.action || "", "fail", 9000);
  }

  // ------------------------------------------------------------------ modal
  /**
   * Confirmation dialog for sensitive operations. Resolves true only when the
   * user explicitly clicks the confirm button (Escape / backdrop = cancel).
   * options: { title, before, after, risk, confirmLabel, danger }
   */
  function confirmDialog(options) {
    const backdrop = $("#modal");
    return new Promise((resolve) => {
      const section = (label, text, extra = "") => text
        ? el("div", { class: "modal-section " + extra }, el("div", { class: "lbl", text: label }), el("div", { text }))
        : null;
      const cancel = el("button", { class: "btn", type: "button", text: "Annuler" });
      const confirm = el("button", {
        class: "btn " + (options.danger ? "btn-danger" : "btn-primary"),
        type: "button",
        text: options.confirmLabel || "Continuer",
      });
      const dialog = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "modal-title" },
        el("h2", { id: "modal-title", text: options.title }),
        section("AVANT", options.before),
        section("APRÈS", options.after),
        section("RISQUE", options.risk, "risk"),
        el("div", { class: "modal-section" },
          el("div", { class: "lbl", text: "CONFIRMATION" }),
          el("div", { text: options.question || "Voulez-vous continuer ?" })),
        el("div", { class: "modal-actions" }, cancel, confirm));
      const close = (result) => {
        document.removeEventListener("keydown", onKey);
        backdrop.hidden = true;
        backdrop.replaceChildren();
        resolve(result);
      };
      const onKey = (event) => { if (event.key === "Escape") close(false); };
      cancel.addEventListener("click", () => close(false));
      confirm.addEventListener("click", () => close(true));
      backdrop.onclick = (event) => { if (event.target === backdrop) close(false); };
      document.addEventListener("keydown", onKey);
      backdrop.replaceChildren(dialog);
      backdrop.hidden = false;
      cancel.focus();
    });
  }

  // ------------------------------------------------------------ shared state
  const state = { selectedDeviceId: null };

  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined) return "—";
    const units = ["o", "Ko", "Mo", "Go", "To"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return value.toFixed(unit >= 3 ? 1 : 0) + " " + units[unit];
  }

  // ------------------------------------------------------------------ router
  const views = {};
  let currentView = null;

  function registerView(name, { title, onEnter, onLeave }) {
    views[name] = { title, onEnter, onLeave };
  }

  function route() {
    const name = (location.hash.replace(/^#\//, "") || "dashboard").split("/")[0];
    const target = views[name] ? name : "dashboard";
    if (currentView && currentView !== target && views[currentView].onLeave) views[currentView].onLeave();
    document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== "view-" + target; });
    document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("active", a.dataset.view === target));
    $("#page-title").textContent = views[target].title;
    $("#sidebar").classList.remove("open");
    const entering = currentView !== target;
    currentView = target;
    if (entering && views[target].onEnter) views[target].onEnter();
  }

  // --------------------------------------------------------------- dashboard
  const STATUS_SYMBOL = { ok: "✓", warn: "!", fail: "✗", info: "i" };
  const STATUS_LABEL = { ok: "OK", warn: "Attention", fail: "Échec", info: "Info" };
  const RING_COLOR = { ok: "var(--ok)", warn: "var(--warn)", fail: "var(--fail)" };

  function toolCard(label, info) {
    let status = "fail";
    let value = "Introuvable";
    if (info.found && !info.error) {
      value = info.version || "Version inconnue";
      status = info.meets_minimum === false || !info.version ? "warn" : "ok";
    } else if (info.found) {
      value = "Erreur";
    }
    return el("div", { class: "card stat-card" },
      el("div", { class: "stat-top" },
        el("span", { class: "stat-label", text: label }),
        el("span", { class: "badge " + status, text: STATUS_LABEL[status] })),
      el("div", { class: "stat-value", text: value }),
      el("div", { class: "stat-sub", text: info.path || "Non installé" }),
      info.minimum_version ? el("div", { class: "muted small", text: "Minimum GrapheneOS : " + info.minimum_version }) : null);
  }

  async function loadDeviceCard() {
    const badge = $("#device-card-badge");
    try {
      const status = await api.get("/api/device/status");
      const ready = status.devices.filter((d) => d.ready);
      let kind = "fail";
      let label = "Aucun";
      let value = "Aucun appareil";
      if (ready.length === 1) {
        const d = ready[0];
        kind = "ok"; label = d.transport === "fastboot" ? "Fastboot" : "ADB";
        value = d.model_hint || d.codename_hint || d.product_hint || "Appareil " + d.serial_masked;
      } else if (ready.length > 1) {
        kind = "info"; label = ready.length + " appareils"; value = "Plusieurs appareils";
      } else if (status.devices.length) {
        kind = "warn"; label = "Action requise"; value = "Appareil non prêt";
      }
      badge.className = "badge " + kind;
      badge.textContent = label;
      $("#device-card-value").textContent = value;
      $("#device-card-sub").textContent = status.message;
    } catch (error) {
      badge.className = "badge fail";
      badge.textContent = "Erreur";
      $("#device-card-value").textContent = "Indisponible";
      $("#device-card-sub").textContent = error.payload ? error.payload.message : String(error);
    }
  }

  async function loadEnvironment() {
    loadDeviceCard();
    const button = $("#env-refresh");
    const ring = $("#env-ring");
    button.disabled = true;
    button.classList.add("loading");
    ring.classList.add("scanning");
    $("#env-ring-label").textContent = "…";
    $("#env-summary").textContent = "Analyse de l'ordinateur en cours…";
    try {
      const report = await api.get("/api/system/environment");
      const checks = report.checks;
      const okCount = checks.filter((c) => c.status === "ok" || c.status === "info").length;
      ring.style.setProperty("--pct", Math.round((okCount / checks.length) * 100));
      ring.style.setProperty("--ring-color", RING_COLOR[report.overall]);
      $("#env-ring-label").textContent = okCount + "/" + checks.length;
      const summary = {
        ok: "Tout est prêt : ADB et Fastboot sont opérationnels.",
        warn: "Utilisable, mais certains points méritent votre attention.",
        fail: "Des prérequis manquent. Suivez les actions indiquées ci-dessous.",
      }[report.overall];
      $("#env-summary").textContent = summary;
      $("#host-chip").replaceChildren(
        el("span", { class: "chip", text: report.host.platform + " · " + report.host.machine }),
        el("span", { class: "chip", text: "Python " + report.host.python }));
      $("#tool-cards").replaceChildren(toolCard("ADB", report.tools.adb), toolCard("Fastboot", report.tools.fastboot));
      $("#env-checks").replaceChildren(...checks.map((c) =>
        el("li", { class: "check-item" },
          el("span", { class: "check-icon " + c.status, text: STATUS_SYMBOL[c.status] || "?" }),
          el("div", {},
            el("div", { class: "check-label", text: c.label }),
            el("div", { class: "check-detail", text: c.detail }),
            c.action && c.status !== "ok" ? el("div", { class: "check-action", text: c.action }) : null),
          el("span", { class: "badge " + c.status, text: STATUS_LABEL[c.status] || c.status }))));
      $("#env-updated").textContent = "Mis à jour à " + new Date().toLocaleTimeString();
    } catch (error) {
      $("#env-summary").textContent = "";
      $("#env-checks").replaceChildren(el("li", {}, errorBox(error)));
      ring.style.setProperty("--pct", 0);
      $("#env-ring-label").textContent = "—";
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
      ring.classList.remove("scanning");
    }
  }

  // -------------------------------------------------------------------- logs
  const logState = { lastId: 0, timer: null, paused: false };

  function appendLogs(entries) {
    const view = $("#log-view");
    const stick = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
    view.querySelector(".log-empty")?.remove();
    for (const entry of entries) {
      view.append(el("div", { class: "log-line " + entry.level },
        el("span", { class: "ts", text: entry.timestamp + " " }),
        el("span", { class: "lvl", text: entry.level }),
        " " + entry.message));
    }
    while (view.childElementCount > 3000) view.firstElementChild.remove();
    if (stick) view.scrollTop = view.scrollHeight;
  }

  async function pollLogs() {
    if (logState.paused) return;
    const level = $("#log-level").value;
    try {
      const data = await api.get("/api/logs?since=" + logState.lastId + (level ? "&level=" + level : ""));
      if (data.entries.length) appendLogs(data.entries);
      logState.lastId = data.last_id;
      if (!$("#log-view").childElementCount) {
        $("#log-view").append(el("div", { class: "log-empty", text: "Aucune entrée pour le moment." }));
      }
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 0)) notifyError(error);
    }
  }

  function resetLogs() {
    logState.lastId = 0;
    $("#log-view").replaceChildren();
    pollLogs();
  }

  // ---------------------------------------------------------------- settings
  const SETTING_LABELS = {
    host: "Adresse d'écoute", port: "Port", host_os: "Système", data_dir: "Données",
    logs_dir: "Logs", downloads_dir: "Téléchargements", backups_dir: "Sauvegardes",
    platform_tools_dir: "Platform Tools (forcé)", log_level: "Niveau de log",
    command_timeout: "Timeout commande (s)", flash_timeout: "Timeout flash (s)",
    grapheneos_releases_url: "Source GrapheneOS", min_fastboot_version: "Fastboot minimum",
  };

  async function loadSettings() {
    try {
      const data = await api.get("/api/settings");
      $("#settings-list").replaceChildren(...Object.entries(data).flatMap(([key, value]) => [
        el("dt", { text: SETTING_LABELS[key] || key }),
        el("dd", { text: value === null ? "—" : String(value) }),
      ]));
    } catch (error) {
      $("#settings-list").replaceChildren(errorBox(error));
    }
    loadAudit();
  }

  async function loadAudit() {
    try {
      const data = await api.get("/api/audit?limit=50");
      const rows = data.events.slice().reverse().map((e) => el("tr", {},
        el("td", { class: "mono", text: (e.ts || "").replace("T", " ").replace("+00:00", "") }),
        el("td", {}, el("span", { class: "badge " + ({ INFO: "info", WARN: "warn", WARNING: "warn", ERROR: "fail" }[e.level] || "info"), text: e.level })),
        el("td", { class: "mono", text: e.event })));
      $("#audit-events").replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { colspan: 3, class: "muted", text: "Aucun évènement." }))]));
    } catch (error) {
      $("#audit-events").replaceChildren(el("tr", {}, el("td", { colspan: 3 }, errorBox(error))));
    }
  }

  async function verifyAudit() {
    const target = $("#audit-result");
    try {
      const result = await api.get("/api/audit/verify");
      target.replaceChildren(result.valid
        ? el("p", {}, el("span", { class: "badge ok", text: "Intègre" }), " " + result.events + " évènement(s) vérifié(s).")
        : el("p", {}, el("span", { class: "badge fail", text: "Altéré" }),
          " Chaîne rompue à la ligne " + result.first_invalid_line + " : " + result.reason));
    } catch (error) {
      target.replaceChildren(errorBox(error));
    }
  }

  // -------------------------------------------------------------------- init
  async function init() {
    registerView("dashboard", { title: "Dashboard", onEnter: loadEnvironment });
    registerView("logs", {
      title: "Logs",
      onEnter: () => { pollLogs(); logState.timer = setInterval(pollLogs, 2000); },
      onLeave: () => clearInterval(logState.timer),
    });
    registerView("settings", { title: "Paramètres", onEnter: loadSettings });

    $("#env-refresh").addEventListener("click", loadEnvironment);
    $("#log-level").addEventListener("change", resetLogs);
    $("#log-clear").addEventListener("click", () => $("#log-view").replaceChildren());
    $("#log-pause").addEventListener("click", (event) => {
      logState.paused = !logState.paused;
      event.currentTarget.textContent = logState.paused ? "Reprendre" : "Pause";
      event.currentTarget.setAttribute("aria-pressed", String(logState.paused));
      if (!logState.paused) pollLogs();
    });
    $("#audit-verify").addEventListener("click", verifyAudit);
    $("#menu-toggle").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
    window.addEventListener("hashchange", route);

    try {
      const health = await api.get("/api/health");
      $("#app-version").textContent = "v" + health.version;
    } catch (error) {
      notifyError(error);
    }
    route();
  }

  document.addEventListener("DOMContentLoaded", init);
  return { api, el, toast, errorBox, notifyError, registerView, confirmDialog, formatBytes, state, ApiError };
})();

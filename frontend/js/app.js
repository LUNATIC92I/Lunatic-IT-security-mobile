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
  const BOOLEAN_ATTRS = new Set(["checked", "disabled", "hidden", "open", "selected", "readonly", "required"]);

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (BOOLEAN_ATTRS.has(key) && value !== true) throw new TypeError("el(): attribute " + key + " needs a boolean");
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
      const opener = document.activeElement;
      const close = (result) => {
        document.removeEventListener("keydown", onKey);
        backdrop.hidden = true;
        backdrop.replaceChildren();
        if (opener && opener.isConnected && typeof opener.focus === "function") opener.focus();
        resolve(result);
      };
      const onKey = (event) => {
        if (event.key === "Escape") { close(false); return; }
        if (event.key !== "Tab") return;
        // Keep keyboard focus inside the dialog.
        const focusable = [...dialog.querySelectorAll("button, input, select, textarea, a[href], [tabindex]:not([tabindex='-1'])")]
          .filter((node) => !node.disabled);
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        else if (!dialog.contains(document.activeElement)) { event.preventDefault(); first.focus(); }
      };
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

  /* Chart tooltip, reachable by mouse AND keyboard: the row is focusable and
   * carries the same text as an accessible label. */
  function attachTooltip(node, title, text) {
    const tooltip = document.getElementById("tooltip");
    const place = (x, y) => {
      tooltip.replaceChildren(el("strong", { text: title }), text);
      tooltip.hidden = false;
      tooltip.style.left = Math.max(8, Math.min(x + 14, window.innerWidth - tooltip.offsetWidth - 8)) + "px";
      tooltip.style.top = Math.max(8, Math.min(y + 14, window.innerHeight - tooltip.offsetHeight - 8)) + "px";
    };
    const hide = () => { tooltip.hidden = true; };
    node.tabIndex = 0;
    node.setAttribute("aria-label", title + " : " + text);
    node.addEventListener("mousemove", (event) => place(event.clientX, event.clientY));
    node.addEventListener("mouseleave", hide);
    node.addEventListener("focus", () => { const r = node.getBoundingClientRect(); place(r.left + r.width / 2, r.bottom); });
    node.addEventListener("blur", hide);
  }

  /* Horizontal bar chart: one hue, value at the tip, optional tooltip. */
  function hbars(container, rows, max, tooltipFor) {
    if (!rows.length) {
      container.replaceChildren(el("p", { class: "muted", text: "Aucune donnée." }));
      return;
    }
    container.replaceChildren(...rows.map((row) => {
      const fill = el("span", { class: "hbar-fill" });
      fill.style.width = (max ? Math.max(0, Math.min(100, (row.value / max) * 100)) : 0) + "%";
      const node = el("div", { class: "hbar-row" },
        el("span", { class: "hbar-label", text: row.label }),
        el("span", { class: "hbar-track", "aria-hidden": "true" }, fill),
        el("span", { class: "hbar-value", text: String(row.display ?? row.value) }));
      if (tooltipFor) attachTooltip(node, row.label, tooltipFor(row));
      return node;
    }));
  }

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

  function setSidebar(open) {
    $("#sidebar").classList.toggle("open", open);
    $("#menu-toggle").setAttribute("aria-expanded", String(open));
    $("#menu-toggle").setAttribute("aria-label", open ? "Fermer le menu" : "Ouvrir le menu");
    $("#sidebar-scrim").hidden = !open;
  }

  function route() {
    const name = (location.hash.replace(/^#\//, "") || "dashboard").split("/")[0];
    const target = views[name] ? name : "dashboard";
    if (currentView && currentView !== target && views[currentView].onLeave) views[currentView].onLeave();
    document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== "view-" + target; });
    document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("active", a.dataset.view === target));
    document.querySelectorAll(".nav-item").forEach((a) => {
      if (a.dataset.view === target) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    $("#page-title").textContent = views[target].title;
    document.title = views[target].title + " — LUNATIC MOBILE SECURITY";
    const wasOpen = $("#sidebar").classList.contains("open");
    setSidebar(false);
    const entering = currentView !== target;
    // Keyboard and screen-reader users land on the new page title (not on first load).
    if (entering && currentView !== null) $("#page-title").focus({ preventScroll: true });
    else if (wasOpen) $("#menu-toggle").focus();
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

  async function loadScoreCard() {
    try {
      const report = await api.get("/api/security/report");
      const status = { excellent: "ok", good: "ok", average: "warn", weak: "warn", critical: "fail" }[report.grade] || "info";
      $("#score-card-badge").className = "badge " + status;
      $("#score-card-badge").textContent = report.grade_label;
      $("#score-card-value").textContent = report.score + " / 100";
      const counts = report.severity_counts;
      $("#score-card-sub").textContent = (report.model || "Appareil") + " · " + (counts.critical + counts.high)
        + " problème(s) critique(s) ou élevé(s) · " + new Date(report.created_at).toLocaleString();
    } catch (error) {
      if (!(error instanceof ApiError && error.payload.code === "report_not_found")) {
        $("#score-card-sub").textContent = error.payload ? error.payload.message : String(error);
      }
    }
  }

  async function loadEnvironment() {
    loadDeviceCard();
    loadScoreCard();
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
  /* Real-time feed over Server-Sent Events (EventSource reconnects by itself and
   * resumes with Last-Event-ID). If the stream cannot be opened, the view falls
   * back to polling /api/logs every 2 s. */
  const MAX_LOG_LINES = 3000;
  const logState = { lastId: 0, boot: null, source: null, timer: null, paused: false, buffer: [] };

  function setLogConnection(kind) {
    const badge = $("#log-conn");
    const [cls, text] = {
      live: ["ok", "En direct"], polling: ["warn", "Rafraîchissement 2 s"],
      paused: ["neutral", "En pause"], offline: ["fail", "Serveur injoignable"], idle: ["neutral", "Hors ligne"],
    }[kind];
    badge.className = "badge " + cls;
    badge.textContent = text;
  }

  function logMatches(line) {
    const needle = $("#log-filter").value.trim().toLowerCase();
    return !needle || line.dataset.text.includes(needle);
  }

  function updateLogCount() {
    const view = $("#log-view");
    const total = view.querySelectorAll(".log-line").length;
    const shown = view.querySelectorAll(".log-line:not([hidden])").length;
    $("#log-count").textContent = total ? (shown === total ? total + " ligne(s)." : shown + " / " + total + " ligne(s) affichée(s).") : "";
  }

  function appendLogs(entries) {
    if (!entries.length) return;
    const view = $("#log-view");
    const stick = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
    view.querySelector(".log-empty")?.remove();
    const fragment = document.createDocumentFragment();
    for (const entry of entries) {
      if (entry.boot && entry.boot !== logState.boot) {
        // The application restarted: its log ids start over.
        if (logState.boot !== null) fragment.append(el("div", { class: "log-sep", text: "— Application redémarrée —" }));
        logState.boot = entry.boot;
        logState.lastId = 0;
      }
      if (entry.id <= logState.lastId) continue;
      logState.lastId = entry.id;
      const line = el("div", { class: "log-line " + entry.level },
        el("span", { class: "ts", text: entry.timestamp + " " }),
        el("span", { class: "lvl", text: entry.level }),
        " " + entry.message);
      line.dataset.text = (entry.level + " " + entry.message).toLowerCase();
      line.hidden = !logMatches(line);
      fragment.append(line);
    }
    view.append(fragment);
    while (view.childElementCount > MAX_LOG_LINES) view.firstElementChild.remove();
    if (stick) view.scrollTop = view.scrollHeight;
    updateLogCount();
  }

  function showEmptyLogs() {
    const view = $("#log-view");
    if (!view.childElementCount) view.append(el("div", { class: "log-empty", text: "Aucune entrée pour le moment." }));
  }

  function receive(entries) {
    if (logState.paused) logState.buffer.push(...entries);
    else appendLogs(entries);
  }

  function levelParam() {
    const level = $("#log-level").value;
    return level ? "&level=" + level : "";
  }

  async function pollLogs() {
    try {
      let data = await api.get("/api/logs?since=" + logState.lastId + levelParam());
      if (logState.boot !== null && data.boot !== logState.boot) {
        data = await api.get("/api/logs?since=0" + levelParam()); // restarted: ids start over
      }
      receive(data.entries.map((entry) => ({ ...entry, boot: data.boot })));
      showEmptyLogs();
      if (!logState.paused) setLogConnection("polling");
    } catch (error) {
      setLogConnection("offline");
      if (!(error instanceof ApiError && error.status === 0)) notifyError(error);
    }
  }

  function startLogs() {
    stopLogs();
    if (typeof EventSource === "undefined") {
      pollLogs();
      logState.timer = setInterval(pollLogs, 2000);
      return;
    }
    // Entries already displayed are skipped client-side (ids per boot), so asking
    // from 0 after a level change or a restart is always correct.
    const source = new EventSource("/api/logs/stream?since=" + (logState.boot ? logState.lastId : 0) + levelParam());
    logState.source = source;
    let opened = false;
    source.addEventListener("open", () => {
      opened = true;
      if (!logState.paused) setLogConnection("live");
      showEmptyLogs();
    });
    source.addEventListener("log", (event) => {
      try { receive([JSON.parse(event.data)]); } catch { /* malformed event: ignored */ }
    });
    source.addEventListener("error", () => {
      if (source.readyState === EventSource.CLOSED || !opened) {
        // Stream unavailable (proxy, old browser...): fall back to polling.
        source.close();
        if (logState.source === source) {
          logState.source = null;
          pollLogs();
          logState.timer = setInterval(pollLogs, 2000);
        }
      } else {
        setLogConnection("offline"); // EventSource retries on its own
      }
    });
  }

  function stopLogs() {
    if (logState.source) { logState.source.close(); logState.source = null; }
    clearInterval(logState.timer);
    logState.timer = null;
    setLogConnection("idle");
  }

  function resetLogs() {
    logState.lastId = 0;
    logState.buffer = [];
    $("#log-view").replaceChildren();
    updateLogCount();
    startLogs();
  }

  function togglePause(event) {
    logState.paused = !logState.paused;
    event.currentTarget.textContent = logState.paused ? "Reprendre" : "Pause";
    event.currentTarget.setAttribute("aria-pressed", String(logState.paused));
    if (logState.paused) {
      setLogConnection("paused");
    } else {
      appendLogs(logState.buffer.splice(0));
      setLogConnection(logState.source ? "live" : "polling");
    }
  }

  function applyLogFilter() {
    for (const line of $("#log-view").querySelectorAll(".log-line")) line.hidden = !logMatches(line);
    updateLogCount();
  }

  // ---------------------------------------------------------------- settings
  const SETTING_LABELS = {
    host: "Adresse d'écoute", port: "Port", host_os: "Système", data_dir: "Données",
    logs_dir: "Logs", downloads_dir: "Téléchargements", backups_dir: "Sauvegardes",
    platform_tools_dir: "Platform Tools (forcé)", log_level: "Niveau de log",
    command_timeout: "Timeout commande (s)", flash_timeout: "Timeout flash (s)",
    grapheneos_releases_url: "Source GrapheneOS", min_fastboot_version: "Fastboot minimum",
  };

  function kvRows(pairs) {
    return pairs.flatMap(([key, value]) => [el("dt", { text: key }), el("dd", { text: value === null || value === undefined || value === "" ? "—" : String(value) })]);
  }

  async function loadSettings() {
    try {
      const data = await api.get("/api/settings");
      $("#settings-list").replaceChildren(...kvRows(Object.entries(data).map(([k, v]) => [SETTING_LABELS[k] || k, v])));
    } catch (error) {
      $("#settings-list").replaceChildren(errorBox(error));
    }
    loadTools();
    loadStorage();
    loadAudit();
  }

  async function loadTools() {
    const target = $("#tools-list");
    try {
      const data = await api.get("/api/system/environment");
      const rows = [];
      for (const name of ["adb", "fastboot"]) {
        const tool = data.tools[name] || {};
        rows.push([name, tool.found ? (tool.version || "version inconnue") : "introuvable"]);
        rows.push(["Chemin " + name, tool.path]);
      }
      const fastboot = data.tools.fastboot || {};
      if (fastboot.found) {
        rows.push(["Version GrapheneOS", fastboot.meets_minimum === false
          ? "Trop ancienne : mettez à jour les platform-tools"
          : fastboot.meets_minimum ? "Compatible avec l'installation" : "Non déterminée"]);
      }
      target.replaceChildren(...kvRows(rows));
    } catch (error) {
      target.replaceChildren(errorBox(error));
    }
  }

  async function loadStorage() {
    try {
      const data = await api.get("/api/settings/storage");
      const max = Math.max(1, ...data.folders.map((f) => f.bytes));
      hbars($("#storage-bars"), data.folders.map((f) => ({ label: f.label, value: f.bytes, display: formatBytes(f.bytes), path: f.path, files: f.files })),
        max, (row) => row.files + " fichier(s) — " + row.path);
      $("#storage-summary").textContent = "Total utilisé : " + formatBytes(data.total_bytes)
        + (data.disk_free_bytes !== null ? " · Espace libre sur le disque : " + formatBytes(data.disk_free_bytes) : "");
      const tmp = data.folders.find((f) => f.key === "tmp");
      $("#purge-temp").disabled = !tmp || tmp.files === 0;
      $("#purge-temp").title = tmp && tmp.files === 0 ? "Aucun fichier temporaire." : "";
    } catch (error) {
      $("#storage-bars").replaceChildren(errorBox(error));
    }
  }

  async function purgeTemp() {
    const ok = await confirmDialog({
      title: "Vider les fichiers temporaires",
      before: "Le dossier temporaire contient des restes d'opérations (extraction d'image interrompue, etc.).",
      after: "Son contenu est supprimé. Les images vérifiées, sauvegardes, rapports et logs ne sont pas touchés.",
      risk: "Aucun pour le téléphone. Refusé automatiquement si une étape d'installation est en cours.",
      question: "Supprimer le contenu du dossier temporaire ?",
      confirmLabel: "Vider",
      danger: true,
    });
    if (!ok) return;
    try {
      const result = await api.post("/api/settings/purge-temp", { confirm: true });
      if (result.errors) {
        toast("Nettoyage incomplet", result.removed + " élément(s) supprimé(s), " + result.errors + " en échec (voir Logs).", "warn");
      } else {
        toast("Fichiers temporaires supprimés", formatBytes(result.freed_bytes) + " libéré(s).", "ok");
      }
    } catch (error) {
      notifyError(error);
    }
    await loadStorage();
    if ($("#purge-temp").disabled && document.activeElement === document.body) $("#storage-refresh").focus();
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
    registerView("logs", { title: "Logs", onEnter: startLogs, onLeave: stopLogs });
    registerView("settings", { title: "Paramètres", onEnter: loadSettings });

    $("#env-refresh").addEventListener("click", loadEnvironment);
    $("#log-level").addEventListener("change", resetLogs);
    $("#log-filter").addEventListener("input", applyLogFilter);
    $("#log-clear").addEventListener("click", () => { $("#log-view").replaceChildren(); updateLogCount(); });
    $("#log-pause").addEventListener("click", togglePause);
    $("#tools-refresh").addEventListener("click", loadTools);
    $("#storage-refresh").addEventListener("click", loadStorage);
    $("#purge-temp").addEventListener("click", purgeTemp);
    $("#audit-verify").addEventListener("click", verifyAudit);
    $("#menu-toggle").addEventListener("click", () => {
      const open = !$("#sidebar").classList.contains("open");
      setSidebar(open);
      if (open) ($("#sidebar .nav-item.active") || $("#sidebar .nav-item"))?.focus();
    });
    $("#sidebar-scrim").addEventListener("click", () => setSidebar(false));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && $("#sidebar").classList.contains("open") && $("#modal").hidden) {
        setSidebar(false);
        $("#menu-toggle").focus();
      }
    });
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
  return { api, el, toast, errorBox, notifyError, registerView, confirmDialog, formatBytes, hbars, attachTooltip, state, ApiError };
})();

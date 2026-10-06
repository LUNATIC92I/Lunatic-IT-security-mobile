/* LUNATIC MOBILE SECURITY - security views.
 *
 * Security Scan (score, categories, recommendations), Applications,
 * Permissions, Réseau, Chiffrement, Bootloader, Mises à jour.
 * Every view only reads data: nothing here changes the phone.
 */
"use strict";

(() => {
  const { api, el, errorBox, notifyError, toast, state, hbars } = LMS;
  const $ = (selector) => document.querySelector(selector);

  const SEVERITY = {
    critical: { label: "Critique", badge: "fail", icon: "!!" },
    high: { label: "Élevée", badge: "fail", icon: "!" },
    medium: { label: "Moyenne", badge: "warn", icon: "!" },
    low: { label: "Faible", badge: "info", icon: "i" },
    info: { label: "Info", badge: "neutral", icon: "i" },
  };
  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const CATEGORY = {
    system: "Système", boot: "Démarrage sécurisé", applications: "Applications", permissions: "Permissions",
    network: "Réseau", encryption: "Chiffrement", updates: "Mises à jour",
  };
  const GRADE_STATUS = { excellent: "ok", good: "ok", average: "warn", weak: "warn", critical: "fail" };
  const RISK = { high: ["fail", "Élevé"], medium: ["warn", "Moyen"], low: ["ok", "Faible"] };
  const GROUP_LABELS = {
    camera: "Caméra", microphone: "Micro", location: "Localisation", background_location: "Localisation (arrière-plan)",
    sms: "SMS", contacts: "Contacts", phone: "Téléphone", storage: "Stockage",
  };
  const SPECIAL_LABELS = {
    accessibility: "Accessibilité", notification_listener: "Notifications", device_admin: "Administrateur",
    device_owner: "Propriétaire (MDM)", install_packages: "Installation d'apps", vpn: "VPN permanent",
  };

  const deviceQuery = () => (state.selectedDeviceId ? "?device_id=" + encodeURIComponent(state.selectedDeviceId) : "");

  // ------------------------------------------------------------- builders
  function severityBadge(severity) {
    const s = SEVERITY[severity] || SEVERITY.info;
    return el("span", { class: "badge " + s.badge, text: s.label });
  }

  function findingCard(f, open = false) {
    const body = el("div", { class: "finding-body" },
      el("div", {}, el("div", { class: "lbl", text: "POURQUOI C'EST IMPORTANT" }), el("div", { text: f.why })),
      el("div", {}, el("div", { class: "lbl", text: "PREUVE TECHNIQUE" }), el("pre", { text: f.evidence })),
      el("div", {}, el("div", { class: "lbl", text: "RECOMMANDATION" }), el("div", { text: f.recommendation })),
      el("div", {}, el("div", { class: "lbl", text: "MÉTHODE DE CORRECTION" }), el("div", { text: f.remediation })),
      f.affected && f.affected.length
        ? el("div", {}, el("div", { class: "lbl", text: "ÉLÉMENTS CONCERNÉS" }),
          el("div", { class: "perm-chips" }, ...f.affected.map((a) => el("span", { class: "chip", text: a }))))
        : null,
      f.hardening_action
        ? el("div", {}, el("a", { class: "btn", href: "#/hardening", text: "Corriger avec l'assistant de renforcement →" }))
        : null);
    return el("details", { class: "finding", open: open || null },
      el("summary", {},
        severityBadge(f.severity),
        el("div", {},
          el("div", { class: "finding-title", text: f.title }),
          el("div", { class: "finding-cat", text: (CATEGORY[f.category] || f.category) + " · " + (SEVERITY[f.severity] || SEVERITY.info).label })),
        null),
      body);
  }

  function findingsBlock(findings, emptyText) {
    if (!findings.length) {
      return el("div", { class: "card" }, el("p", { class: "muted", text: emptyText || "Aucun problème détecté pour cette section." }));
    }
    return el("div", { class: "card" },
      el("div", { class: "card-header" }, el("h3", { text: "Recommandations (" + findings.length + ")" })),
      el("div", { class: "findings" }, ...findings.map((f) => findingCard(f))));
  }

  function kvCard(title, rows, extra) {
    const dl = el("dl", { class: "prop-list" });
    for (const [label, value, badge] of rows) {
      const missing = value === null || value === undefined || value === "";
      const dd = el("dd", { class: missing ? "na" : null });
      if (badge) dd.append(el("span", { class: "badge " + badge[0], text: badge[1] }), " ");
      dd.append(missing ? "Non disponible" : String(value));
      dl.append(el("dt", { text: label }), dd);
    }
    return el("div", { class: "card" }, el("div", { class: "card-header" }, el("h3", { text: title })), dl, extra || null);
  }

  function limitationsCard(items) {
    if (!items || !items.length) return null;
    return el("div", { class: "card" },
      el("div", { class: "card-header" }, el("h3", { text: "Limites" })),
      el("ul", { class: "notes" }, ...items.map((t) => el("li", { text: t }))));
  }

  const yesNo = (v, yes = "Oui", no = "Non") => (v === true ? yes : v === false ? no : null);

  /** Generic loader for the read-only section views. */
  async function loadSection(target, path, render) {
    target.replaceChildren(el("div", { class: "card muted", text: "Lecture des informations du téléphone…" }));
    try {
      const data = await api.get(path + deviceQuery());
      target.replaceChildren(...render(data).filter(Boolean));
    } catch (error) {
      target.replaceChildren(el("div", { class: "card" }, errorBox(error)));
    }
  }

  // ========================================================== SECURITY SCAN
  let pollTimer = null;
  let findingFilter = "all";
  let currentReport = null;

  function renderReport(report) {
    currentReport = report;
    const status = GRADE_STATUS[report.grade] || "info";
    const ring = $("#score-ring");
    ring.classList.remove("scanning");
    ring.style.setProperty("--pct", report.score);
    ring.style.setProperty("--ring-color", "var(--" + (status === "ok" ? "ok" : status === "warn" ? "warn" : "fail") + ")");
    ring.setAttribute("aria-label", "Score de sécurité " + report.score + " sur 100, " + report.grade_label);
    $("#score-value").textContent = report.score;
    const grade = $("#score-grade");
    grade.className = "badge " + status;
    grade.textContent = report.grade_label;
    $("#score-device").textContent = [report.manufacturer, report.model].filter(Boolean).join(" ") || "Appareil Android";
    $("#score-meta").textContent = "Android " + (report.android_version || "?") + " · N° " + report.serial_masked
      + " · analysé le " + new Date(report.created_at).toLocaleString() + " en " + report.duration_seconds + " s";

    $("#severity-tiles").replaceChildren(...SEVERITY_ORDER.map((sev) =>
      el("div", { class: "card sev-tile" },
        el("div", { class: "sev-head" }, el("span", { class: "sev-icon " + sev, text: SEVERITY[sev].icon }), SEVERITY[sev].label),
        el("div", { class: "sev-count", text: String(report.severity_counts[sev] || 0) }))));

    hbars($("#category-bars"), report.categories.map((c) => ({
      label: c.label, value: c.score, display: c.score, findings: c.findings, penalty: c.penalty, max: c.max_penalty,
    })), 100, (row) => row.findings + " constat(s) · pénalité " + row.penalty + " / " + row.max + " points");

    $("#scan-limitations").replaceChildren(...report.limitations.map((t) => el("li", { text: t })));
    renderFindingFilters();
    renderFindings();
    $("#scan-results").hidden = false;
  }

  function renderFindingFilters() {
    const counts = currentReport.severity_counts;
    const options = [["all", "Toutes (" + currentReport.findings.length + ")"]]
      .concat(SEVERITY_ORDER.filter((s) => counts[s]).map((s) => [s, SEVERITY[s].label + " (" + counts[s] + ")"]));
    $("#finding-filters").replaceChildren(...options.map(([key, label]) =>
      el("button", {
        type: "button", class: "chip" + (findingFilter === key ? " active" : ""), text: label,
        onclick: () => { findingFilter = key; renderFindingFilters(); renderFindings(); },
      })));
  }

  function renderFindings() {
    const list = currentReport.findings.filter((f) => findingFilter === "all" || f.severity === findingFilter);
    $("#findings").replaceChildren(...(list.length
      ? list.map((f, i) => findingCard(f, i === 0 && findingFilter === "all" && ["critical", "high"].includes(f.severity)))
      : [el("p", { class: "muted", text: "Aucun problème détecté. Consultez les limites de l'analyse." })]));
  }

  function renderProgress(status) {
    $("#scan-progress").hidden = false;
    $("#scan-bar").style.width = status.progress + "%";
    $("#scan-step").textContent = status.step + "…";
    $("#scan-elapsed").textContent = status.elapsed_seconds !== null ? status.elapsed_seconds + " s" : "";
    $("#scan-steps").replaceChildren(...status.steps_done.map((s) => el("li", { text: s })));
  }

  function setScanning(on) {
    $("#scan-start").disabled = on;
    const ring = $("#score-ring");
    ring.classList.toggle("scanning", on);
    if (on) {
      $("#score-value").textContent = "…";
      $("#score-grade").className = "badge info";
      $("#score-grade").textContent = "Analyse en cours";
    }
  }

  async function pollScan() {
    try {
      const status = await api.get("/api/security/scan");
      if (status.state === "running") {
        renderProgress(status);
        return;
      }
      clearInterval(pollTimer);
      pollTimer = null;
      setScanning(false);
      $("#scan-progress").hidden = true;
      if (status.state === "completed") {
        const report = await api.get("/api/security/report?report_id=" + status.report_id);
        renderReport(report);
        toast("Analyse terminée", "Score : " + report.score + "/100 (" + report.grade_label + ")", GRADE_STATUS[report.grade] || "info");
      } else if (status.state === "failed") {
        $("#scan-error").replaceChildren(el("div", { class: "card" }, errorBox(new LMS.ApiError(status.error, 500))));
        $("#score-grade").className = "badge fail";
        $("#score-grade").textContent = "Analyse échouée";
        $("#score-value").textContent = currentReport ? currentReport.score : "—";
      }
    } catch (error) {
      clearInterval(pollTimer);
      pollTimer = null;
      setScanning(false);
      notifyError(error);
    }
  }

  function startPolling() {
    if (!pollTimer) pollTimer = setInterval(pollScan, 700);
  }

  async function startScan() {
    $("#scan-error").replaceChildren();
    try {
      const body = state.selectedDeviceId ? { device_id: state.selectedDeviceId } : {};
      const status = await api.post("/api/security/scan", body);
      setScanning(true);
      renderProgress(status);
      startPolling();
    } catch (error) {
      $("#scan-error").replaceChildren(el("div", { class: "card" }, errorBox(error)));
    }
  }

  async function enterScan() {
    try {
      const status = await api.get("/api/security/scan");
      if (status.state === "running") {
        setScanning(true);
        renderProgress(status);
        startPolling();
        return;
      }
      const report = await api.get("/api/security/report" + deviceQuery());
      renderReport(report);
    } catch (error) {
      if (!(error instanceof LMS.ApiError && error.payload.code === "report_not_found")) notifyError(error);
    }
  }

  $("#scan-start").addEventListener("click", startScan);
  LMS.registerView("scan", { title: "Security Scan", onEnter: enterScan });

  // =========================================================== APPLICATIONS
  let appsData = null;
  let appsFilter = "third_party";
  const APP_FILTERS = [
    ["third_party", "Tierces", (a) => !a.system],
    ["risk", "Risque moyen ou élevé", (a) => a.risk_level !== "low"],
    ["sideloaded", "Hors magasin", (a) => a.sideloaded],
    ["recent", "Récentes", (a) => a.recently_installed && !a.system],
    ["system", "Système", (a) => a.system],
    ["disabled", "Désactivées", (a) => !a.enabled],
    ["all", "Toutes", () => true],
  ];

  function renderAppFilters() {
    const apps = appsData.applications.apps;
    $("#apps-filters").replaceChildren(...APP_FILTERS.map(([key, label, test]) =>
      el("button", {
        type: "button", class: "chip" + (appsFilter === key ? " active" : ""),
        text: label + " (" + apps.filter(test).length + ")",
        onclick: () => { appsFilter = key; renderAppFilters(); renderApps(); },
      })));
  }

  function permChips(app) {
    return el("div", { class: "perm-chips" },
      ...app.granted_groups.map((g) => el("span", { class: "chip", text: GROUP_LABELS[g] || g })),
      ...app.special_access.map((s) => el("span", { class: "chip active", text: SPECIAL_LABELS[s] || s })));
  }

  function riskBadge(app) {
    if (app.system) return el("span", { class: "badge neutral", text: "Système" });
    const [kind, label] = RISK[app.risk_level] || RISK.low;
    return el("span", { class: "badge " + kind, text: label + " · " + app.risk_score });
  }

  function renderApps() {
    const [, , test] = APP_FILTERS.find(([key]) => key === appsFilter);
    const query = $("#apps-search").value.trim().toLowerCase();
    const apps = appsData.applications.apps.filter(test).filter((a) => !query || a.package.toLowerCase().includes(query));
    const rows = [];
    for (const app of apps.slice(0, 500)) {
      const reasons = el("tr", { class: "app-reasons", hidden: true },
        el("td", { colspan: 5 },
          app.risk_reasons.length ? el("ul", { class: "notes" }, ...app.risk_reasons.map((r) => el("li", { text: r })))
            : el("span", { text: app.system ? "Application système." : "Aucun facteur de risque particulier." }),
          el("div", { class: "small", text: "Version " + (app.version || "?") + " · cible SDK " + (app.target_sdk || "?")
            + (app.last_update ? " · mise à jour " + app.last_update : "") })));
      const row = el("tr", { class: "app-row", onclick: () => { reasons.hidden = !reasons.hidden; } },
        el("td", {}, el("div", { class: "app-name", text: app.package }),
          !app.enabled ? el("span", { class: "badge neutral", text: "Désactivée" }) : null,
          app.recently_installed && !app.system ? el("span", { class: "badge info", text: "Récente" }) : null),
        el("td", {}, app.sideloaded ? el("span", { class: "badge warn", text: "Hors magasin" }) : null, " " + app.installer_label),
        el("td", { class: "mono", text: app.first_install ? app.first_install.slice(0, 10) : "—" }),
        el("td", {}, permChips(app)),
        el("td", {}, riskBadge(app)));
      rows.push(row, reasons);
    }
    $("#apps-body").replaceChildren(...(rows.length ? rows
      : [el("tr", {}, el("td", { colspan: 5, class: "muted", text: "Aucune application ne correspond." }))]));
  }

  async function loadApps() {
    const body = $("#apps-body");
    body.replaceChildren(el("tr", {}, el("td", { colspan: 5, class: "muted", text: "Lecture de la liste des applications…" })));
    $("#apps-findings").replaceChildren();
    try {
      appsData = await api.get("/api/applications" + deviceQuery());
      const a = appsData.applications;
      $("#apps-title").textContent = "Applications installées : " + a.total + " (" + a.third_party + " tierces, " + a.system + " système)";
      if (appsData.findings.length) $("#apps-findings").replaceChildren(findingsBlock(appsData.findings));
      renderAppFilters();
      renderApps();
    } catch (error) {
      body.replaceChildren(el("tr", {}, el("td", { colspan: 5 }, errorBox(error))));
    }
  }

  $("#apps-search").addEventListener("input", () => appsData && renderApps());
  $("#apps-refresh").addEventListener("click", loadApps);
  LMS.registerView("applications", { title: "Applications", onEnter: loadApps });

  // ============================================================ PERMISSIONS
  async function loadPermissions() {
    $("#perm-bars").replaceChildren(el("p", { class: "muted", text: "Lecture des permissions…" }));
    $("#perm-findings").replaceChildren();
    try {
      const data = await api.get("/api/permissions" + deviceQuery());
      const groups = data.permissions.groups;
      const max = Math.max(1, ...groups.map((g) => g.third_party_apps.length));
      hbars($("#perm-bars"), groups.map((g) => ({
        label: g.label, value: g.third_party_apps.length, apps: g.third_party_apps, system: g.system_apps_count,
      })), max, (row) => (row.apps.length ? row.apps.slice(0, 8).join(", ") + (row.apps.length > 8 ? "…" : "") : "Aucune application tierce")
        + " · " + row.system + " application(s) système");

      const special = data.permissions.special_access;
      $("#perm-special").replaceChildren(...Object.entries(SPECIAL_LABELS).map(([key, label]) => {
        const items = special[key] || [];
        return el("div", { class: "special-group" },
          el("h4", {}, label, el("span", { class: "badge " + (items.length ? "info" : "neutral"), text: String(items.length) })),
          items.length ? el("div", { class: "perm-chips" }, ...items.map((p) => el("span", { class: "chip", text: p })))
            : el("div", { class: "muted small", text: "Aucune application." }));
      }), data.permissions.default_sms_app
        ? el("p", { class: "muted small", text: "Application SMS par défaut : " + data.permissions.default_sms_app })
        : null);

      $("#perm-apps").replaceChildren(...(data.apps.length ? data.apps.map((app) =>
        el("tr", {},
          el("td", {}, el("div", { class: "app-name", text: app.package }), el("div", { class: "muted small", text: app.installer_label })),
          el("td", {}, permChips(app)),
          el("td", {}, riskBadge(app), app.risk_reasons.length
            ? el("ul", { class: "reason-list" }, ...app.risk_reasons.map((r) => el("li", { text: r }))) : null)))
        : [el("tr", {}, el("td", { colspan: 3, class: "muted", text: "Aucune application tierce ne dispose de permission sensible." }))]));
      if (data.findings.length) $("#perm-findings").replaceChildren(findingsBlock(data.findings));
    } catch (error) {
      $("#perm-bars").replaceChildren(errorBox(error));
    }
  }

  $("#perm-refresh").addEventListener("click", loadPermissions);
  LMS.registerView("permissions", { title: "Permissions", onEnter: loadPermissions });

  // ================================================================ NETWORK
  LMS.registerView("network", {
    title: "Réseau",
    onEnter: () => loadSection($("#network-content"), "/api/network", (data) => {
      const n = data.network;
      const dns = { off: "Désactivé", opportunistic: "Automatique", hostname: "Fournisseur : " + (n.private_dns_host || "?") }[n.private_dns_mode];
      return [
        el("div", { class: "grid two" },
          kvCard("Connexion", [
            ["Transports actifs", n.active_transports.length ? n.active_transports.join(", ") : null],
            ["Accès Internet validé", yesNo(n.internet_validated)],
            ["Wi-Fi", yesNo(n.wifi_enabled, "Activé", "Désactivé")],
            ["Wi-Fi connecté", yesNo(n.wifi_connected)],
            ["Sécurité du Wi-Fi", n.wifi_security],
            ["Mode avion", yesNo(n.airplane_mode, "Activé", "Désactivé")],
            ["Bluetooth", yesNo(n.bluetooth_enabled, "Activé", "Désactivé")],
          ]),
          kvCard("Confidentialité du trafic", [
            ["DNS privé (chiffré)", dns || null, n.private_dns_mode === "off" ? ["warn", "Off"] : null],
            ["Serveurs DNS actifs", n.dns_servers.length ? n.dns_servers.join(", ") : null],
            ["Proxy global", n.proxy || "Aucun", n.proxy ? ["warn", "Actif"] : null],
            ["VPN actif", yesNo(n.vpn_active)],
            ["VPN permanent", n.always_on_vpn_app || "Aucun"],
            ["Blocage hors VPN", yesNo(n.vpn_lockdown)],
            ["ADB sans fil", yesNo(n.adb_over_wifi, "Activé", "Désactivé"), n.adb_over_wifi ? ["warn", "Actif"] : null],
          ])),
        findingsBlock(data.findings, "Aucun problème de configuration réseau détecté."),
        limitationsCard(data.limitations.concat(["Aucun scan réseau n'est effectué : seules les informations exposées par Android sont lues. Le nom du Wi-Fi et les adresses MAC/IP ne sont pas conservés."])),
      ];
    }),
  });

  // ============================================================= ENCRYPTION
  LMS.registerView("encryption", {
    title: "Chiffrement",
    onEnter: () => loadSection($("#encryption-content"), "/api/security/encryption", (data) => {
      const e = data.encryption;
      const badge = e.state === "encrypted" ? ["ok", "Chiffré"] : e.state === "unencrypted" ? ["fail", "Non chiffré"] : null;
      return [
        kvCard("Chiffrement du stockage", [
          ["État", e.label, badge],
          ["ro.crypto.state", e.state],
          ["ro.crypto.type", e.type === "file" ? "file (chiffrement par fichier, FBE)" : e.type === "block" ? "block (FDE, obsolète)" : e.type],
        ]),
        findingsBlock(data.findings, "Le stockage est chiffré selon le mécanisme moderne d'Android."),
        limitationsCard(["La robustesse du chiffrement dépend du code de verrouillage, qui n'est pas lisible via ADB : utilisez un code PIN d'au moins 6 chiffres ou une phrase de passe."]),
      ];
    }),
  });

  // ============================================================= BOOTLOADER
  LMS.registerView("bootloader", {
    title: "Bootloader",
    onEnter: () => loadSection($("#bootloader-content"), "/api/security/boot", (data) => {
      const b = data.boot;
      const vb = { green: ["ok", "green"], yellow: ["ok", "yellow"], orange: ["fail", "orange"], red: ["fail", "red"] }[b.verified_boot_state];
      return [
        el("div", { class: "grid two" },
          kvCard("Chaîne de démarrage", [
            ["Bootloader", yesNo(b.bootloader_locked, "Verrouillé", "Déverrouillé"), b.bootloader_locked === true ? ["ok", "OK"] : b.bootloader_locked === false ? ["fail", "Risque"] : null],
            ["Verified Boot", b.verified_boot_label, vb],
            ["Déverrouillage OEM autorisé", yesNo(b.oem_unlock_allowed)],
          ]),
          kvCard("Intégrité du système", [
            ["SELinux", b.selinux, b.selinux ? (b.selinux.toLowerCase() === "enforcing" ? ["ok", "OK"] : ["fail", "Risque"]) : null],
            ["Type de build", b.build_type],
            ["Clés de signature", b.build_tags],
            ["Build débogable", yesNo(b.debuggable)],
            ["Binaire su (root)", b.su_binary || "Absent", b.su_binary ? ["fail", "Root"] : null],
          ])),
        findingsBlock(data.findings, "La chaîne de démarrage ne présente pas de faiblesse détectable."),
        limitationsCard(data.limitations),
      ];
    }),
  });

  // ================================================================ UPDATES
  LMS.registerView("updates", {
    title: "Mises à jour",
    onEnter: () => loadSection($("#updates-content"), "/api/updates", (data) => {
      const u = data.updates;
      const age = u.security_patch_age_days;
      const badge = age === null ? null : age <= 31 ? ["ok", u.status] : age <= 90 ? ["info", u.status] : age <= 180 ? ["warn", u.status] : ["fail", u.status];
      return [
        kvCard("Version et correctifs", [
          ["Android", u.android_version],
          ["SDK", u.sdk_version],
          ["Version encore maintenue", yesNo(u.supported_android)],
          ["Correctif de sécurité", u.security_patch ? u.security_patch + (age !== null ? " (il y a " + age + " jours)" : "") : null, badge],
          ["Correctif fournisseur", u.vendor_security_patch],
        ], el("p", { class: "muted small", text: u.update_check })),
        findingsBlock(data.findings, "Le téléphone dispose de correctifs de sécurité récents."),
      ];
    }),
  });
})();

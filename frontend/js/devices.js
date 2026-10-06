/* LUNATIC MOBILE SECURITY - "Appareils" view.
 *
 * Lists devices seen by ADB and Fastboot with a plain-language status and
 * the action to take, and shows the read-only details of the selected device.
 * Only the masked serial and the opaque device_id ever reach the browser.
 */
"use strict";

(() => {
  const { api, el, errorBox, notifyError, toast, confirmDialog, formatBytes, state } = LMS;
  const $ = (selector) => document.querySelector(selector);
  const POLL_MS = 3000;
  let timer = null;
  let detailsFor = null;
  let loading = false;

  const PHONE_ICON = () => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M16 1H8a3 3 0 0 0-3 3v16a3 3 0 0 0 3 3h8a3 3 0 0 0 3-3V4a3 3 0 0 0-3-3Zm1 19a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v16Zm-5-2.5a1.25 1.25 0 1 0 0-2.5 1.25 1.25 0 0 0 0 2.5Z");
    svg.append(path);
    return svg;
  };

  const STATE_BADGE = {
    device: ["ok", "Prêt"],
    fastboot: ["ok", "Fastboot"],
    unauthorized: ["warn", "Non autorisé"],
    offline: ["fail", "Hors ligne"],
    no_permissions: ["fail", "Accès USB refusé"],
    authorizing: ["info", "Autorisation…"],
    connecting: ["info", "Connexion…"],
    recovery: ["info", "Recovery"],
    sideload: ["info", "Sideload"],
    rescue: ["info", "Rescue"],
    bootloader: ["info", "Bootloader"],
    unknown: ["warn", "Inconnu"],
  };

  // --------------------------------------------------------------- listing
  function deviceItem(device) {
    const [kind, label] = STATE_BADGE[device.state] || STATE_BADGE.unknown;
    const title = device.model_hint || device.codename_hint || device.product_hint
      || (device.transport === "fastboot" ? "Appareil en mode Fastboot" : "Appareil Android");
    const selected = state.selectedDeviceId === device.device_id;
    const actions = el("div", { class: "device-actions" },
      el("span", { class: "badge " + kind, text: label }));
    if (device.ready) {
      actions.append(el("button", {
        class: "btn " + (selected ? "btn-primary" : ""),
        type: "button",
        text: selected ? "Sélectionné" : "Sélectionner",
        onclick: () => selectDevice(device.device_id),
      }));
    }
    return el("div", { class: "device-item" + (selected ? " selected" : "") },
      el("div", { class: "device-icon" }, PHONE_ICON()),
      el("div", {},
        el("div", { class: "device-title", text: title }),
        el("div", { class: "device-meta" },
          el("span", { class: "chip", text: device.transport === "fastboot" ? "Fastboot" : "ADB" }),
          el("span", { class: "chip", text: "N° " + device.serial_masked }),
          device.codename_hint ? el("span", { class: "chip", text: device.codename_hint }) : null,
          device.usb ? el("span", { class: "chip", text: "USB " + device.usb }) : null),
        el("div", { class: "check-detail", text: device.message }),
        device.action ? el("div", { class: "check-action", text: device.action }) : null),
      actions);
  }

  function emptyState(message) {
    const wrap = el("div", { class: "empty-state" }, PHONE_ICON());
    wrap.append(el("div", { text: message }));
    wrap.append(el("ol", { class: "notes" },
      el("li", { text: "Activez les Options pour les développeurs : Paramètres › À propos du téléphone › touchez 7 fois « Numéro de build »." }),
      el("li", { text: "Activez « Débogage USB » dans Paramètres › Système › Options pour les développeurs." }),
      el("li", { text: "Branchez le téléphone avec un câble USB de données et acceptez l'autorisation sur l'écran." })));
    return wrap;
  }

  async function refresh() {
    if (loading) return;
    loading = true;
    const button = $("#devices-refresh");
    button.classList.add("loading");
    try {
      const status = await api.get("/api/device/status");
      $("#devices-message").textContent = status.message;
      const errors = [];
      if (status.adb_error) errors.push(errorBox(new LMS.ApiError(status.adb_error, 503)));
      if (status.fastboot_error) errors.push(errorBox(new LMS.ApiError(status.fastboot_error, 503)));
      $("#devices-errors").replaceChildren(...errors);

      const ids = status.devices.map((d) => d.device_id);
      if (state.selectedDeviceId && !ids.includes(state.selectedDeviceId)) {
        toast("Appareil déconnecté", "L'appareil sélectionné n'est plus détecté.", "warn");
        state.selectedDeviceId = null;
      }
      const ready = status.devices.filter((d) => d.ready);
      if (!state.selectedDeviceId && ready.length === 1) state.selectedDeviceId = ready[0].device_id;
      const selectedReady = ready.some((d) => d.device_id === state.selectedDeviceId);

      $("#device-list").replaceChildren(...(status.devices.length
        ? status.devices.map(deviceItem)
        : [emptyState("Aucun appareil détecté.")]));

      if (!selectedReady) {
        detailsFor = null;
        $("#device-details").replaceChildren();
      } else if (detailsFor !== state.selectedDeviceId) {
        loadDetails(state.selectedDeviceId);
      }
    } catch (error) {
      $("#devices-errors").replaceChildren(errorBox(error));
    } finally {
      loading = false;
      button.classList.remove("loading");
    }
  }

  function selectDevice(deviceId) {
    state.selectedDeviceId = deviceId;
    detailsFor = null;
    refresh();
  }

  // --------------------------------------------------------------- details
  const NA = "Non disponible";

  function prop(label, value, badge) {
    const missing = value === null || value === undefined || value === "";
    const dd = el("dd", { class: missing ? "na" : null });
    if (badge) dd.append(el("span", { class: "badge " + badge[0], text: badge[1] }), " ");
    dd.append(missing ? NA : String(value));
    return [el("dt", { text: label }), dd];
  }

  function yesNo(value, yes = "Oui", no = "Non") {
    return value === true ? yes : value === false ? no : null;
  }

  function section(title, rows, extra) {
    return el("div", { class: "card" },
      el("div", { class: "card-header" }, el("h3", { text: title })),
      el("dl", { class: "prop-list" }, ...rows.flat()),
      extra || null);
  }

  function patchBadge(days) {
    if (days === null || days === undefined) return null;
    if (days <= 62) return ["ok", "Récent"];
    if (days <= 120) return ["warn", days + " j"];
    return ["fail", days + " j"];
  }

  function renderDetails(d) {
    const boot = d.bootloader;
    const viaAdb = d.transport === "adb";
    const adbOnly = (row) => (viaAdb ? row : []);
    const lockBadge = boot.locked === true ? ["ok", "Verrouillé"] : boot.locked === false ? ["fail", "Déverrouillé"] : null;
    const vbBadge = { green: ["ok", "green"], yellow: ["ok", "yellow"], orange: ["fail", "orange"], red: ["fail", "red"] }[boot.verified_boot_state] || null;
    const encBadge = d.encryption ? (d.encryption.state === "encrypted" ? ["ok", "OK"] : ["fail", "Risque"]) : null;

    const identity = section("Identité", [
      adbOnly(prop("Constructeur", d.manufacturer)),
      adbOnly(prop("Modèle", d.model, d.is_google_pixel ? ["info", "Google Pixel"] : null)),
      prop("Codename", d.codename),
      adbOnly(prop("Marque", d.brand)),
      prop("N° de série", d.serial_masked),
      prop("Connexion", d.transport === "fastboot" ? "Fastboot (bootloader)" : "ADB"),
    ]);
    const system = section("Système", [
      adbOnly([
        prop("Android", d.android_version),
        prop("SDK", d.sdk_version),
        prop("Build", d.build_id),
        prop("Build affiché", d.build_display),
        prop("Type de build", d.build_type ? d.build_type + (d.build_tags ? " / " + d.build_tags : "") : null),
        prop("Patch de sécurité", d.security_patch, patchBadge(d.security_patch_age_days)),
      ].flat()),
      prop("Slot actif", d.current_slot),
    ]);
    const security = section("Sécurité", [
      prop("Bootloader", boot.locked === null ? null : "lu via " + (boot.source === "fastboot" ? "Fastboot" : "ADB"), lockBadge),
      adbOnly([
        prop("Verified Boot", boot.verified_boot_label, vbBadge),
        prop("Déverrouillage OEM autorisé", yesNo(boot.oem_unlock_allowed)),
        prop("Chiffrement", d.encryption ? d.encryption.label : null, encBadge),
      ].flat()),
      prop("Intégrité", d.integrity),
      adbOnly([
        prop("ADB activé", yesNo(d.adb_enabled), d.adb_enabled ? ["warn", "Actif"] : null),
        prop("Débogage USB", yesNo(d.usb_debugging, "Actif (connexion autorisée)", "Inactif")),
        prop("Options développeur", yesNo(d.developer_options, "Activées", "Désactivées")),
      ].flat()),
    ]);

    let storageExtra = null;
    if (d.storage) {
      const pct = Math.round((d.storage.used_bytes / d.storage.total_bytes) * 100);
      const bar = el("span");
      bar.style.width = pct + "%";
      storageExtra = el("div", { class: "modal-section" },
        el("div", { class: "muted small", text: "Stockage /data utilisé : " + pct + " %" }),
        el("div", { class: "meter" }, bar));
    }
    const hardware = section("Matériel", [
      adbOnly([
        prop("Stockage total", d.storage ? formatBytes(d.storage.total_bytes) : null),
        prop("Stockage libre", d.storage ? formatBytes(d.storage.free_bytes) : null),
        prop("Batterie", d.battery && d.battery.level !== null ? d.battery.level + " %" + (d.battery.status ? " — " + d.battery.status : "") : null),
        prop("Santé batterie", d.battery ? d.battery.health : null),
        prop("Température", d.battery && d.battery.temperature_c !== null ? d.battery.temperature_c + " °C" : null),
      ].flat()),
      prop("Version bootloader", d.bootloader_version),
      prop("Version baseband", d.baseband_version),
    ], storageExtra);

    const notes = d.unavailable.length
      ? el("div", { class: "card" },
        el("div", { class: "card-header" }, el("h3", { text: "Limites de l'analyse" })),
        el("ul", { class: "notes" }, ...d.unavailable.map((n) => el("li", { text: n }))))
      : null;

    $("#device-details").replaceChildren(
      el("div", { class: "detail-grid" }, identity, system, security, hardware),
      notes ? el("div", { class: "modal-section" }, notes) : null);
  }

  async function loadDetails(deviceId) {
    detailsFor = deviceId;
    $("#device-details").replaceChildren(el("div", { class: "card muted", text: "Lecture des informations de l'appareil…" }));
    try {
      const details = await api.get("/api/device?device_id=" + encodeURIComponent(deviceId));
      if (detailsFor === deviceId) renderDetails(details);
    } catch (error) {
      if (detailsFor === deviceId) $("#device-details").replaceChildren(el("div", { class: "card" }, errorBox(error)));
    }
  }

  // --------------------------------------------------------------- actions
  async function restartAdb() {
    const ok = await confirmDialog({
      title: "Redémarrer le serveur ADB",
      before: "Le serveur ADB local est en cours d'exécution.",
      after: "Le serveur est arrêté puis relancé ; les appareils sont détectés à nouveau.",
      risk: "Les autres programmes utilisant ADB sur cet ordinateur (Android Studio, scrcpy…) seront déconnectés. Aucune donnée du téléphone n'est modifiée.",
      confirmLabel: "Redémarrer",
    });
    if (!ok) return;
    const button = $("#adb-restart");
    button.disabled = true;
    try {
      await api.post("/api/device/adb/restart-server");
      toast("Serveur ADB redémarré", "Détection des appareils relancée.", "ok");
      detailsFor = null;
      await refresh();
    } catch (error) {
      notifyError(error);
    } finally {
      button.disabled = false;
    }
  }

  function startPolling() {
    stopPolling();
    if ($("#devices-auto").checked) timer = setInterval(refresh, POLL_MS);
  }
  function stopPolling() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  $("#devices-refresh").addEventListener("click", () => { detailsFor = null; refresh(); });
  $("#devices-auto").addEventListener("change", startPolling);
  $("#adb-restart").addEventListener("click", restartAdb);

  LMS.registerView("devices", {
    title: "Appareils",
    onEnter: () => { detailsFor = null; refresh(); startPolling(); },
    onLeave: stopPolling,
  });
})();

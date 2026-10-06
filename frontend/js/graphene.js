/* LUNATIC MOBILE SECURITY - GrapheneOS view (compatibility and official releases).
 *
 * Every piece of release information comes live from releases.grapheneos.org
 * through the backend; the compatibility verdict is computed from what is read
 * on the connected phone and on this computer.
 */
"use strict";

(() => {
  const { api, el, errorBox, formatBytes, state, confirmDialog, toast, notifyError } = LMS;
  let pollTimer = null;
  const $ = (selector) => document.querySelector(selector);
  const STATUS_SYMBOL = { ok: "✓", warn: "!", fail: "✗", info: "i" };
  const STATUS_LABEL = { ok: "OK", warn: "Attention", fail: "Bloquant", info: "Info" };

  function checkItem(c) {
    return el("li", { class: "check-item" },
      el("span", { class: "check-icon " + c.status, text: STATUS_SYMBOL[c.status] || "?" }),
      el("div", {},
        el("div", { class: "check-label", text: c.label }),
        el("div", { class: "check-detail", text: c.detail }),
        c.action && c.status !== "ok" ? el("div", { class: "check-action", text: c.action }) : null),
      el("span", { class: "badge " + c.status, text: STATUS_LABEL[c.status] || c.status }));
  }

  function renderRelease(release) {
    if (!release) {
      $("#graphene-release").replaceChildren();
      return;
    }
    $("#graphene-release").replaceChildren(el("div", { class: "card" },
      el("div", { class: "card-header" },
        el("h3", { text: "Version officielle pour " + release.model }),
        el("span", { class: "badge info", text: "Canal " + release.channel })),
      el("div", { class: "release-grid" },
        el("div", {}, el("div", { class: "stat-label", text: "VERSION" }), el("div", { class: "stat-value", text: release.version })),
        el("div", {}, el("div", { class: "stat-label", text: "DATE DE COMPILATION" }), el("div", { class: "stat-value", text: release.build_date })),
        el("div", {}, el("div", { class: "stat-label", text: "PUBLIÉE" }), el("div", { class: "stat-value", text: release.published_at ? new Date(release.published_at).toLocaleDateString() : "—" })),
        el("div", {}, el("div", { class: "stat-label", text: "TAILLE DE L'IMAGE" }), el("div", { class: "stat-value", text: release.size_bytes ? formatBytes(release.size_bytes) : "—" }))),
      el("ul", { class: "url-list" },
        el("li", { text: "Image d'installation : " + release.install_url }),
        el("li", { text: "Signature : " + release.signature_url }),
        el("li", { text: "Clé de signature : " + release.allowed_signers_url }),
        el("li", { text: "Métadonnées : " + release.source })),
      el("p", { class: "muted small", text: "Ces fichiers seront téléchargés depuis ces adresses officielles uniquement, puis vérifiés (SHA-256 et signature GrapheneOS) avant toute utilisation." }),
      el("div", { class: "hero-actions" },
        el("button", { type: "button", class: "btn btn-primary", text: "Télécharger et vérifier", onclick: () => startDownload(release) }))));
  }

  // ------------------------------------------------- download + verification
  function setPipeline(phase, state) {
    const order = ["download", "verification", "ready"];
    const index = order.indexOf(phase);
    document.querySelectorAll("#pipeline-steps li").forEach((li, i) => {
      li.className = "";
      if (state === "failed" && i === index) li.className = "failed";
      else if (i < index || (state === "completed" && phase === "ready")) li.className = "done";
      else if (i === index && state === "running") li.className = "active";
    });
  }

  function renderStatus(s) {
    if (!s || s.state === "idle") return;
    $("#graphene-pipeline").hidden = false;
    $("#pipeline-title").textContent = (s.kind === "verify" ? "Vérification" : "Téléchargement officiel") + " — " + (s.model || s.codename) + " " + s.version;
    $("#pipeline-cancel").hidden = s.state !== "running";
    let phase = s.phase;
    if (s.state === "completed") phase = "ready";
    setPipeline(phase, s.state);
    let pct = 0;
    if (phase === "download" && s.bytes_total) pct = (s.bytes_done / s.bytes_total) * 100;
    if (phase === "verification" && s.bytes_total) pct = ((s.verify_done || 0) / s.bytes_total) * 100;
    if (s.state === "completed") pct = 100;
    $("#pipeline-bar").style.width = Math.round(pct) + "%";
    if (s.state === "running") {
      $("#pipeline-info").textContent = phase === "download"
        ? formatBytes(s.bytes_done) + " / " + formatBytes(s.bytes_total) + (s.speed_bps ? " · " + formatBytes(s.speed_bps) + "/s" : "") + (s.eta_seconds ? " · reste ~" + s.eta_seconds + " s" : "") + (s.resumed_from ? " · reprise à " + formatBytes(s.resumed_from) : "")
        : "Calcul SHA-256 / SHA-512 et vérification de la signature GrapheneOS… " + formatBytes(s.verify_done || 0) + " / " + formatBytes(s.bytes_total);
      $("#pipeline-result").replaceChildren();
      return;
    }
    $("#pipeline-info").textContent = s.elapsed_seconds ? "Durée : " + s.elapsed_seconds + " s" : "";
    const steps = s.verification ? el("ul", { class: "verify-steps" }, ...s.verification.steps.map((x) =>
      el("li", { text: (x.ok ? "✓ " : "✗ ") + x.detail }))) : null;
    if (s.state === "completed") {
      $("#pipeline-result").replaceChildren(el("div", { class: "harden-result ok" },
        el("span", { class: "badge ok", text: "READY" }), " Image authentique et intègre, prête pour l'installation.",
        steps, el("div", { class: "mono-hash", text: "SHA-256 " + s.verification.sha256 })));
    } else if (s.result === "verification_failed") {
      $("#pipeline-result").replaceChildren(el("div", { class: "blocked-banner", role: "alert" },
        el("strong", { text: "VERIFICATION FAILED — INSTALLATION BLOCKED" }),
        el("div", { text: s.error.cause }), el("div", { class: "muted small", text: s.error.action }), steps));
    } else if (s.state === "failed" || s.state === "cancelled") {
      $("#pipeline-result").replaceChildren(errorBox(new LMS.ApiError(s.error, 500)),
        el("p", { class: "muted small", text: "Le fichier partiel est conservé : relancez pour reprendre où le téléchargement s'est arrêté." }));
    }
  }

  async function poll() {
    try {
      const s = await api.get("/api/graphene/download/status");
      renderStatus(s);
      if (s.state !== "running") {
        clearInterval(pollTimer);
        pollTimer = null;
        loadImages();
        if (s.state === "completed") toast("Image GrapheneOS vérifiée", s.codename + " " + s.version, "ok");
        if (s.result === "verification_failed") toast("Vérification échouée", "Installation bloquée", "fail", 12000);
      }
    } catch (error) {
      clearInterval(pollTimer);
      pollTimer = null;
      notifyError(error);
    }
  }

  function startPolling() {
    if (!pollTimer) pollTimer = setInterval(poll, 600);
  }

  async function startDownload(release) {
    const ok = await confirmDialog({
      title: "Télécharger GrapheneOS " + release.version,
      before: "Aucune image GrapheneOS vérifiée pour " + release.model + " sur cet ordinateur.",
      after: "Téléchargement de " + (release.size_bytes ? formatBytes(release.size_bytes) : "l'image") + " depuis releases.grapheneos.org, puis vérification SHA-256 et signature GrapheneOS. Aucun changement sur le téléphone.",
      risk: "Utilise de la bande passante et environ 2,5 fois la taille de l'image sur le disque (décompression lors de l'installation). Un fichier invalide est supprimé automatiquement.",
      confirmLabel: "Télécharger",
    });
    if (!ok) return;
    try {
      renderStatus(await api.post("/api/graphene/download", { codename: release.codename, channel: release.channel }));
      startPolling();
    } catch (error) {
      notifyError(error);
    }
  }

  async function loadImages() {
    try {
      const data = await api.get("/api/graphene/images");
      const label = { ready: ["ok", "Vérifiée"], partial: ["warn", "Partielle"], unverified: ["warn", "Non vérifiée"], empty: ["neutral", "Vide"] };
      $("#graphene-images").replaceChildren(...(data.images.length ? data.images.map((img) => {
        const [kind, text] = label[img.status] || ["neutral", img.status];
        const actions = el("td", {});
        if (img.status === "ready" || img.status === "unverified") {
          actions.append(el("button", { type: "button", class: "btn", text: "Revérifier", onclick: async () => {
            try {
              renderStatus(await api.post("/api/graphene/verify", { codename: img.codename, version: img.version }));
              startPolling();
            } catch (error) { notifyError(error); }
          } }), " ");
        }
        actions.append(el("button", { type: "button", class: "btn", text: "Supprimer", onclick: async () => {
          const ok = await confirmDialog({
            title: "Supprimer l'image " + img.codename + " " + img.version,
            before: "Fichiers présents sur cet ordinateur (" + formatBytes(img.size || 0) + ").",
            after: "Les fichiers sont supprimés de l'ordinateur ; ils pourront être téléchargés de nouveau.",
            risk: "Aucun impact sur le téléphone.", confirmLabel: "Supprimer", danger: true,
          });
          if (!ok) return;
          try {
            await api.post("/api/graphene/images/delete", { codename: img.codename, version: img.version });
            loadImages();
          } catch (error) { notifyError(error); }
        } }));
        return el("tr", {},
          el("td", {}, el("div", { class: "app-name", text: img.codename + "-install-" + img.version + ".zip" }), el("div", { class: "muted small", text: formatBytes(img.size || 0) })),
          el("td", {}, el("span", { class: "badge " + kind, text: text }), img.verified_at ? el("div", { class: "muted small", text: new Date(img.verified_at).toLocaleString() }) : null),
          el("td", { class: "mono-hash", text: img.sha256 || "—" }),
          actions);
      }) : [el("tr", {}, el("td", { colspan: 4, class: "muted", text: "Aucune image téléchargée." }))]));
    } catch (error) {
      $("#graphene-images").replaceChildren(el("tr", {}, el("td", { colspan: 4 }, errorBox(error))));
    }
  }

  async function checkCompatibility() {
    const button = $("#graphene-check");
    button.disabled = true;
    $("#graphene-result").replaceChildren(el("p", { class: "muted", text: "Lecture du téléphone et interrogation de releases.grapheneos.org…" }));
    $("#graphene-release").replaceChildren();
    try {
      const params = new URLSearchParams({ channel: $("#graphene-channel").value });
      if (state.selectedDeviceId) params.set("device_id", state.selectedDeviceId);
      const r = await api.get("/api/graphene/compatibility?" + params);
      const kind = r.compatible ? (r.ready_to_prepare ? "ok" : "warn") : "fail";
      $("#graphene-result").replaceChildren(
        el("div", { class: "compat-head" },
          el("span", { class: "badge " + kind, text: r.compatible ? (r.ready_to_prepare ? "Compatible" : "Compatible — prérequis manquants") : "Non compatible" }),
          el("span", { class: "compat-model", text: (r.model || "Appareil") + (r.codename ? " (" + r.codename + ")" : "") }),
          el("span", { class: "chip", text: (r.transport === "fastboot" ? "Fastboot" : "ADB") + " · N° " + r.serial_masked })),
        el("p", { text: r.summary }),
        el("ul", { class: "check-list" }, ...r.checks.map(checkItem)),
        el("p", { class: "muted small", text: "Liste des appareils : grapheneos.org au " + r.catalog_date + " ; versions vérifiées en direct sur releases.grapheneos.org." }));
      renderRelease(r.release);
    } catch (error) {
      $("#graphene-result").replaceChildren(errorBox(error));
    } finally {
      button.disabled = false;
    }
  }

  async function loadCatalog() {
    $("#graphene-devices").replaceChildren(el("tr", {}, el("td", { colspan: 4, class: "muted", text: "Interrogation de releases.grapheneos.org…" })));
    try {
      const data = await api.get("/api/graphene/releases");
      $("#graphene-source").textContent = data.error ? "" : "Source : " + data.source;
      const rows = data.devices.map((d) => {
        const support = d.months_left < 0 ? ["warn", "terminé"] : d.months_left === 0 ? ["warn", "ce mois-ci"]
          : d.months_left <= 6 ? ["warn", "dans " + d.months_left + " mois"] : ["ok", ""];
        return el("tr", {},
          el("td", { text: d.model }),
          el("td", { class: "mono", text: d.codename }),
          el("td", { class: "mono", text: d.stable || "—" }),
          el("td", {}, d.oem_support_end + " ", support[1] ? el("span", { class: "badge " + support[0], text: support[1] }) : null));
      });
      $("#graphene-devices").replaceChildren(...(data.error ? [el("tr", {}, el("td", { colspan: 4 }, errorBox(new LMS.ApiError(data.error, 502))))] : []), ...rows);
    } catch (error) {
      $("#graphene-devices").replaceChildren(el("tr", {}, el("td", { colspan: 4 }, errorBox(error))));
    }
  }

  $("#graphene-check").addEventListener("click", checkCompatibility);
  $("#images-refresh").addEventListener("click", loadImages);
  $("#pipeline-cancel").addEventListener("click", async () => {
    try { await api.post("/api/graphene/download/cancel"); } catch (error) { notifyError(error); }
  });
  LMS.registerView("graphene", {
    title: "GrapheneOS",
    onEnter: async () => {
      loadCatalog();
      loadImages();
      const s = await api.get("/api/graphene/download/status").catch(() => null);
      if (s && s.state !== "idle") {
        renderStatus(s);
        if (s.state === "running") startPolling();
      }
    },
  });
})();

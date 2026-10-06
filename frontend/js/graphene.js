/* LUNATIC MOBILE SECURITY - GrapheneOS view (compatibility and official releases).
 *
 * Every piece of release information comes live from releases.grapheneos.org
 * through the backend; the compatibility verdict is computed from what is read
 * on the connected phone and on this computer.
 */
"use strict";

(() => {
  const { api, el, errorBox, formatBytes, state } = LMS;
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
      el("p", { class: "muted small", text: "Ces fichiers seront téléchargés depuis ces adresses officielles uniquement, puis vérifiés (SHA-256 et signature GrapheneOS) avant toute utilisation." })));
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
  LMS.registerView("graphene", { title: "GrapheneOS", onEnter: loadCatalog });
})();

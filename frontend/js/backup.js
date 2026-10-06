/* LUNATIC MOBILE SECURITY - Backup view.
 *
 * Backs up only what Android lets ADB read (shared storage, third-party APKs),
 * shows what cannot be backed up, and reports a backup as "verified" only when
 * every file's SHA-256 computed on the phone matches the copy on the computer.
 */
"use strict";

(() => {
  const { api, el, errorBox, notifyError, toast, confirmDialog, formatBytes, state } = LMS;
  const $ = (selector) => document.querySelector(selector);
  const FOLDER_LABELS = {
    DCIM: "Photos et vidéos (DCIM)", Pictures: "Images", Movies: "Vidéos", Music: "Musique", Documents: "Documents",
    Download: "Téléchargements", Recordings: "Enregistrements", Podcasts: "Podcasts", Audiobooks: "Livres audio",
    Ringtones: "Sonneries", Alarms: "Alarmes", Notifications: "Sons de notification",
  };
  let estimate = null;
  let pollTimer = null;
  let freeBytes = null;

  const deviceQuery = () => (state.selectedDeviceId ? "?device_id=" + encodeURIComponent(state.selectedDeviceId) : "");

  // ------------------------------------------------------------ selection
  function selectedFolders() {
    return [...document.querySelectorAll("#backup-folders input:checked")].map((i) => i.value);
  }

  function updateSummary() {
    if (!estimate) return;
    const total = estimate.folders.filter((f) => selectedFolders().includes(f.name)).reduce((sum, f) => sum + (f.bytes || 0), 0);
    $("#backup-selected-size").textContent = formatBytes(total) + ($("#backup-apks").checked ? " + APK" : "");
    $("#backup-free").textContent = freeBytes === null ? "?" : formatBytes(freeBytes);
    $("#backup-free").className = freeBytes !== null && freeBytes < total * 1.05 ? "text-fail" : "";
  }

  async function loadEstimate() {
    $("#backup-folders").replaceChildren(el("p", { class: "muted", text: "Lecture du stockage du téléphone…" }));
    try {
      estimate = await api.get("/api/backup/estimate" + deviceQuery());
      $("#backup-folders").replaceChildren(...estimate.folders.map((f) =>
        el("label", { class: "folder-row" + (f.exists && f.bytes ? "" : " disabled") },
          el("input", {
            type: "checkbox", value: f.name, disabled: !(f.exists && f.bytes),
            checked: Boolean(f.exists && f.bytes) && ["DCIM", "Pictures", "Documents", "Download", "Recordings"].includes(f.name),
            onchange: updateSummary,
          }),
          el("span", {}, FOLDER_LABELS[f.name] || f.name, " ", el("span", { class: "muted small", text: "/" + f.name })),
          el("span", { class: "folder-size", text: f.exists ? (f.bytes ? f.label : "vide") : "absent" }))));
      $("#backup-apk-count").textContent = "(" + estimate.third_party_apps + " application(s))";
      $("#backup-not-possible").replaceChildren(...estimate.not_backed_up.map((t) => el("li", { text: t })));
      updateSummary();
    } catch (error) {
      estimate = null;
      $("#backup-folders").replaceChildren(errorBox(error));
    }
  }

  // ----------------------------------------------------------- destination
  async function browse(path) {
    const box = $("#backup-browser");
    try {
      const data = await api.get("/api/backup/browse" + (path ? "?path=" + encodeURIComponent(path) : ""));
      box.replaceChildren(
        el("div", { class: "dir-head" },
          data.parent ? el("button", { type: "button", class: "btn", text: "↑", "aria-label": "Dossier parent", onclick: () => browse(data.parent) }) : null,
          el("span", { text: data.path }),
          el("button", { type: "button", class: "btn btn-primary", text: "Choisir ce dossier", disabled: !data.writable,
            onclick: () => { setDestination(data.path, data.free_bytes); box.hidden = true; } })),
        ...(data.directories.length
          ? data.directories.map((name) => el("button", { type: "button", class: "dir-entry", text: name,
            onclick: () => browse(data.path.replace(/[\\/]$/, "") + (data.path.includes("\\") ? "\\" : "/") + name) }))
          : [el("p", { class: "muted small", text: "  Aucun sous-dossier." })]));
      if (!$("#backup-dest").value) setDestination(data.default, null);
    } catch (error) {
      box.replaceChildren(errorBox(error));
    }
  }

  async function setDestination(path, free) {
    $("#backup-dest").value = path;
    freeBytes = free;
    if (free === null || free === undefined) {
      try {
        freeBytes = (await api.get("/api/backup/browse?path=" + encodeURIComponent(path))).free_bytes;
      } catch {
        freeBytes = null;
      }
    }
    updateSummary();
    loadList();
  }

  // ------------------------------------------------------------- backups
  async function loadList() {
    const dest = $("#backup-dest").value.trim();
    try {
      const data = await api.get("/api/backup/list" + (dest ? "?destination=" + encodeURIComponent(dest) : ""));
      $("#backup-list-dest").textContent = data.destination;
      $("#backup-list").replaceChildren(...(data.backups.length ? data.backups.map((b) => {
        const verifyBtn = el("button", { type: "button", class: "btn", text: "Vérifier l'intégrité" });
        const cell = el("td", {}, verifyBtn);
        verifyBtn.addEventListener("click", async () => {
          verifyBtn.disabled = true;
          verifyBtn.textContent = "Vérification…";
          try {
            const r = await api.post("/api/backup/verify", { path: b.path });
            cell.replaceChildren(el("span", { class: "badge " + (r.valid ? "ok" : "fail"), text: r.valid ? "Intègre" : "Altérée" }),
              el("div", { class: "muted small", text: r.files_ok + " fichier(s) OK" + (r.valid ? "" : " · " + r.mismatches.length + " modifié(s), " + r.missing.length + " manquant(s)") }));
            toast(r.valid ? "Sauvegarde intègre" : "Sauvegarde altérée", b.name, r.valid ? "ok" : "fail");
          } catch (error) {
            cell.replaceChildren(errorBox(error));
          }
        });
        return el("tr", {},
          el("td", {}, el("div", { class: "app-name", text: b.name }), el("div", { class: "muted small", text: b.created_at ? new Date(b.created_at).toLocaleString() : "" })),
          el("td", { text: [b.device.model, b.device.serial_masked].filter(Boolean).join(" · ") }),
          el("td", { text: (b.folders || []).join(", ") + (b.include_apks ? " + APK" : "") + " · " + b.files + " fichiers · " + formatBytes(b.bytes) }),
          el("td", {}, el("span", { class: "badge " + (b.status === "verified" ? "ok" : "warn"), text: b.status === "verified" ? "Vérifiée" : "Incomplète" })),
          cell);
      }) : [el("tr", {}, el("td", { colspan: 5, class: "muted", text: "Aucune sauvegarde dans ce dossier." }))]));
    } catch (error) {
      $("#backup-list").replaceChildren(el("tr", {}, el("td", { colspan: 5 }, errorBox(error))));
    }
  }

  // ----------------------------------------------------------------- run
  function renderProgress(s) {
    $("#backup-progress").hidden = false;
    $("#backup-bar").style.width = (s.progress || 0) + "%";
    $("#backup-step").textContent = s.step + "…";
    $("#backup-counters").textContent = formatBytes(s.bytes_done || 0) + " / ~" + formatBytes(s.bytes_total || 0)
      + " · " + (s.files_verified || 0) + " / " + (s.files_total || 0) + " fichier(s) vérifié(s)"
      + (s.elapsed_seconds ? " · " + s.elapsed_seconds + " s" : "");
  }

  function list(title, items) {
    return items && items.length
      ? el("div", { class: "modal-section" }, el("div", { class: "lbl", text: title + " (" + items.length + ")" }),
        el("ul", { class: "result-list" }, ...items.slice(0, 200).map((i) => el("li", { text: i }))))
      : null;
  }

  function renderResult(s) {
    $("#backup-progress").hidden = true;
    if (s.state === "completed") {
      const ok = s.result === "verified";
      $("#backup-result").replaceChildren(el("div", { class: "card" },
        el("div", { class: "card-header" },
          el("h3", { text: ok ? "Sauvegarde terminée et vérifiée" : "Sauvegarde terminée avec des anomalies" }),
          el("span", { class: "badge " + (ok ? "ok" : "warn"), text: ok ? "SHA-256 vérifié" : "Incomplète" })),
        el("p", { text: s.files_verified + " fichier(s) vérifié(s) sur " + s.files_total + " · " + formatBytes(s.bytes_done) + " · " + s.elapsed_seconds + " s" }),
        el("p", {}, "Dossier : ", el("code", { text: s.backup_path })),
        list("Fichiers différents après transfert (non certifiés)", s.mismatches),
        list("Fichiers manquants", s.missing),
        list("Fichiers apparus pendant la sauvegarde (non vérifiés)", s.changed_during_backup),
        list("Erreurs", s.errors),
        list("Remarques", s.notes)));
      toast(ok ? "Sauvegarde vérifiée" : "Sauvegarde incomplète", s.files_verified + " fichier(s) vérifié(s)", ok ? "ok" : "warn");
      loadList();
    } else if (s.state === "failed" || s.state === "cancelled") {
      $("#backup-result").replaceChildren(el("div", { class: "card" },
        el("div", { class: "card-header" }, el("h3", { text: s.state === "cancelled" ? "Sauvegarde annulée" : "Sauvegarde échouée" })),
        s.state === "failed" ? errorBox(new LMS.ApiError(s.error, 500)) : null,
        el("p", { class: "muted", text: s.partial_removed ? "Les fichiers partiellement copiés ont été supprimés." : "Aucun fichier partiel à nettoyer." })));
    }
    $("#backup-start").disabled = false;
  }

  async function poll() {
    try {
      const s = await api.get("/api/backup/status");
      if (s.state === "running") {
        renderProgress(s);
        return;
      }
      clearInterval(pollTimer);
      pollTimer = null;
      renderResult(s);
    } catch (error) {
      clearInterval(pollTimer);
      pollTimer = null;
      notifyError(error);
    }
  }

  async function start() {
    $("#backup-error").replaceChildren();
    const folders = selectedFolders();
    const apks = $("#backup-apks").checked;
    const destination = $("#backup-dest").value.trim();
    const ok = await confirmDialog({
      title: "Démarrer la sauvegarde",
      before: "Éléments sélectionnés : " + (folders.map((f) => FOLDER_LABELS[f] || f).join(", ") || "aucun dossier") + (apks ? " + APK des applications tierces" : "") + " (" + $("#backup-selected-size").textContent + ").",
      after: "Copie dans un nouveau sous-dossier de " + (destination || "la destination par défaut") + ", avec vérification SHA-256 de chaque fichier.",
      risk: "Lecture seule : rien n'est modifié ni supprimé sur le téléphone. Gardez-le branché et déverrouillé pendant la copie.",
      confirmLabel: "Démarrer",
    });
    if (!ok) return;
    try {
      const s = await api.post("/api/backup/start", { device_id: state.selectedDeviceId, folders, include_apks: apks, destination: destination || null });
      $("#backup-start").disabled = true;
      $("#backup-result").replaceChildren();
      renderProgress(s);
      if (!pollTimer) pollTimer = setInterval(poll, 700);
    } catch (error) {
      $("#backup-error").replaceChildren(errorBox(error));
    }
  }

  async function cancel() {
    const ok = await confirmDialog({
      title: "Annuler la sauvegarde",
      before: "Une sauvegarde est en cours.",
      after: "La copie est interrompue et les fichiers partiellement copiés sont supprimés de l'ordinateur.",
      risk: "Aucun impact sur le téléphone.",
      confirmLabel: "Annuler la sauvegarde",
      danger: true,
    });
    if (ok) {
      try {
        await api.post("/api/backup/cancel");
      } catch (error) {
        notifyError(error);
      }
    }
  }

  $("#backup-refresh").addEventListener("click", loadEstimate);
  $("#backup-apks").addEventListener("change", updateSummary);
  $("#backup-start").addEventListener("click", start);
  $("#backup-cancel").addEventListener("click", cancel);
  $("#backup-browse-toggle").addEventListener("click", () => {
    const box = $("#backup-browser");
    box.hidden = !box.hidden;
    if (!box.hidden) browse($("#backup-dest").value.trim() || null);
  });
  $("#backup-dest").addEventListener("change", () => setDestination($("#backup-dest").value.trim(), null));

  LMS.registerView("backup", {
    title: "Backup",
    onEnter: async () => {
      if (!$("#backup-dest").value) {
        try {
          const data = await api.get("/api/backup/browse");
          await setDestination(data.default, null);
        } catch (error) {
          notifyError(error);
        }
      } else {
        loadList();
      }
      loadEstimate();
      const s = await api.get("/api/backup/status").catch(() => null);
      if (s && s.state === "running") {
        $("#backup-start").disabled = true;
        renderProgress(s);
        if (!pollTimer) pollTimer = setInterval(poll, 700);
      }
    },
  });
})();

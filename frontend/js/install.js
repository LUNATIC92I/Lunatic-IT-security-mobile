/* LUNATIC MOBILE SECURITY - GrapheneOS installation wizard (13 steps).
 *
 * The server enforces the order of the steps; this view only shows the
 * current step, its explanation and the corresponding action. Destructive
 * actions always go through a confirmation dialog and are sent with
 * confirm: true. Fastboot output is displayed as-is, never hidden.
 */
"use strict";

(() => {
  const { api, el, errorBox, notifyError, toast, confirmDialog, state } = LMS;
  const $ = (selector) => document.querySelector(selector);
  let session = null;
  let pollTimer = null;
  let working = false;

  const p = (text, cls) => el("p", { class: cls || null, text });
  const phone = (text) => el("div", { class: "phone-instruction" }, el("strong", { text: "Sur le téléphone : " }), text);

  async function act(action, options = {}) {
    if (working) return;
    if (options.confirm) {
      const ok = await confirmDialog(options.confirm);
      if (!ok) return;
    }
    working = true;
    $("#install-error").replaceChildren();
    document.querySelectorAll("#install-panel button").forEach((b) => { b.disabled = true; });
    try {
      const data = await api.post("/api/graphene/install/action", { session_id: session.id, action, confirm: Boolean(options.confirm) });
      render(data);
      if (options.success) toast(options.success, "", "ok");
    } catch (error) {
      $("#install-error").replaceChildren(errorBox(error));
      await refresh();
    } finally {
      working = false;
      document.querySelectorAll("#install-panel button").forEach((b) => { b.disabled = false; });
    }
  }

  function button(label, onclick, cls = "btn-primary") {
    return el("button", { type: "button", class: "btn " + cls, text: label, onclick });
  }

  function stepStatus(id) {
    return (session.steps.find((s) => s.id === id) || {}).status || "pending";
  }

  function currentStep() {
    return session.steps.find((s) => s.status !== "done") || null;
  }

  // ------------------------------------------------------------ panels
  function panelConfirmation() {
    const loss = el("input", { type: "checkbox" });
    const backup = el("input", { type: "checkbox" });
    const phrase = el("input", { class: "input", placeholder: session.confirmation_phrase, autocomplete: "off", spellcheck: "false" });
    return [
      el("div", { class: "blocked-banner" }, el("strong", { text: "AVERTISSEMENT" }), el("div", { text: session.warning })),
      p("Le déverrouillage du bootloader, le flashage puis le verrouillage effacent chacun intégralement le téléphone : photos, messages, applications et comptes. Cette perte est définitive."),
      el("div", { class: "confirm-form" },
        el("label", {}, loss, "J'ai compris que toutes les données du téléphone seront définitivement effacées."),
        el("label", {}, backup, "J'ai sauvegardé les données que je souhaite conserver (ou je n'en ai pas besoin)."),
        el("label", {}, "Pour confirmer, saisissez exactement : ", el("code", { text: session.confirmation_phrase })),
        phrase,
        el("div", {}, button("Confirmer l'effacement", async () => {
          try {
            render(await api.post("/api/graphene/install/confirm", { session_id: session.id, phrase: phrase.value, data_loss_ack: loss.checked, backup_ack: backup.checked }));
          } catch (error) {
            $("#install-error").replaceChildren(errorBox(error));
          }
        }, "btn-danger"))),
    ];
  }

  function panelPrepare() {
    const partial = stepStatus("prepare") === "partial";
    return [
      p("Préparation selon la procédure officielle : activer le déverrouillage OEM, démarrer en mode Fastboot, puis déverrouiller le bootloader."),
      partial ? p("Le téléphone est en mode Fastboot.", "muted") : el("div", {},
        phone("Paramètres › À propos du téléphone : touchez 7 fois « Numéro de build ». Puis Paramètres › Système › Options pour les développeurs › activez « Déverrouillage OEM » (connexion Internet requise). Le débogage USB doit être autorisé."),
        button("Redémarrer en mode Fastboot", () => act("reboot_bootloader", {
          confirm: { title: "Redémarrer en mode Fastboot", before: "Téléphone démarré sous Android.", after: "Le téléphone redémarre sur l'écran « Fastboot Mode » (triangle rouge).", risk: "Aucune donnée n'est effacée à cette étape.", confirmLabel: "Redémarrer" },
        })),
        p("Si le téléphone est déjà sur l'écran « Fastboot Mode », passez directement au déverrouillage.", "muted small")),
      el("div", { class: "modal-section" },
        phone("Après avoir cliqué, l'écran du téléphone demande confirmation : sélectionnez « Unlock the bootloader » avec les touches de volume, puis validez avec le bouton marche. N'appuyez pas sur « Start »."),
        button("Déverrouiller le bootloader", () => act("unlock", {
          confirm: { title: "Déverrouiller le bootloader", before: "Bootloader verrouillé : seul le système d'origine peut démarrer.", after: "Bootloader déverrouillé : l'installation de GrapheneOS devient possible.", risk: "TOUTES LES DONNÉES DU TÉLÉPHONE SONT EFFACÉES. Le téléphone affichera un avertissement au démarrage tant qu'il ne sera pas reverrouillé (dernière étape).", question: "Voulez-vous continuer ? L'effacement est définitif.", confirmLabel: "Déverrouiller et effacer", danger: true },
          success: "Bootloader déverrouillé",
        }), "btn-danger")),
    ];
  }

  function panelImage() {
    return [
      p("Le logiciel vérifie que l'image officielle " + session.codename + " est présente puis la revérifie entièrement : signature GrapheneOS, SHA-256/SHA-512, contenu de l'archive et clé Verified Boot."),
      button("Vérifier l'image officielle", () => act("prepare_image", { success: "Image vérifiée" })),
      p("Si l'image n'est pas encore téléchargée : page GrapheneOS › « Vérifier le téléphone connecté » › « Télécharger et vérifier ».", "muted small"),
      el("a", { class: "link small", href: "#/graphene", text: "Ouvrir la page GrapheneOS →" }),
    ];
  }

  function panelFlash() {
    const nodes = [];
    if (stepStatus("flash") === "running") {
      return panelFlashing();
    }
    nodes.push(p("Contrôles préalables obligatoires avant tout flashage. Le flashage n'est possible que si TOUS les contrôles sont validés (valables 15 minutes, une seule utilisation)."));
    nodes.push(button("Lancer les contrôles préalables", () => act("preflight"), session.ready_to_install ? "" : "btn-primary"));
    if (session.preflight) {
      nodes.push(el("ul", { class: "preflight-list" }, ...session.preflight.map((c) =>
        el("li", {}, el("span", { class: c.ok ? "ok" : "ko", text: c.ok ? "✓" : "✗" }), el("span", {}, el("strong", { text: c.label }), " — " + c.detail)))));
    }
    if (session.ready_to_install) {
      nodes.push(el("div", { class: "ready-banner", text: "READY TO INSTALL" }));
      nodes.push(phone("Laissez le téléphone branché sur l'écran « Fastboot Mode » et ne touchez à rien pendant le flashage (plusieurs minutes, redémarrages automatiques du bootloader)."));
      nodes.push(button("Flasher GrapheneOS " + session.version, () => act("flash", {
        confirm: { title: "Flasher GrapheneOS " + session.version, before: "Bootloader déverrouillé, image officielle vérifiée, contrôles préalables validés.", after: "GrapheneOS est installé par le script officiel flash-all (micrologiciel puis système).", risk: "Le système actuel et toutes les données sont remplacés. Ne débranchez pas le téléphone pendant l'opération : une interruption oblige à recommencer le flashage.", question: "Voulez-vous continuer ?", confirmLabel: "Flasher maintenant", danger: true },
      }), "btn-danger"));
    }
    if (stepStatus("flash") === "failed") nodes.push(flashLog(true));
    return nodes;
  }

  function flashLog(failed) {
    const log = el("div", { class: "flash-log", role: "log" }, ...session.flash_log.map((line) =>
      el("div", { class: /FAILED|error|ÉCHEC|Error/.test(line) ? "err" : null, text: line })));
    setTimeout(() => { log.scrollTop = log.scrollHeight; }, 0);
    return el("div", {},
      failed ? el("div", { class: "blocked-banner" }, el("strong", { text: "FLASHAGE ÉCHOUÉ" }), el("div", { text: (session.steps.find((s) => s.id === "flash") || {}).detail || "" }),
        el("div", { class: "muted small", text: "Ne verrouillez pas le bootloader et ne redémarrez pas le téléphone : relancez les contrôles préalables puis le flashage. Sortie Fastboot complète ci-dessous." })) : null,
      log);
  }

  function panelFlashing() {
    const bar = el("span");
    bar.style.width = session.flash_progress + "%";
    return [
      el("p", {}, el("strong", { text: "Flashage en cours — ne débranchez pas le téléphone." })),
      el("div", { class: "progress" }, bar),
      el("p", { class: "scan-step" }, el("span", { class: "pulse-dot" }), (session.flash_stage || "Préparation") + "… " + session.flash_progress + " %"),
      flashLog(false),
    ];
  }

  function panelResult() {
    const partial = stepStatus("result") === "partial";
    const nodes = [p("Le script officiel s'est terminé sans erreur. Le logiciel relit les variables du bootloader, puis vous proposez de verrouiller le bootloader : c'est indispensable pour activer Verified Boot.")];
    if (!partial) nodes.push(button("Vérifier le résultat", () => act("verify_result")));
    nodes.push(el("div", { class: "modal-section" },
      phone("Après avoir cliqué, sélectionnez « Lock the bootloader » avec les touches de volume puis validez avec le bouton marche."),
      button("Verrouiller le bootloader", () => act("lock", {
        confirm: { title: "Verrouiller le bootloader", before: "GrapheneOS installé, bootloader déverrouillé (Verified Boot inactif).", after: "Bootloader verrouillé : Verified Boot protège le système à chaque démarrage.", risk: "Le verrouillage efface de nouveau les données (aucune n'a encore été créée sur GrapheneOS).", confirmLabel: "Verrouiller", danger: true },
        success: "Bootloader verrouillé",
      }), "btn-danger")));
    if (session.flash_log.length) nodes.push(flashLog(false));
    return nodes;
  }

  function panelSetup() {
    return [
      p("GrapheneOS est installé et le bootloader est verrouillé."),
      button("Démarrer GrapheneOS", () => act("reboot", { confirm: { title: "Démarrer GrapheneOS", before: "Téléphone en mode Fastboot.", after: "Le téléphone démarre sur GrapheneOS (avertissement jaune normal au démarrage).", risk: "Aucun.", confirmLabel: "Démarrer" } })),
      el("ul", { class: "notes" },
        el("li", { text: "Au démarrage, un écran jaune indique un système tiers : c'est normal. Il affiche l'empreinte de la clé à comparer à l'étape suivante." }),
        el("li", { text: "Dans l'assistant de configuration, laissez cochée l'option qui DÉSACTIVE le déverrouillage OEM (dernier écran)." }),
        el("li", { text: "Choisissez un code PIN robuste (6 chiffres minimum) ou une phrase de passe." })),
    ];
  }

  function panelPostCheck() {
    return [
      p("Vérification de l'installation. Comparez l'empreinte affichée en jaune au démarrage avec l'empreinte officielle de votre modèle :"),
      el("pre", { class: "mono-hash", text: session.expected_key_hash || "—" }),
      p("Vérification automatique (optionnelle) : activez temporairement le débogage USB dans GrapheneOS, branchez le téléphone, autorisez l'ordinateur, puis cliquez. Le logiciel contrôle Verified Boot (yellow), le verrouillage du bootloader et le modèle."),
      button("Vérifier l'état de sécurité", () => act("post_check", { success: "Installation vérifiée" })),
      p("Pour une attestation matérielle complète, utilisez l'application officielle Auditor de GrapheneOS. Pensez ensuite à désactiver le débogage USB.", "muted small"),
    ];
  }

  function panelDone() {
    return [el("div", { class: "ready-banner", text: "INSTALLATION TERMINÉE ET VÉRIFIÉE" }),
      p("Désactivez le débogage USB et les options pour les développeurs dans GrapheneOS. Vous pouvez lancer une analyse de sécurité complète avant de les désactiver.")];
  }

  const PANELS = {
    confirmation: panelConfirmation,
    tools: () => [p("Vérification d'adb et de fastboot sur cet ordinateur (fastboot 35.0.1 minimum)."), button("Vérifier ADB / Fastboot", () => act("tools"))],
    prepare: panelPrepare,
    download: panelImage,
    verify: panelImage,
    flash: panelFlash,
    result: panelResult,
    setup: panelSetup,
    post_check: panelPostCheck,
  };

  // ------------------------------------------------------------ render
  function render(data) {
    session = data && data.session !== undefined ? data.session : data;
    const started = Boolean(session);
    $("#install-start-panel").hidden = started;
    $("#install-layout").hidden = !started;
    $("#install-abandon").hidden = !started;
    if (!started) return;
    const current = currentStep();
    $("#install-steps").replaceChildren(...session.steps.map((s) =>
      el("li", { class: s.status === "done" ? "done" : s === current ? "current " + s.status : s.status },
        el("span", {}, s.label, s.detail ? el("span", { class: "step-detail", text: s.detail }) : null))));
    const builder = current ? PANELS[current.id] : panelDone;
    const title = current ? current.label : "Terminé";
    $("#install-panel").replaceChildren(el("div", { class: "card" },
      el("div", { class: "card-header" }, el("h3", { text: title }), el("span", { class: "chip", text: session.model + " · " + session.codename + " · N° " + session.serial_masked })),
      ...(builder ? builder() : [])));
    const flashing = session.busy === "flash" || stepStatus("flash") === "running";
    if (flashing && !pollTimer) pollTimer = setInterval(refresh, 1000);
    if (!flashing && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
      if (stepStatus("flash") === "done") toast("Flashage terminé", "Script officiel terminé sans erreur", "ok");
      if (stepStatus("flash") === "failed") toast("Flashage échoué", "Voir la sortie Fastboot", "fail", 12000);
    }
  }

  function stopPolling() {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  async function refresh() {
    try {
      render(await api.get("/api/graphene/install/status"));
    } catch (error) {
      // One message, not one per second: polling resumes when the page is opened again.
      stopPolling();
      notifyError(error);
    }
  }

  $("#install-start").addEventListener("click", async () => {
    $("#install-error").replaceChildren();
    $("#install-start").disabled = true;
    try {
      render(await api.post("/api/graphene/install", { device_id: state.selectedDeviceId, channel: $("#install-channel").value }));
    } catch (error) {
      $("#install-error").replaceChildren(errorBox(error));
    } finally {
      $("#install-start").disabled = false;
    }
  });
  $("#install-abandon").addEventListener("click", async () => {
    const ok = await confirmDialog({ title: "Abandonner l'assistant", before: "Session d'installation en cours.", after: "La session est fermée ; il faudra recommencer depuis l'étape 1.", risk: "Si le bootloader a déjà été déverrouillé, le téléphone reste déverrouillé : ne l'utilisez pas en l'état.", confirmLabel: "Abandonner", danger: true });
    if (!ok) return;
    try {
      render(await api.post("/api/graphene/install/abandon", { session_id: session.id }));
    } catch (error) {
      notifyError(error);
    }
  });

  // Leaving the page never affects the flash itself (it runs on the server); coming back resumes the display.
  LMS.registerView("install", { title: "Installation GrapheneOS", onEnter: refresh, onLeave: stopPolling });
})();

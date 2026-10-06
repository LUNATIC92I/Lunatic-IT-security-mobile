/* LUNATIC MOBILE SECURITY - security hardening assistant.
 *
 * Shows each proposed change as [AVANT] / [APRÈS] / [RISQUE], asks for an
 * explicit confirmation, applies ONE change at a time and displays the
 * verification read back from the phone. A change is reported as successful
 * only when the server says "verified".
 */
"use strict";

(() => {
  const { api, el, errorBox, notifyError, toast, confirmDialog, state } = LMS;
  const $ = (selector) => document.querySelector(selector);
  const GROUPS = { permissions: "Applications et permissions", network: "Réseau", system: "Système" };
  const STATUS_SYMBOL = { ok: "✓", warn: "!", fail: "✗", info: "i" };
  const STATUS_LABEL = { ok: "OK", warn: "À vérifier", fail: "Risque", info: "Info" };
  let busy = false;

  function block(label, text, cls = "") {
    return el("div", { class: cls }, el("div", { class: "lbl", text: label }), el("div", { text }));
  }

  function itemCard(item) {
    const button = el("button", {
      type: "button",
      class: "btn " + (item.ends_adb_session ? "btn-danger" : "btn-primary"),
      text: "Appliquer…",
    });
    const resultBox = el("div");
    const card = el("div", { class: "card harden-item" },
      el("div", { class: "card-header" },
        el("h3", { text: item.title + (item.target ? " — " + item.target : "") }),
        item.ends_adb_session ? el("span", { class: "badge fail", text: "À faire en dernier" }) : null),
      el("div", { class: "ba" }, block("AVANT", item.before), block("APRÈS", item.after)),
      block("RISQUE", item.risk, "risk"),
      el("div", { class: "harden-foot" },
        el("span", { class: "muted small", text: "Pour revenir en arrière : " + item.revert }),
        button),
      resultBox);
    button.addEventListener("click", () => applyItem(item, button, card, resultBox));
    return card;
  }

  async function applyItem(item, button, card, resultBox) {
    if (busy) return;
    const confirmed = await confirmDialog({
      title: item.title + (item.target ? " — " + item.target : ""),
      before: item.before,
      after: item.after,
      risk: item.risk,
      confirmLabel: item.ends_adb_session ? "Désactiver le débogage USB" : "Appliquer",
      danger: item.ends_adb_session,
    });
    if (!confirmed) return;
    busy = true;
    button.disabled = true;
    button.textContent = "Application…";
    try {
      const result = await api.post("/api/hardening/apply", {
        device_id: state.selectedDeviceId,
        action_id: item.action_id,
        target: item.target,
        plan_token: item.plan_token,
        issued_at: item.issued_at,
        confirm: true,
      });
      const verified = result.status === "verified";
      resultBox.replaceChildren(el("div", { class: "harden-result " + (verified ? "ok" : "warn") },
        el("span", { class: "badge " + (verified ? "ok" : "warn"), text: verified ? "Vérifié" : "Non vérifié" }),
        " " + (verified ? "Modification appliquée et confirmée par le téléphone : " : "La commande a été envoyée mais la relecture ne confirme pas le changement : ")
          + result.after_observed
          + (verified ? "" : " Vérifiez ce réglage manuellement sur le téléphone.")));
      card.classList.add("done");
      button.textContent = verified ? "Appliqué" : "À vérifier";
      toast(verified ? "Correction vérifiée" : "Correction non vérifiée", item.title, verified ? "ok" : "warn");
      if (result.ends_adb_session && verified) {
        state.selectedDeviceId = null;
        document.querySelectorAll("#hardening-actions .btn").forEach((b) => { b.disabled = true; });
        $("#hardening-error").replaceChildren(el("div", { class: "danger-note",
          text: "Le débogage USB est désactivé : le logiciel n'a plus accès au téléphone. Pour une nouvelle analyse, réactivez-le dans les Options pour les développeurs." }));
      }
    } catch (error) {
      button.disabled = false;
      button.textContent = "Appliquer…";
      resultBox.replaceChildren(errorBox(error));
      if (error instanceof LMS.ApiError && ["hardening_state_changed", "hardening_not_applicable"].includes(error.payload.code)) {
        toast("Plan à actualiser", error.payload.message, "warn");
      } else {
        notifyError(error);
      }
    } finally {
      busy = false;
    }
  }

  function renderChecklist(items) {
    $("#hardening-checklist").replaceChildren(...items.map((c) =>
      el("li", { class: "check-item" },
        el("span", { class: "check-icon " + c.status, text: STATUS_SYMBOL[c.status] || "?" }),
        el("div", {},
          el("div", { class: "check-label", text: c.label }),
          el("div", { class: "check-detail", text: c.detail }),
          el("div", { class: "check-action", text: c.action }),
          c.view ? el("a", { class: "link small", href: "#/" + c.view, text: "Voir le détail →" }) : null),
        el("span", { class: "badge " + c.status, text: STATUS_LABEL[c.status] || c.status }))));
  }

  async function loadPlan() {
    $("#hardening-error").replaceChildren();
    $("#hardening-actions").replaceChildren(el("div", { class: "card muted", text: "Lecture de la configuration du téléphone…" }));
    const refresh = $("#hardening-refresh");
    refresh.disabled = true;
    try {
      const query = state.selectedDeviceId ? "?device_id=" + encodeURIComponent(state.selectedDeviceId) : "";
      const plan = await api.get("/api/hardening/plan" + query);
      const groups = {};
      for (const item of plan.actions) (groups[item.category] = groups[item.category] || []).push(item);
      const sections = Object.keys(GROUPS).filter((key) => groups[key]).map((key) =>
        el("div", { class: "harden-group" }, el("h3", { text: GROUPS[key] + " (" + groups[key].length + ")" }), ...groups[key].map(itemCard)));
      $("#hardening-actions").replaceChildren(...(sections.length ? sections
        : [el("div", { class: "card empty-card", text: "Aucune correction automatique n'est nécessaire. Consultez les vérifications manuelles ci-dessous." })]));
      renderChecklist(plan.checklist);
    } catch (error) {
      $("#hardening-actions").replaceChildren();
      $("#hardening-error").replaceChildren(errorBox(error));
      $("#hardening-checklist").replaceChildren();
    } finally {
      refresh.disabled = false;
    }
  }

  $("#hardening-refresh").addEventListener("click", loadPlan);
  LMS.registerView("hardening", { title: "Renforcement", onEnter: loadPlan });
})();

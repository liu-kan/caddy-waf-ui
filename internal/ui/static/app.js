// Caddy WAF UI client behavior (CSP script-src 'self'): no inline handlers.
// All handlers are attached here and wired via data-* attributes.
(function () {
  // Dismiss flash notices (data-dismiss-toast on the close control).
  document.querySelectorAll("[data-dismiss-toast]").forEach(function (el) {
    el.addEventListener("click", function () {
      el.parentElement.style.display = "none";
    });
  });

  // Confirmation when switching the WAF to Off mode (protection bypass):
  // the message travels server-side in data-confirm-off. In sites.html the
  // form uses radios; in overview.html submit buttons name=mode. The confirm
  // only fires when the chosen mode is Off.
  document.querySelectorAll("form[data-confirm-off]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var mode;
      var radio = form.querySelector('input[type="radio"][name="mode"]:checked');
      if (radio) {
        mode = radio.value;
      } else if (event.submitter && event.submitter.getAttribute("name") === "mode") {
        mode = event.submitter.getAttribute("value");
      }
      if (mode === "Off" && !window.confirm(form.getAttribute("data-confirm-off"))) {
        event.preventDefault();
      }
    });
  });

  // Applying a policy or exclusion requires a reason (recorded in the change
  // history); previews do not.
  document.querySelectorAll("form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var submitter = event.submitter;
      if (!submitter || !submitter.hasAttribute("data-require-reason")) {
        return;
      }
      var reason = form.querySelector('input[name="reason"]');
      if (reason && reason.value.trim() === "") {
        event.preventDefault();
        reason.setCustomValidity("Describe why this change is needed.");
        reason.reportValidity();
        reason.addEventListener("input", function () { reason.setCustomValidity(""); }, { once: true });
      }
    });
  });

  // Confirmation dialog for destructive actions (snapshot restore). The
  // message is rendered server-side into data-confirm.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });
})();

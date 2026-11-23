/* ThreatWatch email signup: email address only, posted to the provider in subscription-config.json.
   No address is stored by this site. The provider (Buttondown by default) sends a confirmation email
   (double opt-in) before anyone is subscribed. */
(function () {
  "use strict";
  var form = document.getElementById("subscribe-form");
  if (!form) return;
  var input = document.getElementById("sub-email");
  var msg = document.getElementById("sub-msg");
  var btn = form.querySelector("button[type=submit]");
  var EMAIL_RE = /^[^\s@<>"']{1,64}@[^\s@<>"']+\.[^\s@<>"']{2,}$/;
  var cfg = null;

  function say(text, kind) {
    msg.textContent = text;
    msg.className = "sub-msg" + (kind ? " " + kind : "");
  }
  function endpoint(c) {
    var u = c && c.enabled && typeof c.signupUrl === "string" ? c.signupUrl : "";
    return /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null;
  }

  // Pages outside /threatwatch/ point at the shared config with data-config="../threatwatch/subscription-config.json".
  var cfgUrl = form.getAttribute("data-config") || "subscription-config.json";
  if (!/^(\.\.\/)?[\w\-\/]*subscription-config\.json$/.test(cfgUrl)) cfgUrl = "subscription-config.json";
  fetch(cfgUrl, { cache: "no-cache" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (c) { cfg = c; var u = endpoint(c); if (u) form.action = u; })
    .catch(function () { cfg = null; });

  form.addEventListener("submit", function (ev) {
    var email = (input.value || "").trim();
    input.value = email;
    if (!email || !EMAIL_RE.test(email) || !input.checkValidity()) {
      ev.preventDefault();
      input.setAttribute("aria-invalid", "true");
      say("Please enter a valid email address.", "err");
      input.focus();
      return;
    }
    input.removeAttribute("aria-invalid");
    var url = endpoint(cfg);
    if (!url) {
      ev.preventDefault();
      say("Email signup opens soon. Thank you for your interest. Please check back shortly.", "info");
      return;
    }
    form.action = url;
    // The provider's confirmation page opens in a new tab (target=_blank); this page stays put.
    say("Almost done: check your inbox and click the confirmation link to start receiving the brief.", "ok");
    btn.disabled = true;
    setTimeout(function () { form.reset(); btn.disabled = false; }, 1500);
  });
  input.addEventListener("input", function () {
    if (input.getAttribute("aria-invalid")) { input.removeAttribute("aria-invalid"); say(""); }
  });
})();

// Ban/unban actions and asciinema player mounting for the IP detail page.
(function () {
  "use strict";

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";
  var status = document.getElementById("action-status");

  function say(text) {
    if (status) { status.textContent = text; }
  }

  document.querySelectorAll("button.act[data-action]").forEach(function (button) {
    button.addEventListener("click", function () {
      var action = button.getAttribute("data-action");
      var ip = button.getAttribute("data-ip");
      if (action === "ban" && !window.confirm("Ban " + ip + "?")) { return; }

      say("Working…");
      fetch("/api/" + action + "/" + encodeURIComponent(ip), {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf }
      })
        .then(function (response) { return response.json(); })
        .then(function (body) {
          say(body.ok ? action + " succeeded — reloading…" : "Failed: " + (body.error || "unknown"));
          if (body.ok) { setTimeout(function () { window.location.reload(); }, 800); }
        })
        .catch(function () { say("Request failed."); });
    });
  });

  document.querySelectorAll(".player[data-src]").forEach(function (node) {
    if (typeof window.AsciinemaPlayer === "undefined") { return; }
    try {
      window.AsciinemaPlayer.create(node.getAttribute("data-src"), node, {
        fit: "width", speed: 1, idleTimeLimit: 3, theme: "asciinema"
      });
    } catch (error) {
      node.textContent = "Unable to load recording.";
    }
  });
})();

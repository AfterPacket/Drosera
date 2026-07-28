// Ban/unban actions and session playback for the IP detail page.
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
      // Only banning is confirmed. Tarpit changes are cheap and reversible;
      // a ban writes a firewall rule and is the one worth pausing over.
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

  // Mount on demand rather than on load: an IP with a dozen recordings would
  // otherwise fetch and replay all of them at once.
  document.querySelectorAll(".player[data-src]").forEach(function (node) {
    var button = document.createElement("button");
    button.className = "act";
    button.textContent = "Play";
    node.parentNode.insertBefore(button, node);

    button.addEventListener("click", function () {
      if (node.dataset.mounted === "1") {
        window.DroseraCast.stop(node);
        node.dataset.mounted = "0";
        button.textContent = "Play";
        return;
      }
      window.DroseraCast.play(node.getAttribute("data-src"), node);
      node.dataset.mounted = "1";
      button.textContent = "Hide";
    });
  });
})();

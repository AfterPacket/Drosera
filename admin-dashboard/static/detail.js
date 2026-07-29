// Ban/unban actions, the service timeline, and session playback for the IP
// detail page.
(function () {
  "use strict";

  // Timeline points are rendered into a data attribute rather than fetched:
  // the server already had them to build the page, and a second round trip over
  // the operator's SSH tunnel to redraw what it just sent is a wasted wait.
  var host = document.getElementById("c-timeline");
  if (host && window.DroseraCharts) {
    var draw = function () {
      try {
        window.DroseraCharts.timeline(host,
          JSON.parse(host.getAttribute("data-points") || "[]"));
      } catch (error) { /* leave the box empty rather than break the page */ }
    };
    draw();
    // Both handlers redraw the same SVG: it is sized against its container and
    // coloured from CSS variables, so neither survives on its own.
    window.addEventListener("resize", draw);
    window.addEventListener("drosera:themechange", draw);
  }

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

  // Mount on demand rather than on load. The stitched recording is every
  // connection this address ever made, so it is the one thing on the page worth
  // not fetching until somebody asks for it.
  document.querySelectorAll(".player-shell[data-src]").forEach(function (node) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "act primary";
    button.textContent = "Play engagement";
    node.parentNode.insertBefore(button, node);

    button.addEventListener("click", function () {
      if (node.dataset.mounted === "1") {
        window.DroseraCast.stop(node);
        node.dataset.mounted = "0";
        button.textContent = "Play engagement";
        return;
      }
      window.DroseraCast.play(node.getAttribute("data-src"), node);
      node.dataset.mounted = "1";
      button.textContent = "Close player";
      // The player takes the keyboard once it exists, so hand focus over
      // rather than making the operator click into it.
      var screen = node.querySelector(".cast-screen");
      if (screen) { screen.focus(); }
    });
  });
})();

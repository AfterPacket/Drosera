// Sessions being recorded right now, on the live feed page.
//
// One-way by construction. The honeypot container writes a .cast; this polls a
// list of the ones without a completion sidecar and, if you open one, re-reads
// that file. There is no socket to the honeypot from here and no route that
// sends anything toward an attacker, so watching a session cannot become
// interfering with one.
(function () {
  "use strict";

  var POLL_MS = 5000;
  var open = null;          // name of the recording currently being watched

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function bytes(n) {
    if (n < 1024) { return n + " B"; }
    if (n < 1024 * 1024) { return (n / 1024).toFixed(1) + " KB"; }
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  function ago(seconds) {
    if (seconds < 2) { return "just now"; }
    if (seconds < 60) { return Math.round(seconds) + "s ago"; }
    return Math.floor(seconds / 60) + "m ago";
  }

  function watch(name) {
    var slot = document.getElementById("live-player");
    if (!slot) { return; }
    if (open === name) {
      window.DroseraCast.stop(slot);
      open = null;
      render.last = null;   // force a redraw so the button label flips back
      return;
    }
    window.DroseraCast.stop(slot);
    open = name;
    // follow(), not play(): this session is still being written. Replaying it
    // with its original timing would mean watching the last five minutes over
    // again before reaching the present, which is not what "live" means.
    window.DroseraCast.follow("/sessions/" + encodeURIComponent(name) + "/raw", slot);
  }

  function render(rows) {
    var count = document.getElementById("live-count");
    if (count) {
      count.textContent = rows.length;
      count.className = "pill " + (rows.length ? "on" : "off");
    }

    var body = document.getElementById("live-rows");
    if (!body) { return; }

    // Re-rendering the table every five seconds would fight the operator for
    // the mouse, so it only redraws when the set of live sessions actually
    // changes -- not when a byte count ticks.
    var signature = rows.map(function (r) { return r.name; }).join("|")
      + "#" + (open || "");
    if (render.last === signature) {
      rows.forEach(function (row) {
        var cell = body.querySelector('[data-idle="' + CSS.escape(row.name) + '"]');
        if (cell) { cell.textContent = ago(row.idle_seconds); }
        var size = body.querySelector('[data-bytes="' + CSS.escape(row.name) + '"]');
        if (size) { size.textContent = bytes(row.bytes); }
      });
      return;
    }
    render.last = signature;

    body.textContent = "";
    if (!rows.length) {
      var empty = el("tr");
      var cell = el("td", "muted", "Nothing being recorded right now.");
      cell.colSpan = 6;
      empty.appendChild(cell);
      body.appendChild(empty);
      // A session that ended while you were watching it stops here rather
      // than replaying from the top forever.
      if (open) {
        window.DroseraCast.stop(document.getElementById("live-player"));
        open = null;
      }
      return;
    }

    rows.forEach(function (row) {
      var tr = el("tr");

      var ip = el("td", "mono nowrap");
      var link = el("a", null, row.ip);
      link.href = "/ip/" + encodeURIComponent(row.ip);
      ip.appendChild(link);
      tr.appendChild(ip);

      tr.appendChild(el("td", null, row.service || "-"));
      tr.appendChild(el("td", "mono nowrap", (row.started || "").slice(11, 19)));

      var size = el("td", "mono num", bytes(row.bytes));
      size.setAttribute("data-bytes", row.name);
      tr.appendChild(size);

      var idle = el("td", "mono nowrap", ago(row.idle_seconds));
      idle.setAttribute("data-idle", row.name);
      tr.appendChild(idle);

      var actions = el("td");
      var button = el("button", "act", open === row.name ? "Stop" : "Watch");
      button.type = "button";
      button.addEventListener("click", function () { watch(row.name); });
      actions.appendChild(button);
      tr.appendChild(actions);

      body.appendChild(tr);
    });
  }

  function poll() {
    fetch("/api/sessions/live", { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(render)
      .catch(function () { /* transient; the next tick retries */ });
  }

  poll();
  setInterval(poll, POLL_MS);
})();

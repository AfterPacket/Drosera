// Live event feed. Polls /api/events and rebuilds the table via DOM APIs only --
// never innerHTML, so attacker-controlled payload text cannot inject markup.
(function () {
  "use strict";

  var tbody = document.getElementById("events");
  var stamp = document.getElementById("refreshed");
  if (!tbody) { return; }

  function cell(row, text, mono) {
    var td = document.createElement("td");
    td.textContent = text === null || text === undefined ? "" : String(text);
    if (mono) { td.className = "mono"; }
    row.appendChild(td);
    return td;
  }

  function render(events) {
    tbody.textContent = "";
    if (!events.length) {
      var empty = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 6;
      td.className = "muted";
      td.textContent = "No events yet.";
      empty.appendChild(td);
      tbody.appendChild(empty);
      return;
    }
    events.forEach(function (event) {
      var row = document.createElement("tr");
      cell(row, String(event.timestamp || "").slice(0, 19), true);

      var ipCell = document.createElement("td");
      ipCell.className = "mono";
      if (event.real_ip) {
        var link = document.createElement("a");
        link.href = "/ip/" + encodeURIComponent(event.real_ip);
        link.textContent = event.real_ip;
        ipCell.appendChild(link);
      }
      row.appendChild(ipCell);

      cell(row, event.service || "-");
      cell(row, event.event_type || "-");
      cell(row, event.cumulative_score === undefined ? "-" : event.cumulative_score, true);

      var detail = cell(row, event.payload_excerpt || event.reason || "", true);
      detail.className = "mono wrap";

      tbody.appendChild(row);
    });
  }

  function poll() {
    fetch("/api/events?n=50", { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) { throw new Error("http " + response.status); }
        return response.json();
      })
      .then(function (events) {
        render(events);
        if (stamp) {
          stamp.textContent = "· updated " + new Date().toLocaleTimeString();
        }
      })
      .catch(function () {
        if (stamp) { stamp.textContent = "· refresh failed"; }
      });
  }

  poll();
  setInterval(poll, 10000);
})();

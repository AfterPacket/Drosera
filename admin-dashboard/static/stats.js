// Chart rendering for the stats page. All data comes from /api/stats.
(function () {
  "use strict";

  var C = window.DroseraCharts.colours;

  function set(id, value) {
    var node = document.getElementById(id);
    if (node) { node.textContent = value; }
  }

  function host(id) { return document.getElementById(id); }

  function topRows(rows) {
    var tbody = document.getElementById("t-top");
    if (!tbody) { return; }
    tbody.textContent = "";
    if (!rows.length) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 5;
      td.className = "muted";
      td.textContent = "No data.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");

      var ipCell = document.createElement("td");
      ipCell.className = "mono";
      if (row.ip && row.ip !== "unknown") {
        var link = document.createElement("a");
        link.href = "/ip/" + encodeURIComponent(row.ip);
        link.textContent = row.ip;
        ipCell.appendChild(link);
      } else {
        ipCell.textContent = "unknown";
      }
      tr.appendChild(ipCell);

      [row.score, row.tool, row.services].forEach(function (value, index) {
        var td = document.createElement("td");
        td.textContent = value === null || value === undefined ? "" : String(value);
        if (index === 0) { td.className = "mono"; }
        tr.appendChild(td);
      });
      var statusCell = document.createElement("td");
      var pill = document.createElement("span");
      pill.className = "pill " + row.status;
      pill.textContent = row.status;
      statusCell.appendChild(pill);
      tr.appendChild(statusCell);
      tbody.appendChild(tr);
    });
  }

  fetch("/api/stats", { credentials: "same-origin" })
    .then(function (response) { return response.json(); })
    .then(function (data) {
      set("t-total", data.total_ips);
      set("t-active", data.active_today);
      set("t-banned", data.banned_total);
      set("t-tarpit", data.tarpitted_total);
      set("t-events", data.events_today);
      set("t-wasted", data.attacker_minutes_wasted);

      window.DroseraCharts.line(host("c-hourly"),
        (data.hourly || []).map(function (d) {
          return { label: d.hour, value: d.count };
        }));

      // Horizontal: service and tool names are words, and rotated x-axis
      // labels are the usual alternative to this and are worse to read.
      window.DroseraCharts.hbars(host("c-service"),
        (data.by_service || []).map(function (d) {
          return { label: d.service, value: d.count };
        }));

      window.DroseraCharts.hbars(host("c-tools"),
        (data.tools || []).map(function (d) {
          return { label: d.tool, value: d.count };
        }), { colour: C.accent });

      if (data.geoip) {
        window.DroseraCharts.hbars(host("c-countries"),
          (data.countries || []).map(function (d) {
            return { label: d.country, value: d.count };
          }));
      } else {
        // Say why it is empty rather than showing an empty box. The database
        // is licensed and cannot ship with the repo.
        host("c-countries").textContent = "";
        var note = document.getElementById("geo-note");
        if (note) { note.style.display = "block"; }
      }

      // Buckets are ordered and comparable, so vertical bars read as a
      // distribution rather than a ranking.
      window.DroseraCharts.bars(host("c-scores"),
        (data.score_distribution || []).map(function (d) {
          return { label: d.bucket, value: d.count };
        }), { colour: C.accent });

      topRows(data.top_ips || []);
    })
    .catch(function () {
      set("t-total", "err");
    });
})();

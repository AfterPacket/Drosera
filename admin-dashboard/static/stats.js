// Chart rendering for the stats page. All data comes from /api/stats.
(function () {
  "use strict";

  var INK = "#f0f6fc";
  var MUTED = "#8b949e";
  var LINE = "#30363d";
  // Categorical ramp chosen for contrast on the dark surface.
  var SERIES = ["#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff",
                "#39c5cf", "#db61a2", "#e3b341"];

  Chart.defaults.color = MUTED;
  Chart.defaults.borderColor = LINE;
  Chart.defaults.font.family = "ui-monospace, SFMono-Regular, Menlo, monospace";
  Chart.defaults.font.size = 11;

  function set(id, value) {
    var node = document.getElementById(id);
    if (node) { node.textContent = value; }
  }

  function axes(stacked) {
    return {
      x: { grid: { color: LINE }, ticks: { color: MUTED } },
      y: { grid: { color: LINE }, ticks: { color: MUTED, precision: 0 },
           beginAtZero: true, stacked: !!stacked }
    };
  }

  function make(id, config) {
    var canvas = document.getElementById(id);
    if (!canvas) { return; }
    return new Chart(canvas.getContext("2d"), config);
  }

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

      make("c-hourly", {
        type: "line",
        data: {
          labels: data.hourly.map(function (d) { return d.hour; }),
          datasets: [{
            label: "Connections", data: data.hourly.map(function (d) { return d.count; }),
            borderColor: SERIES[0], backgroundColor: "rgba(88,166,255,.15)",
            fill: true, tension: .3, pointRadius: 2
          }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: axes() }
      });

      make("c-service", {
        type: "bar",
        data: {
          labels: data.by_service.map(function (d) { return d.service; }),
          datasets: [{
            label: "Events", data: data.by_service.map(function (d) { return d.count; }),
            backgroundColor: SERIES[1]
          }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: axes() }
      });

      make("c-tools", {
        type: "doughnut",
        data: {
          labels: data.tools.map(function (d) { return d.tool; }),
          datasets: [{
            data: data.tools.map(function (d) { return d.count; }),
            backgroundColor: SERIES, borderColor: "#161b22", borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          plugins: { legend: { position: "right", labels: { color: INK, boxWidth: 12 } } }
        }
      });

      make("c-scores", {
        type: "bar",
        data: {
          labels: data.score_distribution.map(function (d) { return d.bucket; }),
          datasets: [{
            label: "IPs", data: data.score_distribution.map(function (d) { return d.count; }),
            backgroundColor: SERIES[4]
          }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: axes() }
      });

      topRows(data.top_ips || []);
    })
    .catch(function () {
      set("t-total", "err");
    });
})();

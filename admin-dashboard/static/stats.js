// Chart rendering for the stats page. One selected day comes from /api/stats,
// the history strip from /api/stats/trend, and the live hold table from
// /api/holds -- which is the only one that keeps polling.
(function () {
  "use strict";

  var C = window.DroseraCharts.colours;

  function set(id, value) {
    var node = document.getElementById(id);
    if (node) { node.textContent = value; }
  }

  function host(id) { return document.getElementById(id); }

  function ipLink(ip) {
    var link = document.createElement("a");
    link.href = "/ip/" + encodeURIComponent(ip);
    link.textContent = ip;
    return link;
  }

  function ipCell(ip) {
    var cell = document.createElement("td");
    cell.className = "mono";
    if (ip && ip !== "unknown") {
      cell.appendChild(ipLink(ip));
    } else {
      cell.textContent = "unknown";
    }
    return cell;
  }

  function statusCell(status) {
    var cell = document.createElement("td");
    var pill = document.createElement("span");
    pill.className = "pill " + status;
    pill.textContent = status;
    cell.appendChild(pill);
    return cell;
  }

  // Both IP tables are IP + three plain columns + a status pill, so they share
  // one renderer; only which fields go in the middle differs.
  function ipTable(id, rows, fields, monoAt) {
    var tbody = document.getElementById(id);
    if (!tbody) { return; }
    tbody.textContent = "";
    if (!rows.length) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = fields.length + 2;
      td.className = "muted";
      td.textContent = "No data.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      tr.appendChild(ipCell(row.ip));
      fields.forEach(function (field, index) {
        var td = document.createElement("td");
        var value = row[field];
        td.textContent = value === null || value === undefined ? "" : String(value);
        if (monoAt.indexOf(index) !== -1) { td.className = "mono"; }
        tr.appendChild(td);
      });
      tr.appendChild(statusCell(row.status));
      tbody.appendChild(tr);
    });
  }

  function tile(id, value, sub) {
    set(id, value === null || value === undefined || value === "" ? "—" : value);
    var node = document.getElementById(id + "-sub");
    if (node) { node.textContent = sub || ""; }
  }

  function plural(n, word) {
    return n + " " + word + (n === 1 ? "" : "s");
  }

  // The busiest host of the day is the one an operator most often wants to open
  // next, so the tile itself is the link rather than something to copy out.
  function linkifyTile(id, ip) {
    var node = document.getElementById(id);
    if (!node || !ip) { return; }
    node.textContent = "";
    node.appendChild(ipLink(ip));
  }

  var days = [];
  var current = null;
  var latest = null;        // last /api/stats payload, for redraws
  var redrawTimer = null;

  function label(day) {
    var today = new Date().toISOString().slice(0, 10);
    if (day === today) { return day + "  (today)"; }
    return day;
  }

  function renderDayBar(data) {
    days = data.available_days || [];
    current = data.day;

    var select = document.getElementById("day-select");
    if (select) {
      select.textContent = "";
      days.forEach(function (day) {
        var option = document.createElement("option");
        option.value = day;
        option.textContent = label(day);
        if (day === current) { option.selected = true; }
        select.appendChild(option);
      });
    }

    var index = days.indexOf(current);
    // days[] is newest-first, so "previous day" is the *higher* index.
    var prev = document.getElementById("day-prev");
    var next = document.getElementById("day-next");
    if (prev) { prev.disabled = index < 0 || index >= days.length - 1; }
    if (next) { next.disabled = index <= 0; }

    var note = document.getElementById("day-note");
    if (note) {
      note.textContent = data.is_today
        ? "live · counters reset at 00:00 UTC"
        : "archived day · " + (data.events_today || 0) + " events";
    }
  }

  function load(day) {
    var url = "/api/stats" + (day ? "?day=" + encodeURIComponent(day) : "");
    return fetch(url, { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(render)
      .then(markTrend)
      .catch(function () { set("t-total", "err"); });
  }

  // The trend spans every retained day, so it does not change when the day
  // selection does. Fetched once and redrawn locally to move the highlight.
  var trend = [];

  function drawTrend() {
    if (!host("c-trend")) { return; }
    window.DroseraCharts.bars(host("c-trend"), trend.map(function (d) {
      return {
        label: d.day.slice(5),
        title: d.day,
        value: d.events,
        tip: d.day + " · " + plural(d.events, "event") + " · " + plural(d.ips, "IP"),
        selected: d.day === current
      };
    }), {
      height: 200,
      // Roughly six dates across the axis, whatever the window length.
      labelEvery: Math.max(1, Math.ceil(trend.length / 6)),
      onSelect: function (row) { load(row.title); }
    });
  }

  function markTrend() {
    if (trend.length) { drawTrend(); }
  }

  // All-time totals. Independent of the day selection, so it is fetched once
  // and never redrawn -- these are plain numbers, not sized-to-container SVG.
  function loadLifetime() {
    return fetch("/api/stats/lifetime", { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        set("lt-ips", (data.unique_ips || 0).toLocaleString());
        set("lt-blocked", (data.ips_blocked || 0).toLocaleString());
        set("lt-events", (data.events || 0).toLocaleString());
        set("lt-hours", Math.round((data.minutes_wasted || 0) / 60).toLocaleString());
        set("lt-countries", data.countries || 0);
        set("lt-busiest", data.busiest_day || "—");
        var sub = document.getElementById("lt-busiest-sub");
        if (sub && data.busiest_day) {
          sub.textContent = plural(data.busiest_day_events || 0, "event");
        }
        var range = document.getElementById("lt-range");
        if (range && data.first_day) {
          range.textContent = data.first_day + " → " + data.last_day
            + " · " + plural(data.days_observed || 0, "day");
        }
      })
      .catch(function () { /* the day view is unaffected */ });
  }

  function loadTrend() {
    return fetch("/api/stats/trend?days=30", { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        trend = data.days || [];
        drawTrend();
      })
      .catch(function () { /* the day view is still usable without it */ });
  }

  document.addEventListener("click", function (event) {
    var index = days.indexOf(current);
    if (event.target.id === "day-prev" && index < days.length - 1) {
      load(days[index + 1]);
    } else if (event.target.id === "day-next" && index > 0) {
      load(days[index - 1]);
    } else if (event.target.id === "day-today") {
      load(days[0]);
    }
  });

  document.addEventListener("change", function (event) {
    if (event.target.id === "day-select") { load(event.target.value); }
  });

  function render(data) {
    latest = data;
    renderDayBar(data);
    return Promise.resolve(data)
    .then(function (data) {
      set("t-total", data.total_ips);
      set("t-active", data.countries_total || "—");
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
        window.DroseraCharts.geomap(host("c-map"), data.origins || []);
        window.DroseraCharts.hbars(host("c-countries"),
          (data.countries || []).map(function (d) {
            return { label: d.country, value: d.count };
          }));
      } else {
        host("c-map").textContent = "";
        var mapNote = document.getElementById("map-note");
        if (mapNote) { mapNote.hidden = false; }
        // Say why it is empty rather than showing an empty box. The database
        // is licensed and cannot ship with the repo.
        host("c-countries").textContent = "";
        var note = document.getElementById("geo-note");
        if (note) { note.hidden = false; }
      }

      // Buckets are ordered and comparable, so vertical bars read as a
      // distribution rather than a ranking.
      window.DroseraCharts.bars(host("c-scores"),
        (data.score_distribution || []).map(function (d) {
          return { label: d.bucket, value: d.count };
        }), { colour: C.accent });

      window.DroseraCharts.hbars(host("c-usernames"),
        (data.usernames || []).map(function (d) {
          return { label: d.label, value: d.count };
        }));
      window.DroseraCharts.hbars(host("c-passwords"),
        (data.passwords || []).map(function (d) {
          return { label: d.label, value: d.count };
        }), { colour: C.accent });
      var credNote = document.getElementById("cred-note");
      if (credNote) { credNote.hidden = (data.usernames || []).length > 0; }

      tile("t-topip", data.top_ip, data.top_ip
        ? plural(data.top_ip_events, "event") : "");
      linkifyTile("t-topip", data.top_ip);
      tile("t-topcountry", data.top_country, data.top_country
        ? plural(data.top_country_ips, "IP") : "");
      tile("t-topservice", data.top_service, data.top_service
        ? plural(data.top_service_events, "event") : "");
      tile("t-peakhour", data.busiest_hour ? data.busiest_hour + ":00" : null,
        data.busiest_hour ? plural(data.busiest_hour_events, "event") + " UTC" : "");
      // Both counts, because their ratio is the useful signal: many passwords
      // against one user is a brute force, one password against many users is
      // a spray, and the attempt total alone does not separate them.
      tile("t-creds", data.credential_attempts, data.credential_attempts
        ? plural(data.distinct_usernames, "user") + " · "
          + plural(data.distinct_passwords, "password")
        : "");

      ipTable("t-top", data.top_ips || [], ["score", "tool", "services"], [0]);
      ipTable("t-noisy", data.noisiest_ips || [],
              ["events", "country", "score"], [0, 2]);
    });
  }

  // Live holds poll independently of the day view. They are "right now", so
  // they have no meaning for an archived day and must not be cached alongside
  // the day's aggregates.
  function renderHolds(holds) {
    var count = document.getElementById("hold-count");
    if (count) {
      count.textContent = holds.length;
      count.className = "pill " + (holds.length ? "on" : "off");
    }

    var tbody = document.getElementById("t-holds");
    if (!tbody) { return; }
    tbody.textContent = "";

    if (!holds.length) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 3;
      cell.className = "muted";
      cell.textContent = "Nothing held right now.";
      empty.appendChild(cell);
      tbody.appendChild(empty);
      return;
    }

    holds.forEach(function (hold) {
      var row = document.createElement("tr");

      row.appendChild(ipCell(hold.ip));

      var svc = document.createElement("td");
      svc.textContent = hold.service || "-";
      row.appendChild(svc);

      var held = document.createElement("td");
      held.className = "mono";
      var seconds = Number(hold.seconds || 0);
      held.textContent = seconds >= 60
        ? Math.floor(seconds / 60) + "m " + Math.round(seconds % 60) + "s"
        : seconds.toFixed(1) + "s";
      row.appendChild(held);

      tbody.appendChild(row);
    });
  }

  function pollHolds() {
    fetch("/api/holds", { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(renderHolds)
      .catch(function () { /* transient; the next tick retries */ });
  }

  // The charts are SVG sized against their container and coloured from CSS
  // variables, so neither a resize nor a theme change survives without a
  // redraw. Both replay the last payload rather than refetching it.
  function redraw() {
    if (!latest) { return; }
    clearTimeout(redrawTimer);
    redrawTimer = setTimeout(function () {
      render(latest);
      markTrend();
    }, 120);
  }

  window.addEventListener("resize", redraw);
  window.addEventListener("drosera:themechange", redraw);

  load();
  loadTrend();
  loadLifetime();
  pollHolds();
  setInterval(pollHolds, 5000);
})();

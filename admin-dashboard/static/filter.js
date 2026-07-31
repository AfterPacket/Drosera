// Row filtering for the tracked-addresses table.
//
// Client-side, because the rows are already in the page: narrowing them needs
// no round trip, keeps sort order, and works while the live feed below carries
// on polling. With a few thousand rows this is a single pass over the DOM per
// keystroke, which is fast enough that debouncing would only add latency.
//
// Filters read from data- attributes rather than cell text, so a change to how
// a column is rendered -- a flag, a link, a pill -- cannot silently break
// matching.
(function () {
  "use strict";

  var table = document.getElementById("tracked");
  if (!table) { return; }

  var ip = document.getElementById("f-ip");
  var status = document.getElementById("f-status");
  var country = document.getElementById("f-country");
  var clear = document.getElementById("f-clear");
  var count = document.getElementById("f-count");
  var body = table.tBodies[0];
  if (!body) { return; }

  function apply() {
    var needle = (ip.value || "").trim().toLowerCase();
    var wantStatus = status.value;
    var wantCountry = country.value;
    var shown = 0;
    var rows = body.rows;

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      // Skip the "no data" placeholder and any continuation row.
      if (!row.dataset.ip) { continue; }

      var visible = true;
      if (wantStatus && row.dataset.status !== wantStatus) { visible = false; }
      if (visible && wantCountry && row.dataset.country !== wantCountry) { visible = false; }
      if (visible && needle) {
        // IP or tool: an operator hunting a scanner knows one or the other,
        // and searching both costs nothing.
        var hay = (row.dataset.ip + " " + (row.dataset.tool || "")).toLowerCase();
        if (hay.indexOf(needle) === -1) { visible = false; }
      }

      row.hidden = !visible;
      if (visible) { shown++; }
    }

    if (count) {
      var total = 0;
      for (var j = 0; j < rows.length; j++) { if (rows[j].dataset.ip) { total++; } }
      count.textContent = shown === total
        ? total + " addresses"
        : shown + " of " + total + " addresses";
    }
  }

  ["input", "change"].forEach(function (event) {
    ip.addEventListener(event, apply);
    status.addEventListener(event, apply);
    country.addEventListener(event, apply);
  });

  if (clear) {
    clear.addEventListener("click", function () {
      ip.value = "";
      status.value = "";
      country.value = "";
      apply();
      ip.focus();
    });
  }

  // Clicking a status pill filters to it. The pills were already the obvious
  // thing to click and previously did nothing, which reads as broken.
  body.addEventListener("click", function (event) {
    var pill = event.target.closest(".pill");
    if (!pill || !body.contains(pill)) { return; }
    var value = pill.textContent.trim();
    status.value = status.value === value ? "" : value;
    apply();
  });

  apply();
})();

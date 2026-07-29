// Click-to-sort for every data table on the dashboard.
//
// Applied by scanning the DOM rather than by marking each table up: the tables
// are spread across six templates and two of them are built by JS after a
// fetch, so an opt-in attribute would have to be remembered in seven places and
// would be forgotten in the eighth.
//
// Sorting is by column TYPE, sniffed from the data. That matters most for IP
// addresses, which are the column an operator actually wants to sort by and the
// one a naive string sort ruins -- lexically, 9.0.0.1 sorts after 100.0.0.1,
// and every /8 interleaves with every other.
(function () {
  "use strict";

  var IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

  function cellText(row, index) {
    var cell = row.children[index];
    return cell ? cell.textContent.trim() : "";
  }

  // 32-bit value, so ordering is numeric per octet.
  function ipKey(value) {
    var parts = value.split(".");
    var out = 0;
    for (var i = 0; i < 4; i++) {
      out = out * 256 + (parseInt(parts[i], 10) || 0);
    }
    return out;
  }

  function numberKey(value) {
    // Tolerate units and separators the tables render: "14.8s", "473 B",
    // "1,024", "5226.6 min".
    var cleaned = value.replace(/,/g, "").match(/-?\d+(\.\d+)?/);
    return cleaned ? parseFloat(cleaned[0]) : NaN;
  }

  function detect(values) {
    var seen = 0;
    var ips = 0;
    var numbers = 0;
    for (var i = 0; i < values.length; i++) {
      var value = values[i];
      if (!value || value === "-" || value === "—") { continue; }
      seen++;
      if (IPV4.test(value)) { ips++; }
      if (!isNaN(numberKey(value))) { numbers++; }
    }
    if (!seen) { return "text"; }
    if (ips / seen > 0.8) { return "ip"; }
    // Timestamps are left as text on purpose: every one this dashboard renders
    // is ISO-8601 and zero-padded, so lexical order IS chronological order, and
    // parsing them would only add a way to get it wrong.
    if (numbers / seen > 0.8) { return "number"; }
    return "text";
  }

  function keyFor(kind, value) {
    if (!value || value === "-" || value === "—") { return null; }
    if (kind === "ip") { return ipKey(value); }
    if (kind === "number") {
      var n = numberKey(value);
      return isNaN(n) ? null : n;
    }
    return value.toLowerCase();
  }

  // A row whose first cell spans the table is a continuation of the row above,
  // not a record of its own -- the sessions page hangs an inline player under
  // each recording that way. Grouping them keeps a player attached to the row
  // that opens it; sorting the flat row list would deal them out at random.
  function groups(body) {
    var out = [];
    Array.prototype.forEach.call(body.rows, function (row) {
      var first = row.cells[0];
      var continuation = out.length && first && first.colSpan > 1;
      if (continuation) {
        out[out.length - 1].rows.push(row);
      } else {
        out.push({ lead: row, rows: [row] });
      }
    });
    return out;
  }

  function sort(table, index, direction) {
    var body = table.tBodies[0];
    if (!body) { return; }
    var blocks = groups(body);
    if (blocks.length < 2) { return; }

    var kind = detect(blocks.map(function (b) { return cellText(b.lead, index); }));

    var decorated = blocks.map(function (block, position) {
      return {
        rows: block.rows,
        key: keyFor(kind, cellText(block.lead, index)),
        // Original position breaks ties, so sorting twice on the same column
        // does not reshuffle rows that compare equal.
        position: position
      };
    });

    decorated.sort(function (a, b) {
      // Blanks sink to the bottom whichever way the column is pointing: they
      // are absent values, not the smallest ones.
      if (a.key === null && b.key === null) { return a.position - b.position; }
      if (a.key === null) { return 1; }
      if (b.key === null) { return -1; }
      if (a.key < b.key) { return -direction; }
      if (a.key > b.key) { return direction; }
      return a.position - b.position;
    });

    var fragment = document.createDocumentFragment();
    decorated.forEach(function (entry) {
      entry.rows.forEach(function (row) { fragment.appendChild(row); });
    });
    body.appendChild(fragment);
  }

  function wire(table) {
    if (table.dataset.sortable === "1") { return; }
    var head = table.tHead;
    if (!head || !head.rows.length) { return; }
    var body = table.tBodies[0];
    if (!body || body.rows.length < 2) { return; }
    table.dataset.sortable = "1";

    Array.prototype.forEach.call(head.rows[0].cells, function (cell, index) {
      if (!cell.textContent.trim()) { return; }
      cell.classList.add("sortable");
      cell.setAttribute("tabindex", "0");
      cell.setAttribute("role", "button");
      cell.setAttribute("aria-sort", "none");

      function activate() {
        // Third click does not return to insertion order: the tables arrive
        // already sorted by the column that matters (last seen, score), and
        // "unsorted" is not a state anyone asks for.
        var next = cell.dataset.dir === "1" ? -1 : 1;
        Array.prototype.forEach.call(head.rows[0].cells, function (other) {
          delete other.dataset.dir;
          other.setAttribute("aria-sort", "none");
        });
        cell.dataset.dir = String(next);
        cell.setAttribute("aria-sort", next === 1 ? "ascending" : "descending");
        sort(table, index, next);
      }

      cell.addEventListener("click", activate);
      cell.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activate();
        }
      });
    });
  }

  function scan() {
    document.querySelectorAll("table").forEach(wire);
  }

  document.addEventListener("DOMContentLoaded", function () {
    scan();
    // The live feed and the stats tables are filled in after a fetch, and the
    // feed keeps appending. Re-scanning on mutation is what makes those
    // sortable at all; wire() is idempotent so repeat scans are free.
    var pending = null;
    var observer = new MutationObserver(function () {
      clearTimeout(pending);
      pending = setTimeout(scan, 150);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  });
})();

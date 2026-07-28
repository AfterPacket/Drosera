// Dependency-free SVG charts for the operator dashboard.
//
// Replaces Chart.js from cdnjs. The dashboard is reached over an SSH tunnel to
// a box with no egress, and a chart library that silently fails to load leaves
// four empty boxes with no explanation. Everything here is inline SVG built
// from the same /api/stats payload.
//
// Every chart on this page is a SINGLE series, which is a deliberate design
// choice rather than a limitation: with one series per chart, colour carries no
// identity, so there is no categorical ramp to get wrong for colour-blind
// readers. Identity lives in axis labels and direct value labels instead.
// That is also why the tool breakdown is a horizontal bar chart and not the
// doughnut it used to be -- a doughnut asks you to compare angles and needs a
// distinct hue per slice to do it.
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";

  // GitHub-dark derived, matching the rest of the dashboard.
  var C = {
    ink: "#f0f6fc",
    muted: "#8b949e",
    grid: "#30363d",
    surface: "#161b22",
    series: "#58a6ff",
    accent: "#bc8cff"
  };

  var FONT = "ui-monospace, SFMono-Regular, Menlo, monospace";

  function el(name, attrs) {
    var node = document.createElementNS(NS, name);
    for (var key in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, key)) {
        node.setAttribute(key, String(attrs[key]));
      }
    }
    return node;
  }

  function text(x, y, value, opts) {
    opts = opts || {};
    var node = el("text", {
      x: x, y: y,
      fill: opts.fill || C.muted,
      "font-family": FONT,
      "font-size": opts.size || 10,
      "text-anchor": opts.anchor || "start",
      "dominant-baseline": opts.baseline || "auto"
    });
    node.textContent = value;
    return node;
  }

  function surface(host, height) {
    host.textContent = "";
    var width = Math.max(host.clientWidth || 420, 260);
    var svg = el("svg", {
      viewBox: "0 0 " + width + " " + height,
      width: "100%", height: height, role: "img"
    });
    host.appendChild(svg);
    return { svg: svg, w: width, h: height };
  }

  function empty(host, height) {
    host.textContent = "";
    var note = document.createElement("div");
    note.className = "muted";
    note.style.padding = "2rem 0";
    note.style.fontSize = ".8rem";
    note.textContent = "No data yet.";
    host.appendChild(note);
  }

  function niceMax(value) {
    if (value <= 5) { return 5; }
    var magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    return Math.ceil(value / magnitude) * magnitude;
  }

  // Shared tooltip. One node reused by every chart on the page.
  var tip = null;
  function tooltip() {
    if (!tip) {
      tip = document.createElement("div");
      tip.className = "chart-tip";
      tip.style.display = "none";
      document.body.appendChild(tip);
    }
    return tip;
  }
  function showTip(event, label) {
    var node = tooltip();
    node.textContent = label;
    node.style.display = "block";
    node.style.left = (event.clientX + 12) + "px";
    node.style.top = (event.clientY + 12) + "px";
  }
  function hideTip() { if (tip) { tip.style.display = "none"; } }

  function hoverable(node, label) {
    node.addEventListener("mousemove", function (event) { showTip(event, label); });
    node.addEventListener("mouseleave", hideTip);
  }

  // ------------------------------------------------------------------ line

  function line(host, rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) { return empty(host); }

    var pad = { t: 12, r: 14, b: 24, l: 38 };
    var box = surface(host, opts.height || 180);
    var plotW = box.w - pad.l - pad.r;
    var plotH = box.h - pad.t - pad.b;
    var max = niceMax(Math.max.apply(null, rows.map(function (r) { return r.value; })));

    var x = function (i) {
      return pad.l + (rows.length === 1 ? plotW / 2 : (i / (rows.length - 1)) * plotW);
    };
    var y = function (v) { return pad.t + plotH - (v / max) * plotH; };

    // Recessive horizontal grid only; vertical rules add noise without aiding
    // the comparison this chart is for.
    [0, 0.5, 1].forEach(function (fraction) {
      var gy = pad.t + plotH - fraction * plotH;
      box.svg.appendChild(el("line", {
        x1: pad.l, y1: gy, x2: box.w - pad.r, y2: gy,
        stroke: C.grid, "stroke-width": 1
      }));
      box.svg.appendChild(text(pad.l - 6, gy + 3, String(Math.round(max * fraction)),
                               { anchor: "end" }));
    });

    var path = rows.map(function (row, i) {
      return (i ? "L" : "M") + x(i).toFixed(1) + " " + y(row.value).toFixed(1);
    }).join(" ");

    var area = path + " L" + x(rows.length - 1).toFixed(1) + " " + (pad.t + plotH)
             + " L" + x(0).toFixed(1) + " " + (pad.t + plotH) + " Z";
    box.svg.appendChild(el("path", { d: area, fill: C.series, "fill-opacity": .12 }));
    box.svg.appendChild(el("path", {
      d: path, fill: "none", stroke: C.series, "stroke-width": 2,
      "stroke-linejoin": "round", "stroke-linecap": "round"
    }));

    rows.forEach(function (row, i) {
      // Markers are 8px targets even though the dot is small, so hovering does
      // not require pixel precision.
      var dot = el("circle", { cx: x(i), cy: y(row.value), r: 2.5, fill: C.series });
      box.svg.appendChild(dot);
      var hit = el("circle", { cx: x(i), cy: y(row.value), r: 9, fill: "transparent" });
      hoverable(hit, row.label + " · " + row.value);
      box.svg.appendChild(hit);

      // Label every fourth tick: one per hour is unreadable at this width.
      if (rows.length <= 8 || i % 4 === 0) {
        box.svg.appendChild(text(x(i), box.h - 8, row.label, { anchor: "middle" }));
      }
    });
  }

  // ----------------------------------------------------------- vertical bars

  function bars(host, rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) { return empty(host); }

    var pad = { t: 12, r: 14, b: 28, l: 38 };
    var box = surface(host, opts.height || 180);
    var plotW = box.w - pad.l - pad.r;
    var plotH = box.h - pad.t - pad.b;
    var max = niceMax(Math.max.apply(null, rows.map(function (r) { return r.value; })));
    // 2px of surface between bars keeps adjacent marks legible.
    var slot = plotW / rows.length;
    var width = Math.max(slot - 2, 3);
    var colour = opts.colour || C.series;

    [0, 0.5, 1].forEach(function (fraction) {
      var gy = pad.t + plotH - fraction * plotH;
      box.svg.appendChild(el("line", {
        x1: pad.l, y1: gy, x2: box.w - pad.r, y2: gy,
        stroke: C.grid, "stroke-width": 1
      }));
      box.svg.appendChild(text(pad.l - 6, gy + 3, String(Math.round(max * fraction)),
                               { anchor: "end" }));
    });

    rows.forEach(function (row, i) {
      var height = (row.value / max) * plotH;
      var bx = pad.l + i * slot + (slot - width) / 2;
      // rx rounds all corners; the bar is anchored to the baseline so only the
      // top pair reads as rounded.
      var bar = el("rect", {
        x: bx, y: pad.t + plotH - height, width: width,
        height: Math.max(height, row.value > 0 ? 2 : 0),
        rx: Math.min(4, width / 2), fill: colour
      });
      hoverable(bar, row.label + " · " + row.value);
      box.svg.appendChild(bar);
      box.svg.appendChild(text(bx + width / 2, box.h - 8, row.label,
                               { anchor: "middle" }));
    });
  }

  // --------------------------------------------------------- horizontal bars

  // For categorical magnitude. Horizontal because service and tool names are
  // words: rotated x-axis labels are the usual alternative and they are worse.
  function hbars(host, rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) { return empty(host); }

    rows = rows.slice().sort(function (a, b) { return b.value - a.value; }).slice(0, 8);

    var rowH = 24;
    var pad = { t: 8, r: 44, b: 8, l: 96 };
    var box = surface(host, pad.t + pad.b + rows.length * rowH);
    var plotW = box.w - pad.l - pad.r;
    var max = Math.max.apply(null, rows.map(function (r) { return r.value; })) || 1;
    var colour = opts.colour || C.series;

    rows.forEach(function (row, i) {
      var y = pad.t + i * rowH;
      var width = Math.max((row.value / max) * plotW, row.value > 0 ? 2 : 0);

      box.svg.appendChild(text(pad.l - 8, y + rowH / 2 + 3, row.label,
                               { anchor: "end", fill: C.ink }));

      var bar = el("rect", {
        x: pad.l, y: y + 4, width: width, height: rowH - 10,
        rx: 4, fill: colour
      });
      hoverable(bar, row.label + " · " + row.value);
      box.svg.appendChild(bar);

      // Direct value label: with ≤ 8 rows every bar can carry its number, which
      // removes the need to read against a gridline at all.
      box.svg.appendChild(text(pad.l + width + 6, y + rowH / 2 + 3,
                               String(row.value), { fill: C.muted }));
    });
  }

  // ------------------------------------------------------------- attack map

  // Land outline, fetched once and reused. Natural Earth 110m, public domain.
  // GeoJSON coordinates are [lon, lat], which the equirectangular projection
  // consumes directly -- no projection library, no topology decoding.
  var _land = null;
  var _landPending = null;

  function loadLand() {
    if (_land !== null) { return Promise.resolve(_land); }
    if (_landPending) { return _landPending; }
    _landPending = fetch("/static/world.geojson", { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) { throw new Error("http " + response.status); }
        return response.json();
      })
      .then(function (geo) { _land = geo; return geo; })
      .catch(function () { _land = false; return false; });
    return _landPending;
  }

  // Must match LAT_BOTTOM in geomap: land below the drawn band is skipped.
  var LAND_MIN_LAT = -56;

  function drawLand(svg, geo, x, y) {
    (geo.features || []).forEach(function (feature) {
      var geometry = feature.geometry;
      if (!geometry) { return; }
      var polygons = geometry.type === "Polygon" ? [geometry.coordinates]
                   : geometry.type === "MultiPolygon" ? geometry.coordinates
                   : [];
      polygons.forEach(function (polygon) {
        polygon.forEach(function (ring) {
          if (ring.length < 3) { return; }
          // Rings entirely below the drawn band are dropped rather than
          // clamped. y() pins out-of-range latitudes to the edge, which turns
          // Antarctica into a solid grey bar across the bottom of the map.
          var north = -90;
          for (var k = 0; k < ring.length; k++) {
            if (ring[k][1] > north) { north = ring[k][1]; }
          }
          if (north < LAND_MIN_LAT) { return; }
          var d = "";
          for (var i = 0; i < ring.length; i++) {
            d += (i ? "L" : "M") + x(ring[i][0]).toFixed(1)
                                 + " " + y(ring[i][1]).toFixed(1);
          }
          svg.appendChild(el("path", {
            d: d + " Z", fill: "#1b2029",
            stroke: "#2b3240", "stroke-width": 0.4
          }));
        });
      });
    });
  }

  // Equirectangular projection of attack origins over the land outline.
  function geomap(host, points, opts) {
    opts = opts || {};
    if (!points || !points.length) { return empty(host); }

    var pad = 6;
    var available = Math.max(host.clientWidth || 900, 320) - pad * 2;

    // Equirectangular must keep its aspect or every dot drifts off the
    // coastline it belongs to. Full -90..90 forces 2:1, which on a wide card
    // meant either a very tall panel or -- what it actually did -- capping the
    // width at 920 and letterboxing the rest into empty margins.
    //
    // Clipping the latitudes nobody attacks from fixes both. Antarctica and the
    // empty southern ocean are ~30% of the height and zero percent of the data,
    // so dropping them widens the natural aspect to ~2.6:1: the map fills the
    // card and every dot gets bigger, with the projection still honest.
    var LAT_TOP = 78, LAT_BOTTOM = LAND_MIN_LAT;
    var latSpan = LAT_TOP - LAT_BOTTOM;
    var ratio = latSpan / 360;

    var maxH = opts.maxHeight || 520;
    var mapW = available;
    var mapH = mapW * ratio;
    if (mapH > maxH) { mapH = maxH; mapW = mapH / ratio; }

    var box = surface(host, mapH + pad * 2);
    var ox = pad + (box.w - pad * 2 - mapW) / 2;
    var oy = pad;

    var x = function (lon) { return ox + ((Number(lon) + 180) / 360) * mapW; };
    var y = function (lat) {
      // Clamped rather than dropped: a point outside the drawn band belongs at
      // the edge, not silently missing from the totals the map is showing.
      var v = Math.min(LAT_TOP, Math.max(LAT_BOTTOM, Number(lat)));
      return oy + ((LAT_TOP - v) / latSpan) * mapH;
    };

    var w = mapW;
    var h = mapH;
    box.svg.appendChild(el("rect", {
      x: ox, y: oy, width: mapW, height: mapH,
      fill: "#0c0e12", stroke: C.grid, "stroke-width": 1, rx: 4
    }));

    // Land goes in first so the dots sit on top of it. Drawn asynchronously
    // and inserted beneath everything else, so a missing or slow world.geojson
    // degrades to the graticule rather than blocking the plot.
    loadLand().then(function (geo) {
      if (!geo) { return; }
      var layer = el("g", {});
      drawLand(layer, geo, x, y);
      box.svg.insertBefore(layer, box.svg.firstChild.nextSibling);
    });

    // Graticule every 30 degrees, kept faint. It carries the whole map when
    // world.geojson is absent, and is a subtle reference when it is present.
    for (var lon = -150; lon <= 150; lon += 30) {
      box.svg.appendChild(el("line", {
        x1: x(lon), y1: oy, x2: x(lon), y2: oy + h,
        stroke: C.grid, "stroke-width": 0.5, "stroke-opacity": .35
      }));
    }
    for (var lat = -30; lat <= 60; lat += 30) {
      box.svg.appendChild(el("line", {
        x1: ox, y1: y(lat), x2: ox + w, y2: y(lat),
        stroke: C.grid, "stroke-width": 0.5, "stroke-opacity": .35
      }));
    }

    var max = Math.max.apply(null, points.map(function (p) { return p.count; })) || 1;

    // Labels are placed only where they do not collide with one already
    // placed. Ranking alone is not enough: the busiest sources cluster
    // geographically -- half of Europe lands within twenty pixels -- so
    // "label the top four" produced four labels stacked into illegible mush.
    var placed = [];
    var seenLabels = {};
    var CHAR_W = 6;    // 10px monospace
    var LINE_H = 11;
    var MAX_LABELS = 8;

    function fits(bx, by, bw, bh) {
      if (bx + bw > ox + w) { return false; }   // would run off the edge
      for (var i = 0; i < placed.length; i++) {
        var p = placed[i];
        if (bx < p.x + p.w && bx + bw > p.x &&
            by < p.y + p.h && by + bh > p.y) { return false; }
      }
      return true;
    }

    // Area proportional to count, not radius: radius-scaling exaggerates the
    // big sources by the square of their lead.
    points.slice().sort(function (a, b) { return b.count - a.count; })
      .forEach(function (point) {
        if (point.lat === null || point.lon === null ||
            point.lat === undefined || point.lon === undefined) { return; }
        var radius = 2 + Math.sqrt(point.count / max) * 6;
        var cx = x(point.lon);
        var cy = y(point.lat);

        box.svg.appendChild(el("circle", {
          cx: cx, cy: cy, r: radius,
          fill: C.series, "fill-opacity": .35,
          stroke: C.series, "stroke-width": 1.5
        }));

        var label = (point.label || "?") + " · " + point.count;
        var hit = el("circle", { cx: cx, cy: cy, r: Math.max(radius, 10),
                                 fill: "transparent" });
        hoverable(hit, label);
        box.svg.appendChild(hit);

        // One label per distinct name. GeoLite2 has no city for most
        // datacentre ranges, so several unrelated hosts come back as bare
        // "United States" -- repeating it says nothing and crowds the plot.
        if (placed.length >= MAX_LABELS || !point.label) { return; }
        if (seenLabels[point.label]) { return; }
        seenLabels[point.label] = true;

        var bw = point.label.length * CHAR_W;
        var bx = cx + radius + 4;
        var by = cy - LINE_H / 2;
        if (!fits(bx, by, bw, LINE_H)) { return; }

        placed.push({ x: bx, y: by, w: bw, h: LINE_H });
        box.svg.appendChild(text(bx, cy + 3, point.label, { fill: C.ink }));
      });
  }

  window.DroseraCharts = {
    line: line, bars: bars, hbars: hbars, geomap: geomap, colours: C
  };
})();

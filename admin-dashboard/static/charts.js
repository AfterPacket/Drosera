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
//
// The attack map is the one place colour varies, and it varies with magnitude
// rather than identity: a single-hue sequential ramp, which is safe for the
// same reason -- no reader has to tell two hues apart to read it.
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";

  // The palette lives in style.css so the charts and the chrome around them
  // cannot drift apart, and so both follow the light/dark theme from one place.
  // Read live rather than cached at load: switching theme re-reads these and
  // redraws, and a cached copy would leave every chart in the old scheme.
  var FALLBACK = {
    ink: "#f0f6fc", muted: "#8b949e", grid: "#30363d",
    surface: "#161b22", series: "#58a6ff", accent: "#bc8cff"
  };

  // Memoised, because getComputedStyle is not cheap and these are read from
  // inside the drawing loops -- the world outline alone asks for a stroke
  // colour once per polygon ring. The only thing that can change them is a
  // theme switch, which says so.
  var varCache = {};

  function readVar(name, fallback) {
    if (Object.prototype.hasOwnProperty.call(varCache, name)) {
      return varCache[name] || fallback;
    }
    var value = "";
    try {
      value = getComputedStyle(document.documentElement)
        .getPropertyValue(name).trim();
    } catch (error) {
      value = "";
    }
    varCache[name] = value;
    return value || fallback;
  }

  window.addEventListener("drosera:themechange", function () { varCache = {}; });

  // Property access on a plain object, so every existing `C.series` call site
  // keeps working while the value now depends on the active theme.
  var C = {};
  Object.keys(FALLBACK).forEach(function (key) {
    Object.defineProperty(C, key, {
      enumerable: true,
      get: function () { return readVar("--chart-" + key, FALLBACK[key]); }
    });
  });

  // Sequential ramp for the attack map's density field: ONE hue, stepped so the
  // low end recedes toward the surface and the brightest step is reserved for
  // the peak. Never a rainbow -- hue carries no identity here, only magnitude,
  // which is the same reason every other chart is a single series. Low -> high,
  // and reversed in light mode because "recedes toward the surface" means pale
  // on dark and dark on pale.
  function heatRamp() {
    var ramp = readVar("--chart-heat", "").split(",")
      .map(function (part) { return part.trim(); })
      .filter(Boolean);
    return ramp.length ? ramp
      : ["#0d366b", "#184f95", "#256abf", "#3987e5", "#6da7ec", "#9ec5f4"];
  }

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

    // A month of dates cannot all be written under a 700px axis without the
    // labels overlapping into mush, so long series thin them and lean on the
    // hover tooltip -- which names every bar -- for the ones left out. Counted
    // from the right so the newest point always keeps its label: it is the one
    // every other bar is being read against.
    var every = opts.labelEvery || 1;
    var last = rows.length - 1;
    var selectedFill = C.accent;
    var selectedEdge = C.ink;

    rows.forEach(function (row, i) {
      var height = (row.value / max) * plotH;
      var bx = pad.l + i * slot + (slot - width) / 2;
      // rx rounds all corners; the bar is anchored to the baseline so only the
      // top pair reads as rounded.
      var bar = el("rect", {
        x: bx, y: pad.t + plotH - height, width: width,
        height: Math.max(height, row.value > 0 ? 2 : 0),
        rx: Math.min(4, width / 2), fill: row.selected ? selectedFill : colour
      });
      if (row.selected) {
        // Which bar you are reading is a selection, not a category, so it is
        // marked twice over -- fill and outline. The outline is what carries it
        // for a reader who cannot separate the two hues, which is the same
        // reason nothing else on this page encodes meaning in colour alone.
        bar.setAttribute("stroke", selectedEdge);
        bar.setAttribute("stroke-width", 1.5);
      }
      var tip = row.tip || ((row.title || row.label) + " · " + row.value);
      hoverable(bar, tip);
      if (opts.onSelect) {
        // The whole slot is clickable, not just the drawn bar: a day with two
        // events is a 2px target and a day with none is not there at all.
        var hit = el("rect", {
          x: pad.l + i * slot, y: pad.t, width: slot, height: plotH,
          fill: "transparent", cursor: "pointer"
        });
        hoverable(hit, tip);
        hit.addEventListener("click", function () { opts.onSelect(row); });
        box.svg.appendChild(bar);
        box.svg.appendChild(hit);
      } else {
        box.svg.appendChild(bar);
      }
      if ((last - i) % every === 0) {
        box.svg.appendChild(text(bx + width / 2, box.h - 8, row.label,
                                 { anchor: "middle" }));
      }
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
            d: d + " Z", fill: readVar("--chart-land", "#1b2029"),
            stroke: C.grid, "stroke-width": 0.4
          }));
        });
      });
    });
  }

  // Equirectangular projection of attack origins over the land outline.
  function geomap(host, points, opts) {
    opts = opts || {};
    if (!points || !points.length) { return empty(host); }

    var HEAT = heatRamp();
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

    // + LEGEND_BAND: the sequential ramp is drawn under the map, so the surface
    // has to be tall enough to hold it or it clips against the viewBox.
    var LEGEND_BAND = 28;
    var box = surface(host, mapH + pad * 2 + LEGEND_BAND);
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
      fill: C.surface, stroke: C.grid, "stroke-width": 1, rx: 4
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

    // ----------------------------------------------------------- density field
    //
    // A heat map rather than a dot per origin. Dots answered "where is there an
    // attacker" one at a time; the question the stats page is actually asked is
    // where attacks concentrate, and a hundred overlapping semi-transparent
    // circles is the worst possible way to show that -- the busiest regions are
    // exactly where the marks stop being separable.
    //
    // Each origin splats a Gaussian weighted by its count onto a grid, and the
    // grid is drawn in one sequential ramp. Overlap now accumulates instead of
    // occluding, which is the entire point.
    var CELL = 9;             // px per bin
    var RADIUS = 34;          // px of influence per origin
    var cols = Math.ceil(mapW / CELL);
    var rows = Math.ceil(mapH / CELL);
    var grid = new Array(cols * rows);
    for (var gi = 0; gi < grid.length; gi++) { grid[gi] = 0; }

    var sigma = RADIUS / 2;
    var falloff = 2 * sigma * sigma;

    points.forEach(function (point) {
      if (point.lat === null || point.lon === null ||
          point.lat === undefined || point.lon === undefined) { return; }
      var weight = Math.max(Number(point.count) || 0, 0);
      if (!weight) { return; }
      var px = x(point.lon), py = y(point.lat);
      var c0 = Math.max(0, Math.floor((px - ox - RADIUS) / CELL));
      var c1 = Math.min(cols - 1, Math.floor((px - ox + RADIUS) / CELL));
      var r0 = Math.max(0, Math.floor((py - oy - RADIUS) / CELL));
      var r1 = Math.min(rows - 1, Math.floor((py - oy + RADIUS) / CELL));
      for (var r = r0; r <= r1; r++) {
        for (var c = c0; c <= c1; c++) {
          var dx = ox + c * CELL + CELL / 2 - px;
          var dy = oy + r * CELL + CELL / 2 - py;
          var d2 = dx * dx + dy * dy;
          if (d2 > RADIUS * RADIUS) { continue; }
          grid[r * cols + c] += weight * Math.exp(-d2 / falloff);
        }
      }
    });

    var peak = 0;
    for (var pi = 0; pi < grid.length; pi++) {
      if (grid[pi] > peak) { peak = grid[pi]; }
    }

    if (peak > 0) {
      var heat = el("g", {});
      for (var ri = 0; ri < rows; ri++) {
        for (var ci = 0; ci < cols; ci++) {
          var value = grid[ri * cols + ci] / peak;
          // Leave the coastline legible where nothing happened, rather than
          // washing the whole ocean in the palest step.
          if (value < 0.04) { continue; }
          // sqrt, because one prolific source otherwise sets a peak that
          // flattens every other region into the bottom step.
          var t = Math.sqrt(value);
          var step = Math.min(HEAT.length - 1, Math.floor(t * HEAT.length));
          heat.appendChild(el("rect", {
            x: ox + ci * CELL, y: oy + ri * CELL,
            width: Math.min(CELL, mapW - ci * CELL),
            height: Math.min(CELL, mapH - ri * CELL),
            fill: HEAT[step], "fill-opacity": 0.3 + t * 0.5
          }));
        }
      }
      box.svg.appendChild(heat);
    }

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

    // The origins themselves stay inspectable. The field shows concentration;
    // hover still answers "which city, how many" for every individual source,
    // which the heat alone cannot -- a bin is a neighbourhood, not a datum.
    points.slice().sort(function (a, b) { return b.count - a.count; })
      .forEach(function (point) {
        if (point.lat === null || point.lon === null ||
            point.lat === undefined || point.lon === undefined) { return; }
        var cx = x(point.lon);
        var cy = y(point.lat);

        var label = (point.label || "?") + " · " + point.count;
        var hit = el("circle", { cx: cx, cy: cy, r: 10, fill: "transparent" });
        hoverable(hit, label);
        box.svg.appendChild(hit);

        // One label per distinct name. GeoLite2 has no city for most
        // datacentre ranges, so several unrelated hosts come back as bare
        // "United States" -- repeating it says nothing and crowds the plot.
        if (placed.length >= MAX_LABELS || !point.label) { return; }
        if (seenLabels[point.label]) { return; }
        seenLabels[point.label] = true;

        var bw = point.label.length * CHAR_W;
        var bx = cx + 6;
        var by = cy - LINE_H / 2;
        if (!fits(bx, by, bw, LINE_H)) { return; }

        placed.push({ x: bx, y: by, w: bw, h: LINE_H });
        // A 1.5px anchor so the label points at something. Deliberately not a
        // magnitude mark -- count is the field's job now, and encoding it twice
        // would let the two disagree.
        box.svg.appendChild(el("circle", {
          cx: cx, cy: cy, r: 1.5, fill: C.ink, "fill-opacity": .8
        }));
        box.svg.appendChild(text(bx, cy + 3, point.label, { fill: C.ink }));
      });

    // Sequential legend. A magnitude ramp is unreadable without one: the reader
    // has no way to know whether bright means ten or ten thousand.
    var legendY = oy + mapH + 14;
    var swatch = 26;
    var legendW = swatch * HEAT.length;
    var lx = ox;
    box.svg.appendChild(text(lx, legendY + 9, "fewer", { fill: C.muted }));
    var labelPad = 34;
    for (var si = 0; si < HEAT.length; si++) {
      box.svg.appendChild(el("rect", {
        x: lx + labelPad + si * swatch, y: legendY,
        width: swatch - 2, height: 8,
        fill: HEAT[si], "fill-opacity": 0.3 + Math.sqrt((si + 1) / HEAT.length) * 0.5,
        rx: 1
      }));
    }
    box.svg.appendChild(text(lx + labelPad + legendW + 6, legendY + 9,
                             "more attacks", { fill: C.muted }));
  }

  // ------------------------------------------------------------- timeline

  // One attacker's scored events against a clock, in a lane per service.
  //
  // Lanes rather than a single row of coloured dots: which service an event
  // belongs to is then carried by vertical position, which no reader can fail
  // to separate. Hue is a second, redundant encoding on top -- the same
  // discipline as everywhere else here, where colour never carries identity by
  // itself. Dot area grows with the score the event scored, so the moment an
  // engagement turned serious is visible without reading a single label.
  function timeline(host, points, opts) {
    opts = opts || {};
    if (!points || !points.length) { return empty(host, 120); }

    var services = [];
    points.forEach(function (point) {
      if (services.indexOf(point.service) === -1) { services.push(point.service); }
    });
    services.sort();

    var lane = 22;
    var pad = { t: 10, r: 14, b: 24, l: 74 };
    var height = pad.t + pad.b + services.length * lane;
    var box = surface(host, height);
    var plotW = box.w - pad.l - pad.r;

    var first = points[0].t;
    var last = points[points.length - 1].t;
    var span = last - first;
    // A burst inside one second would otherwise divide by zero and stack every
    // event on the left edge; give it a nominal minute and centre it.
    if (span <= 0) { first -= 30; span = 60; }

    function xAt(t) { return pad.l + ((t - first) / span) * plotW; }

    var palette = heatRamp();
    var grid = C.grid;
    var ring = C.surface;

    services.forEach(function (service, row) {
      var y = pad.t + row * lane + lane / 2;
      box.svg.appendChild(el("line", {
        x1: pad.l, y1: y, x2: box.w - pad.r, y2: y,
        stroke: grid, "stroke-width": 1
      }));
      box.svg.appendChild(text(pad.l - 8, y + 3, service, { anchor: "end" }));
    });

    var peak = Math.max.apply(null, points.map(function (p) {
      return Math.abs(p.points) || 0;
    })) || 1;

    points.forEach(function (point) {
      var row = services.indexOf(point.service);
      var y = pad.t + row * lane + lane / 2;
      var weight = Math.sqrt(Math.abs(point.points || 0) / peak);
      var dot = el("circle", {
        cx: xAt(point.t), cy: y,
        r: 2.5 + weight * 4,
        fill: palette[Math.min(palette.length - 1,
                               Math.floor(weight * palette.length))],
        "fill-opacity": .85,
        stroke: ring, "stroke-width": 1
      });
      hoverable(dot, point.label + " · " + point.service + " · " + point.event
                     + (point.points ? " · +" + point.points : ""));
      box.svg.appendChild(dot);
    });

    // Ends only. Intermediate ticks on a span that can be four seconds or four
    // days would need their own formatting rules to stay honest.
    box.svg.appendChild(text(pad.l, box.h - 8, points[0].label));
    box.svg.appendChild(text(box.w - pad.r, box.h - 8,
                             points[points.length - 1].label, { anchor: "end" }));
  }

  window.DroseraCharts = {
    line: line, bars: bars, hbars: hbars, geomap: geomap, timeline: timeline,
    colours: C
  };
})();
